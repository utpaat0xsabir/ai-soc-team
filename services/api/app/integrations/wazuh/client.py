from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4
import re
import ssl

import httpx

from app.integrations.wazuh.cursor import WazuhCursor, validate_sort_values


class WazuhIndexerError(Exception):
    """Raised when a Wazuh Indexer operation fails."""

    def __init__(self, code: str, *, retryable: bool = False):
        super().__init__(code)
        self.retryable = retryable


def alert_query_fingerprint(index_names, source_filter, query_context=None):
    """Stable snapshot query identity, also used to verify legacy checkpoints."""
    return hashlib.sha256(json.dumps({
        'indices': tuple(sorted(index_names)), 'scope': source_filter,
        'sort': ['timestamp', '_index', 'id'], 'version': 1,
        'context': query_context,
    }, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _json_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _json_constant(value: str):
    raise ValueError()


class WazuhIndexerClient:
    """
    Read-only client for the Wazuh Indexer.

    Only alert-search operations are exposed.
    No document creation, update, or deletion methods are provided.
    """

    def __init__(
        self,
        *,
        base_url: str,
        username: str,
        password: str,
        ca_certificate: str,
        timeout: float = 15.0,
        max_page_size: int = 100,
    ):
        if not base_url.startswith("https://"):
            raise ValueError("wazuh_indexer_requires_https")

        if not username or not password:
            raise ValueError("wazuh_indexer_credentials_required")

        if timeout <= 0:
            raise ValueError("invalid_wazuh_timeout")

        if not 1 <= max_page_size <= 1000:
            raise ValueError("invalid_wazuh_max_page_size")

        ca_path = Path(ca_certificate)

        if not ca_path.is_file():
            raise ValueError("wazuh_ca_certificate_not_found")

        self.base_url = base_url.rstrip("/")
        self.max_page_size = max_page_size

        ssl_context = ssl.create_default_context(
            cafile=str(ca_path)
        )

        self._client = httpx.Client(
            auth=(username, password),
            verify=ssl_context,
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _snapshot_request(self, method: str, path: str, **kwargs) -> dict:
        """Bound response bytes and suppress upstream secrets in exceptions."""
        try:
            with self._client.stream(method, f"{self.base_url}{path}", **kwargs) as response:
                if response.status_code == 404 and path == "/_search":
                    raise WazuhIndexerError("wazuh_snapshot_expired", retryable=True) from None
                response.raise_for_status()
                content = bytearray()
                for chunk in response.iter_bytes(chunk_size=65536):
                    if len(content) + len(chunk) > 8 * 1024 * 1024:
                        raise WazuhIndexerError("wazuh_indexer_invalid_response") from None
                    content.extend(chunk)
                data = json.loads(content, object_pairs_hook=_json_object,
                                  parse_constant=_json_constant)
                if not isinstance(data, dict):
                    raise ValueError()
                return data
        except httpx.HTTPStatusError as exc:
            raise WazuhIndexerError("wazuh_indexer_request_failed", retryable=(
                method != 'DELETE' and exc.response.status_code in (429, 502, 503, 504))) from None
        except httpx.HTTPError:
            raise WazuhIndexerError("wazuh_indexer_connection_failed", retryable=method != 'DELETE') from None
        except (ValueError, UnicodeError, RecursionError):
            raise WazuhIndexerError("wazuh_indexer_invalid_response") from None

    @contextmanager
    def alert_snapshot(
        self, *, tenant_id: UUID, integration_id: UUID,
        index_names: tuple[str, ...], window_start_ms: int, window_end_ms: int,
        source_filter: dict, query_context: dict | None = None,
    ):
        """Open an internal, tenant-context-bound read-only alert scan.

        The caller must authorize the integration and supply its trustworthy
        upstream scope. Explicit match_all is suitable only for dedicated sources.
        Concrete indices are mandatory; discovery/UUID verification belongs to
        the integration service. Context release deletes no source documents.
        """
        scan = _WazuhAlertSnapshot(
            self, tenant_id, integration_id, index_names,
            window_start_ms, window_end_ms, source_filter, query_context,
        )
        try:
            scan._open()
            yield scan
        except BaseException:
            try:
                scan.close()
            except WazuhIndexerError:
                # Keep the primary failure; the context also expires after 1m.
                pass
            raise
        else:
            scan.close()

    def inspect_alert_indices(self, *, scope_field: str | None = None,
                              scope_value: str | None = None) -> dict[str, str]:
        """Resolve concrete index identities and compatible sort mappings.

        No permission fallback: unavailable metadata prevents synchronization.
        """
        fields = {"timestamp": "date", "id": "keyword"}
        if scope_field is not None:
            if (not isinstance(scope_field, str) or len(scope_field) > 200
                    or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*", scope_field) is None
                    or scope_field == 'timestamp'):
                raise WazuhIndexerError("wazuh_indexer_invalid_metadata") from None
            fields[scope_field] = 'keyword'
        settings = self._snapshot_request("GET", "/wazuh-alerts-*/_settings/index.uuid")
        mappings = self._snapshot_request("GET", f"/wazuh-alerts-*/_mapping/field/{','.join(fields)}")
        try:
            if not 1 <= len(settings) <= 100 or set(settings) != set(mappings):
                raise ValueError()
            manifest = {}
            for name, data in settings.items():
                if len(name) > 255 or re.fullmatch(r"wazuh-alerts-[a-z0-9._-]+", name) is None:
                    raise ValueError()
                identity = data["settings"]["index"]["uuid"]
                if not isinstance(identity, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity) is None:
                    raise ValueError()
                for field, kind in fields.items():
                    definitions = mappings[name]["mappings"][field]["mapping"]
                    definition = definitions.get(field, definitions.get(field.split('.')[-1]))
                    if definition.get("type") != kind or definition.get("doc_values", True) is not True:
                        raise ValueError()
                    if field == scope_field and definition.get('normalizer') is not None:
                        raise ValueError()
                    if field == scope_field:
                        if definition.get('index', True) is not True:
                            raise ValueError()
                        threshold = definition.get('ignore_above')
                        if threshold is not None and (type(threshold) is not int
                                or (scope_value is not None and len(scope_value) > threshold)):
                            raise ValueError()
                manifest[name] = identity
            return manifest
        except (KeyError, TypeError, AttributeError, ValueError):
            raise WazuhIndexerError("wazuh_indexer_invalid_metadata") from None

    def search_alerts(
        self,
        *,
        size: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Retrieve a bounded page of Wazuh alerts."""

        if not 1 <= size <= self.max_page_size:
            raise ValueError("invalid_wazuh_page_size")

        if not 0 <= offset <= 9900:
            raise ValueError("invalid_wazuh_offset")

        try:
            response = self._client.get(
                f"{self.base_url}/wazuh-alerts-*/_search",
                params={
                    "size": size,
                    "from": offset,
                },
            )
            response.raise_for_status()
            data = response.json()

        except httpx.HTTPStatusError as exc:
            raise WazuhIndexerError(
                "wazuh_indexer_request_failed"
            ) from exc

        except httpx.RequestError as exc:
            raise WazuhIndexerError(
                "wazuh_indexer_connection_failed"
            ) from exc

        except ValueError as exc:
            raise WazuhIndexerError(
                "wazuh_indexer_invalid_response"
            ) from exc

        if not isinstance(data, dict):
            raise WazuhIndexerError(
                "wazuh_indexer_invalid_response"
            )

        hits_container = data.get("hits")

        if not isinstance(hits_container, dict):
            raise WazuhIndexerError(
                "wazuh_indexer_invalid_response"
            )

        hits = hits_container.get("hits")

        if not isinstance(hits, list):
            raise WazuhIndexerError(
                "wazuh_indexer_invalid_response"
            )

        total_data = hits_container.get("total", 0)

        if isinstance(total_data, dict):
            total = total_data.get("value", 0)
        else:
            total = total_data

        if (
            not isinstance(total, int)
            or isinstance(total, bool)
            or total < 0
        ):
            raise WazuhIndexerError(
                "wazuh_indexer_invalid_response"
            )

        alerts = [
            normalize_wazuh_alert(hit)
            for hit in hits
        ]

        return {
            "items": alerts,
            "total": total,
            "size": size,
            "offset": offset,
        }


def _complete_shards(data: dict) -> bool:
    shards = data.get("_shards")
    if not isinstance(shards, dict):
        return False
    values = [shards.get(name) for name in ("total", "successful", "skipped", "failed")]
    if not all(type(value) is int and value >= 0 for value in values):
        return False
    total, successful, skipped, failed = values
    return total > 0 and successful == total and failed == 0 and skipped <= successful


def _pit_token(value: object) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= 65536
            and all(33 <= ord(char) <= 126 for char in value))


class _WazuhAlertSnapshot:
    """One PIT lifetime. Opaque tokens are private and excluded from results/repr."""

    def __init__(self, client, tenant_id, integration_id, index_names,
                 window_start_ms, window_end_ms, source_filter, query_context=None):
        if (not isinstance(index_names, tuple) or not 1 <= len(index_names) <= 100
                or not all(isinstance(name, str) and len(name) <= 255
                           and re.fullmatch(r"wazuh-alerts-[a-z0-9._-]+", name)
                           for name in index_names)
                or len(set(index_names)) != len(index_names)
                or not isinstance(source_filter, dict) or not source_filter):
            raise ValueError("invalid_wazuh_snapshot")
        try:
            scope = json.dumps(source_filter, sort_keys=True, separators=(",", ":"), allow_nan=False)
            if len(scope.encode("utf-8")) > 16384:
                raise ValueError()
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise ValueError("invalid_wazuh_snapshot") from None
        self._indices = tuple(sorted(index_names))
        self._scope = scope
        fingerprint = alert_query_fingerprint(self._indices, json.loads(scope), query_context)
        # Reuse the strict context contract, including bounds and UUID checks.
        self._context = WazuhCursor(
            tenant_id=tenant_id, integration_id=integration_id,
            query_fingerprint=fingerprint, generation=0,
            window_start_ms=window_start_ms, window_end_ms=window_end_ms,
            snapshot_id=uuid4(), sort_values=(window_start_ms, self._indices[0], "initial"),
        )
        self._client = client
        self._token = None
        self._closed = False

    @property
    def snapshot_id(self):
        return self._context.snapshot_id

    @property
    def query_fingerprint(self):
        return self._context.query_fingerprint

    def _open(self):
        data = self._client._snapshot_request(
            "POST", f"/{','.join(self._indices)}/_search/point_in_time",
            params={"keep_alive": "1m", "allow_partial_pit_creation": "false",
                    "ignore_unavailable": "false"},
        )
        token = data.get("pit_id")
        if not _pit_token(token):
            raise WazuhIndexerError("wazuh_indexer_invalid_response") from None
        self._token = token  # Retain for cleanup even if coverage validation fails.
        if not _complete_shards(data):
            raise WazuhIndexerError("wazuh_indexer_invalid_response") from None
        self._shard_count = data["_shards"]["total"]

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._token is None:
            return
        token, self._token = self._token, None
        data = self._client._snapshot_request(
            "DELETE", "/_search/point_in_time", json={"pit_id": [token]},
        )
        pits = data.get("pits")
        if (not isinstance(pits, list) or len(pits) != 1
                or not isinstance(pits[0], dict) or pits[0].get("pit_id") != token
                or pits[0].get("successful") is not True):
            raise WazuhIndexerError("wazuh_snapshot_cleanup_failed") from None

    def page(self, *, size: int = 50, cursor: WazuhCursor | None = None,
             generation: int = 0) -> dict:
        if self._closed or self._token is None:
            raise ValueError("wazuh_snapshot_closed")
        if type(size) is not int or not 1 <= size <= min(100, self._client.max_page_size):
            raise ValueError("invalid_wazuh_page_size")
        context = self._context
        args = dict(
            tenant_id=context.tenant_id, integration_id=context.integration_id,
            query_fingerprint=context.query_fingerprint, generation=generation,
            window_start_ms=context.window_start_ms, window_end_ms=context.window_end_ms,
            snapshot_id=context.snapshot_id,
        )
        # Validate generation even on the first page, before making a request.
        WazuhCursor(**args, sort_values=context.sort_values)
        if cursor is not None:
            if not isinstance(cursor, WazuhCursor):
                raise ValueError("invalid_wazuh_cursor")
            WazuhCursor.deserialize(cursor.serialize(), **args)
        query = {"size": size + 1, "track_total_hits": False,
                 "pit": {"id": self._token, "keep_alive": "1m"},
                 "sort": [{"timestamp": "asc"}, {"_index": "asc"}, {"id": "asc"}],
                 "query": {"bool": {"filter": [json.loads(self._scope), {
                     "bool": {"should": [
                         {"range": {"timestamp": {"gte": context.window_start_ms,
                                                   "lt": context.window_end_ms,
                                                   "format": "epoch_millis"}}},
                         {"bool": {"must_not": [{"exists": {"field": "timestamp"}}]}},
                     ], "minimum_should_match": 1}
                 }]}}}
        if cursor is not None:
            query["search_after"] = list(cursor.sort_values)
        data = self._client._snapshot_request(
            "POST", "/_search", params={"allow_partial_search_results": "false"}, json=query,
        )
        if "pit_id" in data:
            if not _pit_token(data["pit_id"]):
                raise WazuhIndexerError("wazuh_indexer_invalid_response") from None
            self._token = data["pit_id"]
        if (data.get("timed_out") is not False or not _complete_shards(data)
                or data["_shards"]["total"] != self._shard_count):
            raise WazuhIndexerError("wazuh_indexer_invalid_response") from None
        container = data.get("hits")
        hits = container.get("hits") if isinstance(container, dict) else None
        if not isinstance(hits, list) or len(hits) > size + 1:
            raise WazuhIndexerError("wazuh_indexer_invalid_response") from None
        normalized = []
        previous = cursor.sort_values if cursor is not None else None
        positions = []
        try:
            # Validate the extra hit as well; never advance past a tied boundary.
            for hit in hits:
                if not isinstance(hit, dict):
                    raise ValueError()
                position = validate_sort_values(hit.get("sort"))
                WazuhCursor(**args, sort_values=position)
                if previous is not None and position <= previous:
                    raise ValueError()
                if hit.get("_index") not in self._indices or position[1] != hit.get("_index"):
                    raise ValueError()
                source = hit.get("_source")
                if not isinstance(source, dict) or source.get("id") != position[2]:
                    raise ValueError()
                alert = normalize_wazuh_alert(hit)
                event_time = alert["event_time"]
                if event_time is None:
                    raise ValueError()
                delta = event_time.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
                millis = delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000
                if millis != position[0]:
                    raise ValueError()
                previous = position
                positions.append(position)
                normalized.append(alert)
        except (ValueError, TypeError, OverflowError, WazuhIndexerError):
            raise WazuhIndexerError("wazuh_indexer_invalid_response") from None
        emitted = min(size, len(normalized))
        next_cursor = (WazuhCursor(**args, sort_values=positions[emitted - 1])
                       if emitted else cursor)
        return {"items": normalized[:emitted], "next_cursor": next_cursor,
                "exhausted": not hits}


def parse_wazuh_timestamp(value: Any) -> datetime | None:
    """Parse a timezone-aware Wazuh timestamp."""

    if not isinstance(value, str) or not value:
        return None

    normalized = value.strip()

    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    # Python 3.10 compatibility: convert +0530 to +05:30.
    normalized = re.sub(
        r"([+-]\d{2})(\d{2})$",
        r"\1:\2",
        normalized,
    )

    try:
        parsed = datetime.fromisoformat(normalized)

        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None

        return parsed

    except ValueError:
        return None


def normalize_wazuh_alert(
    document: dict[str, Any],
) -> dict[str, Any]:
    """
    Normalize searchable Wazuh alert fields.

    Preserve the complete original document for evidence provenance.
    """

    if not isinstance(document, dict):
        raise WazuhIndexerError(
            "wazuh_alert_invalid_document"
        )

    index = document.get("_index")
    document_id = document.get("_id")
    source = document.get("_source")

    if not isinstance(index, str) or not index:
        raise WazuhIndexerError(
            "wazuh_alert_missing_index"
        )

    if not isinstance(document_id, str) or not document_id:
        raise WazuhIndexerError(
            "wazuh_alert_missing_document_id"
        )

    if not isinstance(source, dict):
        raise WazuhIndexerError(
            "wazuh_alert_missing_source"
        )

    rule = source.get("rule")
    agent = source.get("agent")
    manager = source.get("manager")

    if not isinstance(rule, dict):
        rule = {}

    if not isinstance(agent, dict):
        agent = {}

    if not isinstance(manager, dict):
        manager = {}

    groups = rule.get("groups", [])

    if not isinstance(groups, list):
        groups = []

    return {
        "source_type": "wazuh",
        "source_reference": f"{index}/{document_id}",
        "event_time": parse_wazuh_timestamp(
            source.get("timestamp")
        ),
        "rule": {
            "id": rule.get("id"),
            "level": rule.get("level"),
            "description": rule.get("description"),
            "groups": groups,
        },
        "agent": {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "ip": agent.get("ip"),
        },
        "manager": {
            "name": manager.get("name"),
        },
        "location": source.get("location"),
        "decoder": source.get("decoder"),
        "full_log": source.get("full_log"),
        "raw_document": document,
    }
