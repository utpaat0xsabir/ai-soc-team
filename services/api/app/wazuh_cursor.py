"""Internal cursor contract for the candidate timestamp/index/id sort.

Not an authentication token or a claim that source IDs are unique. Callers must
load the authoritative checkpoint through a tenant-scoped query and supply its
context. Snapshot IDs identify local PIT lifetimes, never raw Indexer PIT IDs.
"""

import json
import re
from dataclasses import asdict, dataclass, replace
from uuid import UUID


MAX_TIMESTAMP_MS = 253402300799999
MAX_CURSOR_BYTES = 8192
SortValues = tuple[int, str, str]


def _invalid() -> ValueError:
    return ValueError("invalid_wazuh_cursor")


def _integer(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _text(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return len(value.encode("utf-8")) <= 512 and all(
            ord(char) >= 32 and ord(char) != 127 for char in value
        )
    except UnicodeError:
        return False


def validate_sort_values(value: object) -> SortValues:
    """Validate epoch-millisecond, index, and keyword-ID values without coercion."""
    if (
        not isinstance(value, (list, tuple))
        or len(value) != 3
        or not _integer(value[0], MAX_TIMESTAMP_MS)
        or not _text(value[1])
        or not _text(value[2])
    ):
        raise _invalid()
    return tuple(value)


def _unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _invalid()
        result[key] = value
    return result


@dataclass(frozen=True)
class WazuhCursor:
    tenant_id: UUID
    integration_id: UUID
    query_fingerprint: str
    generation: int
    window_start_ms: int
    window_end_ms: int
    snapshot_id: UUID
    sort_values: SortValues
    version: int = 1

    def __post_init__(self) -> None:
        if (
            type(self.version) is not int or self.version != 1
            or not all(isinstance(value, UUID) for value in (
                self.tenant_id, self.integration_id, self.snapshot_id
            ))
            or not isinstance(self.query_fingerprint, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.query_fingerprint) is None
            or not _integer(self.generation, 2**63 - 1)
            or not _integer(self.window_start_ms, MAX_TIMESTAMP_MS)
            or not _integer(self.window_end_ms, MAX_TIMESTAMP_MS)
            or self.window_start_ms >= self.window_end_ms
        ):
            raise _invalid()
        position = validate_sort_values(self.sort_values)
        if not self.window_start_ms <= position[0] < self.window_end_ms:
            raise _invalid()
        object.__setattr__(self, "sort_values", position)

    def advance(self, values: object) -> "WazuhCursor":
        """Return a new cursor; reject ties as well as backwards movement."""
        position = validate_sort_values(values)
        if position <= self.sort_values:
            raise _invalid()
        return replace(self, sort_values=position)

    def serialize(self) -> str:
        data = asdict(self)
        for name in ("tenant_id", "integration_id", "snapshot_id"):
            data[name] = str(data[name])
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    @classmethod
    def deserialize(
        cls,
        value: str,
        *,
        tenant_id: UUID,
        integration_id: UUID,
        query_fingerprint: str,
        generation: int,
        window_start_ms: int,
        window_end_ms: int,
        snapshot_id: UUID,
    ) -> "WazuhCursor":
        """Decode internal storage and bind it to authoritative checkpoint context.

        This is deliberately unsigned: never accept it as public authorization.
        The context must come from the database, not the serialized document.
        """
        try:
            if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_CURSOR_BYTES:
                raise _invalid()
            data = json.loads(value, object_pairs_hook=_unique_object)
            if not isinstance(data, dict) or set(data) != set(cls.__dataclass_fields__):
                raise _invalid()
            for name in ("tenant_id", "integration_id", "snapshot_id"):
                if not isinstance(data[name], str):
                    raise _invalid()
                data[name] = UUID(data[name])
            result = cls(**data)
            # Validate the supplied context too (e.g. bool must not equal int).
            expected = cls(
                tenant_id=tenant_id, integration_id=integration_id,
                query_fingerprint=query_fingerprint, generation=generation,
                window_start_ms=window_start_ms, window_end_ms=window_end_ms,
                snapshot_id=snapshot_id, sort_values=result.sort_values,
            )
            if result != expected:
                raise _invalid()
            return result
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise _invalid() from None
