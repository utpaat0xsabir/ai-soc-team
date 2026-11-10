import certifi
from pathlib import Path

import httpx
import pytest

from app.wazuh import (
    WazuhIndexerClient,
    WazuhIndexerError,
    normalize_wazuh_alert,
    parse_wazuh_timestamp,
)


@pytest.fixture
def ca_file():
    ca_path = certifi.where()

    if not Path(ca_path).is_file():
        pytest.fail("Certifi CA bundle is unavailable")

    return ca_path


def sample_document():
    return {
        "_index": "wazuh-alerts-4.x-2026.11.09",
        "_id": "sample-alert-001",
        "_source": {
            "timestamp": "2026-11-09T13:59:37.087+0530",
            "rule": {
                "id": "5502",
                "level": 3,
                "description": "PAM: Login session closed.",
                "groups": ["pam", "syslog"],
            },
            "agent": {
                "id": "000",
                "name": "mail.godcompl3x.com",
                "ip": "127.0.0.1",
            },
            "manager": {
                "name": "mail.godcompl3x.com",
            },
            "location": "journald",
            "full_log": "Example security event",
        },
        "fields": {
            "timestamp": ["2026-11-09T08:29:37.087Z"]
        },
        "sort": [1794212977087],
    }


def make_mocked_client(ca_file, handler):
    client = WazuhIndexerClient(
        base_url="https://127.0.0.1:9200",
        username="test",
        password="test",
        ca_certificate=ca_file,
    )

    client._client.close()
    client._client = httpx.Client(
        transport=httpx.MockTransport(handler)
    )

    return client


def test_parse_timezone_aware_timestamp():
    result = parse_wazuh_timestamp(
        "2026-11-09T13:59:37.087+0530"
    )

    assert result is not None
    assert result.utcoffset().total_seconds() == 19800


def test_parse_invalid_or_naive_timestamp():
    assert parse_wazuh_timestamp("invalid") is None
    assert parse_wazuh_timestamp("2026-11-09T13:59:37") is None
    assert parse_wazuh_timestamp(None) is None


def test_normalize_wazuh_alert():
    document = sample_document()

    result = normalize_wazuh_alert(document)

    assert result["source_type"] == "wazuh"
    assert result["source_reference"] == (
        "wazuh-alerts-4.x-2026.11.09/sample-alert-001"
    )

    assert result["rule"]["id"] == "5502"
    assert result["rule"]["level"] == 3
    assert result["agent"]["name"] == "mail.godcompl3x.com"
    assert result["event_time"] is not None

    # Original document remains complete.
    assert result["raw_document"] == document
    assert result["raw_document"]["fields"] == document["fields"]
    assert result["raw_document"]["sort"] == document["sort"]


def test_normalize_rejects_missing_document_id():
    document = sample_document()
    del document["_id"]

    with pytest.raises(WazuhIndexerError):
        normalize_wazuh_alert(document)


def test_client_rejects_http_url(ca_file):
    with pytest.raises(ValueError):
        WazuhIndexerClient(
            base_url="http://127.0.0.1:9200",
            username="test",
            password="test",
            ca_certificate=ca_file,
        )


def test_client_rejects_missing_ca():
    with pytest.raises(ValueError):
        WazuhIndexerClient(
            base_url="https://127.0.0.1:9200",
            username="test",
            password="test",
            ca_certificate="/nonexistent/root-ca.pem",
        )


def test_client_rejects_invalid_page_size(ca_file):
    client = WazuhIndexerClient(
        base_url="https://127.0.0.1:9200",
        username="test",
        password="test",
        ca_certificate=ca_file,
    )

    try:
        with pytest.raises(
            ValueError,
            match="invalid_wazuh_page_size",
        ):
            client.search_alerts(size=5000)
    finally:
        client.close()


def test_search_alerts_success(ca_file):
    document = sample_document()

    def handler(request):
        assert request.method == "GET"
        assert request.url.path.endswith(
            "/wazuh-alerts-*/_search"
        )
        assert request.url.params["size"] == "10"
        assert request.url.params["from"] == "0"

        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {
                        "value": 1,
                        "relation": "eq",
                    },
                    "hits": [document],
                }
            },
        )

    client = make_mocked_client(ca_file, handler)

    try:
        result = client.search_alerts(size=10)

        assert result["total"] == 1
        assert len(result["items"]) == 1
        assert result["items"][0]["rule"]["id"] == "5502"
    finally:
        client.close()


def test_search_alerts_handles_http_error(ca_file):
    def handler(request):
        return httpx.Response(
            403,
            json={"error": "forbidden"},
        )

    client = make_mocked_client(ca_file, handler)

    try:
        with pytest.raises(
            WazuhIndexerError,
            match="wazuh_indexer_request_failed",
        ):
            client.search_alerts()
    finally:
        client.close()


def test_search_alerts_rejects_malformed_response(ca_file):
    def handler(request):
        return httpx.Response(
            200,
            json={"unexpected": "response"},
        )

    client = make_mocked_client(ca_file, handler)

    try:
        with pytest.raises(
            WazuhIndexerError,
            match="wazuh_indexer_invalid_response",
        ):
            client.search_alerts()
    finally:
        client.close()
