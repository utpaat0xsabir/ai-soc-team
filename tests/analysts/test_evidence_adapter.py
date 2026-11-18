"""Trusted offline evidence lookup and L1 admission."""

import json
from uuid import UUID

import pytest

from app.analysts import contracts, inference
from app.analysts.evidence_adapter import EvidenceRejected, TrustedEvidenceAdapter
from app.analysts.orchestration import orchestrate_l1
from app.evidence.hashing import calculate_evidence_hash
from tests.analysts.test_analyst_contracts import NOW, fixture
from tests.analysts.test_analyst_inference import setup


def verified_reference(item=None, **changes):
    item = fixture()[2].evidence[0] if item is None else item
    data = item.model_dump()
    data.update(trust_level="source_verified", **changes)
    data["content_sha256"] = calculate_evidence_hash(
        **{key: data[key] for key in (
            "evidence_type", "source_type", "source_reference", "collector_name",
            "collector_version", "event_time", "trust_level",
        )},
        payload=json.loads(data["payload_json"]),
    )
    return contracts.EvidenceReference.model_validate(data)


def test_tenant_scoped_lookup_preserves_provenance_and_order(monkeypatch):
    import socket

    def network(*args, **kwargs):
        pytest.fail("offline adapter opened a socket")

    monkeypatch.setattr(socket, "socket", network)
    context = fixture()[0]
    first = verified_reference()
    second = verified_reference(evidence_id=UUID(int=42))
    records = {(context.tenant_id, item.evidence_id): item for item in (second, first)}
    foreign = verified_reference(tenant_id=UUID(int=99))
    records[(foreign.tenant_id, foreign.evidence_id)] = foreign

    adapter = TrustedEvidenceAdapter(records)
    assert adapter.load_bundle(context, (second.evidence_id, first.evidence_id)) == (first, second)
    assert adapter.load_bundle(context, (first.evidence_id, second.evidence_id)) == (first, second)
    assert adapter.load_bundle(context, (first.evidence_id,))[0].model_dump() == first.model_dump()


@pytest.mark.parametrize(("changes", "reason"), [
    ({"tenant_id": UUID(int=99)}, "EVIDENCE_SCOPE_MISMATCH"),
    ({"evidence_id": UUID(int=99)}, "EVIDENCE_SCOPE_MISMATCH"),
    ({"content_sha256": "0" * 64}, "HASH_MISMATCH"),
    ({"content_sha256": "malformed"}, "INVALID_EVIDENCE"),
    ({"payload_json": '["secret canary"]'}, "INVALID_EVIDENCE"),
    ({"trust_level": "unverified"}, "UNVERIFIED_EVIDENCE"),
    ({"trust_level": "unknown"}, "UNSUPPORTED_TRUST_LEVEL"),
    ({"source_type": "unknown"}, "UNSUPPORTED_SOURCE"),
    ({"classification": "OBSERVED"}, "UNSUPPORTED_CLASSIFICATION"),
    ({"classification": None}, "UNSUPPORTED_CLASSIFICATION"),
])
def test_ineligible_records_are_rejected_with_safe_reason(changes, reason):
    context = fixture()[0]
    item = verified_reference()
    adapter = TrustedEvidenceAdapter({
        (context.tenant_id, item.evidence_id): item.model_copy(update=changes)
    })
    with pytest.raises(EvidenceRejected) as error:
        adapter.load_bundle(context, (item.evidence_id,))
    assert error.value.reason == reason
    assert str(error.value) == reason


def test_cross_tenant_and_missing_records_have_the_same_denial():
    context = fixture()[0]
    item = verified_reference(tenant_id=UUID(int=99))
    adapter = TrustedEvidenceAdapter({(item.tenant_id, item.evidence_id): item})
    for evidence_id in (item.evidence_id, UUID(int=42)):
        with pytest.raises(EvidenceRejected, match="EVIDENCE_NOT_FOUND"):
            adapter.load_bundle(context, (evidence_id,))


@pytest.mark.parametrize("ids", [(), (UUID(int=0),), ("bad",), (UUID(int=3),) * 2,
                                  tuple(UUID(int=i) for i in range(1, 34))])
def test_invalid_and_oversized_id_requests_fail_before_lookup(ids):
    class ForbiddenLookup(dict):
        def get(self, key):
            pytest.fail("invalid request reached lookup")

    with pytest.raises(EvidenceRejected, match="INVALID_EVIDENCE_IDS"):
        TrustedEvidenceAdapter(ForbiddenLookup()).load_bundle(fixture()[0], ids)


def test_unvalidated_context_is_rejected_before_lookup():
    context = fixture()[0].model_copy(update={"tenant_id": str(UUID(int=1))})
    with pytest.raises(EvidenceRejected, match="INVALID_CONTEXT"):
        TrustedEvidenceAdapter({}).load_bundle(context, (UUID(int=3),))


@pytest.mark.parametrize("outcome", [
    "valid", "missing", "unverified", "observed", "tampered_task", "string_id",
])
def test_l1_loads_adapter_bundle_before_inference(outcome):
    args = setup("L1")
    task = args["task"]
    context = args["context"]
    original = args["snapshot"].evidence[0]
    item = verified_reference(original)
    response = args["provider"].steps[0].data.replace(
        original.content_sha256.encode(), item.content_sha256.encode()
    )
    args["provider"] = inference.FakeModelProvider(
        steps=(inference.FakeStep(data=response, final=True),)
    )
    captured_at = NOW
    snapshot = contracts.build_snapshot(
        context, snapshot_id=task.snapshot_id, captured_at=captured_at, evidence=(item,)
    )
    task = task.model_copy(update={"snapshot_sha256": snapshot.snapshot_sha256})
    if outcome == "unverified":
        item = args["snapshot"].evidence[0]
    elif outcome == "observed":
        item = item.model_copy(update={"classification": "OBSERVED"})
    elif outcome == "tampered_task":
        task = task.model_copy(update={"principal_id": UUID(int=99)})
    elif outcome == "string_id":
        task = task.model_copy(update={"original_evidence_ids": (str(item.evidence_id),)})

    class ForbiddenLookup(dict):
        def get(self, key):
            pytest.fail("invalid task reached lookup")

    if outcome in ("tampered_task", "string_id"):
        records = ForbiddenLookup()
    else:
        records = {} if outcome == "missing" else {(context.tenant_id, item.evidence_id): item}
    result = orchestrate_l1(
        context, task, TrustedEvidenceAdapter(records), args["configuration"],
        args["provider"], args["admission"], args["control"], captured_at=captured_at, at=NOW,
    )
    assert result.status == ("COMPLETED" if outcome == "valid" else "DENIED")
    assert args["provider"].calls == (1 if outcome == "valid" else 0)


def test_bundle_byte_limit_rejects_instead_of_truncating():
    context = fixture()[0]
    large = json.dumps({"text": "x" * 7500})
    records = {}
    for index in range(1, 11):
        item = verified_reference(evidence_id=UUID(int=index), payload_json=large)
        records[(context.tenant_id, item.evidence_id)] = item
    ids = tuple(evidence_id for _, evidence_id in records)
    adapter = TrustedEvidenceAdapter(records)
    assert len(adapter.load_bundle(context, ids[:2])) == 2
    with pytest.raises(EvidenceRejected, match="EVIDENCE_BUNDLE_TOO_LARGE"):
        adapter.load_bundle(context, ids)


def test_unclassified_storage_row_is_never_relabelled_for_offline_inference():
    from app.database.models import EvidenceRecord

    context = fixture()[0]
    item = EvidenceRecord(id=UUID(int=3), tenant_id=context.tenant_id, trust_level="source_verified")
    adapter = TrustedEvidenceAdapter({(context.tenant_id, item.id): item})
    with pytest.raises(EvidenceRejected, match="INVALID_EVIDENCE"):
        adapter.load_bundle(context, (item.id,))
