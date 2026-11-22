"""Admission proof supplied by the authenticated host enforcement channel."""
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import re
from time import monotonic


@dataclass(frozen=True)
class AdmissionProof:
    decision_id: str
    run_id: str
    approval_sha256: str
    container_id: str
    database: str
    endpoint: tuple[str, int]
    tls_identity: str
    tls_ca_sha256: str
    instance: tuple[int, datetime, int]
    identities: tuple[str, ...]
    tcp_paths: tuple[tuple[str, int], ...]
    policy_sha256: str
    freeze_sha256: str
    valid_from: datetime
    expires_at: datetime
    stop_by: float
    digest: str

    @classmethod
    def validate(cls, raw, packet, run, approval_digest, stop_by, *, cleanup=False):
        fields = {
            "decision_id", "run_id", "approval_sha256", "container_id", "database", "endpoint",
            "tls_identity", "tls_ca_sha256", "instance", "identities", "tcp_paths", "unix_paths",
            "initial_sessions", "replication", "freeze_held", "policy_sha256", "freeze_sha256",
            "valid_from", "expires_at", "stop_by",
        }
        if type(raw) is not dict or set(raw) != fields:
            raise PermissionError("missing admission proof")
        expected = {
            "decision_id": packet.decision_id, "run_id": run, "approval_sha256": approval_digest,
            "container_id": packet.approved_target.container_id, "database": packet.database,
            "endpoint": list(packet.endpoint), "tls_identity": packet.tls_server_identity,
            "tls_ca_sha256": packet.tls_ca_sha256, "identities": [packet.migrator_login, packet.observer_login],
            "tcp_paths": [list(packet.endpoint)], "unix_paths": [], "initial_sessions": [],
            "freeze_sha256": packet.freeze_sha256,
        }
        if (any(raw[key] != value for key, value in expected.items())
                or len(set(expected["identities"])) != 2 or raw["replication"] is not False
                or raw["freeze_held"] is not True or type(raw["policy_sha256"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", raw["policy_sha256"])):
            raise PermissionError("admission policy or target mismatch")
        version, started, oid = raw["instance"]
        started, valid_from, expires_at = map(datetime.fromisoformat,
                                              (started, raw["valid_from"], raw["expires_at"]))
        now = datetime.now(timezone.utc)
        if (any(value.utcoffset() is None for value in (started, valid_from, expires_at))
                or type(version) is not int or version // 10000 != 16
                or type(oid) is not int or oid <= 0 or started > valid_from
                or not packet.valid_from <= valid_from <= now
                or not valid_from < expires_at <= packet.expires_at
                or type(raw["stop_by"]) not in (int, float) or not math.isfinite(raw["stop_by"])
                or raw["stop_by"] != stop_by
                or not math.isfinite(stop_by)
                or (not cleanup and not 0 < stop_by - monotonic() <= (expires_at - now).total_seconds())):
            raise PermissionError("admission proof expired or invalid")
        digest = sha256(json.dumps(raw, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        return cls(packet.decision_id, run, approval_digest, raw["container_id"], packet.database,
                   packet.endpoint, raw["tls_identity"], raw["tls_ca_sha256"], (version, started, oid),
                   tuple(raw["identities"]), tuple(map(tuple, raw["tcp_paths"])), raw["policy_sha256"],
                   raw["freeze_sha256"], valid_from, expires_at, stop_by, digest)
