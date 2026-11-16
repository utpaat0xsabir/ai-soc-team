# TRUST-04E case-152 evidence reconstruction

2026-11-16. Documentation-only TRUST-04E. No cryptographic execution, hashing, signing, installation or profile amendment. All proposed decisions are unapproved.

## Finding and evidence boundary

CASE-152 EVIDENCE: CONFIRMED. IDENTITY-KEY DISCREPANCY: CONFIRMED.
This is confirmation from retained evidence, not an independently repeated execution
or attestation of the old verifier host. No observed production bypass is established.

Compared the original public corpus and saved results byte-for-byte through hex
string equality and decoded byte inspection. Both contain the same exact input.
The source tcId is 152; the harness sorts by tcId, and this is coincidentally execution
position 152, not an identifier inferred from a list index. Source location is
one-based test group 79, test 1. Its group source is
`github/paragonie/sodium_compat/boundary-regressions`, version `2.5.2`.
The containing corpus is commit `a3d5d1423f2592d6646836a45a21a1b209da9f4d`.

| Item | Retained evidence |
| --- | --- |
| Original file | [public corpus](../../tests/iam/fixtures/trust04c_public_vectors/wycheproof-ed25519-a3d5d142.json), testGroups[78].tests[0].tcId |
| Actual result | [results.json](../../tests/iam/fixtures/trust04d_offline_validation/results.json), wycheproof entry with tcId=152 |
| Source verdict / flag | acceptable / SmallOrderPublicKey |
| Source comment | identity public key universal forgery |
| Actual / exception | ACCEPT / null |
| Project expectation | REJECT, PROFILE_INCOMPATIBLE |
| Python | 3.10.12 |
| Dependencies | cryptography 50.0.2; cffi 2.0.0; pycparser 2.22; typing-extensions 4.15.0 |
| Backend reported by harness | OpenSSL 4.0.3 29 Sep 2026 |
| Input message | Raw seven ASCII bytes `message`; no IAM label, length or canonical body |
| Application diagnostic | None executed; profile_expectation/classification are harness annotations |

Exact public, non-secret TEST bytes (hex; no private material):

```text
public_key: 0100000000000000000000000000000000000000000000000000000000000000
message:    6d657373616765
signature:  58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000
```

Decoded lengths are 32, 7 and 64 bytes. Public key is the canonical identity encoding:
y=1, x sign bit zero. Signature R is the standard encoded base point; scalar S is
little-endian one. These are byte-level identifications, not newly executed curve
operations or signature verification.

## Harness reconstruction

[compatibility.py](../../tests/iam/fixtures/trust04d_offline_validation/compatibility.py),
function verify, decodes hex, calls Ed25519PublicKey.from_public_bytes, then
verify(signature, message). Returning normally means ACCEPT; exceptions mean REJECT
and an exception class. The constructor result was not subject to a separate point
or subgroup validator. The harness classifies small/mixed-order flags as strict
REJECT; it does not implement subgroup validation. No root pins, quorum, domain,
tenant, canonical-body, revocation or IAM admission checks ran.

The saved run contains three passing RFC vectors, followed by 88 valid accepted,
63 invalid rejected and this one acceptable accepted case. It stopped immediately.
The remaining 58 results are absent, not failures or passes. Earlier NOT_RUN sections
in TRUST-04D reports are historical; their later continuation records installation
and results. Use the continuation and machine evidence together.

## Causal assessment

| Proposed explanation | Evidence classification | Conclusion / limit |
| --- | --- | --- |
| Identity public key accepted on these exact bytes | CONFIRMED_BY_EXISTING_EVIDENCE | Saved normal API return; no exception; key matches source |
| Missing strict application key-validation boundary | CONFIRMED_BY_EXISTING_EVIDENCE | Static harness has no such step; library call did not enforce nonidentity here |
| Canonical low-order key, rather than merely a malformed length | SUPPORTED_BY_AUTHORITATIVE_SOURCE | Corpus flag/notes and RFC encoding interpretation; identity is order one |
| Noncanonical key encoding or out-of-range scalar caused this case | UNRESOLVED as a general backend issue; not supported for this case | Observed encoding is canonical, S=1; other cases require tests |
| Pure equation can hold without possession under identity A | SUPPORTED_BY_AUTHORITATIVE_SOURCE | With A=identity, R=B and S=1, the kA term vanishes for either RFC equation; conceptual explanation only |
| Backend specifically selected the cofactored equation | HYPOTHESIS_REQUIRING_TEST | This case satisfies either equation and cannot distinguish implementations |
| Specific OpenSSL source defect or all-version behavior | UNRESOLVED | Backend version string and one observation do not establish internal path/build or general vulnerability |
| Harness used a wrong message or transformed signature | Not supported by inspected evidence | Source and results exact equality; raw message passed directly |

ROOT CAUSE: CONFIRMED at the acceptance-boundary level: equation verification without
an effective project-required nonidentity-key gate admitted this input. Internal
OpenSSL equation/path attribution remains UNRESOLVED. No blanket library-unsafety
or complete strict-profile conformance conclusion follows.

Primary-source ledger and boundary alternatives are in the
[boundary review](iam03c-trust04e-strict-ed25519-verification-boundary.md).
