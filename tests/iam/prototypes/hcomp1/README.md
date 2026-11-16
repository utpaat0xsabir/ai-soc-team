# H-COMP-1 TEST-only verifier prototype

This isolated prototype validates one Ed25519 public key/signature/message tuple. It is not imported by application code and does not implement trust anchors, tenant binding, custodian quorum, ROOT_POLICY parsing, the IAM diagnostics, or authorization.

It uses the exact pinned `curve25519-dalek 4.1.3` and `ed25519-dalek 2.2.0` dependency graph from the isolated toolchain audit. A/R encoding is checked by decompressing and re-encoding the original bytes, subgroup membership by `is_torsion_free`, A identity is rejected, R identity is allowed at point validation, and S is checked with `Scalar::from_canonical_bytes`. It then uses the ordinary pure `Verifier::verify` entry point, never `verify_strict`. The cached source describes this path as recomputing and byte-comparing `R = [S]B - [k]A` with `k = SHA-512(R || A || M)`; this is implementation-source evidence, not independent review.

The implementation preserves the exact A, signature, and message bytes across stages. It fails closed on backend errors or byte changes. A successful result means only that this isolated signature equation passed these checks; it does not establish signer identity, quorum, trusted authority, or IAM permission.

## Offline tests

From this directory, with the isolated environment:

```sh
export RUSTUP_HOME="$HOME/ai-soc-hcomp1-toolchain/rustup"
export CARGO_HOME="$HOME/ai-soc-hcomp1-toolchain/cargo"
export PATH="$CARGO_HOME/bin:$PATH"
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/target"
python3 tests/prepare_vectors.py
cargo test --offline --locked -- --nocapture
```

The Python standard-library helper only extracts IDs, source verdicts, flags, and exact public bytes from the unchanged TRUST-04C files. It performs no cryptographic operation. The TSV uses `-` only to represent an empty hex field. For Wycheproof, valid requires acceptance, invalid requires rejection, and acceptable cases are expected to reject only when the source flag identifies an A point forbidden by the frozen profile; any other acceptable case is reported `REVIEW_REQUIRED`.

This is experimental TEST evidence only. No production keys, anchors, or IAM paths are used.
