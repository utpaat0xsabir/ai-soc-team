# H-COMP-1 public test-vector provenance report

**Classification:** Public, non-secret verification test material; TEST-only and non-authorizing. **Reviewed:** 2026-11-16.
**Scope:** Read-only source retrieval and comparison. No verifier, corpus, TSV, dependency, or frozen specification was modified. The verifier was not run in this provenance task.

## RFC 8032 provenance

- Official RFC Editor publication: [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), retrieved as [`rfc8032.txt`](https://www.rfc-editor.org/rfc/rfc8032.txt) on 2026-11-16; publication identifier RFC 8032, January 2017; Ed25519 vectors are Section 7.1, TEST 1–3.
- Retrieved source SHA-256: `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3` (103210 bytes). Local extracted JSON SHA-256: `fe800b1c0011d9a7ccedec69fabaaef72806e183b216dff699d6d8d2546e32ee` (1848 bytes); manifest records POSIX CRC `1429421017`, which is non-cryptographic and not a publisher hash.
- Comparison normalized only RFC visual line wrapping and ASCII whitespace in hex fields. For each vector, public-key bytes, message bytes (including empty TEST 1), and signature bytes match the official text exactly; no expected values were changed.

| Local vector ID | Official RFC section/vector | Source result | Exact field comparison | Result |
|---|---|---|---|
| `RFC8032-7.1-TEST-1` | `valid` | exact pk/message/signature match | PASS |
| `RFC8032-7.1-TEST-2` | `valid` | exact pk/message/signature match | PASS |
| `RFC8032-7.1-TEST-3` | `valid` | exact pk/message/signature match | PASS |

### Exact RFC fields (hex; message `-` means empty)

| Vector | Public key | Message | Signature |
|---|---|---|---|
| RFC8032-7.1-TEST-1 | `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a` | `-` | `e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b` |
| RFC8032-7.1-TEST-2 | `3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c` | `72` | `92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00` |
| RFC8032-7.1-TEST-3 | `fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025` | `af82` | `6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a` |

## Wycheproof/C2SP provenance

- Intended upstream: [C2SP/wycheproof](https://github.com/C2SP/wycheproof), immutable commit `a3d5d1423f2592d6646836a45a21a1b209da9f4d`, source path `testvectors_v1/ed25519_test.json`.
- Retrieved exact commit-pinned raw file from [raw.githubusercontent.com](https://raw.githubusercontent.com/C2SP/wycheproof/a3d5d1423f2592d6646836a45a21a1b209da9f4d/testvectors_v1/ed25519_test.json) on 2026-11-16. Source SHA-256: `ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3` (172628 bytes).
- Upstream Git blob ID computed from Git blob framing: `3f991dd56496129e3a99b6b486408ef8f3df6945`; manifest value: `3f991dd56496129e3a99b6b486408ef8f3df6945`. They match. Retrieved source bytes compare byte-for-byte equal to the local JSON fixture. The upstream JSON records 210 tests.
- Original upstream verdict distribution: `valid` 117, `invalid` 64, `acceptable` 29. Project profile mapping remains separate: ACCEPT 117, REJECT 93, REVIEW_REQUIRED 0; all 29 `acceptable` rows carry `SmallOrderPublicKey` or `MixedOrderPublicKey` and are rejected under the project key policy. This is not a rewriting of the source verdicts.
- ID audit: exactly 210 rows, exactly 210 unique IDs, complete set `1..=210`, with no duplicate, missing, or unexpected ID.
- Publisher signature: **NOT_VERIFIED**. Exact source revision, bytes, SHA-256, and Git blob identity are reproducible; this work did not establish a cryptographic maintainer signature or independent publisher endorsement. HTTPS retrieval and matching object identity do not prove publisher signing.

### Case-by-case upstream to local TSV comparison

For each row below, comparison covers tcId, public key, message, signature, original verdict, flags, and the separately derived project-profile expected result. The source corpus matches local JSON byte-for-byte, and the TSV was reconstructed in memory using the checked-in extractor rules and matches local TSV bytes exactly. No filtering or source verdict transformation occurred.

| tcId | Original verdict | Project-profile expectation | Upstream flags | Comparison | Result |
|---:|---|---|---|---|---|
| 1 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 2 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 3 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 4 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 5 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 6 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 7 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 8 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 9 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 10 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 11 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 12 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 13 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 14 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 15 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 16 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 17 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 18 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 19 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 20 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 21 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 22 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 23 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 24 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 25 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 26 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 27 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 28 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 29 | invalid | REJECT | `InvalidSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 30 | invalid | REJECT | `TruncatedSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 31 | invalid | REJECT | `TruncatedSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 32 | invalid | REJECT | `TruncatedSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 33 | invalid | REJECT | `SignatureWithGarbage` | exact pk/message/signature/verdict/flags match | PASS |
| 34 | invalid | REJECT | `SignatureWithGarbage` | exact pk/message/signature/verdict/flags match | PASS |
| 35 | invalid | REJECT | `SignatureWithGarbage` | exact pk/message/signature/verdict/flags match | PASS |
| 36 | invalid | REJECT | `SignatureWithGarbage` | exact pk/message/signature/verdict/flags match | PASS |
| 37 | invalid | REJECT | `SignatureWithGarbage` | exact pk/message/signature/verdict/flags match | PASS |
| 38 | invalid | REJECT | `CompressedSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 39 | invalid | REJECT | `CompressedSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 40 | invalid | REJECT | `CompressedSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 41 | invalid | REJECT | `CompressedSignature` | exact pk/message/signature/verdict/flags match | PASS |
| 42 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 43 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 44 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 45 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 46 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 47 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 48 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 49 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 50 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 51 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 52 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 53 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 54 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 55 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 56 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 57 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 58 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 59 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 60 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 61 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 62 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 63 | invalid | REJECT | `SignatureMalleability` | exact pk/message/signature/verdict/flags match | PASS |
| 64 | invalid | REJECT | `SignatureMalleability` | exact pk/message/signature/verdict/flags match | PASS |
| 65 | invalid | REJECT | `SignatureMalleability` | exact pk/message/signature/verdict/flags match | PASS |
| 66 | invalid | REJECT | `SignatureMalleability` | exact pk/message/signature/verdict/flags match | PASS |
| 67 | invalid | REJECT | `SignatureMalleability` | exact pk/message/signature/verdict/flags match | PASS |
| 68 | invalid | REJECT | `SignatureMalleability` | exact pk/message/signature/verdict/flags match | PASS |
| 69 | invalid | REJECT | `SignatureMalleability` | exact pk/message/signature/verdict/flags match | PASS |
| 70 | invalid | REJECT | `SignatureMalleability` | exact pk/message/signature/verdict/flags match | PASS |
| 71 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 72 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 73 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 74 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 75 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 76 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 77 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 78 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 79 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 80 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 81 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 82 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 83 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 84 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 85 | invalid | REJECT | `InvalidKtv` | exact pk/message/signature/verdict/flags match | PASS |
| 86 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 87 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 88 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 89 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 90 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 91 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 92 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 93 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 94 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 95 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 96 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 97 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 98 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 99 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 100 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 101 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 102 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 103 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 104 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 105 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 106 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 107 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 108 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 109 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 110 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 111 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 112 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 113 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 114 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 115 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 116 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 117 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 118 | valid | ACCEPT | `Ktv` | exact pk/message/signature/verdict/flags match | PASS |
| 119 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 120 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 121 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 122 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 123 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 124 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 125 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 126 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 127 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 128 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 129 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 130 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 131 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 132 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 133 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 134 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 135 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 136 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 137 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 138 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 139 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 140 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 141 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 142 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 143 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 144 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 145 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 146 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 147 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 148 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 149 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 150 | valid | ACCEPT | `TinkOverflow` | exact pk/message/signature/verdict/flags match | PASS |
| 151 | invalid | REJECT | `InvalidEncoding` | exact pk/message/signature/verdict/flags match | PASS |
| 152 | acceptable | REJECT | `SmallOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 153 | acceptable | REJECT | `SmallOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 154 | acceptable | REJECT | `SmallOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 155 | acceptable | REJECT | `SmallOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 156 | acceptable | REJECT | `SmallOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 157 | acceptable | REJECT | `SmallOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 158 | acceptable | REJECT | `SmallOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 159 | acceptable | REJECT | `SmallOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 160 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 161 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 162 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 163 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 164 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 165 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 166 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 167 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 168 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 169 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 170 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 171 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 172 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 173 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 174 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 175 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 176 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 177 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 178 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 179 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 180 | acceptable | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |
| 181 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 182 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 183 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 184 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 185 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 186 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 187 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 188 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 189 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 190 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 191 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 192 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 193 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 194 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 195 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 196 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 197 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 198 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 199 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 200 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 201 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 202 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 203 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 204 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 205 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 206 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 207 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 208 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 209 | valid | ACCEPT | `Valid` | exact pk/message/signature/verdict/flags match | PASS |
| 210 | invalid | REJECT | `MixedOrderPublicKey` | exact pk/message/signature/verdict/flags match | PASS |

### tcId 152

- Source tcId: `152`; original verdict: `acceptable`; flag: `SmallOrderPublicKey`; source comment: `identity public key universal forgery`.
- Public key: `0100000000000000000000000000000000000000000000000000000000000000`; message: `6d657373616765`; signature: `58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000`.
- Source and local corpus fields match exactly. Project-profile expected result: REJECT because the key is the prohibited identity/small-order public key; the upstream `acceptable` label remains unchanged.

## Extraction reproducibility

- Extractor: [`tests/prepare_vectors.py`](prepare_vectors.py); source files: local RFC JSON and local commit-pinned Wycheproof JSON. No code was executed because the script writes directly over the protected TSV files.
- Instead, equivalent extraction logic was reproduced in memory and compared byte-for-byte with both TSVs. RFC extraction: PASS; regenerated/local TSV SHA-256 `ef7e1d147aacd35987858421b9ead6cfa5b6de719e7ca8afdc607220cf65a7bb`. Wycheproof extraction: PASS; regenerated/local TSV SHA-256 `0999ed91e329f37fd3285e56f45d390a940597b408d1f31a710edde59f02e92e`.
- Inputs: RFC source text SHA-256 `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3`; local RFC JSON SHA-256 `fe800b1c0011d9a7ccedec69fabaaef72806e183b216dff699d6d8d2546e32ee`; pinned Wycheproof JSON SHA-256 `ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3`. Exact source and output sizes/hashes are recorded above.
- RFC normalization is limited to removal of display line folds and whitespace around hex. TSV fields preserve exact decoded bytes as lowercase hex, with `-` for empty bytes. Wycheproof TSV reconstruction preserves each source field and original verdict; flags are serialized in source order.

## Assurance limits and status

| Assurance claim | Status | Basis / limit |
|---|---|---|
| Local Wycheproof corpus consistent with pinned upstream content | VERIFIED | Byte-for-byte equality; SHA-256 and Git blob object ID match. |
| Immutable Wycheproof revision identified | VERIFIED | Manifest-pinned 40-hex commit retrieved from official C2SP GitHub repository. |
| Three local RFC vectors match official RFC text | VERIFIED | Exact cryptographic fields compared after documented text-layout normalization. |
| TSV extraction reproducible | VERIFIED | In-memory regeneration byte-equal; protected files not overwritten. |
| Upstream publisher signature / endorsement | NOT_VERIFIED | No cryptographic signature verification was performed or established. |
| Independent cryptographic review | PENDING | Provenance comparison is not cryptographic implementation review. |
| Offline H-COMP-1 regression in this task | NOT_RUN | Optional and outside the provenance comparisons performed. |
| Original corpus and verifier modified | NO | Read-only comparison; only this report is created. |

Network requests completed over HTTPS without following redirects; contacted hosts were `www.rfc-editor.org`, `raw.githubusercontent.com`, and `github.com`, all within the authorized allowlist. No package/dependency downloads, application services, databases, or external transfers were used.

**Assessment:** RFC and Wycheproof local vector content is reproducibly matched to the identified public sources. Wycheproof revision and artifact identity are established, but publisher signature authenticity remains unverified. This does not authorize implementation, operational IAM, or production use.
