# TRUST-04D TEST-only compatibility evidence

Public, non-secret, non-authorizing material. No private keys, operational anchors,
application verifier or production authority. Original TRUST-04C fixtures remain unchanged.

The harness requires copied original public fixtures in a sibling public_vectors directory,
a separately approved disposable environment, and the four exact pinned wheels.
It must run using the network-isolated command recorded in the runtime report.
It intentionally stops on the first frozen-profile incompatibility. It is not TRUST-05.

results.json records all executed cases; unexecuted cases are not passes.
Case 152 is the mandatory stop. No project-specific signatures or goldens were generated.
