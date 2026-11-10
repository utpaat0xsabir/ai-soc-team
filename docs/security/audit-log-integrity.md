# Audit Log Integrity and Security Limitations

## Current protections

The audit log uses multiple integrity controls:

1. PostgreSQL append-only trigger rejects UPDATE, DELETE, and TRUNCATE.
2. Each audit record contains a SHA-256 hash.
3. Each record references the previous record's hash.
4. Sequence numbers are monotonically increasing per tenant.
5. A tenant FOR NO KEY UPDATE row lock serializes concurrent audit writers while
   permitting evidence foreign-key KEY SHARE locks, avoiding a lock-upgrade deadlock.
6. Business operations and their audit records share a database transaction.
7. The verification endpoint checks sequence continuity, previous hashes,
   and recalculated entry hashes.

## Hash-chain verification limitations

The hash chain detects modifications to existing records, broken links,
and missing records in the middle of a chain.

However, verification only examines records currently present in the
database. It cannot independently establish that the latest record
has not been deleted.

For example, if a tenant has records with sequence numbers 1, 2, and 3,
deleting record 3 leaves a valid chain containing records 1 and 2.
Deleting every record also leaves an empty chain that the current
verifier accepts.

Therefore, a successful verification means that the available records
are internally consistent. It does not prove that the complete history
has been preserved.

## Privileged database access

The append-only trigger protects against ordinary UPDATE, DELETE, and
TRUNCATE operations. A sufficiently privileged database administrator
can disable or remove the trigger, modify data, or rewrite the chain.

The hash chain alone is not protection against an attacker who can
rewrite all audit records and recalculate their hashes.

## Future protection: external chain anchoring

To detect tail deletion and privileged database tampering, a future
implementation should periodically export an independently verifiable
checkpoint containing:

- Tenant identifier
- Latest sequence number
- Latest audit entry hash
- Checkpoint creation timestamp
- Digital signature or equivalent authenticity proof

The checkpoint must be stored outside the PostgreSQL trust boundary,
ideally in independently controlled immutable or WORM storage.

Verification can then compare the database's current chain head with
the latest trusted external checkpoint.

## Security terminology

The current implementation provides append-only enforcement for
ordinary database operations and hash-chain integrity verification.

It must not be described as fully tamper-proof or as independently
proving that no audit records have ever been deleted.
