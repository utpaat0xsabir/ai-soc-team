import argparse
import sys

from sqlalchemy import select

from app.api_keys import generate_api_key, hash_api_key
from app.audit import record_audit_event
from app.db import SessionLocal
from app.models import Tenant, TenantAPIKey


def main():
    parser = argparse.ArgumentParser(
        description="Create an API key for an existing tenant."
    )
    parser.add_argument("--slug", required=True)
    parser.add_argument("--key-name", required=True)
    args = parser.parse_args()

    if not args.key_name.strip():
        parser.error("--key-name cannot be empty")

    api_key = generate_api_key()
    key_hash = hash_api_key(api_key)

    with SessionLocal.begin() as db:
        tenant = db.scalar(
            select(Tenant).where(Tenant.slug == args.slug)
        )

        if tenant is None:
            print("Error: tenant not found.", file=sys.stderr)
            sys.exit(1)

        key_record = TenantAPIKey(
            tenant_id=tenant.id,
            name=args.key_name.strip(),
            key_hash=key_hash,
        )

        db.add(key_record)
        db.flush()

        record_audit_event(
            db,
            tenant_id=tenant.id,
            actor_type="system",
            actor_id=None,
            action="tenant.api_key_provisioned",
            resource_type="api_key",
            resource_id=key_record.id,
            details={
                "key_name": key_record.name,
            },
        )

        tenant_name = tenant.name
        tenant_id = tenant.id
        key_name = key_record.name

    print("API key created successfully.")
    print(f"Tenant: {tenant_name}")
    print(f"Tenant ID: {tenant_id}")
    print(f"Key label: {key_name}")
    print()
    print("COPY THIS KEY NOW. IT WILL NOT BE DISPLAYED AGAIN:")
    print(api_key)


if __name__ == "__main__":
    main()
