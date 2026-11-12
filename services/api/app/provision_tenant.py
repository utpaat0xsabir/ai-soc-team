import argparse
import sys

from sqlalchemy.exc import IntegrityError

from app.iam.api_keys import generate_api_key, hash_api_key
from app.db import SessionLocal
from app.database.models import Tenant, TenantAPIKey


def main():
    parser = argparse.ArgumentParser(
        description="Create a tenant and its first API key."
    )
    parser.add_argument("--name", required=True, help="Organization name")
    parser.add_argument("--slug", required=True, help="Unique tenant slug")
    parser.add_argument(
        "--key-name",
        default="initial-key",
        help="Label for the initial API key",
    )
    args = parser.parse_args()

    api_key = generate_api_key()
    key_hash = hash_api_key(api_key)

    try:
        with SessionLocal.begin() as db:
            tenant = Tenant(
                name=args.name,
                slug=args.slug,
            )
            db.add(tenant)
            db.flush()

            db.add(
                TenantAPIKey(
                    tenant_id=tenant.id,
                    name=args.key_name,
                    key_hash=key_hash,
                )
            )

            tenant_id = tenant.id

    except IntegrityError:
        print(
            "Error: tenant creation failed. The slug may already exist.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("Tenant created successfully.")
    print(f"Tenant ID: {tenant_id}")
    print(f"Tenant name: {args.name}")
    print(f"Tenant slug: {args.slug}")
    print()
    print("API KEY — COPY IT NOW. IT WILL NOT BE DISPLAYED AGAIN:")
    print(api_key)


if __name__ == "__main__":
    main()
