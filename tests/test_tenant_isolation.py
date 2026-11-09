from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api_keys import generate_api_key, hash_api_key
from app.db import engine, get_db
from app.main import app
from app.models import Tenant, TenantAPIKey


def test_tenant_isolation_and_revoked_key():
    """
    Verify that:
    1. Each API key identifies only its own tenant.
    2. A revoked API key is rejected.
    3. Test data is rolled back and does not persist.
    """

    with engine.connect() as connection:
        outer_transaction = connection.begin()

        db = Session(
            bind=connection,
            join_transaction_mode="create_savepoint",
        )

        previous_override = app.dependency_overrides.get(get_db)

        def override_get_db():
            yield db

        app.dependency_overrides[get_db] = override_get_db

        try:
            # Create two independent tenants.
            tenant_a = Tenant(
                name="Isolation Test Tenant A",
                slug=f"isolation-a-{uuid4().hex}",
            )
            tenant_b = Tenant(
                name="Isolation Test Tenant B",
                slug=f"isolation-b-{uuid4().hex}",
            )

            db.add_all([tenant_a, tenant_b])
            db.flush()

            # Generate separate API keys.
            key_a = generate_api_key()
            key_b = generate_api_key()
            revoked_key = generate_api_key()

            db.add_all([
                TenantAPIKey(
                    tenant_id=tenant_a.id,
                    name="test-key-a",
                    key_hash=hash_api_key(key_a),
                ),
                TenantAPIKey(
                    tenant_id=tenant_b.id,
                    name="test-key-b",
                    key_hash=hash_api_key(key_b),
                ),
                TenantAPIKey(
                    tenant_id=tenant_a.id,
                    name="revoked-test-key",
                    key_hash=hash_api_key(revoked_key),
                    revoked_at=datetime.now(timezone.utc),
                ),
            ])

            db.flush()

            client = TestClient(app)

            # Tenant A must receive Tenant A's identity.
            response_a = client.get(
                "/v1/tenant",
                headers={"X-API-Key": key_a},
            )

            assert response_a.status_code == 200
            assert response_a.json()["id"] == str(tenant_a.id)
            assert response_a.json()["slug"] == tenant_a.slug

            # Tenant B must receive Tenant B's identity.
            response_b = client.get(
                "/v1/tenant",
                headers={"X-API-Key": key_b},
            )

            assert response_b.status_code == 200
            assert response_b.json()["id"] == str(tenant_b.id)
            assert response_b.json()["slug"] == tenant_b.slug

            # Neither response should disclose stored key hashes.
            assert "key_hash" not in response_a.json()
            assert "key_hash" not in response_b.json()

            # A revoked key must not authenticate.
            response_revoked = client.get(
                "/v1/tenant",
                headers={"X-API-Key": revoked_key},
            )

            assert response_revoked.status_code == 401
            assert response_revoked.json()["detail"] == "invalid_api_key"

            print("Tenant A authentication: PASS")
            print("Tenant B authentication: PASS")
            print("Tenant isolation: PASS")
            print("Revoked API key rejection: PASS")
            print("API key hash protection: PASS")

        finally:
            if previous_override is None:
                app.dependency_overrides.pop(get_db, None)
            else:
                app.dependency_overrides[get_db] = previous_override

            db.close()

            if outer_transaction.is_active:
                outer_transaction.rollback()
