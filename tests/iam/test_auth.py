from uuid import uuid4

import pytest
from fastapi import HTTPException

from types import SimpleNamespace

from app.iam.auth import get_current_principal
from app.iam.api_keys import generate_api_key
from app.iam.auth import get_current_tenant


class FakeDB:
    """Small database substitute for authentication unit tests."""

    def __init__(self, result=None):
        self.result = result
        self.statement = None

    def scalar(self, statement):
        self.statement = statement
        return self.result


def test_valid_api_key_returns_tenant_id():
    tenant_id = uuid4()
    api_key = generate_api_key()
    db = FakeDB(result=tenant_id)

    result = get_current_tenant(
        x_api_key=api_key,
        db=db,
    )

    assert result == tenant_id
    assert db.statement is not None


def test_missing_api_key_is_rejected():
    db = FakeDB()

    with pytest.raises(HTTPException) as exc:
        get_current_tenant(
            x_api_key=None,
            db=db,
        )

    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid_api_key"


def test_malformed_api_key_is_rejected():
    db = FakeDB()

    with pytest.raises(HTTPException) as exc:
        get_current_tenant(
            x_api_key="invalid_key",
            db=db,
        )

    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid_api_key"


def test_unknown_or_revoked_api_key_is_rejected():
    api_key = generate_api_key()
    db = FakeDB(result=None)

    with pytest.raises(HTTPException) as exc:
        get_current_tenant(
            x_api_key=api_key,
            db=db,
        )

    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid_api_key"


def test_valid_api_key_returns_authenticated_principal():
    tenant_id = uuid4()
    api_key_id = uuid4()
    api_key = generate_api_key()

    db = FakeDB(
        result=SimpleNamespace(
            id=api_key_id,
            tenant_id=tenant_id,
        )
    )

    result = get_current_principal(
        x_api_key=api_key,
        db=db,
    )

    assert result.tenant_id == tenant_id
    assert result.api_key_id == api_key_id
    assert db.statement is not None


def test_principal_rejects_missing_api_key():
    db = FakeDB()

    with pytest.raises(HTTPException) as exc:
        get_current_principal(
            x_api_key=None,
            db=db,
        )

    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid_api_key"


def test_principal_rejects_unknown_or_revoked_api_key():
    db = FakeDB(result=None)

    with pytest.raises(HTTPException) as exc:
        get_current_principal(
            x_api_key=generate_api_key(),
            db=db,
        )

    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid_api_key"
