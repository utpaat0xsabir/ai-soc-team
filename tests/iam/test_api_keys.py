import re

import pytest

from app.iam.api_keys import generate_api_key, hash_api_key


def test_generate_api_key_has_expected_prefix():
    key = generate_api_key()

    assert key.startswith("soc_")


def test_generate_api_key_is_random():
    first_key = generate_api_key()
    second_key = generate_api_key()

    assert first_key != second_key


def test_hash_api_key_returns_sha256_hex_digest():
    key = generate_api_key()

    digest = hash_api_key(key)

    assert len(digest) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_hash_api_key_is_deterministic():
    key = generate_api_key()

    assert hash_api_key(key) == hash_api_key(key)


def test_hash_api_key_rejects_invalid_prefix():
    with pytest.raises(ValueError):
        hash_api_key("invalid_key")
