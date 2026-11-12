"""Deprecated compatibility import; use app.iam.api_keys. Retire separately."""

from app.iam.api_keys import (
    API_KEY_PREFIX as API_KEY_PREFIX,
    generate_api_key as generate_api_key,
    hash_api_key as hash_api_key,
    hashlib as hashlib,
    secrets as secrets,
)
