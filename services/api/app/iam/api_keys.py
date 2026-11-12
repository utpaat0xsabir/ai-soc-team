import hashlib
import secrets


API_KEY_PREFIX = "soc_"


def generate_api_key() -> str:
    """Generate a cryptographically secure API key."""
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    """Return the SHA-256 hash of an API key."""
    if not isinstance(api_key, str) or not api_key.startswith(API_KEY_PREFIX):
        raise ValueError("Invalid API key format")

    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()
