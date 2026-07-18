import hashlib


def content_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
