"""Authentication helpers."""
from __future__ import annotations

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="quote-tool-reset")


def generate_reset_token(email: str) -> str:
    return _serializer().dumps({"email": email})


def verify_reset_token(token: str, max_age: int = 3600) -> str | None:
    try:
        data = _serializer().loads(token, max_age=max_age)
        return data.get("email")
    except SignatureExpired:
        return None
    except BadSignature:
        return None
