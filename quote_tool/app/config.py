"""Application configuration helpers."""
from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

try:  # Optional dependency; tests run without loading from .env
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - fallback for environments without python-dotenv
    def load_dotenv(*_args, **_kwargs):
        return False

load_dotenv(Path(__file__).resolve().parents[2] / ".env")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///quote_tool.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_PROTECTION = "strong"
    REMEMBER_COOKIE_DURATION = timedelta(days=14)
    WTF_CSRF_ENABLED = True
    GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY")
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    MAIL_SENDER = os.getenv("MAIL_SENDER", "no-reply@example.com")
    RATELIMIT_DEFAULT = ["200 per day", "50 per hour"]
    RATELIMIT_LOGIN = "5 per minute"
    RATELIMIT_RESET = "5 per minute"
    RATELIMIT_TOKEN = "1 per 15 minute"

    @classmethod
    def as_dict(cls) -> dict:
        """Return config values as a plain dictionary."""
        return {
            key: value
            for key, value in cls.__dict__.items()
            if key.isupper() and not key.startswith("__")
        }


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False
