"""
Application configuration for UEAB Smart Hostel Checkout.
"""

import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "development-only-change-before-deployment"
    )

    # PostgreSQL connection supplied by the deployment environment.
    DATABASE_URL = os.environ.get("DATABASE_URL")

    # Local SQLite fallback for development only.
    DATABASE = os.environ.get(
        "DATABASE_PATH",
        os.path.join(BASE_DIR, "instance", "hostel_checkout.db")
    )

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_COOKIE_SECURE = (
        os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    )

    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
