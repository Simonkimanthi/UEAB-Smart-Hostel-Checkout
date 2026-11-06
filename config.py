"""
Application configuration for UEAB Smart Hostel Checkout.

Loads sensitive settings from environment variables and defines
secure defaults for local development and production deployment.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Application secret must be supplied through the environment.
    SECRET_KEY = os.environ.get("SECRET_KEY")

    if not SECRET_KEY:
        SECRET_KEY = "development-only-change-before-deployment"

    # Database location can be overridden for persistent deployment storage.
    DATABASE = os.environ.get(
        "DATABASE_PATH",
        os.path.join(BASE_DIR, "instance", "hostel_checkout.db")
    )

    # Session cookie security.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = (
        os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    )

    # Disable debug mode unless explicitly configured.
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"