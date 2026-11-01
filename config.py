"""
DocShield Bharat Configuration Module (config.py)
Loads environment variables safely without ever hardcoding database passwords or API keys.
Automatically detects Tesseract OCR on Windows (C:\\Program Files\\Tesseract-OCR\\tesseract.exe) if installed.
"""

import os
import shutil
from pathlib import Path

# Try loading .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = Path(__file__).resolve().parent


def _detect_tesseract_cmd() -> str:
    """Auto-detect Tesseract executable path on Windows/Linux/macOS."""
    env_cmd = os.environ.get("TESSERACT_CMD", "").strip()
    if env_cmd and os.path.exists(env_cmd):
        return env_cmd
    which_cmd = shutil.which("tesseract")
    if which_cmd:
        return which_cmd
    win_default = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.path.exists(win_default):
        return win_default
    return ""


class Config:
    """Centralized configuration for Flask, OCR, Supabase PostgreSQL, and Storage."""

    # Flask Security & Upload Settings
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-college-prototype-change-in-prod")
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", "10")) * 1024 * 1024  # Default 10 MB limit
    ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png"}

    # Local Temporary Upload & Fallback Storage Directory
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", str(BASE_DIR / "uploads"))

    # Tesseract OCR Binary Path (Auto-detected on Windows & Linux)
    TESSERACT_CMD = _detect_tesseract_cmd()

    # Database Configuration:
    # In production on Render, set DATABASE_URL to your Supabase PostgreSQL Connection Pooler URI:
    # postgresql://postgres.[project-ref]:[password]@aws-0-ap-south-1.pooler.supabase.com:6543/postgres?sslmode=require
    # If DATABASE_URL is not set, DocShield automatically falls back to a local SQLite database for offline testing.
    DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
    LOCAL_SQLITE_PATH = os.environ.get("LOCAL_SQLITE_PATH", str(BASE_DIR / "docshield_local.db"))

    # Supabase Private Storage Configuration:
    # Never commit SUPABASE_SERVICE_ROLE_KEY to Git! Configure in Render Environment Variables.
    SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    SUPABASE_BUCKET = os.environ.get("SUPABASE_BUCKET", "documents-private").strip()
    SIGNED_URL_EXPIRY_SECONDS = int(os.environ.get("SIGNED_URL_EXPIRY_SECONDS", "3600"))
