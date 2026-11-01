"""
DocShield Storage Layer (storage.py)
Uploads raw documents to Supabase Storage via REST API using the server-side key.
Falls back to local filesystem storage if cloud credentials fail.
"""

import os
import urllib.request
import urllib.error
import json
from pathlib import Path
from typing import Tuple
from config import Config


MIME_TYPES = {
    "pdf": "application/pdf",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
}


def is_supabase_storage_configured() -> bool:
    """Return True if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided."""
    return bool(Config.SUPABASE_URL and Config.SUPABASE_SERVICE_ROLE_KEY)


def store_document(local_file_path: str, safe_object_name: str, ext: str) -> Tuple[str, str]:
    """
    Store a validated document in Supabase Storage (or local uploads directory).
    Returns a tuple of (stored_path_or_object_key, storage_backend_name).
    """
    if is_supabase_storage_configured():
        bucket = Config.SUPABASE_BUCKET
        object_key = f"scans/{safe_object_name}"
        upload_url = f"{Config.SUPABASE_URL}/storage/v1/object/{bucket}/{object_key}"
        content_type = MIME_TYPES.get(ext.lower(), "application/octet-stream")

        with open(local_file_path, "rb") as f:
            file_bytes = f.read()

        req = urllib.request.Request(
            upload_url,
            data=file_bytes,
            method="POST",
            headers={
                "Authorization": f"Bearer {Config.SUPABASE_SERVICE_ROLE_KEY}",
                "apikey": Config.SUPABASE_SERVICE_ROLE_KEY,
                "Content-Type": content_type,
                "x-upsert": "true",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status in (200, 201):
                    return f"{bucket}/{object_key}", "supabase_private"
        except urllib.error.HTTPError as exc:
            err_msg = exc.read().decode("utf-8", errors="ignore")
            print(f"[Storage Warning] Supabase upload failed (HTTP {exc.code}): {err_msg}; keeping local copy.")
        except urllib.error.URLError as exc:
            print(f"[Storage Warning] Supabase upload failed ({exc}); keeping local copy.")

    # Local storage fallback
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    dest_path = str(Path(Config.UPLOAD_FOLDER) / safe_object_name)
    if os.path.abspath(local_file_path) != os.path.abspath(dest_path):
        with open(local_file_path, "rb") as src, open(dest_path, "wb") as dst:
            dst.write(src.read())
    return safe_object_name, "local"


def create_signed_download_url(stored_path: str, storage_backend: str) -> str:
    """
    Generate a short-lived signed URL for a file stored in Supabase.
    Returns empty string if using local storage or if signing fails.
    """
    if storage_backend != "supabase_private" or not is_supabase_storage_configured():
        return ""

    parts = stored_path.split("/", 1)
    if len(parts) != 2:
        return ""
    bucket, object_key = parts
    sign_endpoint = f"{Config.SUPABASE_URL}/storage/v1/object/sign/{bucket}/{object_key}"
    payload = json.dumps({"expiresIn": Config.SIGNED_URL_EXPIRY_SECONDS}).encode("utf-8")

    req = urllib.request.Request(
        sign_endpoint,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {Config.SUPABASE_SERVICE_ROLE_KEY}",
            "apikey": Config.SUPABASE_SERVICE_ROLE_KEY,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            signed_path = data.get("signedURL", "")
            if signed_path:
                return f"{Config.SUPABASE_URL}/storage/v1{signed_path}"
    except Exception:
        pass
    return ""