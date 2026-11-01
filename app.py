"""
DocShield Bharat Main Application (app.py)
Made in India Document Fraud Detection & Screening System built with Python Flask.
Orchestrates the 9-stage Pipeline for Indian Official, KYC, Tax & Academic Documents:
Document Upload -> File Validation -> Image Preprocessing -> OCR Extraction ->
Indian Entity Analysis (PAN, Aadhaar, GSTIN, IFSC, PIN, Roll/Cert No) ->
Indian Compliance & Fraud Indicator Detection -> Risk Assessment ->
Database Storage -> Results Dashboard.
"""

import os
import re
import uuid
from typing import Any, Dict

from config import Config
from database import (
    find_by_sha256,
    get_dashboard_stats,
    get_scan_by_id,
    init_db,
    insert_scan_record,
    list_scans,
    use_postgres,
)
from fraud_analyzer import evaluate_fraud_indicators, extract_entities
from ocr_pipeline import (
    compute_sha256,
    process_image_document,
    process_pdf_document,
    validate_file,
)
from storage import (
    create_signed_download_url,
    is_supabase_storage_configured,
    store_document,
)

try:
    from flask import (
        Flask,
        flash,
        jsonify,
        redirect,
        render_template,
        request,
        send_from_directory,
        url_for,
    )
    from werkzeug.utils import secure_filename
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

    def secure_filename(name: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def execute_full_scan_pipeline(temp_file_path: str, original_filename: str) -> Dict[str, Any]:
    """
    Execute the complete 9-stage DocShield Bharat pipeline on a local file and store the result.
    Returns a dictionary containing the saved scan_id and full screening record.
    """
    # Stage 1 & 2: File Validation (extension, size, magic-byte header)
    is_valid, ext, error_msg = validate_file(temp_file_path, original_filename)
    if not is_valid:
        raise ValueError(error_msg)

    file_size = os.path.getsize(temp_file_path)

    # Stage 6 (Pre-check): Compute SHA-256 hash & check for duplicate documents
    sha256_hash = compute_sha256(temp_file_path)
    duplicate_record = find_by_sha256(sha256_hash)

    # Store file in Supabase Private Storage (or local fallback)
    safe_base = secure_filename(original_filename) or f"document.{ext}"
    unique_object_name = f"{uuid.uuid4().hex[:12]}_{safe_base}"
    stored_path, storage_backend = store_document(temp_file_path, unique_object_name, ext)

    # Stage 3 & 4: OpenCV Image Preprocessing + PyMuPDF / Tesseract OCR Extraction
    if ext == "pdf":
        pipeline_out = process_pdf_document(temp_file_path)
    else:
        pipeline_out = process_image_document(temp_file_path)

    extracted_text = pipeline_out["extracted_text"]
    pdf_metadata = pipeline_out["pdf_metadata"]

    # Stage 5: Indian Entity Extraction (PAN, Aadhaar, GSTIN, IFSC, PIN, Holder Name, DD/MM/YYYY Dates)
    entities = extract_entities(extracted_text)
    pdf_metadata["indian_document_category"] = entities.get("document_category", "General Indian Official Document")
    pdf_metadata["indian_identifiers_breakdown"] = entities.get("indian_details", {})

    # Stage 7 & 8: Indian Fraud Indicator Detection & Risk Assessment (Low / Medium / High Risk)
    risk_result = evaluate_fraud_indicators(
        extracted_text=extracted_text,
        entities=entities,
        pdf_metadata=pdf_metadata,
        duplicate_record=duplicate_record,
    )

    # Stage 9: Store Document Info, Extracted Text & Screening Results in Database
    record = {
        "original_filename": original_filename,
        "stored_path": stored_path,
        "storage_backend": storage_backend,
        "file_type": ext.upper(),
        "file_size_bytes": file_size,
        "sha256_hash": sha256_hash,
        "is_duplicate": bool(duplicate_record),
        "duplicate_of_id": duplicate_record["id"] if duplicate_record else None,
        "extracted_text": extracted_text,
        "extracted_name": entities["extracted_name"],
        "extracted_dates": entities["extracted_dates"],
        "extracted_doc_numbers": entities["extracted_doc_numbers"],
        "pdf_metadata": pdf_metadata,
        "fraud_indicators": risk_result["fraud_indicators"],
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
    }
    scan_id = insert_scan_record(record)
    record["id"] = scan_id
    return record


def create_app() -> "Flask":
    """Flask Application Factory."""
    app = Flask(__name__)
    app.config.from_object(Config)

    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    db_engine_name = init_db()

    @app.context_processor
    def inject_system_status():
        return {
            "db_engine": "Supabase PostgreSQL (Mumbai ap-south-1)" if use_postgres() else "SQLite (Local Mode)",
            "storage_engine": "Supabase Private Bucket" if is_supabase_storage_configured() else "Local Uploads Folder",
        }

    @app.route("/", methods=["GET"])
    def index():
        """Home page: Indian Document Upload form, 9-Stage Pipeline Diagram, and 5 most recent scans."""
        recent_scans = list_scans(limit=5)
        stats = get_dashboard_stats()
        return render_template("index.html", recent_scans=recent_scans, stats=stats)

    @app.route("/upload", methods=["POST"])
    def upload_document():
        """Handle document upload, run the Indian OCR & Fraud Screening Pipeline, and redirect to results."""
        if "document" not in request.files:
            flash("No file field found in request. Please select a PDF, JPG, JPEG, or PNG file.", "danger")
            return redirect(url_for("index"))

        uploaded_file = request.files["document"]
        if not uploaded_file or not uploaded_file.filename:
            flash("Please choose an Indian document before clicking Scan Document.", "warning")
            return redirect(url_for("index"))

        original_filename = uploaded_file.filename
        safe_temp_name = f"tmp_{uuid.uuid4().hex}_{secure_filename(original_filename)}"
        temp_path = os.path.join(Config.UPLOAD_FOLDER, safe_temp_name)

        try:
            uploaded_file.save(temp_path)
            result = execute_full_scan_pipeline(temp_path, original_filename)
            flash(
                f"Scan #{result['id']} ({result['pdf_metadata'].get('indian_document_category')}) completed! "
                f"Screening Classification: {result['risk_level']} (Score: {result['risk_score']}/100).",
                "success",
            )
            return redirect(url_for("view_scan", scan_id=result["id"]))
        except ValueError as val_err:
            flash(f"Validation Error: {val_err}", "danger")
            return redirect(url_for("index"))
        except Exception as exc:
            flash(f"Processing Error during OCR/Analysis: {exc}", "danger")
            return redirect(url_for("index"))
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    @app.route("/scan/<int:scan_id>", methods=["GET"])
    def view_scan(scan_id: int):
        """Display the full screening report for a single scanned Indian document."""
        scan = get_scan_by_id(scan_id)
        if not scan:
            flash(f"Scan record #{scan_id} was not found.", "warning")
            return redirect(url_for("dashboard"))

        signed_url = create_signed_download_url(scan["stored_path"], scan["storage_backend"])
        return render_template("result.html", scan=scan, signed_url=signed_url)

    @app.route("/dashboard", methods=["GET"])
    def dashboard():
        """Display full history of previous scans with risk filtering and summary metrics."""
        risk_filter = request.args.get("risk", "").strip()
        scans = list_scans(limit=100, risk_filter=risk_filter if risk_filter else None)
        stats = get_dashboard_stats()
        return render_template(
            "dashboard.html",
            scans=scans,
            stats=stats,
            active_filter=risk_filter,
        )

    @app.route("/files/<path:filename>", methods=["GET"])
    def serve_local_file(filename: str):
        """Serve locally stored document when running in local fallback mode."""
        safe_name = os.path.basename(filename)
        return send_from_directory(Config.UPLOAD_FOLDER, safe_name)

    @app.route("/health", methods=["GET"])
    def health_check():
        """Health check endpoint for Render zero-downtime deployment monitoring."""
        return jsonify({
            "status": "healthy",
            "service": "DocShield Bharat – Made in India Document Fraud Screening System",
            "country_profile": "India (PAN, UIDAI Aadhaar Verhoeff, GSTIN, RBI IFSC, India Post PIN)",
            "timezone": "Asia/Kolkata (IST UTC+05:30)",
            "database": db_engine_name,
            "supabase_storage_enabled": is_supabase_storage_configured(),
        }), 200

    @app.errorhandler(413)
    def request_entity_too_large(error):
        max_mb = Config.MAX_CONTENT_LENGTH // (1024 * 1024)
        flash(f"Uploaded file is too large. Maximum allowed file size is {max_mb} MB.", "danger")
        return redirect(url_for("index"))

    return app


if HAS_FLASK:
    app = create_app()

if __name__ == "__main__":
    if not HAS_FLASK:
        raise RuntimeError("Flask is not installed. Run `pip install -r requirements.txt` first.")
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
