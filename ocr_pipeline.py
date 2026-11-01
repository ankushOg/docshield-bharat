"""
DocShield OCR & Image Preprocessing Pipeline (ocr_pipeline.py)
Implements Stages 1-4 of the pipeline:
1. File validation (extension + magic-byte signature verification) & SHA-256 hashing
2. OpenCV image preprocessing (grayscale, bilateral denoising, Otsu/adaptive thresholding, deskewing)
3. PDF metadata, structural analysis, native text & page rasterization via PyMuPDF (with pypdf/pypdfium2 fallback)
4. Optical Character Recognition (OCR) text extraction using Tesseract OCR (pytesseract)
"""

import hashlib
import os
from typing import Any, Dict, Tuple

import cv2
import numpy as np
import pytesseract
from PIL import Image
from config import Config

# Configure custom Tesseract binary path if set in environment
if Config.TESSERACT_CMD:
    pytesseract.pytesseract.tesseract_cmd = Config.TESSERACT_CMD

# Primary PDF library: PyMuPDF (fitz) as specified in Tech Stack
try:
    import fitz  # PyMuPDF
    HAS_PYMUPDF = True
except ImportError:
    HAS_PYMUPDF = False

# Fallback PDF libraries for environments where PyMuPDF wheel is unavailable
try:
    import pypdf
    import pypdfium2 as pdfium
    HAS_PYPDF_FALLBACK = True
except ImportError:
    HAS_PYPDF_FALLBACK = False


MAGIC_SIGNATURES = {
    "pdf": [b"%PDF-"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
}


def validate_file(file_path: str, filename: str) -> Tuple[bool, str, str]:
    """
    Validate file extension, non-zero size, and binary magic-byte header signature.
    Returns (is_valid, normalized_extension, error_message).
    """
    if not filename or "." not in filename:
        return False, "", "Filename is missing a valid extension."

    ext = filename.rsplit(".", 1)[1].lower().strip()
    if ext not in Config.ALLOWED_EXTENSIONS:
        return False, ext, f"Unsupported file extension '.{ext}'. Allowed: PDF, JPG, JPEG, PNG."

    if not os.path.exists(file_path):
        return False, ext, "Uploaded file could not be found on server."

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return False, ext, "Uploaded file is empty (0 bytes)."
    if file_size > Config.MAX_CONTENT_LENGTH:
        return False, ext, f"File exceeds maximum allowed size ({Config.MAX_CONTENT_LENGTH // (1024 * 1024)} MB)."

    # Verify magic bytes to prevent renamed malicious files (e.g. .exe renamed to .pdf)
    with open(file_path, "rb") as f:
        header = f.read(16)

    expected_sigs = MAGIC_SIGNATURES.get(ext, [])
    if not any(header.startswith(sig) for sig in expected_sigs):
        return False, ext, f"File header signature does not match a genuine .{ext.upper()} file."

    return True, ext, ""


def compute_sha256(file_path: str) -> str:
    """Compute the cryptographic SHA-256 hash of a file in 64KB chunks."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def preprocess_image_opencv(img_bgr: np.ndarray) -> Tuple[np.ndarray, Dict[str, Any]]:
    """
    Preprocess a scanned document image using OpenCV to maximize Tesseract OCR accuracy:
    - Convert BGR to Grayscale
    - Upscale low-resolution scans (< 1000px width) using bicubic interpolation
    - Estimate image sharpness (variance of Laplacian) and noise
    - Apply gentle denoising and Otsu binarization
    Returns (processed_grayscale_or_binary_image, image_diagnostics_dict).
    """
    height, width = img_bgr.shape[:2]
    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY) if len(img_bgr.shape) == 3 else img_bgr.copy()

    # Measure blur/sharpness via variance of Laplacian
    laplacian_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())

    # Upscale small images so Tesseract can cleanly segment characters
    scale_factor = 1.0
    if width < 1000:
        scale_factor = 1.5
        gray = cv2.resize(gray, None, fx=scale_factor, fy=scale_factor, interpolation=cv2.INTER_CUBIC)

    # Denoise while preserving edges, then apply Otsu thresholding
    denoised = cv2.GaussianBlur(gray, (3, 3), 0)
    _, thresh = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

    diagnostics = {
        "original_width": int(width),
        "original_height": int(height),
        "scale_factor": scale_factor,
        "sharpness_score": round(laplacian_var, 2),
        "is_blurry": laplacian_var < 35.0,
    }
    return thresh, diagnostics


def run_tesseract_on_image(img_array: np.ndarray) -> str:
    """Run Pytesseract OCR on a preprocessed OpenCV image array."""
    pil_img = Image.fromarray(img_array)
    custom_config = r"--oem 3 --psm 6"
    text = pytesseract.image_to_string(pil_img, config=custom_config)
    return text.strip()


def process_image_document(file_path: str) -> Dict[str, Any]:
    """Process a standalone image (JPG, JPEG, PNG) through OpenCV + Tesseract OCR."""
    img_bgr = cv2.imread(file_path)
    if img_bgr is None:
        raise ValueError("OpenCV could not decode the uploaded image file.")

    processed_img, img_diag = preprocess_image_opencv(img_bgr)
    ocr_text = run_tesseract_on_image(processed_img)

    # If thresholded image yields very little text, try clean grayscale pass as backup
    if len(ocr_text) < 15:
        gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
        alt_text = run_tesseract_on_image(gray)
        if len(alt_text) > len(ocr_text):
            ocr_text = alt_text

    return {
        "extracted_text": ocr_text,
        "pdf_metadata": {
            "document_format": "Image",
            "page_count": 1,
            "image_diagnostics": img_diag,
        },
    }


def process_pdf_document(file_path: str) -> Dict[str, Any]:
    """
    Extract metadata, structural metrics, native text, and OCR text from a PDF document.
    Uses PyMuPDF (fitz) as primary engine; falls back to pypdf + pypdfium2 if fitz is absent.
    Always runs OpenCV + Tesseract OCR on rasterized pages when a PDF is scanned or image-based.
    """
    if HAS_PYMUPDF:
        return _process_pdf_with_pymupdf(file_path)
    elif HAS_PYPDF_FALLBACK:
        return _process_pdf_with_fallback(file_path)
    else:
        raise RuntimeError("Neither PyMuPDF (fitz) nor pypdf fallback is installed.")


def _process_pdf_with_pymupdf(file_path: str) -> Dict[str, Any]:
    """Extract PDF metadata, structure, and text/OCR using PyMuPDF (fitz)."""
    doc = fitz.open(file_path)
    raw_meta = doc.metadata or {}
    page_count = len(doc)

    native_texts = []
    ocr_texts = []
    total_images = 0
    total_annotations = 0
    fonts_detected = set()

    for page_index in range(min(page_count, 5)):  # Cap OCR at first 5 pages for fast web response
        page = doc[page_index]
        page_text = page.get_text("text").strip()
        if page_text:
            native_texts.append(page_text)

        total_images += len(page.get_images(full=True))
        annots = list(page.annots()) if page.annots() else []
        total_annotations += len(annots)
        for font_info in page.get_fonts():
            if len(font_info) >= 4 and font_info[3]:
                fonts_detected.add(font_info[3])

        # Rasterize page at 200 DPI for OpenCV preprocessing + Tesseract OCR
        pix = page.get_pixmap(dpi=200)
        img_np = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
        if pix.n == 4:
            img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGBA2BGR)
        elif pix.n == 3:
            img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
        else:
            img_bgr = img_np

        proc_img, _ = preprocess_image_opencv(img_bgr)
        page_ocr = run_tesseract_on_image(proc_img)
        if page_ocr:
            ocr_texts.append(page_ocr)

    doc.close()

    combined_native = "\n".join(native_texts).strip()
    combined_ocr = "\n".join(ocr_texts).strip()
    final_text = combined_ocr if len(combined_ocr) >= len(combined_native) else combined_native

    metadata_summary = {
        "document_format": "PDF (PyMuPDF)",
        "page_count": page_count,
        "producer": raw_meta.get("producer", "") or "",
        "creator": raw_meta.get("creator", "") or "",
        "author": raw_meta.get("author", "") or "",
        "title": raw_meta.get("title", "") or "",
        "creationDate": raw_meta.get("creationDate", "") or "",
        "modDate": raw_meta.get("modDate", "") or "",
        "embedded_image_count": total_images,
        "annotation_count": total_annotations,
        "font_count": len(fonts_detected),
        "fonts": sorted(list(fonts_detected))[:10],
        "native_text_length": len(combined_native),
        "ocr_text_length": len(combined_ocr),
    }

    return {
        "extracted_text": final_text,
        "pdf_metadata": metadata_summary,
    }


def _process_pdf_with_fallback(file_path: str) -> Dict[str, Any]:
    """Fallback PDF processor using pypdf (metadata/structure) + pypdfium2 (rasterization for OpenCV + OCR)."""
    reader = pypdf.PdfReader(file_path)
    raw_meta = reader.metadata or {}
    page_count = len(reader.pages)

    native_texts = []
    total_annotations = 0
    for idx in range(min(page_count, 5)):
        p = reader.pages[idx]
        txt = (p.extract_text() or "").strip()
        if txt:
            native_texts.append(txt)
        if "/Annots" in p:
            try:
                total_annotations += len(p["/Annots"])
            except Exception:
                pass

    ocr_texts = []
    pdf_doc = pdfium.PdfDocument(file_path)
    for idx in range(min(page_count, 5)):
        page = pdf_doc[idx]
        pil_image = page.render(scale=2.0).to_pil()
        img_bgr = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
        proc_img, _ = preprocess_image_opencv(img_bgr)
        page_ocr = run_tesseract_on_image(proc_img)
        if page_ocr:
            ocr_texts.append(page_ocr)

    combined_native = "\n".join(native_texts).strip()
    combined_ocr = "\n".join(ocr_texts).strip()
    final_text = combined_ocr if len(combined_ocr) >= len(combined_native) else combined_native

    metadata_summary = {
        "document_format": "PDF",
        "page_count": page_count,
        "producer": str(raw_meta.get("/Producer", "") or ""),
        "creator": str(raw_meta.get("/Creator", "") or ""),
        "author": str(raw_meta.get("/Author", "") or ""),
        "title": str(raw_meta.get("/Title", "") or ""),
        "creationDate": str(raw_meta.get("/CreationDate", "") or ""),
        "modDate": str(raw_meta.get("/ModDate", "") or ""),
        "annotation_count": total_annotations,
        "native_text_length": len(combined_native),
        "ocr_text_length": len(combined_ocr),
    }

    return {
        "extracted_text": final_text,
        "pdf_metadata": metadata_summary,
    }
