"""
DocShield Bharat – Made in India Automated End-to-End Test Suite (tests/test_pipeline.py)
Generates synthetic Indian documents and verifies all 9 stages of the pipeline:
1. Genuine NIT/AICTE Degree & KYC Certificate (Valid Individual PAN matching surname initial 'S' for Sharma,
   Valid 12-Digit UIDAI Aadhaar passing Verhoeff D5 checksum, Valid RBI IFSC SBIN0001234, Valid UP PIN 226001) -> Low Risk
2. Exact Duplicate Upload (SHA-256 Collision) -> Medium Risk
3. Tampered Indian GST Tax Invoice PDF (Invalid GSTIN State Code '99' / PAN mismatch, Invalid Aadhaar failing Verhoeff,
   Invalid RBI IFSC missing 5th zero, Adobe Photoshop metadata, and Future IST Issue Date) -> High Risk
4. Spoofed Executable Disguised as .PDF (Blocked by Magic-Byte Header Validation) -> ValueError
"""

import os
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# Add parent project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import execute_full_scan_pipeline
from database import get_dashboard_stats, init_db
from fraud_analyzer import generate_valid_aadhaar_sample, verify_aadhaar_verhoeff

try:
    import fitz
    HAS_FITZ = True
except ImportError:
    HAS_FITZ = False
    import pypdf


def create_genuine_indian_certificate_image(path: str, valid_aadhaar: str):
    """Create a clean Indian Institute & KYC Verification Certificate passing all Indian compliance checks."""
    img = Image.new("RGB", (1300, 880), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    try:
        font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 32)
        font_body = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 25)
    except Exception:
        font_large = ImageFont.load_default()
        font_body = ImageFont.load_default()

    draw.rectangle([(40, 40), (1260, 840)], outline=(15, 23, 42), width=4)
    draw.text((80, 85), "MOTILAL NEHRU NATIONAL INSTITUTE OF TECHNOLOGY ALLAHABAD", fill=(0, 0, 0), font=font_large)
    draw.text((80, 145), "AICTE APPROVED INDIAN ACADEMIC & KYC VERIFICATION CERTIFICATE", fill=(0, 0, 0), font=font_body)
    draw.text((80, 230), "Student Name: Shri Rohan Sharma", fill=(0, 0, 0), font=font_body)
    draw.text((80, 295), "Certificate No: MNNIT-UP-2025-88412", fill=(0, 0, 0), font=font_body)
    # Individual PAN ('P' as 4th char, 'S' as 5th char matching surname 'Sharma')
    draw.text((80, 360), "PAN Number: ABCPS1234F", fill=(0, 0, 0), font=font_body)
    # Valid 12-digit UIDAI Aadhaar passing Dihedral D5 Verhoeff checksum
    draw.text((80, 425), f"Aadhaar No: {valid_aadhaar}", fill=(0, 0, 0), font=font_body)
    # Valid RBI IFSC Code (5th character is '0') and Uttar Pradesh PIN Code (211004)
    draw.text((80, 490), "Bank IFSC Code: SBIN0002145", fill=(0, 0, 0), font=font_body)
    draw.text((80, 555), "Address: Prayagraj, Uttar Pradesh - Pincode: 211004", fill=(0, 0, 0), font=font_body)
    draw.text((80, 620), "Issue Date: 15/08/2025", fill=(0, 0, 0), font=font_body)
    draw.text((80, 685), "Scholarship Grant: Rs. 45,000.00", fill=(0, 0, 0), font=font_body)
    img.save(path, "PNG")


def create_tampered_indian_gst_pdf(path: str):
    """
    Create a tampered Indian GST Invoice PDF containing multiple India-specific anomalies:
    - Invalid GSTIN State Code ('99' does not exist in Indian Census 01-38)
    - Invalid Aadhaar failing Verhoeff checksum (starts with '1' or wrong check digit)
    - Invalid RBI IFSC Code (5th character is 'X' instead of '0')
    - Future Issue Date (15/12/2030)
    - Adobe Photoshop & Canva PDF editing metadata + CreationDate/ModDate mismatch
    """
    img = Image.new("RGB", (1300, 880), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    try:
        font_body = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 26)
    except Exception:
        font_body = ImageFont.load_default()

    draw.text((90, 90), "INDIAN GST TAX INVOICE (BHARAT TRADERS LUCKNOW)", fill=(0, 0, 0), font=font_body)
    draw.text((90, 170), "Taxpayer Name: Vikram Aditya", fill=(0, 0, 0), font=font_body)
    draw.text((90, 240), "Invoice No: GST-UP-990214", fill=(0, 0, 0), font=font_body)
    # Invalid GSTIN state code 99
    draw.text((90, 310), "GSTIN: 99ABCDE1234F1Z5", fill=(0, 0, 0), font=font_body)
    # Invalid PAN 4th character 'Z' (not in P,C,H,F,A,T,B,L,J,G)
    draw.text((90, 380), "PAN Number: ABCZE9999K", fill=(0, 0, 0), font=font_body)
    # Invalid Aadhaar starting with 1
    draw.text((90, 450), "Aadhaar No: 1234 5678 9012", fill=(0, 0, 0), font=font_body)
    # Invalid RBI IFSC (5th char is 'X' instead of '0')
    draw.text((90, 520), "IFSC Code: HDFC9001234", fill=(0, 0, 0), font=font_body)
    # Future Issue Date
    draw.text((90, 590), "Issue Date: 15/12/2030", fill=(0, 0, 0), font=font_body)
    draw.text((90, 660), "Total Invoice Value: Rs. 1,25,000.00", fill=(0, 0, 0), font=font_body)

    temp_pdf_path = path + ".raw.pdf"
    img.save(temp_pdf_path, "PDF", resolution=150.0)

    if HAS_FITZ:
        doc = fitz.open(temp_pdf_path)
        doc.set_metadata({
            "producer": "Adobe Photoshop 25.0 (Windows)",
            "creator": "Canva PDF Editor",
            "creationDate": "D:20240110093000+05'30'",
            "modDate": "D:20261030184500+05'30'",
        })
        doc.save(path)
        doc.close()
    else:
        reader = pypdf.PdfReader(temp_pdf_path)
        writer = pypdf.PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        writer.add_metadata({
            "/Producer": "Adobe Photoshop 25.0 (Windows)",
            "/Creator": "Canva PDF Editor",
            "/CreationDate": "D:20240110093000+05'30'",
            "/ModDate": "D:20261030184500+05'30'",
        })
        with open(path, "wb") as f:
            writer.write(f)

    if os.path.exists(temp_pdf_path):
        os.remove(temp_pdf_path)


def run_tests():
    print("=" * 78)
    print("DocShield Bharat (Made in India) – End-to-End Pipeline Verification")
    print("=" * 78)

    db_backend = init_db()
    print(f"[1] Database initialized using: {db_backend}")

    valid_aadhaar = generate_valid_aadhaar_sample("34567890123")
    assert verify_aadhaar_verhoeff(valid_aadhaar), "Generated Aadhaar sample must pass Verhoeff D5!"
    print(f"[2] Verified UIDAI Dihedral D5 Verhoeff Sample Aadhaar: {valid_aadhaar}")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Test 1: Clean Genuine Indian Academic & KYC Certificate -> Expect Low Risk
        clean_png = os.path.join(tmpdir, "mnnit_kyc_certificate.png")
        create_genuine_indian_certificate_image(clean_png, valid_aadhaar)
        res1 = execute_full_scan_pipeline(clean_png, "mnnit_kyc_certificate.png")
        print(f"\n[Test 1: Genuine Indian Academic & KYC Document Scan]")
        print(f"  - Scan ID: #{res1['id']} | Category: {res1['pdf_metadata'].get('indian_document_category')}")
        print(f"  - Risk Level: {res1['risk_level']} ({res1['risk_score']}/100)")
        print(f"  - Extracted Holder: {res1['extracted_name']}")
        print(f"  - Extracted Indian Dates: {res1['extracted_dates']}")
        print(f"  - Extracted Indian IDs: {res1['extracted_doc_numbers']}")
        assert res1["risk_level"] == "Low Risk", f"Expected Low Risk, got {res1['risk_level']} ({res1['fraud_indicators']})"
        assert "Rohan Sharma" in (res1["extracted_name"] or ""), "Failed to extract Shri Rohan Sharma"

        # Test 2: Re-uploading the exact same file -> Expect SHA-256 Duplicate Flag (Medium Risk)
        res2 = execute_full_scan_pipeline(clean_png, "mnnit_kyc_certificate_duplicate.png")
        print(f"\n[Test 2: Duplicate Indian Document SHA-256 Check]")
        print(f"  - Scan ID: #{res2['id']} | Duplicate: {res2['is_duplicate']} (of Scan #{res2['duplicate_of_id']})")
        print(f"  - Risk Level: {res2['risk_level']} ({res2['risk_score']}/100)")
        assert res2["is_duplicate"] is True, "SHA-256 duplicate flag was not triggered!"
        assert res2["risk_level"] in ("Medium Risk", "High Risk"), "Duplicate did not elevate risk level!"

        # Test 3: Tampered Indian GST Tax Invoice PDF -> Expect High Risk
        tampered_pdf = os.path.join(tmpdir, "tampered_gst_invoice.pdf")
        create_tampered_indian_gst_pdf(tampered_pdf)
        res3 = execute_full_scan_pipeline(tampered_pdf, "tampered_gst_invoice.pdf")
        print(f"\n[Test 3: Tampered Indian GST Invoice (Invalid GSTIN/PAN/Aadhaar/IFSC + Photoshop)]")
        print(f"  - Scan ID: #{res3['id']} | Category: {res3['pdf_metadata'].get('indian_document_category')}")
        print(f"  - Risk Level: {res3['risk_level']} ({res3['risk_score']}/100)")
        print(f"  - Triggered Indian Compliance & Forensic Flags ({len(res3['fraud_indicators'])}):")
        for ind in res3["fraud_indicators"]:
            print(f"      * [{ind['severity'].upper()} +{ind['points']}] {ind['code']}: {ind['title']}")
        assert res3["risk_level"] == "High Risk", f"Expected High Risk, got {res3['risk_level']}"

        # Test 4: File Validation Rejects Fake/Corrupt File Header
        fake_pdf = os.path.join(tmpdir, "malware_disguised.pdf")
        with open(fake_pdf, "wb") as f:
            f.write(b"MZ_FAKE_EXECUTABLE_CONTENT_NOT_A_PDF")
        try:
            execute_full_scan_pipeline(fake_pdf, "malware_disguised.pdf")
            raise AssertionError("Spoofed PDF should have been rejected by magic-byte validation!")
        except ValueError as expected_err:
            print(f"\n[Test 4: Magic-Byte Spoof Protection]")
            print(f"  - Correctly rejected spoofed file: {expected_err}")

    stats = get_dashboard_stats()
    print("\n" + "=" * 78)
    print(f"All 4 Indian Pipeline Tests PASSED! Dashboard Totals: {stats}")
    print("=" * 78)


if __name__ == "__main__":
    run_tests()
