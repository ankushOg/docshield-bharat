"""
DocShield Bharat – Made in India Fraud Indicator & Risk Assessment Engine (fraud_analyzer.py)
Implements Stages 5-7 of the pipeline specifically tailored to Indian Official, KYC, Tax, and Academic Documents:
1. Auto-Classification of Indian Document Type (Aadhaar, PAN, GST Tax Invoice, University/Board Marksheet, State Govt Certificate, Bank KYC)
2. Indian Entity Extraction:
   - Holder/Applicant Name (supporting Indian honorifics: Shri, Smt., Kumari, S/O, D/O, W/O)
   - Permanent Account Number (PAN - Income Tax Dept 10-char format)
   - UIDAI Aadhaar Number (12-digit UID & Masked Aadhaar format)
   - Goods & Services Tax Identification Number (GSTIN - 15-char format with Indian State Code)
   - RBI IFSC Code (11-char Bank Branch identifier)
   - Indian Voter ID (EPIC), Indian Passport No, University Roll/Registration/PRN No, Certificate/Invoice No
   - Indian PIN Code (6-digit Postal Index Number), Indian Mobile (+91 / 10-digit), and INR (₹ / Rs.) Amounts
   - Indian Dates (DD/MM/YYYY, DD-MM-YYYY, and Indian textual dates)
3. Rule-Based Indian Compliance & Anomaly Screening:
   - Rule 1: Exact Duplicate Document Detection (SHA-256 Match)
   - Rule 2: Income Tax PAN Structural & 4th-Char Entity Code Check + 5th-Char Surname Initial Cross-Check
   - Rule 3: UIDAI Aadhaar First-Digit Rule (2-9) & Dihedral D5 Verhoeff Checksum Verification
   - Rule 4: Indian GSTIN 15-Char Structure, Census State Code (01-38) & Embedded PAN Cross-Verification
   - Rule 5: RBI IFSC 11-Character Structure & Mandatory 5th-Character Zero ('0') Check
   - Rule 6: India Post 6-Digit PIN Code Zone (1-8) & TRAI 10-Digit Mobile Number Check
   - Rule 7: PDF Graphics/Editing Software Signature (Photoshop, Canva, GIMP, Sejda, iLovePDF, CorelDraw)
   - Rule 8: PDF Creation vs. Modification Timestamp Mismatch & Hidden Text Layer / Annotation Checks
   - Rule 9: Indian Standard Time (IST) Future Issue Date, Implausible Year & Image Blur Checks

IMPORTANT EDUCATIONAL DISCLAIMER:
Rule-based heuristics and OCR text screening highlight suspicious anomalies for human review;
they do NOT conclusively prove document forgery or authenticity.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

# Indian Standard Time (IST = UTC + 05:30)
IST_TZ = timezone(timedelta(hours=5, minutes=30))

# Valid 2-Digit Indian GST Census State & Union Territory Codes (01 to 38, plus 97 Other Territory)
INDIAN_GST_STATE_CODES: Dict[str, str] = {
    "01": "Jammu & Kashmir", "02": "Himachal Pradesh", "03": "Punjab", "04": "Chandigarh",
    "05": "Uttarakhand", "06": "Haryana", "07": "Delhi", "08": "Rajasthan",
    "09": "Uttar Pradesh", "10": "Bihar", "11": "Sikkim", "12": "Arunachal Pradesh",
    "13": "Nagaland", "14": "Manipur", "15": "Mizoram", "16": "Tripura",
    "17": "Meghalaya", "18": "Assam", "19": "West Bengal", "20": "Jharkhand",
    "21": "Odisha", "22": "Chhattisgarh", "23": "Madhya Pradesh", "24": "Gujarat",
    "25": "Daman & Diu", "26": "Dadra & Nagar Haveli and Daman & Diu", "27": "Maharashtra",
    "28": "Andhra Pradesh (Old)", "29": "Karnataka", "30": "Goa", "31": "Lakshadweep",
    "32": "Kerala", "33": "Tamil Nadu", "34": "Puducherry", "35": "Andaman & Nicobar Islands",
    "36": "Telangana", "37": "Andhra Pradesh", "38": "Ladakh", "97": "Other Territory",
}

# Valid 4th-character status codes in an Indian Income Tax PAN
PAN_ENTITY_TYPES: Dict[str, str] = {
    "P": "Individual Citizen",
    "C": "Indian Company",
    "H": "Hindu Undivided Family (HUF)",
    "F": "Partnership Firm / LLP",
    "A": "Association of Persons (AOP)",
    "T": "Trust",
    "B": "Body of Individuals (BOI)",
    "L": "Local Authority",
    "J": "Artificial Juridical Person",
    "G": "Government Agency",
}

# Dihedral D5 Verhoeff Algorithm Tables for UIDAI 12-Digit Aadhaar Validation
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verify_aadhaar_verhoeff(aadhaar_12_digits: str) -> bool:
    """
    Validate a 12-digit UIDAI Aadhaar number using the official Dihedral D5 Verhoeff checksum algorithm
    and first-digit rule (must start with digits 2-9, never 0 or 1).
    """
    digits_only = re.sub(r"\s+", "", aadhaar_12_digits)
    if len(digits_only) != 12 or not digits_only.isdigit():
        return False
    if digits_only[0] in ("0", "1"):
        return False
    c = 0
    for i, ch in enumerate(reversed(digits_only)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def generate_valid_aadhaar_sample(eleven_digits: str = "23456789012") -> str:
    """Helper to compute the valid 12th Verhoeff check digit for a given 11-digit prefix."""
    inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
    c = 0
    for i, ch in enumerate(reversed(eleven_digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    check_digit = inv[c]
    full = eleven_digits + str(check_digit)
    return f"{full[:4]} {full[4:8]} {full[8:12]}"


# Common image/PDF editing tools that warrant manual inspection when found on official Indian documents
SUSPICIOUS_EDITORS = [
    "photoshop", "gimp", "illustrator", "canva", "inkscape", "coreldraw",
    "ilovepdf", "sejda", "smallpdf", "pdfescape", "nitro", "foxit phantom",
]

# Indian Name & Honorific Regex Patterns
NAME_PATTERNS = [
    re.compile(
        r"(?:Name|Full\s*Name|Applicant\s*Name|Student\s*Name|Candidate\s*Name|"
        r"Holder\s*Name|Taxpayer\s*Name|Employee\s*Name|Issued\s*To)\s*[:\-]\s*"
        r"(?:(?:Shri|Smt\.?|Kumari|Kr\.?|Mr\.?|Ms\.?|Mrs\.?|Dr\.?)\s+)?([A-Z][A-Za-z.\s]{2,45})",
        re.IGNORECASE,
    ),
    re.compile(r"(?:Shri|Smt\.?|Kumari)\s+([A-Z][A-Za-z\s]{2,40})"),
    re.compile(r"([A-Z][A-Za-z\s]{2,35})\s+(?:S/O|D/O|W/O)\s+[A-Z][A-Za-z\s]{2,35}"),
]

# Indian Date Patterns (DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY, and textual Indian dates)
DATE_PATTERNS = [
    re.compile(r"\b(0?[1-9]|[12][0-9]|3[01])[\/\-\.](0?[1-9]|1[0-2])[\/\-\.]((?:19|20)\d{2})\b"),
    re.compile(r"\b((?:19|20)\d{2})[\/\-](0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12][0-9]|3[01])\b"),
    re.compile(r"\b(\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s,]*(?:19|20)\d{2})\b", re.IGNORECASE),
]


def classify_indian_document(text: str) -> str:
    """Classify the document into an Indian document category based on primary header keywords."""
    low = (text or "").lower()
    if "gstin" in low or "cgst" in low or "sgst" in low or "igst" in low or "tax invoice" in low or "hsn/sac" in low:
        return "Indian GST Tax Invoice / e-Way Bill"
    if any(k in low for k in ["university", "institute of technology", "aicte", "ugc", "cbse", "marksheet", "grade card", "roll no", "semester", "cgpa"]):
        return "Indian Academic Marksheet / Degree Certificate"
    if any(k in low for k in ["tehsildar", "magistrate", "domicile", "caste certificate", "income certificate", "e-district"]):
        return "Indian State Govt / e-District Certificate"
    if "unique identification authority" in low or "mera aadhaar" in low or ("aadhaar" in low and "income tax" not in low):
        return "UIDAI Aadhaar Card / e-Aadhaar"
    if "income tax department" in low or "permanent account number" in low or "p.a.n." in low:
        return "Income Tax PAN Card / e-PAN"
    if any(k in low for k in ["ifsc", "reserve bank", "neft", "rtgs", "account no", "passbook"]):
        return "Indian Banking / Financial KYC Document"
    return "General Indian Official Document"


def extract_entities(text: str) -> Dict[str, Any]:
    """
    Extract Holder Name, Indian Dates, and Indian Official Identifiers (PAN, Aadhaar, GSTIN,
    IFSC, Voter EPIC, Passport, PIN Code, Mobile No, INR Amounts, and Cert/Roll/Invoice IDs).
    """
    clean_text = text or ""
    doc_category = classify_indian_document(clean_text)

    # 1. Extract Holder / Applicant Name
    extracted_name = None
    for pattern in NAME_PATTERNS:
        match = pattern.search(clean_text)
        if match:
            candidate = match.group(1).strip()
            candidate = candidate.splitlines()[0].strip(" :,-.")
            candidate = re.split(r"\b(?:Father|Mother|DOB|Date|PAN|Aadhaar|Roll|GSTIN|Address)\b", candidate, flags=re.IGNORECASE)[0].strip(" :,-.")
            if len(candidate) >= 3:
                extracted_name = candidate
                break

    # 2. Extract Dates (Standardized to Indian DD/MM/YYYY format where possible)
    found_dates: List[str] = []
    for m in DATE_PATTERNS[0].finditer(clean_text):
        date_str = f"{int(m.group(1)):02d}/{int(m.group(2)):02d}/{m.group(3)}"
        if date_str not in found_dates:
            found_dates.append(date_str)

    for m in DATE_PATTERNS[1].finditer(clean_text):
        date_str = f"{int(m.group(3)):02d}/{int(m.group(2)):02d}/{m.group(1)}"
        if date_str not in found_dates:
            found_dates.append(date_str)

    for m in DATE_PATTERNS[2].finditer(clean_text):
        date_str = " ".join(m.group(1).split())
        if date_str not in found_dates:
            found_dates.append(date_str)

    # 3. Extract Specific Indian Identifiers
    # 3a. GSTIN (15-character alphanumeric starting with 2 digits)
    gstin_candidates = []
    for m in re.finditer(r"\b([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[0-9A-Z]{3})\b", clean_text):
        val = m.group(1)
        if val not in gstin_candidates:
            gstin_candidates.append(val)
    for m in re.finditer(r"GSTIN\s*[:\-]?\s*([A-Z0-9]{10,18})", clean_text, re.IGNORECASE):
        val = m.group(1).upper()
        if val not in gstin_candidates:
            gstin_candidates.append(val)

    # 3b. PAN (10-character [A-Z]{5}[0-9]{4}[A-Z])
    pan_candidates = []
    for m in re.finditer(r"\b([A-Z]{5}[0-9]{4}[A-Z])\b", clean_text):
        val = m.group(1)
        if val not in pan_candidates:
            pan_candidates.append(val)

    # 3c. UIDAI Aadhaar (12 digits grouped as XXXX XXXX XXXX or labeled Aadhaar)
    aadhaar_candidates = []
    for m in re.finditer(r"\b(\d{4}[\s\-]\d{4}[\s\-]\d{4})\b", clean_text):
        val = re.sub(r"[\s\-]+", " ", m.group(1))
        if val not in aadhaar_candidates:
            aadhaar_candidates.append(val)
    for m in re.finditer(r"(?:Aadhaar|UID)\s*(?:No|Number)?\s*[:\-]?\s*(\d{12})\b", clean_text, re.IGNORECASE):
        raw12 = m.group(1)
        formatted = f"{raw12[:4]} {raw12[4:8]} {raw12[8:12]}"
        if formatted not in aadhaar_candidates:
            aadhaar_candidates.append(formatted)

    # 3d. Masked Aadhaar (XXXX XXXX 1234)
    masked_aadhaar = []
    for m in re.finditer(r"\b([X\*]{4}[\s\-][X\*]{4}[\s\-]\d{4})\b", clean_text, re.IGNORECASE):
        val = m.group(1).upper()
        if val not in masked_aadhaar:
            masked_aadhaar.append(val)

    # 3e. RBI IFSC Code (Labeled IFSC or standard 4-letter bank + 0 + 6 alphanumeric)
    ifsc_candidates = []
    for m in re.finditer(r"IFSC\s*(?:Code)?\s*[:\-]?\s*([A-Z0-9]{8,13})\b", clean_text, re.IGNORECASE):
        val = m.group(1).upper()
        if val not in ifsc_candidates:
            ifsc_candidates.append(val)
    for m in re.finditer(r"\b([A-Z]{4}0[A-Z0-9]{6})\b", clean_text):
        val = m.group(1)
        if any(ch.isdigit() for ch in val[5:]) and val not in ifsc_candidates:
            ifsc_candidates.append(val)

    # 3f. Indian PIN Code (Explicitly labeled PIN / Pincode)
    pincode_candidates = []
    for m in re.finditer(r"(?:PIN\s*(?:Code)?|Pincode)\s*[:\-]?\s*(\d{6})\b", clean_text, re.IGNORECASE):
        val = m.group(1)
        if val not in pincode_candidates:
            pincode_candidates.append(val)

    # 3g. Indian Mobile Number (+91 / 10-digit)
    mobile_candidates = []
    for m in re.finditer(r"(?:(?:\+91|91)[\s\-]?)?(\b[6-9]\d{9}\b)", clean_text):
        val = m.group(1)
        if val not in mobile_candidates and not any(val in a.replace(" ", "") for a in aadhaar_candidates):
            mobile_candidates.append(f"+91-{val}")

    # 3h. Labeled Certificate / Invoice / Roll / Enrollment / EPIC / Application Numbers
    labeled_ids = []
    labeled_pattern = re.compile(
        r"(?:Cert(?:ificate)?\s*(?:No|ID)|Invoice\s*(?:No|ID)|Roll\s*(?:No|Number)|"
        r"Enrollment\s*(?:No|ID)|Reg(?:istration)?\s*(?:No|ID)|Application\s*(?:No|ID)|"
        r"EPIC\s*(?:No)?|Passport\s*(?:No)?|Challan\s*(?:No)?)\s*[:\-#]?\s*([A-Z0-9\-\/]{4,25})",
        re.IGNORECASE,
    )
    for m in labeled_pattern.finditer(clean_text):
        val = m.group(1).strip(" .,-:")
        if any(ch.isdigit() for ch in val) and val not in labeled_ids:
            labeled_ids.append(val)

    # 3i. INR Currency Amounts (₹ / Rs. / INR)
    inr_amounts = []
    for m in re.finditer(r"(?:₹|Rs\.?|INR)\s*([0-9]{1,3}(?:,[0-9]{2,3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)", clean_text, re.IGNORECASE):
        amt = f"₹{m.group(1)}"
        if amt not in inr_amounts:
            inr_amounts.append(amt)

    # Combine all primary Indian document numbers into extracted_doc_numbers for quick summary display
    combined_doc_numbers: List[str] = []
    for item in (
        [f"PAN: {p}" for p in pan_candidates]
        + [f"Aadhaar: {a}" for a in aadhaar_candidates]
        + [f"Masked Aadhaar: {ma}" for ma in masked_aadhaar]
        + [f"GSTIN: {g}" for g in gstin_candidates]
        + [f"IFSC: {i}" for i in ifsc_candidates]
        + [f"ID: {lid}" for lid in labeled_ids]
        + [f"PIN: {pin}" for pin in pincode_candidates]
    ):
        if item not in combined_doc_numbers:
            combined_doc_numbers.append(item)

    return {
        "document_category": doc_category,
        "extracted_name": extracted_name,
        "extracted_dates": found_dates[:10],
        "extracted_doc_numbers": combined_doc_numbers[:12],
        "indian_details": {
            "document_category": doc_category,
            "pan_numbers": pan_candidates,
            "aadhaar_numbers": aadhaar_candidates,
            "masked_aadhaar": masked_aadhaar,
            "gstin_numbers": gstin_candidates,
            "ifsc_codes": ifsc_candidates,
            "pincodes": pincode_candidates,
            "mobile_numbers": mobile_candidates,
            "labeled_ids": labeled_ids,
            "inr_amounts": inr_amounts[:6],
        },
    }


def _parse_ddmmyyyy(date_str: str) -> Optional[datetime]:
    """Attempt to parse Indian standard DD/MM/YYYY into a datetime object."""
    try:
        return datetime.strptime(date_str, "%d/%m/%Y")
    except ValueError:
        return None


def evaluate_fraud_indicators(
    extracted_text: str,
    entities: Dict[str, Any],
    pdf_metadata: Dict[str, Any],
    duplicate_record: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Run transparent India-specific compliance and anomaly checks across:
    - SHA-256 hash uniqueness
    - Income Tax PAN 10-char structure, 4th-char entity status & 5th-char surname initial match
    - UIDAI 12-digit Aadhaar first-digit (2-9) & Dihedral D5 Verhoeff checksum validation
    - GSTN 15-char GSTIN state code (01-38), 14th-char 'Z', & embedded PAN cross-check
    - RBI 11-char IFSC structure & mandatory 5th-character '0' check
    - India Post 6-digit PIN Code zone check (1-8)
    - PDF metadata editing signatures (Photoshop/Canva/GIMP/Sejda), timestamp mismatches & overlays
    - IST (UTC+05:30) chronological date checks
    """
    indicators: List[Dict[str, Any]] = []
    risk_score = 0
    indian_details = entities.get("indian_details", {})
    holder_name = (entities.get("extracted_name") or "").strip()

    def add_flag(code: str, title: str, severity: str, points: int, detail: str):
        nonlocal risk_score
        risk_score += points
        indicators.append({
            "code": code,
            "title": title,
            "severity": severity,  # "high" | "medium" | "low"
            "points": points,
            "detail": detail,
        })

    # 1. Exact Duplicate Document Detection (SHA-256 Collision)
    if duplicate_record:
        add_flag(
            code="DUPLICATE_SHA256",
            title="Exact Duplicate Document Detected (SHA-256 Match)",
            severity="medium",
            points=35,
            detail=(
                f"This file's SHA-256 cryptographic digest matches Scan #{duplicate_record['id']} "
                f"('{duplicate_record['original_filename']}'), previously uploaded on {duplicate_record['created_at']}."
            ),
        )

    # 2. Income Tax Department of India – PAN Validation Rules
    pan_list: List[str] = indian_details.get("pan_numbers", [])
    gstin_list: List[str] = indian_details.get("gstin_numbers", [])
    gstin_embedded_pans = {g[2:12] for g in gstin_list if len(g) >= 12}

    for pan in pan_list:
        fourth_char = pan[3]
        fifth_char = pan[4]
        if fourth_char not in PAN_ENTITY_TYPES:
            add_flag(
                code="INVALID_INDIAN_PAN_STATUS",
                title="Invalid 4th Character Holder Status in Indian PAN",
                severity="high",
                points=40,
                detail=(
                    f"PAN '{pan}' has '{fourth_char}' as its 4th character, which is not a valid Income Tax India "
                    f"entity code (valid codes: P, C, H, F, A, T, B, L, J, G)."
                ),
            )
        elif fourth_char == "P" and holder_name and pan not in gstin_embedded_pans:
            name_parts = [p for p in re.split(r"\s+", holder_name.upper()) if len(p) >= 2]
            if name_parts:
                valid_initials = {part[0] for part in name_parts}
                if fifth_char not in valid_initials:
                    add_flag(
                        code="PAN_SURNAME_INITIAL_MISMATCH",
                        title="Individual PAN 5th Character Does Not Match Holder Name Initial",
                        severity="medium",
                        points=30,
                        detail=(
                            f"Individual PAN '{pan}' (4th char 'P') has '{fifth_char}' as the 5th character, "
                            f"which does not match the surname/name initials of extracted holder '{holder_name}'."
                        ),
                    )

    # 3. UIDAI Aadhaar 12-Digit & Verhoeff Checksum Validation Rules
    for aadhaar in indian_details.get("aadhaar_numbers", []):
        digits = aadhaar.replace(" ", "")
        if digits[0] in ("0", "1"):
            add_flag(
                code="INVALID_AADHAAR_START_DIGIT",
                title="UIDAI Aadhaar Number Starts with Invalid Digit (0 or 1)",
                severity="high",
                points=45,
                detail=f"Extracted 12-digit Aadhaar '{aadhaar}' begins with '{digits[0]}'. Genuine UIDAI Aadhaar numbers only start with digits 2–9.",
            )
        elif not verify_aadhaar_verhoeff(digits):
            add_flag(
                code="INVALID_AADHAAR_VERHOEFF_CHECKSUM",
                title="UIDAI Aadhaar Failed Dihedral D5 Verhoeff Checksum",
                severity="high",
                points=45,
                detail=(
                    f"Extracted 12-digit Aadhaar '{aadhaar}' failed the mathematical UIDAI Verhoeff dihedral D5 "
                    f"check-digit verification, indicating a fabricated or mistyped Aadhaar number."
                ),
            )

    # 4. Indian GSTN – 15-Character GSTIN & State Code & PAN Cross-Check
    gstin_regex = re.compile(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$")
    for gstin in gstin_list:
        state_code = gstin[:2]
        if state_code not in INDIAN_GST_STATE_CODES:
            add_flag(
                code="INVALID_GSTIN_STATE_CODE",
                title="Invalid Indian Census State Code in GSTIN",
                severity="high",
                points=40,
                detail=(
                    f"GSTIN '{gstin}' starts with state code '{state_code}', which does not belong to any valid "
                    f"Indian State or Union Territory (valid codes: 01 to 38)."
                ),
            )
        elif not gstin_regex.match(gstin):
            add_flag(
                code="INVALID_GSTIN_STRUCTURE",
                title="Malformed 15-Character Indian GSTIN Format",
                severity="high",
                points=35,
                detail=f"GSTIN '{gstin}' violates the standard 15-character GSTN structure ([StateCode][10-char PAN][Entity][Z][Checksum]).",
            )
        else:
            embedded_pan = gstin[2:12]
            standalone_pans = [p for p in pan_list if p != embedded_pan]
            if standalone_pans:
                add_flag(
                    code="GSTIN_PAN_MISMATCH",
                    title="GSTIN Embedded PAN Conflicts with Document PAN",
                    severity="high",
                    points=45,
                    detail=(
                        f"GSTIN '{gstin}' embeds PAN '{embedded_pan}', which conflicts with standalone PAN "
                        f"'{standalone_pans[0]}' printed on the same document."
                    ),
                )

    # 5. Reserve Bank of India (RBI) – 11-Character IFSC Validation
    ifsc_regex = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")
    for ifsc in indian_details.get("ifsc_codes", []):
        if not ifsc_regex.match(ifsc):
            add_flag(
                code="INVALID_RBI_IFSC_CODE",
                title="Invalid RBI 11-Character IFSC Code Format",
                severity="medium",
                points=30,
                detail=(
                    f"IFSC code '{ifsc}' violates RBI structure (must be 11 characters: 4 bank letters, "
                    f"mandatory '0' as the 5th character, and 6 branch characters)."
                ),
            )

    # 6. India Post 6-Digit PIN Code Validation
    for pin in indian_details.get("pincodes", []):
        if pin[0] in ("0", "9"):
            add_flag(
                code="INVALID_INDIAN_PINCODE",
                title="Invalid India Post 6-Digit PIN Code Zone",
                severity="medium",
                points=25,
                detail=f"PIN code '{pin}' begins with '{pin[0]}'. Valid civilian Indian postal zones only begin with digits 1–8.",
            )

    # 7. PDF Metadata & Structure Checks (Editing Software, Timestamps, Overlays)
    producer = (pdf_metadata.get("producer") or "").lower()
    creator = (pdf_metadata.get("creator") or "").lower()
    combined_software = f"{producer} {creator}".strip()
    for editor in SUSPICIOUS_EDITORS:
        if editor in combined_software:
            add_flag(
                code="PDF_EDITOR_SIGNATURE",
                title="Graphics / PDF Editing Software Signature in Metadata",
                severity="high",
                points=40,
                detail=(
                    f"PDF metadata indicates the file was processed by '{editor.title()}' "
                    f"(Producer: '{pdf_metadata.get('producer')}', Creator: '{pdf_metadata.get('creator')}')."
                ),
            )
            break

    creation_date = (pdf_metadata.get("creationDate") or "").strip()
    mod_date = (pdf_metadata.get("modDate") or "").strip()
    if creation_date and mod_date and creation_date != mod_date:
        if creation_date[:12] != mod_date[:12]:
            add_flag(
                code="PDF_TIMESTAMP_MISMATCH",
                title="PDF Modification Date Differs from Creation Date",
                severity="medium",
                points=20,
                detail=f"Document metadata shows post-creation modification (Created: '{creation_date}', Modified: '{mod_date}').",
            )

    annot_count = int(pdf_metadata.get("annotation_count", 0) or 0)
    if annot_count > 0:
        add_flag(
            code="PDF_ANNOTATIONS_PRESENT",
            title="Overlay Annotations or Editable Objects Detected in PDF",
            severity="low",
            points=15,
            detail=f"PDF structure contains {annot_count} annotation/overlay object(s), which can mask original text.",
        )

    native_len = int(pdf_metadata.get("native_text_length", 0) or 0)
    ocr_len = int(pdf_metadata.get("ocr_text_length", 0) or 0)
    if native_len > 30 and ocr_len > 30 and abs(native_len - ocr_len) > max(native_len, ocr_len) * 0.55:
        add_flag(
            code="TEXT_LAYER_MISMATCH",
            title="Hidden Text Layer Discrepancy in PDF",
            severity="medium",
            points=25,
            detail=(
                f"Embedded PDF text length ({native_len} chars) differs substantially from visual OCR text "
                f"({ocr_len} chars), suggesting overlaid images or modified text layers."
            ),
        )

    # 8. Image Sharpness, OCR Text Completeness & Indian Identifier Presence
    img_diag = pdf_metadata.get("image_diagnostics") or {}
    if img_diag.get("is_blurry"):
        add_flag(
            code="LOW_IMAGE_SHARPNESS",
            title="Unusually Blurry or Heavily Compressed Scan",
            severity="low",
            points=15,
            detail=f"Laplacian sharpness score ({img_diag.get('sharpness_score')}) is below threshold (35.0).",
        )

    text_len = len((extracted_text or "").strip())
    if text_len < 30:
        add_flag(
            code="MINIMAL_OCR_TEXT",
            title="Minimal Readable Text Extracted via OCR",
            severity="medium",
            points=30,
            detail=f"Only {text_len} characters were extracted. The document may be blank, degraded, or obfuscated.",
        )

    has_name = bool(entities.get("extracted_name"))
    has_doc_num = bool(entities.get("extracted_doc_numbers"))
    if text_len >= 30 and (not has_name and not has_doc_num):
        add_flag(
            code="MISSING_INDIAN_IDENTIFIERS",
            title="Missing Holder Name and Indian Official Identifiers",
            severity="medium",
            points=25,
            detail="Neither a holder name nor any recognizable Indian identifier (PAN, Aadhaar, GSTIN, IFSC, Roll/Cert No) was found.",
        )
    elif text_len >= 30 and not has_doc_num:
        add_flag(
            code="MISSING_DOC_NUMBER",
            title="No Standard Indian Document / Reference Number Detected",
            severity="low",
            points=10,
            detail="Could not identify a standard PAN, Aadhaar, GSTIN, IFSC, Roll No, or Certificate/Invoice ID.",
        )

    # 9. Indian Date Validity & Chronological Consistency (IST UTC+05:30)
    now_ist = datetime.now(IST_TZ).replace(tzinfo=None)
    for d_str in entities.get("extracted_dates", []):
        dt = _parse_ddmmyyyy(d_str)
        if dt and (dt.year < 1947 or dt.year > now_ist.year + 15):
            add_flag(
                code="IMPLAUSIBLE_INDIAN_DOC_YEAR",
                title="Implausible Year Detected in Document Date",
                severity="high",
                points=35,
                detail=f"Extracted date '{d_str}' falls outside plausible post-independence operational bounds (1947–{now_ist.year + 15}).",
            )

    issue_match = re.search(
        r"(?:Issue\s*Date|Date\s*of\s*Issue|Issued\s*On|Invoice\s*Date)\s*[:\-]?\s*"
        r"(0?[1-9]|[12][0-9]|3[01])[\/\-\.](0?[1-9]|1[0-2])[\/\-\.]((?:19|20)\d{2})",
        extracted_text or "",
        re.IGNORECASE,
    )
    if issue_match:
        issue_str = f"{int(issue_match.group(1)):02d}/{int(issue_match.group(2)):02d}/{issue_match.group(3)}"
        issue_dt = _parse_ddmmyyyy(issue_str)
        if issue_dt and issue_dt > now_ist:
            add_flag(
                code="FUTURE_ISSUE_DATE_IST",
                title="Document Issue / Invoice Date is in the Future (IST)",
                severity="high",
                points=40,
                detail=f"The stated Issue/Invoice Date ({issue_str}) is later than today's Indian Standard Time date ({now_ist.strftime('%d/%m/%Y')}).",
            )

    # Cap total score at 100 and classify Risk Level
    risk_score = min(risk_score, 100)
    if risk_score >= 55:
        risk_level = "High Risk"
    elif risk_score >= 25:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "fraud_indicators": indicators,
    }
