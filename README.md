# DocShield Bharat – Made in India Document Fraud Detection & Screening System 🇮🇳

> **Educational Prototype Disclaimer:** DocShield Bharat is a college-level, **Made in India** educational fraud-screening prototype built with Python Flask, OpenCV, PyMuPDF, Tesseract OCR, and Supabase PostgreSQL (`ap-south-1` Mumbai). Rule-based Indian regulatory checks (Income Tax PAN, UIDAI Aadhaar Verhoeff D5, GSTN 15-Digit State Code, RBI IFSC, India Post PIN), metadata inspection, and OCR extraction highlight suspicious document anomalies for manual review; they **do not conclusively prove or disprove legal forgery**.

## 1. Beginner Step-by-Step Guide: From Downloading Here to Running & Deploying

If you are a complete beginner, follow these exact steps in order. You do **not** need to copy-paste individual code files manually—everything is already packaged inside `docshield_flask_project.zip`.

### Phase A: Download & Extract the Project on Your Laptop

1. **Download the ZIP file:** Click the download icon on the `docshield_flask_project.zip` file card in the chat response.
2. **Extract the ZIP:**
   * **On Windows:** Right-click `docshield_flask_project.zip` in your `Downloads` folder -> click **Extract All...** -> extract it to your Desktop or `C:\Projects\`.
   * **On macOS / Linux:** Double-click `docshield_flask_project.zip` (or run `unzip docshield_flask_project.zip`).
3. Inside the extracted folder, you will see a folder named `docshield` containing all 15 project files (`app.py`, `fraud_analyzer.py`, `ocr_pipeline.py`, `templates/`, `static/`, `Dockerfile`, etc.).

### Phase B: Install the 4 Free Required Tools on Your Laptop

1. **Install Python (3.10 or 3.11+):**
   * Download from the [Official Python Downloads Page](https://www.python.org/downloads/).
   * **CRITICAL FOR WINDOWS USERS:** On the first screen of the Python installer, tick the checkbox at the bottom that says **"Add python.exe to PATH"** before clicking **Install Now**.
2. **Install Visual Studio Code (VS Code):**
   * Download and install from the [Official VS Code Download Page](https://code.visualstudio.com/download).
3. **Install Git:**
   * Download and install from the [Official Git Installer Page](https://git-scm.com/install/windows) (accept all default options during setup).
4. **Install Tesseract OCR Engine (Required so Python can read text from images):**
   * **Windows:** Go to the [UB Mannheim Tesseract Windows Installer Wiki](https://github.com/UB-Mannheim/tesseract/wiki), download the latest 64-bit `tesseract-ocr-w64-setup-*.exe`, and run it. Keep the default installation path (`C:\Program Files\Tesseract-OCR\tesseract.exe`).
   * **Ubuntu / Linux / WSL:** Open your terminal and run:
     ```bash
     sudo apt-get update && sudo apt-get install -y tesseract-ocr libgl1
     ```
   * **macOS:** Open Terminal and run:
     ```bash
     brew install tesseract
     ```

### Phase C: Open the Project in VS Code & Run It on Your Laptop (Offline Mode First!)

You can run the entire app on your laptop **without** setting up Supabase or the cloud first—DocShield automatically creates a local SQLite database (`docshield_local.db`) and local `uploads/` folder when cloud keys are blank.

1. Open **VS Code**, click **File** -> **Open Folder...**, and select the extracted `docshield` folder.
2. Open the built-in VS Code Terminal by pressing `` Ctrl + ` `` (or from the top menu: **Terminal** -> **New Terminal**).
3. **Create a Python Virtual Environment** (run this in the VS Code terminal):
   * **Windows (PowerShell / CMD):**
     ```powershell
     python -m venv venv
     venv\Scripts\activate
     ```
     *(If PowerShell gives an execution policy warning, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first, then run `venv\Scripts\activate`.)*
   * **macOS / Linux:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
4. **Install all Python libraries:**
   ```bash
   pip install -r requirements.txt
   ```
5. **Create your `.env` file:**
   * In VS Code's left sidebar, right-click `.env.example` -> copy and paste it in the same folder -> rename the copy to `.env`.
   * Open `.env`:
     * Leave `DATABASE_URL=` and `SUPABASE_URL=` **empty** for now (`DATABASE_URL=` with nothing after `=`) so it runs in local mode first.
     * **If you are on Windows:** Set `TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe`. (On Mac/Linux, leave `TESSERACT_CMD=` empty).
6. **Run the Automated Test Suite (creates 3 sample Indian documents and scans them):**
   ```bash
   python tests/test_pipeline.py
   ```
   You will see `All 4 Indian Pipeline Tests PASSED!` in the terminal.
7. **Start the Web Application:**
   ```bash
   python app.py
   ```
8. Open your browser (Chrome/Edge) and visit:
   ```text
   http://127.0.0.1:5000
   ```
   Your **DocShield Bharat** web app is now live on your laptop! Try uploading any PDF, JPG, or PNG document (like a sample PAN card, Aadhaar card, marksheet, or GST invoice).

### Phase D: Connect Free Cloud Database & Private Storage (Supabase Mumbai `ap-south-1`)

Once local mode works, connect your cloud PostgreSQL database and private file bucket:

1. Go to [Supabase](https://supabase.com/docs/guides/database/overview), sign up with your GitHub account, and click **New Project**.
2. Name your project `docshield-bharat`, set a strong **Database Password** (save this password in a notepad!), and select **South Asia (Mumbai)** as the Region. Wait ~2 minutes for the database to finish provisioning.
3. **Create the Database Table:**
   * In the left sidebar of Supabase, click **SQL Editor** -> **New query**.
   * Open `schema.sql` from your VS Code project, copy all its contents, paste them into the Supabase SQL Editor, and click **Run**. You will see `Success. No rows returned`.
4. **Create the Private Storage Bucket:**
   * In the left sidebar of Supabase, click **Storage** -> **New bucket** ([Supabase Buckets Guide](https://supabase.com/docs/guides/storage/buckets/creating-buckets)).
   * Name the bucket exactly: `documents-private`
   * Keep **Public bucket** switched **OFF** (so uploaded KYC documents stay private) and click **Save**.
5. **Copy your 3 Supabase Credentials into `.env`:**
   * Click the **Connect** button at the top of the Supabase dashboard -> under **Transaction Pooler (Port 6543)** ([Supabase Connection Pooling](https://supabase.com/docs/guides/database/connecting-to-postgres/pooling-and-limits)), copy the URI and replace `[YOUR-PASSWORD]` with your database password:
     ```ini
     DATABASE_URL=postgresql://postgres.xxxxx:YourActualPassword@aws-0-ap-south-1.pooler.supabase.com:6543/postgres?sslmode=require
     ```
   * In the left sidebar, click **Project Settings (gear icon)** -> **API**:
     * Copy **Project URL** into `SUPABASE_URL=https://xxxxx.supabase.co`
     * Copy the **`service_role` secret** key into `SUPABASE_SERVICE_ROLE_KEY=eyJ...`
6. Restart `python app.py` in VS Code. Notice the top-right badge in the navbar now says **Supabase PostgreSQL (Mumbai ap-south-1)** and **Supabase Private Bucket**!

### Phase E: Upload Code to GitHub & Deploy Online for Free on Render

1. **Create a New GitHub Repository:**
   * Log in to GitHub, click the **+** icon in the top-right corner -> **New repository**.
   * Name it `docshield-bharat`, keep it Public or Private, and click **Create repository**.
2. **Push Your Code from VS Code Terminal:**
   *(Because `.gitignore` is already configured, your secret `.env` file will NOT be uploaded to GitHub.)*
   ```bash
   git init
   git add .
   git commit -m "Initial commit: DocShield Bharat Made in India Fraud Screening System"
   git branch -M main
   git remote add origin https://github.com/YOUR-GITHUB-USERNAME/docshield-bharat.git
   git push -u origin main
   ```
3. **Deploy on Render (Free Tier with Docker for Tesseract OCR):**
   * Sign in to [Render](https://render.com/docs/deploy-flask) using your GitHub account.
   * Click **New +** -> **Web Service** -> connect your `docshield-bharat` GitHub repository.
   * Set **Runtime** to **Docker** ([Render Docker Docs](https://render.com/docs/docker)) — Render will automatically use our included `Dockerfile` to install Linux `tesseract-ocr` and `libgl1` inside the cloud server!
   * Select the **Free** instance type.
   * Scroll down to **Environment Variables** and add these 5 variables:
     * `FLASK_SECRET_KEY` = any random long string (e.g., `my-college-project-secret-2026-india`)
     * `DATABASE_URL` = your Supabase Transaction Pooler URI
     * `SUPABASE_URL` = your Supabase Project URL
     * `SUPABASE_SERVICE_ROLE_KEY` = your Supabase `service_role` key
     * `SUPABASE_BUCKET` = `documents-private`
   * Click **Create Web Service**. After 3–5 minutes, your live `.onrender.com` HTTPS URL will be active!

### Phase F: Connect Your Free Student Custom Domain (GitHub Student Developer Pack)

1. Apply for the [GitHub Student Developer Pack](https://education.github.com/pack) using your college `.ac.in` / `.edu.in` email or college ID card.
2. Once approved, claim a free 1-year domain from [Namecheap Education](https://nc.me/landing/github) (`.me`) or [.TECH Domains](https://get.tech/github-student-developer-pack) (`.tech`).
3. In your Render Web Service dashboard, go to **Settings** -> **Custom Domains** -> click **Add Custom Domain** -> enter your domain (e.g., `docshield.yourname.me`).
4. Log into your Namecheap / .TECH DNS settings and add the `CNAME` (`www` -> `your-app.onrender.com`) and `A` record (`@` -> `216.24.57.1`) shown by Render. Render will automatically activate free HTTPS!

## 2. System Architecture & 9-Stage Indian OCR Pipeline

DocShield Bharat processes uploaded Indian official, KYC, tax, and academic documents (`PDF`, `JPG`, `JPEG`, `PNG`) through a deterministic 9-stage pipeline:

| Stage | Pipeline Step | Module / Function | India-Specific Technical Implementation |
| :--- | :--- | :--- | :--- |
| **1** | **Document Upload** | `app.py` (`/upload`) | Multipart form upload via [Flask](https://flask.palletsprojects.com/) & [Bootstrap 5.3](https://getbootstrap.com/docs/5.3/getting-started/introduction/) UI with Indian Tricolour theme. |
| **2** | **File Validation** | `ocr_pipeline.py` (`validate_file`) | Verifies file extension, enforces 10 MB limit, and inspects binary magic-byte headers (`%PDF-`, `\x89PNG`, `\xff\xd8\xff`) to block renamed executables. |
| **3** | **Image Preprocessing** | `ocr_pipeline.py` (`preprocess_image_opencv`) | Converts image to grayscale using [OpenCV](https://docs.opencv.org/4.9.0/), measures Laplacian sharpness, upscales low-resolution scans (`1.5x` bicubic), denoises with Gaussian blur, and applies Otsu adaptive binarization (`cv2.THRESH_BINARY + cv2.THRESH_OTSU`). |
| **4** | **OCR Extraction** | `ocr_pipeline.py` (`run_tesseract_on_image`) | Extracts text from preprocessed images and rasterized PDF pages (`200 DPI` via [PyMuPDF](https://pymupdf.readthedocs.io/)) using [Tesseract OCR](https://tesseract-ocr.github.io/) and [pytesseract](https://pypi.org/project/pytesseract/) (`--oem 3 --psm 6`). |
| **5** | **Indian Entity Analysis** | `fraud_analyzer.py` (`extract_entities`) | Auto-classifies Indian document category (Aadhaar, PAN, GST Invoice, AICTE/UGC/CBSE Marksheet, e-District Certificate, Bank KYC) and extracts Indian names (`Shri`, `Smt.`, `Kumari`, `S/O`, `D/O`, `W/O`), `DD/MM/YYYY` dates, [Income Tax PAN](https://www.incometaxindia.gov.in/w/how-pan-is-formed-and-how-it-gets-its-unique-identity-), [UIDAI Aadhaar](https://aadhaarvalidate.com/aadhaar-number-format), [15-Digit GSTIN](https://cleartax.in/gst-number-search/), [RBI IFSC](https://www.rbi.org.in/commonman/english/scripts/FAQs.aspx?Id=274), 6-Digit PIN Code, `+91` Mobile, and `₹` (`Rs.`) amounts. |
| **6** | **Duplicate & Metadata Check** | `ocr_pipeline.py` & `fraud_analyzer.py` | Computes 64-character `SHA-256` cryptographic digest (`hashlib.sha256`) to detect duplicate uploads and inspects PDF `/Producer`, `/Creator`, `/CreationDate`, `/ModDate`, annotations, and hidden text layers. |
| **7** | **Indian Fraud Indicator Detection** | `fraud_analyzer.py` (`evaluate_fraud_indicators`) | Evaluates 15 transparent India-specific compliance and forensic heuristics (Verhoeff D5 Aadhaar checksum, PAN 4th-char entity & 5th-char surname match, GSTIN Census state code `01–38` & embedded PAN cross-check, RBI IFSC 5th-char zero check, India Post PIN zone `1–8`, Photoshop/Canva metadata, IST future dates). |
| **8** | **Risk Assessment** | `fraud_analyzer.py` (`evaluate_fraud_indicators`) | Aggregates rule points (`0–100`) into **Low Risk** (`0–24`), **Medium Risk** (`25–54`), or **High Risk** (`55–100`). |
| **9** | **Storage & IST Dashboard** | `database.py`, `storage.py`, `app.py` | Uploads raw files to a private [Supabase Storage](https://supabase.com/docs/guides/storage) bucket, stores structured JSON/text records with **Indian Standard Time (`IST UTC+05:30`)** timestamps in [Supabase PostgreSQL](https://supabase.com/docs/guides/database/connecting-to-postgres), and renders audit reports on the Dashboard. |

## 3. India-Specific Fraud & Compliance Checking Parameters

All checking parameters in `fraud_analyzer.py` are built around official Indian regulatory, tax, banking, and postal standards:

| Rule Code | Indian Standard / Authority | Trigger Condition | Severity | Risk Points | College Viva Explanation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `INVALID_AADHAAR_START_DIGIT` | [UIDAI Aadhaar Format](https://aadhaarvalidate.com/aadhaar-number-format) | 12-digit Aadhaar begins with `0` or `1` | High | `+45` | Genuine 12-digit UIDAI Aadhaar numbers only begin with digits `2–9`. |
| `INVALID_AADHAAR_VERHOEFF_CHECKSUM` | [UIDAI Dihedral D5 Verhoeff](https://www.toolique.in/compliance/aadhaar-data-vault-validator) | 12th digit fails the Dihedral $D_5$ Verhoeff check-digit algorithm | High | `+45` | UIDAI computes the 12th digit of every Aadhaar number using the Verhoeff algorithm (`_VERHOEFF_D` and `_VERHOEFF_P` matrices); any random 12-digit edit fails this mathematical check. |
| `GSTIN_PAN_MISMATCH` | [GSTN 15-Digit Structure](https://cleartax.in/gst-number-search/) | Characters 3–12 of GSTIN (`gstin[2:12]`) conflict with the standalone PAN on the same invoice | High | `+45` | Every Indian GSTIN embeds the taxpayer's 10-character PAN in positions 3–12. A mismatch proves one of the two numbers was altered. |
| `INVALID_GSTIN_STATE_CODE` | [Indian Census GST State Codes](https://www.bajajfinserv.in/gst-state-code) | First 2 digits of GSTIN are outside valid Indian State/UT codes (`01` J&K to `38` Ladakh, `97` Other) | High | `+40` | Flags fabricated GST numbers that start with nonexistent state codes (such as `00` or `99`). |
| `INVALID_INDIAN_PAN_STATUS` | [Income Tax Dept of India](https://www.incometaxindia.gov.in/w/how-pan-is-formed-and-how-it-gets-its-unique-identity-) | 4th character of 10-char PAN is not in `{P, C, H, F, A, T, B, L, J, G}` | High | `+40` | The 4th character of an Indian PAN encodes the legal entity status (`P` = Individual, `C` = Company, `H` = HUF, `F` = Firm, `G` = Govt). |
| `PDF_EDITOR_SIGNATURE` | Digital Document Forensics | PDF `/Producer` or `/Creator` contains Photoshop, GIMP, Canva, Illustrator, Sejda, iLovePDF, CorelDraw | High | `+40` | Official Indian e-District certificates, marksheets, and ERP invoices are not produced in photo editors. |
| `FUTURE_ISSUE_DATE_IST` | Indian Standard Time (`IST`) | Stated `Issue Date` or `Invoice Date` (`DD/MM/YYYY`) is later than current `IST (UTC+05:30)` date | High | `+40` | A valid certificate or GST invoice cannot have an issue date in the future. |
| `INVALID_GSTIN_STRUCTURE` | [GSTN Format Rules](https://cleartax.in/gst-number-search/) | 15-character GSTIN violates `[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]` (e.g., 14th char is not `Z`) | High | `+35` | In every valid Indian GSTIN, the 14th character is `Z` by default. |
| `IMPLAUSIBLE_INDIAN_DOC_YEAR` | Chronological Sanity | Extracted `DD/MM/YYYY` date year is `< 1947` or `> current_year + 15` | High | `+35` | Catches OCR typos or fabricated post-independence dates on altered Indian documents. |
| `DUPLICATE_SHA256` | Cryptographic Integrity | Exact 256-bit `SHA-256` file hash matches an earlier scan in PostgreSQL | Medium | `+35` | Prevents resubmission of the exact same digital file under a different filename. |
| `PAN_SURNAME_INITIAL_MISMATCH` | [Income Tax Dept PAN Rules](https://www.incometaxindia.gov.in/w/how-pan-is-formed-and-how-it-gets-its-unique-identity-) | Individual PAN (`4th char == 'P'`) 5th character does not match holder's name/surname initials | Medium | `+30` | For an Individual Indian citizen (`P`), the 5th character of PAN is the first letter of the holder's surname/last name. |
| `INVALID_RBI_IFSC_CODE` | [Reserve Bank of India (RBI)](https://www.rbi.org.in/commonman/english/scripts/FAQs.aspx?Id=274) | Labeled IFSC code does not match `^[A-Z]{4}0[A-Z0-9]{6}$` (5th character must be `0`) | Medium | `+30` | RBI mandates 11 characters for NEFT/RTGS IFSC codes where the 5th character is always `0` (zero). |
| `INVALID_INDIAN_PINCODE` | India Post (Postal Index Number) | 6-digit PIN code starts with `0` or `9` (outside postal zones `1–8`) | Medium | `+25` | India is divided into 8 regional postal zones (`1` to `8`, plus `9` for Army Postal Service); standard civilian PIN codes never start with `0`. |
| `TEXT_LAYER_MISMATCH` | PDF Structural Inspection | Embedded PDF native text length differs from visual OCR text length by `> 55%` | Medium | `+25` | Detects PDFs where an image was pasted over existing text without flattening. |
| `PDF_TIMESTAMP_MISMATCH` | PDF Metadata Inspection | PDF `/CreationDate` differs from `/ModDate` | Medium | `+20` | Indicates the PDF was modified and re-saved after initial generation. |

## 4. Indian College Viva Voce Preparation Guide (Top Questions & Answers)

1. **How does DocShield Bharat validate an Indian Aadhaar number without calling a paid UIDAI API?**
   * *Answer:* UIDAI generates 12-digit Aadhaar numbers using two deterministic mathematical rules: first, the starting digit is always between `2` and `9` (never `0` or `1`); second, the 12th digit is a cryptographic checksum computed over the first 11 digits using the **Dihedral $D_5$ Verhoeff Algorithm**. Our `verify_aadhaar_verhoeff()` function implements the exact $10 \times 10$ dihedral multiplication matrix (`_VERHOEFF_D`) and $8 \times 10$ permutation matrix (`_VERHOEFF_P`) to catch fabricated or mistyped Aadhaar numbers offline in sub-millisecond time.
2. **How do you cross-verify an Indian PAN card number and a GSTIN on an invoice?**
   * *Answer:* According to the [Income Tax Department of India](https://www.incometaxindia.gov.in/w/how-pan-is-formed-and-how-it-gets-its-unique-identity-), the 4th character of a 10-character PAN must be a valid legal entity status (`P` for Individual, `C` for Company, `H` for HUF, `F` for Firm, etc.), and for an Individual (`P`), the 5th character must match the first letter of the holder's surname. Furthermore, a 15-character Indian GSTIN starts with a 2-digit Census State Code (`01–38`), followed immediately by the taxpayer's 10-character PAN in positions 3–12, and `'Z'` at position 14. Our rule engine verifies both structures and checks that the PAN embedded inside the GSTIN matches any standalone PAN printed on the document.
3. **How is an RBI IFSC code validated in your pipeline?**
   * *Answer:* As mandated by the [Reserve Bank of India (RBI)](https://www.rbi.org.in/commonman/english/scripts/FAQs.aspx?Id=274), every NEFT/RTGS bank branch IFSC code is 11 characters long (`^[A-Z]{4}0[A-Z0-9]{6}$`), where the first 4 letters identify the bank, the **5th character is strictly `0` (zero)** reserved for future use, and the last 6 characters identify the branch.
4. **Why do we preprocess scanned documents with OpenCV before calling Tesseract OCR?**
   * *Answer:* Indian documents are frequently uploaded as mobile phone photos with shadows or background textures (such as the guilloche patterns on PAN and Aadhaar cards). Converting to grayscale (`cv2.cvtColor`), upscaling low-resolution scans (`cv2.resize`), smoothing noise (`cv2.GaussianBlur`), and applying Otsu's adaptive binarization (`cv2.threshold`) cleanly isolates the dark text characters for Tesseract OCR.
5. **Can this system conclusively prove legal forgery under Indian law?**
   * *Answer:* No. DocShield Bharat is an **educational first-pass fraud-screening prototype**. It flags structural, cryptographic (`SHA-256`), metadata (`Photoshop`/`Canva`), and regulatory anomalies (`Verhoeff`, `PAN`, `GSTIN`, `IFSC`) so human verification officers know which documents require forensic inspection or official DigiLocker / NSDL / GST portal verification.
