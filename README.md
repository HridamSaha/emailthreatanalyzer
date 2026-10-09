# Email Threat Analysis and Malware Detection System (ETAS)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![React 19](https://img.shields.io/badge/React-19-61dafb.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-6.0+-3178c6.svg)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-8.3+-646cff.svg)](https://vite.dev/)
[![Tailwind CSS v4](https://img.shields.io/badge/TailwindCSS-v4-38bdf8.svg)](https://tailwindcss.com/)
[![Tests](https://img.shields.io/badge/Tests-43%2F43%20Passing-brightgreen.svg)]()

The **Email Threat Analysis and Malware Detection System (ETAS)** is an enterprise-grade cybersecurity analysis platform engineered for Security Operations Center (SOC) analysts, incident responders, and malware investigators. It performs explainable, non-executing static inspection of suspicious RFC 5322 emails, URLs, and binary attachments without executing malicious payloads or opening network connections to untrusted endpoints.

---

## Key Capabilities

1. **RFC 5322 Email Parsing**: Robust decomposition of headers, body parts, MIME boundaries, and attachments.
2. **Sender Spoofing Detection**: Evaluates identity alignment across `From`, `Reply-To`, and `Return-Path` headers (`EMAIL-001`).
3. **Lexical URL Inspection**: Extracts and analyzes URLs for IP literals, unusual ports, lookalikes, and punycode without network connections (`URL-001` - `URL-003`).
4. **Static Attachment Forensics**: Calculates SHA-256 digests, matches magic signatures against MIME types (`ATTACH-002`), flags dangerous extensions (`ATTACH-001`), and safely inspects archive contents with strict path traversal defenses.
5. **Explainable Risk Scoring**: Configurable 0–100 scoring engine with defensive safeguards preventing single weak anomalies from generating false-positive malicious labels.
6. **Multi-Indicator Correlation**: Heightens risk when independent indicator categories agree (`CORR-001`).
7. **Automated IoC Extraction**: Extracts SHA-256 hashes, domains, IP addresses, and URLs with 1-click clipboard copy and CSV export.
8. **Forensic Report Generation**: Generates downloadable PDF threat dossiers and machine-readable JSON/CSV exports.
9. **Full SOC Dashboard**: Interactive dark-navy cybersecurity dashboard with live KPI cards, Recharts visualizations, and filterable history.
10. **Air-Gapped by Design**: Functions locally without external API keys or third-party service dependencies.

---

## System Architecture

```
email-threat-analysis-system/
├── frontend/                     # React + TypeScript + Vite + Tailwind CSS SOC Interface
│   ├── src/
│   │   ├── components/           # ScoreGauge, ClassificationBadge, Navbar
│   │   ├── pages/                # Dashboard, Analyze, Results, History, Rules, Analytics
│   │   ├── services/             # Typed API client
│   │   ├── types/                # Strict domain interfaces
│   │   └── test/                 # Vitest & Testing Library suites
├── backend/                      # Python 3.11+ FastAPI Static Analysis Engine
│   ├── app/
│   │   ├── api/v1/               # REST Endpoints (Analyze, Analyses, Rules, Stats)
│   │   ├── core/                 # Config, Database engine, Rules Catalog, Lifespan
│   │   ├── models/               # SQLAlchemy ORM Models (Analysis, Finding, IoC, etc.)
│   │   ├── schemas/              # Pydantic v2 validation contracts
│   │   └── services/
│   │       ├── email_parser.py   # RFC message decoding, MIME recursion, link extraction
│   │       ├── url_analyzer.py   # Lexical & structural URL inspection (No network request)
│   │       ├── attachment_analyzer.py # Magic bytes, zipfile traversal checks, file signatures
│   │       ├── hash_service.py   # Cryptographic SHA-256 calculation
│   │       ├── detection_engine.py    # Modular detection rules (EMAIL, URL, ATTACH, CORR, PARSER)
│   │       ├── risk_scorer.py    # Explainable 0-100 scoring & safeguard logic
│   │       ├── ioc_extractor.py  # Structured IoC extraction (hashes, domains, IPs, URLs)
│   │       └── report_generator.py # Professional PDF dossier & CSV export engine
│   └── tests/                    # Comprehensive Pytest test cases (TC01 - TC07)
├── diagrams/                     # Mermaid diagrams (pipeline, sandbox architecture)
├── docs/                         # Architecture, API, Safety, and Testing guides
└── samples/                      # Synthetic benign, suspicious, and malformed .eml fixtures
```

### Analysis Pipeline Flowchart
See [`diagrams/pipeline.mermaid`](diagrams/pipeline.mermaid) for the full Mermaid diagram.

```
Input (.eml / Raw / URL / File)
       │
       ▼
Input Validation & Size Limit (<10MB)
       │
       ▼
Static Header, URL, Body & Attachment Extraction
       │
       ▼
SHA-256 Hashing & Magic Signature Matching
       │
       ▼
Modular Detection Rules Evaluation (EMAIL, URL, ATTACH)
       │
       ▼
Indicator Correlation (CORR-001) & Safeguard Evaluation
       │
       ▼
Explainable 0–100 Scoring & Classification (Safe / Suspicious / Malicious / Manual Review)
       │
       ▼
Database Persistence (SQLite / PostgreSQL)
       │
       ▼
SOC Dashboard Display & PDF / JSON / CSV Dossier Generation
```

---

## Installation & Setup

### Prerequisites
- **Python**: Version 3.11 or higher
- **Node.js**: Version 18.0 or higher (Node 20+ recommended)
- **Git**

---

### Step 1: Clone Repository & Configure Environment

```powershell
# Windows PowerShell
git clone <repo-url>
cd email-threat-analysis-system

# Copy environment template
Copy-Item .env.example backend\.env
```

```bash
# Linux / macOS
git clone <repo-url>
cd email-threat-analysis-system

# Copy environment template
cp .env.example backend/.env
```

---

### Step 2: Backend Setup

```powershell
# Windows PowerShell
cd backend

# Create virtual environment
python -m venv venv
.env\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run backend test suite (32 tests)
pytest

# Start the FastAPI backend server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

```bash
# Linux / macOS
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run backend test suite (32 tests)
pytest

# Start the FastAPI backend server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend API will be live at `http://127.0.0.1:8000`.  
Interactive OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.

---

### Step 3: Frontend Setup

Open a second terminal window:

```powershell
# Windows PowerShell
cd frontend

# Install dependencies
npm install

# Run frontend test suite (11 tests)
npm run test

# Build for production verification
npm run build

# Start development server
npm run dev
```

```bash
# Linux / macOS
cd frontend

# Install dependencies
npm install

# Run frontend test suite (11 tests)
npm run test

# Build for production verification
npm run build

# Start development server
npm run dev
```

The frontend dashboard will be accessible at `http://localhost:5173`.

---

## Demonstration Workflow & Test Samples

Synthetic sample emails are provided in the [`samples/`](samples/) directory:

| Scenario | Sample File | Detection Indicators | Expected Outcome |
|---|---|---|---|
| **TC01 — Benign Email** | `samples/benign.eml` | Legitimate sender, routine staff meeting text | **Safe** (Risk Score < 30) |
| **TC02 — Suspicious URL** | `samples/suspicious-url.eml` | IP literal hostname on non-standard port 8443 | **Suspicious** (Rules: `URL-001`, `URL-003`) |
| **TC03 — Sender Mismatch** | `samples/sender-mismatch.eml` | `From` vs `Reply-To` and `Return-Path` mismatch | **Suspicious** (Rule: `EMAIL-001`) |
| **TC04 — Risky Attachment** | `samples/risky-attachment.eml` | Deceptive extension (`.txt` containing `MZ` binary header) | **Suspicious** (Rules: `ATTACH-001`, `ATTACH-002`) |
| **TC05 — Known Malicious Hash** | Mock fixture | SHA-256 match in local indicator catalog | **Malicious** (Rule: `ATTACH-003`) |
| **TC06 — Multiple Indicators** | `samples/phishing-multi.eml` | Sender spoofing + credential request + urgency language | **Elevated Risk** (Rules: `EMAIL-001`, `EMAIL-003`, `CORR-001`) |
| **TC07 — Malformed Email** | `samples/malformed.eml` | Incomplete or corrupt RFC headers | **Manual Review** (Rule: `PARSER-001`) |

### Step-by-Step Demonstration
1. Navigate to `http://localhost:5173/analyze`.
2. Select **Upload .EML** and drag `samples/phishing-multi.eml`.
3. Click **Execute Threat Analysis**.
4. The system navigates to the **Analysis Results** page displaying:
   - Dynamic Risk Score Gauge (e.g., 40/100).
   - Classification badge (**Suspicious**).
   - Triggered detection rules: `EMAIL-001` (Sender mismatch), `EMAIL-003` (Credential request), `CORR-001` (Multi-indicator correlation).
   - Structured IoC table with 1-click clipboard copy.
   - Click **PDF Report** to download the analysis report.
5. Navigate to **Dashboard** to see updated real-time telemetry and distribution charts.
6. Navigate to **Detection Rules** to inspect and toggle active heuristics.
7. Navigate to **Analysis History** to filter, search, or delete cases.

---

## Detection Rules Catalog

| Rule ID | Rule Name | Category | Severity | Score | Detection Logic Summary |
|---|---|---|---|---|---|
| `EMAIL-001` | Sender Identity Mismatch | Email | High | +15 | Checks discrepancies between `From`, `Reply-To`, and `Return-Path` mailboxes. |
| `EMAIL-002` | Suspicious Sender Domain | Email | Medium | +10 | Identifies lookalike brand strings, numerical domains, and unusual TLDs. |
| `EMAIL-003` | Credential Harvesting Request | Content | High | +15 | Detects requests for passwords, MFA codes, OTPs, or login confirmations. |
| `EMAIL-004` | Urgency & Financial Pressure | Content | Medium | +12 | Detects combinations of urgency ("act now") and financial instructions ("gift card", "wire"). |
| `URL-001` | Suspicious URL Structure | URL | Medium | +10 | Flags userinfo disguises, punycode (xn--), unusual ports, and nested encodings. |
| `URL-002` | Link Destination Mismatch | URL | High | +12 | Flags discrepancies between visible anchor text and actual `href` destination. |
| `URL-003` | IP-Based Destination Host | URL | Medium | +10 | Flags URLs whose destination host is a literal IPv4/IPv6 address. |
| `ATTACH-001`| Risky File Type | Attachment | High | +20 | Flags executable, script, or macro-enabled attachment types (.exe, .bat, .vbs, .docm). |
| `ATTACH-002`| File Signature Mismatch | Attachment | High | +18 | Identifies disagreements between reported MIME type, extension, and magic bytes. |
| `ATTACH-003`| Known Malicious Hash Match | Attachment | Critical | +50 | Matches SHA-256 against configured local or external intelligence indicators. |
| `CORR-001`  | Multi-Indicator Correlation | Correlation| High | +10 | Amplifies risk score when two or more distinct indicator categories trigger together. |
| `PARSER-001`| Malformed or Incomplete Message | Parser | Low | +5 | Flags parsing failures, routing incomplete cases to Manual Review. |
| `INTEL-001` | External Threat Reputation Match| Intel | High | +25 | Identifies positive threat intelligence reputation from configured providers. |

---

## Testing & Quality Assurance

### Automated Backend Tests
Run `pytest` in `backend/`:
```bash
pytest
```
- **32 tests executed, 32 passed (100% pass rate)**.
- Validates RFC parsing, missing headers, URL heuristics, signature detection, SHA-256 accuracy, risk scoring, classification thresholds, database persistence, PDF report generation, and API error handling.

### Automated Frontend Tests
Run `npm run test` in `frontend/`:
```bash
npm run test
```
- **11 tests executed, 11 passed (100% pass rate)**.
- Validates dashboard empty states, KPI metric rendering, classification badges, score gauge thresholds, input validation, and sample loader actions.

---

## Optional Integrations

The system is fully operational in standalone offline mode. Optional integrations can be configured via environment variables:

1. **VirusTotal**: Set `VIRUSTOTAL_API_KEY` in `backend/.env` for hash reputation lookups.
2. **ClamAV**: Set `CLAMAV_ENABLED=true` and configure `CLAMAV_HOST` / `CLAMAV_PORT`.
3. **YARA**: Place defensive `.yar` rules in `backend/yara_rules/` for static string inspection.
4. **Machine Learning Classifier**: Experimental scikit-learn feature extraction module (`backend/app/services/ml/`).

---

## Safety & Threat Model

- **Safe Static Parsing**: Attachments are inspected in-memory; no scripts, macros, or binaries are executed.
- **No Remote Network Requests**: URLs are parsed lexically without contacting remote servers.
- **Archive Extraction Bounds**: Defenses prevent zip-bomb DoS and path traversal attacks (`../`).
- **Sanitized HTML**: Raw untrusted email HTML is stripped to plain text before rendering.
- **Dynamic Analysis Sandbox**: See [`diagrams/sandbox.mermaid`](diagrams/sandbox.mermaid) for isolated VM execution architecture.

---

## License & Academic Attribution
Developed as an academic and engineering reference implementation for **Email Threat Analysis and Malware Detection**. Designed for defensive security research, incident response training, and educational demonstration.
