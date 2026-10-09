# System Architecture & Technical Specifications

## 1. System Overview
The **Email Threat Analysis and Malware Detection System (ETAS)** is an enterprise-grade cybersecurity analysis platform designed for defensive security operations center (SOC) analysts, incident responders, and malware investigators. It performs explainable static inspection of suspicious RFC 5322 emails, URLs, and binary attachments without executing malicious payloads or opening network connections to untrusted endpoints.

## 2. Core Functional Modules

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

## 3. Data Processing Pipeline
1. **Input Validation**: Uploaded `.eml` files or raw streams are checked for size (< 10 MB) and RFC message headers.
2. **Parsing & Decoding**: MIME boundaries are traversed safely, handling encoded word headers (RFC 2047), multi-part alternatives, nested archives, and character set conversions (UTF-8, Latin-1, ASCII).
3. **Static Feature Extraction**:
   - Headers: `From`, `Reply-To`, `Return-Path`, `Message-ID`, `Subject`, `Date`, explicit `Authentication-Results` (SPF, DKIM, DMARC).
   - Body: Plain-text sanitization (HTML stripped, script tags eradicated), keyword matching for credential harvesting, urgency, and financial pressure.
   - URLs: Regex and HTML `href` extraction.
   - Attachments: Extracted payload buffers, filename, size, SHA-256 calculation.
4. **Binary & Artifact Signature Matching**: First 512 bytes are compared against known magic signatures (`MZ`, `%PDF`, `PK`, `7z`, `Rar!`, etc.) to detect deceptive extension mismatches (e.g., `.txt` executable).
5. **Rule Execution**: 13 configurable detection rules evaluate observed artifacts.
6. **Correlation & Scoring**: Independent indicator categories are correlated. The score is computed as $\text{Score} = \min(100, \sum \text{Rules})$, with safeguards applied for single weak anomalies and trusted intelligence matches.
7. **Persistence**: Analysis metadata, findings, and IoCs are recorded in SQLite/PostgreSQL with transactional integrity.
8. **Visualization & Reporting**: Real-time rendering via Recharts and on-demand PDF report generation via ReportLab.
