# REST API Reference Manual

The backend provides a standardized, fully typed OpenAPI REST interface rooted at `/api/v1`.

## Endpoints Summary

### Service Health
- **`GET /health`**
  - **Description**: Lightweight health check endpoint for container orchestrators and load balancers.
  - **Response 200**: `{"status": "ok"}`

### Threat Analysis
- **`POST /api/v1/analyze/email`**
  - **Input**: `multipart/form-data` with `file` (`.eml` file, max 10MB).
  - **Response 200**: `AnalysisResult` object.
  - **Errors**: `400 Bad Request` (invalid format), `413 Payload Too Large` (> 10MB).

- **`POST /api/v1/analyze/raw`**
  - **Input**: `application/json` `{ "raw": "From: ...\nSubject: ...\n\nBody..." }`
  - **Response 200**: `AnalysisResult` object.

- **`POST /api/v1/analyze/url`**
  - **Input**: `application/json` `{ "url": "http://185.199.108.153:8080/login" }`
  - **Description**: Statically inspects URL structure without sending HTTP requests to the target host.
  - **Response 200**: `AnalysisResult` object.

- **`POST /api/v1/analyze/attachment`**
  - **Input**: `multipart/form-data` with `file` (any binary artifact).
  - **Response 200**: `AnalysisResult` object with SHA-256 and signature analysis.

### Case History & Retrieval
- **`GET /api/v1/analyses`**
  - **Query Parameters**:
    - `q` (string): Search query across case ID, filename, subject, domain, hash.
    - `classification` (string): Filter by `safe`, `suspicious`, `malicious`, `manual_review`.
    - `severity` (string): Filter by `low`, `medium`, `high`.
    - `sort` (string): Sort column (`created_at`, `risk_score`, `classification`).
    - `order` (string): `asc` or `desc`.
    - `page` (int), `page_size` (int): Pagination controls.
  - **Response 200**: `{ "total": int, "page": int, "page_size": int, "items": [...] }`

- **`GET /api/v1/analyses/{analysis_id}`**
  - **Response 200**: Complete `AnalysisResult` dossier.
  - **Errors**: `404 Not Found`.

- **`DELETE /api/v1/analyses/{analysis_id}`**
  - **Description**: Permanently removes an analysis case and associated indicators.
  - **Response 200**: `{"status": "deleted", "id": "..."}`

### Report Generation & Export
- **`GET /api/v1/analyses/{analysis_id}/report`**
  - **Response 200**: `application/pdf` binary stream containing formatted analysis dossier.

- **`GET /api/v1/analyses/{analysis_id}/export?format={json|csv}`**
  - **Response 200**: Structured machine-readable export of case findings and IoCs.

### Detection Rules Catalog
- **`GET /api/v1/rules`**
  - **Response 200**: List of all 13 detection rules with category, severity, logic summary, default score, enabled status, and database trigger count.

- **`PATCH /api/v1/rules/{rule_id}`**
  - **Headers**: Optional `X-Admin-Token` if configured.
  - **Input**: `{ "enabled": boolean }`
  - **Response 200**: `{ "rule_id": "...", "enabled": boolean }`

### Telemetry & Dashboard Stats
- **`GET /api/v1/stats`**
  - **Response 200**: Real-time aggregated statistics from stored database records.
