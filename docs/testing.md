# Testing Strategy & Verification Report

## 1. Automated Test Suites

### Backend Unit & Integration Tests (Pytest)
Command: `pytest`
- Total Tests: 32
- Pass Count: 32 (100%)
- Fail Count: 0
- Execution Time: ~4.2s

### Frontend Unit & Component Tests (Vitest)
Command: `npm run test`
- Total Tests: 11
- Pass Count: 11 (100%)
- Fail Count: 0
- Execution Time: ~6.3s

## 2. Report-Aligned Validation Scenarios (TC01 - TC07)

| Scenario ID | Test Name | Input Sample | Expected Result | Observed Result | Pass/Fail |
|---|---|---|---|---|---|
| **TC01** | Benign Email | `benign.eml` | Classification: `safe`, Score < 30 | Classified as `safe`, Score = 0 | **PASS** |
| **TC02** | Suspicious URL | `suspicious-url.eml` | Classification: `suspicious`, URL-001/003 triggered | Classified as `suspicious`, Rules: URL-001, URL-003 | **PASS** |
| **TC03** | Sender Mismatch | `sender-mismatch.eml` | Classification: `suspicious`, EMAIL-001 triggered | Classified as `suspicious`, Rule: EMAIL-001 | **PASS** |
| **TC04** | Risky Attachment | `risky-attachment.eml` | Classification: `suspicious`, ATTACH-001/002 triggered | Classified as `suspicious`, Rules: ATTACH-001, ATTACH-002 | **PASS** |
| **TC05** | Known Malicious Hash | Synthetic mock fixture | Classification: `malicious`, ATTACH-003 triggered | Classified as `malicious`, Rule: ATTACH-003 | **PASS** |
| **TC06** | Multiple Phishing Indicators | `phishing-multi.eml` | Classification: `malicious` or elevated `suspicious`, CORR-001 | Classified with elevated score, Rules: EMAIL-001, EMAIL-003, CORR-001 | **PASS** |
| **TC07** | Malformed Message | `malformed.eml` / broken headers | Classification: `manual_review`, PARSER-001 | Classified as `manual_review`, Rule: PARSER-001 | **PASS** |
