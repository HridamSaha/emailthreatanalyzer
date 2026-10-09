# Security, Safety & Threat Containment Model

## 1. Core Defensive Principles
1. **Never Execute Untrusted Payloads**: Attachments are read into isolated memory buffers solely for calculating cryptographic digests (SHA-256), inspecting binary headers, and parsing non-executable metadata. No scripts, binaries, or office macros are executed.
2. **Never Fetch Untrusted URLs**: Malicious links in emails frequently lead to exploit kits, credential harvesting sites, or tracking beacons. URL inspection is purely lexical, examining schemes, IP literals, punycode, subdomains, and obfuscation.
3. **No Direct HTML Rendering**: Raw email HTML can contain cross-site scripting (XSS), hidden tracking pixels, CSS-based phishing overlays, and iframe embeds. Untrusted HTML is safely converted into sanitized plain text before display.

## 2. Resource Abuse & Denial of Service Defenses
- **Upload Size Bounds**: Strict 10MB limit enforced before parsing (`HTTP 413 Payload Too Large`).
- **Archive Inspection Limits**:
  - Max entries inspected: 40
  - Max archive recursion depth: 1
  - Max member extraction size: 2 MB
- **Path Traversal Defense**: Zipfile members containing relative directory sequences (`../` or `..\`) are strictly rejected and quarantined without filesystem extraction.
- **Rate Limiting**: Rolling in-memory window restricts clients to 30 analysis requests per minute.

## 3. Dynamic Analysis & Sandbox Architecture
For deep behavioral execution, the system defines an isolated disposable virtual machine architecture:
- Physical or virtual isolation from host network.
- Restricted virtual network with DNS/HTTP blackhole sinkholing (e.g., INetSim).
- Process, registry, and memory monitoring (Procmon, Sysmon, Volatility).
- Immediate revert-to-snapshot rollback after sample termination to prevent persistence.
