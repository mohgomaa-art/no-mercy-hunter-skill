# Ontology — No Mercy Hunter v3.0

Full taxonomy of all entities in the bug bounty hunter knowledge domain.

---

## Domain Taxonomy

### DOMAIN::API
All attack surfaces involving HTTP/HTTPS API endpoints.

Sub-domains:
- REST API — versioned endpoints (/v1, /v2, /api/v1)
- GraphQL API — single endpoint with typed schema
- WebSocket API — persistent bidirectional connection
- Internal API — not intended to be public (/internal, /admin, /ops)
- Shadow API — exists but undocumented (/bootstrap, /catalog-v3)

Key attack classes: IDOR, injection, auth bypass, rate limit abuse, batching DoS

### DOMAIN::AI-Platform
Attack surfaces unique to AI/LLM platforms.

Sub-domains:
- Chat Interface — user-facing input to LLM
- API Gateway — programmatic LLM access
- Tool/Function Calling — LLM-invoked external tools
- Memory System — persistent user context storage
- Vector Store — embedding database for RAG
- Model Registry — available models list
- Browsing Tool — LLM-mediated web access

Key attack classes: prompt injection, memory IDOR, vector IDOR, browsing-tool SSRF,
  shadow model enumeration, system prompt extraction

### DOMAIN::Auth
Authentication and authorization mechanisms.

Sub-domains:
- OAuth 2.0 — authorization code, client credentials, ROPC, device code
- JWT — HS256, RS256, ES256, none algorithm
- Session — cookies, server-side sessions
- API Keys — bearer tokens, API key headers
- WebAuthn/FIDO2 — hardware keys
- MFA — TOTP, SMS, backup codes
- Azure AD — Microsoft identity platform, OIDC

Key attack classes: algorithm confusion, state fixation, token theft, ROPC spray,
  device code phishing, unauthenticated client registration

### DOMAIN::Cloud-Infra
Cloud and infrastructure components.

Sub-domains:
- AWS — S3, IMDS, IAM, Lambda, EC2
- GCP — GCS, IMDS, Cloud Run, GKE
- Azure — Blob, IMDS, AKS, Azure AD, Key Vault
- Kubernetes — API server, kubelet, etcd, service accounts
- npm — package registry, scoped packages
- PyPI — Python package index

Key attack classes: bucket misconfiguration, IMDS SSRF, K8s API exposure,
  dependency confusion, service account token theft

### DOMAIN::Client-Side
Browser-side attack surfaces.

Sub-domains:
- JavaScript — source maps, minified bundles, eval
- DOM — clobbering, XSS sinks
- CSS — injection, @import exfil
- postMessage — cross-frame communication
- URL — open redirect, fragment injection
- Storage — localStorage, sessionStorage, indexedDB

Key attack classes: XSS, prototype pollution, postMessage, DOM clobbering, CSS injection

### DOMAIN::Supply-Chain
Third-party dependency and integration surfaces.

Sub-domains:
- npm packages
- PyPI packages
- GitHub Actions
- Docker images
- Terraform modules

Key attack classes: dependency confusion, typosquatting, malicious package injection

### DOMAIN::Race-Conditions
Timing-dependent vulnerabilities.

Sub-domains:
- Business logic race — parallel requests break state machine
- TOCTOU — time-of-check time-of-use
- GraphQL batching — N mutations in one request
- Coupon/credit abuse — parallelism breaks single-use

---

## Activity Taxonomy

### ACTIVITY::Passive-Recon
Zero-footprint intelligence gathering. No requests to target.

Activities:
- Certificate transparency query (crt.sh, Censys, Shodan)
- GitHub code search
- Wayback Machine / GAU query
- Source map analysis (JS already cached by CDN)
- Shodan query for target IPs
- DNS history query (SecurityTrails, PassiveDNS)
- Subdomain permutation (offline only)

Tools: subfinder, amass, assetfinder, gau, waybackurls, mcp__brave-search, mcp__github

### ACTIVITY::Active-Recon
Sends requests to target. Low noise, targeted.

Activities:
- DNS resolution (dnsx)
- Live host probing (httpx)
- Well-known endpoint fetching
- OpenID configuration discovery
- HTTP response header analysis
- Technology fingerprinting

Tools: dnsx, httpx, mcp__fetch, curl

### ACTIVITY::Enumeration
Systematic discovery of resources. Medium noise.

Activities:
- Port scanning (naabu)
- Directory/file discovery (ffuf, dirsearch)
- Parameter discovery (arjun)
- Subdomain brute force
- Codename fuzzing
- GraphQL schema enumeration
- API version enumeration

Tools: naabu, ffuf, dirsearch, arjun, katana, nuclei

### ACTIVITY::Exploitation
Proof of concept development. Only on confirmed vulnerabilities.

Activities:
- JWT token forgery
- OAuth client registration
- SSRF payload delivery
- XSS payload execution
- Race condition triggering
- IDOR access confirmation

Tools: dalfox, Playwright, custom Python scripts, curl

### ACTIVITY::Documentation
Evidence collection and report writing.

Activities:
- HTTP capture (HAR, mitmproxy)
- Screenshot capture (Playwright, browser-tools)
- PoC code writing
- CVSS scoring
- Impact statement writing
- Remediation guidance writing

Tools: Playwright, mcp__browser-tools, sqlite3, mcp__filesystem

### ACTIVITY::Submission
Report delivery to bug bounty platform.

Activities:
- Platform search for duplicates
- Scope verification
- Quality gate check
- Report submission
- Follow-up tracking

Platforms: Bugcrowd, HackerOne, direct disclosure

---

## Asset Taxonomy

### ASSET::Endpoint
HTTP/HTTPS URL that accepts requests.

Properties:
- URL (scheme + host + path + query)
- Method (GET, POST, PUT, PATCH, DELETE)
- Auth required (yes/no/optional)
- Returns sensitive data (yes/no)
- Rate limited (yes/no)
- In scope (yes/no)

Examples: /api/v1/users, /oauth/register, /bootstrap, /graphql

### ASSET::Token
Credential that grants access.

Sub-types:
- JWT (header.payload.signature, base64url)
- OAuth access token (opaque or JWT)
- OAuth refresh token
- API key (static bearer)
- Session cookie
- CSRF token
- Device token / sentinel token (F-09)

Properties:
- Expiry
- Scope/permissions
- Bound to (user, device, session)
- Revocable

### ASSET::OAuth-Client
Registered OAuth application.

Properties:
- client_id (public)
- client_secret (secret)
- redirect_uris (where codes are sent)
- grant_types (authorization_code, client_credentials, device_code, password)
- scope

Vulnerable when: registration is unauthenticated, redirect_uris accept arbitrary domains

### ASSET::WebSocket
Persistent bidirectional channel.

Properties:
- URL (wss:// scheme)
- Auth mechanism (cookie, token in subprotocol, query param)
- Message format (JSON, binary, text)
- Reconnect behavior

Vulnerable when: upgrade accepted without valid session, no origin check

### ASSET::Vector-Store
Embedding database for AI RAG applications.

Properties:
- store_id (UUID or sequential)
- owner_id
- Files/documents indexed
- Embedding model used
- Access control (is it per-user or shared?)

Vulnerable when: store_id can be guessed or enumerated cross-account

### ASSET::Memory
Persistent user context in AI system.

Properties:
- memory_id (UUID or sequential)
- user_id (owner)
- Content (text, structured data)
- Created/modified timestamps

Vulnerable when: memory_id can be read/written by other accounts

### ASSET::Source-Map
JavaScript source map file (.map).

Properties:
- URL (usually {bundle}.js.map or via sourceMappingURL comment)
- Contents: original file paths, original source code
- May contain: developer comments, hardcoded secrets, internal API paths

### ASSET::Subdomain
DNS name under the target's apex domain.

Properties:
- Hostname
- CNAME target (if applicable)
- A record (IP)
- TLS certificate SAN
- Technology stack (from httpx fingerprint)
- Cloud provider (for takeover fingerprint)

Vulnerable when: CNAME points to unclaimed cloud resource

---

## Tool Taxonomy

Tools are scored using: Composite = (Confidence×2) + (InformationGain×3) + (AutomationPotential×2) + (Reusability×2) - Cost

### Category: Subdomain Enumeration

| Tool | Confidence | InfoGain | AutoPot | Reuse | Cost | Score |
|------|-----------|----------|---------|-------|------|-------|
| subfinder | 4 | 4 | 5 | 5 | 1 | 42 |
| amass | 4 | 5 | 4 | 5 | 3 | 42 |
| assetfinder | 3 | 3 | 5 | 5 | 1 | 35 |
| findomain | 3 | 4 | 4 | 5 | 2 | 35 |

### Category: Live Host and Port

| Tool | Confidence | InfoGain | AutoPot | Reuse | Cost | Score |
|------|-----------|----------|---------|-------|------|-------|
| httpx | 5 | 4 | 5 | 5 | 1 | 46 |
| dnsx | 4 | 3 | 5 | 5 | 1 | 40 |
| naabu | 4 | 4 | 5 | 5 | 2 | 43 |

### Category: URL Discovery

| Tool | Confidence | InfoGain | AutoPot | Reuse | Cost | Score |
|------|-----------|----------|---------|-------|------|-------|
| gau | 4 | 5 | 5 | 5 | 1 | 48 |
| waybackurls | 3 | 4 | 5 | 5 | 1 | 43 |
| katana | 4 | 4 | 5 | 5 | 2 | 44 |

### Category: Content Discovery

| Tool | Confidence | InfoGain | AutoPot | Reuse | Cost | Score |
|------|-----------|----------|---------|-------|------|-------|
| ffuf | 4 | 3 | 5 | 5 | 2 | 39 |
| dirsearch | 3 | 3 | 4 | 4 | 2 | 33 |
| arjun | 4 | 4 | 4 | 5 | 2 | 42 |

### Category: Vulnerability Scanning

| Tool | Confidence | InfoGain | AutoPot | Reuse | Cost | Score |
|------|-----------|----------|---------|-------|------|-------|
| nuclei | 4 | 4 | 5 | 5 | 2 | 44 |
| dalfox | 5 | 4 | 5 | 5 | 2 | 46 |
| kxss | 3 | 3 | 5 | 5 | 1 | 38 |

### Category: GraphQL

| Tool | Confidence | InfoGain | AutoPot | Reuse | Cost | Score |
|------|-----------|----------|---------|-------|------|-------|
| InQL | 5 | 5 | 4 | 5 | 2 | 47 |
| graphw00f | 4 | 3 | 5 | 5 | 1 | 42 |
| clairvoyance | 4 | 5 | 4 | 4 | 2 | 44 |
| batchql | 3 | 4 | 4 | 4 | 2 | 38 |
| graphql-cop | 4 | 4 | 5 | 5 | 1 | 46 |

### Category: Browser Automation

| Tool | Confidence | InfoGain | AutoPot | Reuse | Cost | Score |
|------|-----------|----------|---------|-------|------|-------|
| Playwright | 5 | 5 | 5 | 5 | 3 | 49 |
| mcp__browser-tools | 4 | 4 | 3 | 4 | 2 | 39 |
| mcp__playwright | 4 | 4 | 4 | 4 | 2 | 42 |

### Category: MCP Servers

| Tool | Confidence | InfoGain | AutoPot | Reuse | Cost | Score |
|------|-----------|----------|---------|-------|------|-------|
| mcp__filesystem | 5 | 3 | 5 | 5 | 1 | 42 |
| mcp__memory | 4 | 3 | 4 | 5 | 1 | 39 |
| mcp__sequential-thinking | 3 | 4 | 3 | 4 | 1 | 36 |
| mcp__github | 4 | 5 | 4 | 5 | 1 | 46 |
| mcp__brave-search | 3 | 4 | 4 | 4 | 1 | 39 |
| mcp__postgres | 3 | 3 | 4 | 4 | 2 | 34 |
| mcp__sqlite | 4 | 4 | 5 | 5 | 1 | 46 |
| mcp__fetch | 4 | 4 | 5 | 5 | 1 | 46 |
| mcp__playwright | 4 | 4 | 4 | 4 | 2 | 42 |
| mcp__browser-tools | 4 | 4 | 3 | 4 | 2 | 39 |

---

## Evidence Taxonomy

### EVIDENCE::Screenshot
- Format: PNG
- Naming: {finding-id}-{step}-{timestamp}.png
- Must show: URL bar, response body, relevant highlighted section
- Storage: evidence/{finding-id}/screenshots/

### EVIDENCE::HTTP-Log
- Format: HAR or raw HTTP text
- Naming: {finding-id}-{step}.har or {finding-id}-{step}.http
- Must include: full request headers + body, full response headers + body
- Redact: other users' PII, internal tokens not needed for PoC
- Storage: evidence/{finding-id}/http/

### EVIDENCE::PoC-Code
- Format: .py, .sh, .js, or curl command
- Naming: {finding-id}-poc.{ext}
- Must be: runnable as-is (no manual steps to fill in)
- Include: comments explaining each step
- Storage: evidence/{finding-id}/poc/

### EVIDENCE::Timeline
- Format: markdown list
- Naming: {finding-id}-timeline.md
- Contents: discovery time, reproduction time, first PoC, disclosure time
- Storage: evidence/{finding-id}/

### EVIDENCE::Video
- Format: MP4 (screen recording)
- Naming: {finding-id}-demo.mp4
- Required for: complex multi-step chains (P1/P2)
- Storage: evidence/{finding-id}/

---

## Severity Taxonomy

### SEVERITY::P1 (Critical)
CVSS 9.0–10.0
Examples from findings: F-10 (ROPC+Device Code → account takeover chain), HF-01 (OAuth ATO)
Characteristics: unauthenticated access to sensitive data at scale, full account takeover, RCE

### SEVERITY::P2 (High)
CVSS 7.0–8.9
Examples: F-08 (Azure AD tenant leak + user enum), CODEX-01/02/03/04 (classifier bypass)
Characteristics: auth bypass, significant data exposure, sandbox escape

### SEVERITY::P3 (Medium)
CVSS 4.0–6.9
Examples: F-01, F-02, F-05, HF-02, MI-01
Characteristics: info disclosure that enables further attacks, limited auth bypass

### SEVERITY::P4 (Low/Informational)
CVSS 0.0–3.9
Examples: F-03, F-04, F-06, F-07, F-09, AN-01
Characteristics: information disclosure without direct exploitability, configuration exposures
