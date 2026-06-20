# Conflicts — No Mercy Hunter v3.0

Documents real conflicts found between the six source skills, with resolutions.

---

## Conflict 01 — OWASP 2021 vs OWASP 2025 Top 10

Source A: owasp-security skill — references OWASP Top 10 2021 (A01-A10 2021 list)
Source B: vulnerability-scanner skill — references OWASP Top 10 2025 (A01-A10 2025 list)

### 2021 List (owasp-security skill)
A01: Broken Access Control
A02: Cryptographic Failures
A03: Injection
A04: Insecure Design
A05: Security Misconfiguration
A06: Vulnerable and Outdated Components
A07: Identification and Authentication Failures
A08: Software and Data Integrity Failures
A09: Security Logging and Monitoring Failures
A10: Server-Side Request Forgery

### 2025 List (vulnerability-scanner skill)
A01: Broken Access Control (retained)
A02: Cryptographic Failures (retained)
A03: Supply Chain (NEW — was A06 Vulnerable Components, expanded)
A04: Insecure Design (retained)
A05: Security Misconfiguration (retained)
A06: Vulnerable and Outdated Components (now sub-category of A03)
A07: Identification and Authentication Failures (retained)
A08: Software and Data Integrity Failures (retained)
A09: Security Logging and Monitoring Failures (retained)
A10: Exceptional Conditions (NEW — covers race conditions, edge cases, error handling)

### Resolution
Use OWASP 2025. Rationale: more current, Supply Chain (A03) directly applies to dependency
confusion attacks (WF-11), and Exceptional Conditions (A10) directly applies to race
condition testing (WF-10). Both new categories are active in this operator.

When filing bug bounty reports: check which OWASP version the program references. Some
programs still use 2021. Include mapping to both versions in the report to avoid confusion:
"OWASP A10:2025 (Exceptional Conditions) / OWASP A08:2021 (Software and Data Integrity Failures)"

---

## Conflict 02 — Security Headers: Low Signal vs. Configured Correctly

Source A: owasp-security skill — provides full helmet.js configuration for all security headers
(Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy). Treats headers as important security controls.

Source B: security-bounty-hunter skill — explicitly says "missing headers alone" are NOT
reportable. Quality gate: "Skip: missing headers alone."

### The tension
The owasp-security skill wants you to implement all headers. The security-bounty-hunter
skill says missing headers are not worth reporting.

### Resolution
Both are correct in their context:

For DEVELOPMENT (owasp-security context): Implement all security headers. They are
defense-in-depth and follow best practices. Use helmet.js defaults.

For BUG BOUNTY REPORTING (security-bounty-hunter context): Do NOT submit missing headers
as standalone vulnerabilities. Programs do not pay bounties for missing CSP or HSTS.

Exception: Missing headers that enable a demonstrable attack are reportable AS PART OF
that attack:
- Missing SameSite=Strict enables CSRF -> report the CSRF, mention header fix in remediation
- Missing X-Frame-Options enables clickjacking -> report clickjacking if exploitable, not the missing header
- Missing CORS headers that cause ACAC=true reflect arbitrary origins -> report CORS misconfiguration (HF-02 was P3)

Operator rule: Never submit "missing header" as a standalone finding. Only reference
headers in remediation sections.

---

## Conflict 03 — Rate Limiting Advice

Source A: red-team-tools skill — recommends aggressive fuzzing and brute force
as standard technique. No explicit rate limit warnings.

Source B: security-bounty-hunter skill — warns to stop after 3x 429 responses to avoid
lockout risk. "Rate limiting with lockout risk — three 429 responses in 60 seconds -> stop."

Source C: disclosure-policy template — "Testing was performed within program-defined rate limits"
is a required pre-submission disclosure checkbox.

### Resolution
Follow the conservative approach from security-bounty-hunter and disclosure-policy.

Practical rules for this operator:
1. Before any brute force or enumeration: check program scope page for rate limit rules.
   Some programs explicitly state: "Do not send more than X requests per second."
2. If you see 429 responses: stop the scan on that endpoint. Move to next target.
3. Never automate at maximum speed against login endpoints or account creation.
4. For password spray (F-10 pattern): test with a single credential pair first to confirm
   the login mechanism works. Do not run a full wordlist against a live login — demonstrate
   the vulnerability with one test, not a spray.
5. The thread-barrier race condition test (WF-10) sends N=20 requests simultaneously.
   This is acceptable because: it is targeted (one endpoint), non-destructive (testing
   business logic not DoS), and temporary (one test, not continuous).

---

## Conflict 04 — Severity of CORS ACAC=true

Source A: owasp-security skill — treats CORS as a significant security control.
Helmet.js configuration includes explicit CORS policy setup.

Source B: api-fuzzing-bug-bounty skill — lists CORS as a testable vector but does not
assign severity.

Source C: Session findings — HF-02 (CORS reflects arbitrary origins) rated P3.
AN-01 (api-staging CORS ACAC=true) rated P4.

### Resolution
CORS severity depends entirely on what data the endpoint exposes:

P4 (Informational): CORS ACAC=true on endpoint returning no sensitive data (AN-01 pattern).
The staging API reflecting arbitrary origins is P4 because no sensitive data is accessible.

P3 (Medium): CORS ACAC=true on endpoint returning user-specific data (HF-02 pattern).
HuggingFace reflects arbitrary origins with credentials — this means attacker can read
user API keys, profile data, etc. from any attacker-controlled origin.

P2 (High): CORS ACAC=true combined with CSRF on a state-changing endpoint. An attacker
can both read sensitive data AND perform actions cross-origin.

Operator rule: When CORS ACAC=true is found, immediately check what data the endpoint
returns. The severity follows the data sensitivity, not the CORS misconfiguration itself.

---

## Conflict 05 — JWT "none" Algorithm Testing

Source A: api-fuzzing-bug-bounty skill — mentions JWT none algorithm as a test.

Source B: vulnerability-scanner skill — focuses on JWT as an injection/auth bypass vector
but does not detail the none algorithm test.

Source C: WF-03 in this operator — includes none algorithm test as step 6 after HS256 confusion.

### Resolution
Test in this order:
1. HS256 confusion first (higher yield, more common in modern implementations)
2. alg:none second (less common after widespread awareness, but still worth testing)
3. Key confusion (ES256 -> HS256 with public key) if RSA-based

No conflict — run all three in sequence. Total overhead is minimal.

---

## Conflict 06 — Prototype Pollution: Client vs. Server

Source A: bug-bounty-hunter skill — lists prototype pollution as vectors #6 (client) and #7 (server).
Source B: red-team-tools skill — mentions prototype pollution in client-side attack context only.

### Resolution
Both contexts are distinct vulnerabilities:

Client-side prototype pollution:
- Vector: URL query parameter (?__proto__[key]=value)
- Impact: XSS, DOM manipulation, filter bypass
- Detection: Test with ?__proto__[test]=polluted, check if window.test === "polluted"

Server-side prototype pollution:
- Vector: JSON body merge ({"__proto__":{"admin":true}})
- Impact: Auth bypass, RCE (if gadget chain exists in server-side JS)
- Detection: Test with POST body containing __proto__ key, check server behavior

These are independent tests. Operator runs both. Neither conflicts with the other.

---

## Conflict 07 — SSRF Scope: What Targets Are Valid

Source A: bug-bounty-hunter skill — lists 11 internal SSRF targets (IMDS, K8s, etc.)
Source B: disclosure-policy template — "PoC payload is non-destructive (no SSRF to write-side cloud APIs)"

### Resolution
SSRF testing is valid for:
- Read-only metadata endpoints: AWS IMDS /latest/meta-data/, GCP IMDS, Azure IMDS
- Kubernetes API server (GET /version, /api/v1/namespaces) — read only
- Internal HTTP services on port 80/443/8080
- DNS-based SSRF confirmation (use Burp Collaborator or interactsh)

SSRF testing is NOT valid for:
- Write operations to cloud provider APIs (S3 PutObject, IAM CreateUser)
- Deletion operations (S3 DeleteBucket)
- Any SSRF payload that modifies infrastructure

Operator rule: All SSRF PoCs use GET requests to read-only endpoints. Document the read
capability as impact. Never include write-side calls in the PoC.

---

## Summary Resolution Table

| Conflict | Resolved In Favor Of | Rationale |
|----------|---------------------|-----------|
| OWASP 2021 vs 2025 | 2025 | More current, covers supply chain and race conditions |
| Security headers: implement vs. skip | Context-dependent | Implement in code; do not report as standalone findings |
| Rate limiting aggressiveness | Conservative | Program rules + lockout risk |
| CORS severity | Data-dependent | Severity follows endpoint sensitivity, not the CORS config |
| JWT algorithm order | All three in sequence | Minimal overhead, comprehensive coverage |
| Prototype pollution scope | Both client and server | Independent tests, both valid |
| SSRF write operations | Never include | Disclosure policy: non-destructive PoC only |
