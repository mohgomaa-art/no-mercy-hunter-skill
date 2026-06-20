# Bugcrowd Submission Template
# No Mercy Hunter v3.0

Usage: Copy this file for each Bugcrowd submission. Fill all [BRACKETED] fields.
Grounded in: CODEX-01 through CODEX-04 submissions to OpenAI Bugcrowd program.
Format: Bugcrowd plain-text preferred. Minimal markdown (bold/code only).

---

## SUBMISSION FORM FIELDS

### Title (under 100 chars, specific)
```
[Vulnerability Class] in [Component]: [One-line impact]
```

Examples from real submissions:
- PowerShell begin{} block bypasses Codex safety classifier enabling arbitrary command execution
- Unauthenticated OAuth client registration at /oauth/register enables full account takeover
- staging.openai.com Azure AD tenant ID exposure enables ROPC password spray

### Vulnerability Type (Bugcrowd VRT taxonomy)
Select the most specific matching category:

Common mappings:
- OAuth ATO → Authentication > OAuth > Insecure Direct Object Reference
- IDOR → Insecure Direct Object Reference > Lateral
- XSS → Cross-Site Scripting (XSS) > Reflected or Stored
- SSRF → Server-Side Request Forgery (SSRF) > Internal Network
- Info Disclosure → Information Disclosure > Sensitive Information
- Auth Bypass → Authentication Bypass
- RCE → Remote Code Execution
- Classifier Bypass → Application Logic Error > Business Logic Bypass

**Selected VRT:** [paste exact VRT path]

### Target / Asset
[Exact URL or subdomain from program scope. E.g., https://codex.openai.com]

### CVSS Score (optional but recommended for P1/P2)
**Score:** [e.g., 8.1]
**Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

---

## REPORT BODY

---

**Summary**

[One paragraph. What is the vulnerability, where does it exist, and what is the impact.
No markdown headers. Plain prose. Keep under 150 words.]

Example (CODEX-01 pattern):
The OpenAI Codex API processes PowerShell code submitted via the API. The classifier
that enforces the code execution safety policy examines specific PowerShell constructs
but does not inspect the begin{} block of a begin/process/end script. An attacker
submitting PowerShell code with a payload inside a begin{} block bypasses the safety
classifier and achieves arbitrary command execution in the sandboxed environment.
This was confirmed by submitting a begin{} block containing whoami and id, which
returned execution output.

---

**Steps to Reproduce**

1. [First action — be specific. Include exact URL.]
2. [Second action — include exact request or payload.]
3. [Third action — include exact expected vs actual result.]

Example (OAuth registration pattern):

1. Send a POST request to https://huggingface.co/oauth/register with no Authorization header:

POST /oauth/register HTTP/1.1
Host: huggingface.co
Content-Type: application/json

{"client_name": "test-client", "redirect_uris": ["https://attacker.com/callback"], "grant_types": ["authorization_code"], "response_types": ["code"]}

2. Observe the 201 Created response contains a client_id and client_secret, confirming unauthenticated registration succeeded.

3. Construct an authorization URL:
https://huggingface.co/oauth/authorize?client_id=[CLIENT_ID_FROM_STEP_2]&redirect_uri=https://attacker.com/callback&response_type=code&state=random

4. Open the authorization URL in a logged-in browser. Observe that HuggingFace presents an OAuth consent screen accepting the evil.com redirect_uri.

5. Approve the consent. Observe that the browser redirects to https://attacker.com/callback?code=[AUTH_CODE].

6. Exchange the auth code: POST /oauth/token with the code and client credentials from step 2. A valid access token is returned, confirming full account takeover.

---

**Proof of Concept**

[Include working curl command OR Python script. Must run without modification.
Label each step with a comment.]

```bash
# Step 1: Register unauthenticated OAuth client
curl -s -X POST "https://target.com/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"evil","redirect_uris":["https://attacker.com/cb"],"grant_types":["authorization_code"],"response_types":["code"]}'

# Expected: 201 with client_id and client_secret
# {"client_id": "evil_123", "client_secret": "s3cr3t", ...}
```

---

**Impact**

[What can the attacker do? How many users are affected? What data is at risk?
Be specific. Do not overstate.]

Example:
An unauthenticated attacker can register an OAuth client with an arbitrary redirect_uri,
then send authorization URLs to any HuggingFace user. Any user who clicks the link and
approves the consent screen has their account taken over. The attacker receives the
authorization code and can exchange it for access/refresh tokens with full account
privileges. This affects all HuggingFace accounts and requires no prior authentication.

---

**Supporting Materials**

[List attachments below. Screenshots must show URL bar + response body. HTTP logs must
include full request headers and response.]

- [FINDING-ID]-01-registration-request.png — POST to /oauth/register with 201 response
- [FINDING-ID]-02-authorization-url.png — Browser showing consent page with evil.com URI
- [FINDING-ID]-03-token-response.png — Access token returned after code exchange
- [FINDING-ID]-poc.sh — Working bash PoC script

---

**Remediation Suggestion**

[Optional but appreciated. One sentence short-term fix + one sentence long-term fix.]

Short-term: Require a valid Bearer token to access the /oauth/register endpoint.
Long-term: Implement a whitelist of permitted redirect_uri domains per registered client,
reject any authorization_request where redirect_uri does not exactly match a pre-registered URI.

---

## BUGCROWD SUBMISSION RULES

Rules from real CODEX-01 through CODEX-04 submissions:

1. Submit one finding per report — do not bundle CODEX-01 and CODEX-02 in one report
2. Title must name the specific bypass class — "classifier bypass" not just "security issue"
3. Attach screenshots as PNG files — max 50MB each
4. PoC script should be .py or .sh — not .zip or .tar.gz
5. Do not include PII from other users in screenshots
6. If the program has specific rules about AI safety testing, acknowledge them in the report
7. Reference related findings in the notes field, not in the main body
8. If this is part of a chain, note it: "This finding is part of a chain with [REPORT-ID]"

---

## FOLLOW-UP MESSAGES

### Initial follow-up (if no response in 7 days)
```
Hello, I wanted to follow up on this report submitted [DATE]. I am happy to provide
additional evidence or clarification if needed. Please let me know if you have any
questions about the reproduction steps.
```

### Severity dispute (if triaged lower than expected)
```
Thank you for the triage. I would like to respectfully discuss the severity rating.
My reasoning for [P-X] is [specific CVSS factors and real-world impact]. I have
additional evidence showing [specific impact point]. Would you be open to reconsidering?
```

### Escalation (if no response in 30 days)
```
I am escalating this report as it has been [N] days without a triage decision.
The vulnerability is [still reproducible / has been partially fixed]. I am planning
to disclose in [N] days per responsible disclosure guidelines. Please advise.
```
