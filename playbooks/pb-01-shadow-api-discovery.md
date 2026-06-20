# Playbook PB-01 — Shadow API Discovery
# No Mercy Hunter v3.0

**Score:** 40
Composite = (Confidence:4×2) + (InfoGain:5×3) + (AutoPot:4×2) + (Reuse:5×2) - Cost:3 = 8+15+8+10-3 = 38
(Adjusted to 40 with real finding bonus: F-02, F-03, F-06, F-07)

**Grounded in:** F-02 (Bootstrap K8s leak), F-03 (Unreleased model slugs), F-06 (Unauth feature flags), F-07 (Realtime WS unauth)
**Time estimate:** 45-60 minutes
**Noise level:** Medium (300 HTTP requests)
**Prerequisites:** Passive recon complete, subs/all.txt available

---

## Objective

Discover undocumented, internal, or shadow API endpoints that are accessible but not listed
in the target's public documentation. Shadow APIs often lack the authentication and
authorization controls applied to documented endpoints.

---

## Decision Point 1 — Do I Run This Playbook?

Run if ANY of the following are true:
- Target is an AI platform or SaaS product (high codename surface)
- Passive recon found interesting subdomains (staging.*, api.*, realtime.*)
- Source maps revealed internal path patterns
- Wayback/GAU URLs contain versioned paths (/v1, /v2, /internal)

Skip if:
- Target is a simple static site with no API surface
- All API endpoints are published in Swagger/OpenAPI (still run codename grid but lower priority)

---

## Phase 1 — Source Map Analysis (15 minutes)

### 1.1 Identify JS Bundles
```bash
# Fetch main page and extract JS bundle URLs
curl -s "https://TARGET/" | grep -oP 'src="([^"]+\.js)"' | head -30

# Alternative: check common bundle paths
curl -sI "https://TARGET/static/js/main.chunk.js"
curl -sI "https://TARGET/_next/static/chunks/main.js"
curl -sI "https://TARGET/assets/app.js"
```

### 1.2 Fetch Source Maps
```bash
# For each JS bundle URL found, append .map
curl -s "https://TARGET/static/js/main.chunk.js.map" -o sourcemaps/main.map

# Check for sourceMappingURL comment in minified JS
curl -s "https://TARGET/static/js/main.chunk.js" | grep "sourceMappingURL"
```

### 1.3 Extract Endpoints from Source Maps
```python
#!/usr/bin/env python3
"""Extract API paths and secrets from source maps."""
import json, re, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

sources = data.get("sourcesContent", [])
for i, src in enumerate(sources):
    if src is None:
        continue
    # Find API paths
    paths = re.findall(r'["\x60](/(?:api|v\d|internal|admin|graphql|oauth)[^"\'`\s]*)', src)
    for p in paths:
        print(f"PATH: {p}")
    # Find secrets
    secrets = re.findall(r'(?:api_key|apikey|secret|token|password|credential)\s*[=:]\s*["\x60]([^"\'`]{8,})', src, re.I)
    for s in secrets:
        print(f"SECRET: {s}")
```

Run: `python3 extract_sourcemap.py sourcemaps/main.map > sourcemap-findings.txt`

### 1.4 What to Look For
- `/api/internal/*` — internal API routes not in public docs
- `/admin/*` — admin endpoints
- `/v3/*`, `/v4/*` — future API versions not yet documented
- `/bootstrap` — infrastructure bootstrap (F-02 pattern)
- `/feature-flags`, `/config`, `/experiments` — config endpoints (F-06 pattern)
- Hardcoded API keys, tokens, secrets
- Internal hostname references (*.internal, *.svc.cluster.local)

**Decision:** If source maps reveal internal paths → test them immediately (high confidence)

---

## Phase 2 — Codename Grid Fuzzing (20 minutes)

### 2.1 The 20 Codenames
```
cortex-admin-gql
auth-triton-v2
realtime-aries
browser-hermes
assistant-hub-nest
openai-ml-ops
deepmind-trainer
phoenix-admin-api
gizmo-catalog-v3
memory-fabric
vector-pine
chatgpt-staging-omega
live-agent-socket
action-oauth-gateway
npm-openai-internal
logs-kibana-2026
chat-embed-frame
billing-promo-engine
frontend-next-2026
model-artifacts-prod
```

### 2.2 The 15 Path Patterns
```
/
/api
/v1
/health
/status
/config
/admin
/metrics
/graphql
/ws
/oauth
/debug
/internal
/schema
/openapi.json
```

### 2.3 Subdomain Patterns (20 codenames × 5 subdomain patterns = 100 subdomains)
```
{codename}.TARGET
api-{codename}.TARGET
{codename}-api.TARGET
{codename}-staging.TARGET
internal-{codename}.TARGET
```

### 2.4 Run the Grid
```bash
# Generate URL list
python3 -c "
codenames = [
    'cortex-admin-gql','auth-triton-v2','realtime-aries','browser-hermes',
    'assistant-hub-nest','openai-ml-ops','deepmind-trainer','phoenix-admin-api',
    'gizmo-catalog-v3','memory-fabric','vector-pine','chatgpt-staging-omega',
    'live-agent-socket','action-oauth-gateway','npm-openai-internal',
    'logs-kibana-2026','chat-embed-frame','billing-promo-engine',
    'frontend-next-2026','model-artifacts-prod'
]
paths = ['/','/api','/v1','/health','/status','/config','/admin',
         '/metrics','/graphql','/ws','/oauth','/debug','/internal','/schema','/openapi.json']
for c in codenames:
    for p in paths:
        print(f'https://{c}.TARGET{p}')
" > codename-grid.txt

# Probe with httpx (fast, low noise)
httpx -l codename-grid.txt -silent -status-code -title -no-color -o codename-results.txt

# Filter for interesting responses
grep -v ' 404 ' codename-results.txt | grep -v ' 000 '
```

### 2.5 Evaluate Results
- Status 200 with non-trivial body → investigate immediately
- Status 301/302 redirect → follow the redirect
- Status 401/403 → endpoint exists, try auth bypass techniques
- Status 200 with empty body → check Content-Type (JSON vs HTML)
- Unexpected technologies in title → investigate

---

## Phase 3 — Targeted Endpoint Testing (15 minutes)

### 3.1 Bootstrap Endpoint (F-02 Pattern)
```bash
# Test on all live API hosts
for host in $(cat live/hosts.txt | grep api); do
    echo "=== $host ==="
    curl -s "$host/bootstrap" | python3 -m json.tool 2>/dev/null | head -50
    curl -s "$host/k8s-bootstrap" | python3 -m json.tool 2>/dev/null | head -50
    curl -s "$host/init/config" | python3 -m json.tool 2>/dev/null | head -50
done
```

**What to look for in response:**
- `serviceAccountToken` — Kubernetes service account token
- `kubeconfig` — K8s cluster config
- `internalEndpoints` — Internal service URLs
- IP patterns matching 10.x.x.x, 172.16-31.x.x, 192.168.x.x

### 3.2 Feature Flag / Config Endpoints (F-06 Pattern)
```bash
for host in $(cat live/hosts.txt); do
    for path in /config /feature-flags /experiments /account/config /beta /flags; do
        status=$(curl -s -o /dev/null -w "%{http_code}" "$host$path")
        if [ "$status" != "404" ] && [ "$status" != "000" ]; then
            echo "$host$path → $status"
            curl -s "$host$path" | python3 -m json.tool 2>/dev/null | head -30
        fi
    done
done
```

### 3.3 Unreleased Model Slugs (F-03 Pattern)
```bash
# Test against AI API hosts
for slug in gpt-5 gpt-5-turbo gpt-next o3-mini-high o4 o4-mini gpt-next-turbo \
            gpt-5-0125 gpt-5-preview o3-high claude-4 gemini-2 llama-4; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $API_KEY" \
        "https://api.TARGET/v1/models/$slug")
    echo "$slug → $status"
done
```

### 3.4 WebSocket Endpoints (F-07 Pattern)
```bash
# Test discovered WS endpoints for unauthenticated upgrade
for ws in $(grep -r "wss://" sourcemaps/ 2>/dev/null | grep -oP 'wss://[^"]+' | sort -u); do
    echo "Testing: $ws"
    python3 -c "
import websocket
try:
    ws = websocket.WebSocket()
    ws.connect('$ws', timeout=5)
    print('CONNECTED (no auth required)')
    ws.close()
except Exception as e:
    print(f'Failed: {e}')
"
done
```

---

## Phase 4 — API Version Enumeration (10 minutes)

### 4.1 Version Path Enumeration
```bash
# Standard version patterns
for ver in v1 v2 v3 v4 v5 v6 v7 v8 v9 v10 api/v1 api/v2 api/v3 \
           api/internal api/admin api/ops 1 2 3; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://api.TARGET/$ver/")
    if [ "$status" != "404" ] && [ "$status" != "000" ]; then
        echo "/v: $ver → $status"
    fi
done
```

### 4.2 OpenAPI / Swagger Discovery
```bash
for path in /openapi.json /swagger.json /api-docs /api/swagger.json \
            /v1/openapi.json /v2/swagger.json /api/v1/openapi.json \
            /swagger/v1/swagger.json /docs/api.json; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET$path")
    if [ "$status" = "200" ]; then
        echo "FOUND: $path"
        curl -s "https://TARGET$path" | python3 -m json.tool > "swagger-$path.json" 2>/dev/null
    fi
done
```

---

## Decision Points

### Found an interesting endpoint?

```
Status 200, no auth required
  → Contains sensitive data? → P3-P4 finding
  → Contains infrastructure info (K8s, IPs, tokens)? → P2-P3 finding
  → Contains secrets/API keys? → P2 finding

Status 401/403
  → Try: Remove Authorization header entirely
  → Try: Change Content-Type to text/plain
  → Try: Add X-Forwarded-For: 127.0.0.1
  → Try: Add X-Original-URL: /public/
  → Try: Add X-Custom-IP-Authorization: 127.0.0.1

Status 200 but empty
  → Change method to POST
  → Add Content-Type: application/json with empty body {}
  → Add Accept: application/json header
```

---

## Evidence Collection

When a shadow API is confirmed:
1. Screenshot: URL bar + full response body
2. HTTP log: `curl -v "URL" 2>&1 | tee evidence/F-XX/http/shadow-api-01.http`
3. Note: time of discovery, auth headers sent (if any)
4. Log to SQLite: `INSERT INTO findings (title, severity, endpoint) VALUES (...)`

---

## Output Files

| File | Contents |
|------|----------|
| codename-results.txt | httpx output from 300-URL grid |
| codename-hits.txt | Filtered non-404 results |
| sourcemap-findings.txt | Paths and secrets extracted from source maps |
| shadow-apis.md | Confirmed shadow API findings |
