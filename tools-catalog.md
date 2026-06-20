# Tools Catalog — No Mercy Hunter v3.0

All tools scored: Composite = (Confidence x 2) + (InformationGain x 3) + (AutomationPotential x 2) + (Reusability x 2) - Cost

---

## Tier 0 — Environment and Orchestration

| Tool | Purpose | Install | Score |
|------|---------|---------|-------|
| sqlite3 | Findings database | Built-in / pre-installed | 46 |
| Playwright (npm) | Browser automation + session capture | npm install playwright | 49 |
| Python 3 | Scripting, PoC development | Pre-installed | 48 |
| Node.js | JS tooling, Playwright scripts | Pre-installed | 42 |
| PowerShell 7 | Windows automation | Pre-installed | 38 |
| Git Bash | POSIX shell on Windows | Pre-installed | 40 |

---

## Tier 1 — Subdomain Enumeration

| Tool | Purpose | Command | Score | Notes |
|------|---------|---------|-------|-------|
| subfinder | Passive subdomain enum | subfinder -d TARGET -silent | 42 | Fastest, ProjectDiscovery |
| amass | Comprehensive passive enum | amass enum -passive -d TARGET | 42 | Slowest, most coverage |
| assetfinder | Passive enum via multiple sources | assetfinder --subs-only TARGET | 35 | tomnomnom, quick |
| findomain | Certificate transparency enum | findomain -t TARGET --quiet | 35 | Rust binary, BUILDING per INSTALL_REPORT |

All four: Run together, cat + sort -u to deduplicate. Combined coverage > any single tool.

---

## Tier 2 — DNS and Live Host Detection

| Tool | Purpose | Command | Score | Notes |
|------|---------|---------|-------|-------|
| dnsx | DNS resolution + A record lookup | dnsx -l subs.txt -silent -a -resp | 40 | ProjectDiscovery |
| httpx | HTTP/HTTPS probing + tech detect | httpx -l hosts.txt -title -tech-detect -status-code | 46 | Most valuable output |
| httprobe | Simple HTTP probe | cat hosts.txt | httprobe | 28 | Fallback if httpx unavailable |

httpx is the most important tool in the pipeline — its output drives all subsequent scanning.

---

## Tier 3 — Port Scanning

| Tool | Purpose | Command | Score | Notes |
|------|---------|---------|-------|-------|
| naabu | Fast port scanner | naabu -l hosts.txt -top-ports 1000 | 43 | ProjectDiscovery, Go |
| nmap | Comprehensive port + service scan | nmap -sV -p- TARGET | 35 | Slower, more detail |

naabu for speed (bug bounty), nmap for depth (pen test). naabu is sufficient for most BB work.

---

## Tier 4 — URL Discovery and History

| Tool | Purpose | Command | Score | Notes |
|------|---------|---------|-------|-------|
| gau | URL history: CommonCrawl+OTX+Wayback | gau --subs TARGET | 48 | Highest InfoGain |
| waybackurls | Wayback Machine URL history | waybackurls TARGET | 43 | tomnomnom, focused |
| katana | Active crawler | katana -list hosts.txt -d 2 | 44 | ProjectDiscovery, JS-aware |

gau has the best coverage. waybackurls sometimes finds unique URLs. katana finds JS-rendered paths.
Run all three, merge output.

---

## Tier 5 — Content Discovery

| Tool | Purpose | Command | Score | Notes |
|------|---------|---------|-------|-------|
| ffuf | Fast fuzzing framework | ffuf -w wordlist.txt -u URL/FUZZ | 39 | Fastest, most flexible |
| dirsearch | Directory/file brute force | python dirsearch.py -u URL | 33 | Better default wordlists |
| arjun | Parameter discovery | arjun -u URL | 42 | Finds hidden parameters |
| wfuzz | Flexible web fuzzer | wfuzz -c -w wordlist.txt URL/FUZZ | 28 | Installed, less used |
| Kiterunner | Route/endpoint brute force | kr scan TARGET -w routes.kite | 36 | API route focused |

arjun is unique — no other tool does parameter discovery this well.
ffuf preferred over dirsearch for speed; dirsearch as fallback for recursive mode.

---

## Tier 6 — XSS Detection

| Tool | Purpose | Command | Score | Notes |
|------|---------|---------|-------|-------|
| dalfox | Active XSS scanner | dalfox file urls.txt | 46 | Best active XSS tool |
| kxss | Reflection detection | cat urls.txt | kxss | 38 | Pre-filter before dalfox |
| qsreplace | Replace query string values | cat urls.txt | qsreplace PAYLOAD | 40 | Pipeline utility |
| gf | Pattern-based URL filter | gf xss < urls.txt | 35 | tomnomnom patterns |
| ParamSpider | Parameter URL discovery | paramspider -d TARGET | 32 | Mentioned in red-team skill |

XSS pipeline: gau+waybackurls -> grep = -> qsreplace -> kxss -> gf xss -> dalfox

---

## Tier 7 — Vulnerability Scanning

| Tool | Purpose | Command | Score | Notes |
|------|---------|---------|-------|-------|
| nuclei | Template-based vuln scanner | nuclei -l hosts.txt -severity critical,high | 44 | ProjectDiscovery, essential |

nuclei covers: CVEs, exposed panels, misconfigs, default creds, takeovers, cloud misconfigs.
Update weekly: nuclei -update-templates

---

## Tier 8 — GraphQL Tools

| Tool | Purpose | Command | Score | Notes |
|------|---------|---------|-------|-------|
| graphw00f | GraphQL engine fingerprinting | graphw00f -t URL/graphql | 42 | Identifies engine type |
| InQL | Full GraphQL security scanner | python -m inql -t URL/graphql | 47 | Best overall, Burp plugin too |
| clairvoyance | Field suggestion when introspection off | clairvoyance URL/graphql | 44 | Essential when introspection blocked |
| batchql | Batching abuse testing | batchql -u URL/graphql | 38 | Rate limit bypass |
| graphql-cop | Automated security checks | graphql-cop -t URL/graphql | 46 | 10 automated checks |
| GraphCrawler | Schema enumeration | graphcrawler -t URL/graphql | 32 | Path/field enumeration |

GraphQL workflow: graphw00f (fingerprint) -> InQL (schema) -> clairvoyance (if blocked) -> graphql-cop (checks)

---

## Tier 9 — API Testing

| Tool | Purpose | Command | Score | Notes |
|------|---------|---------|-------|-------|
| curl | HTTP requests | curl -v -X POST URL -d BODY | 44 | Universal, in every PoC |
| Postman | API exploration GUI | GUI tool | 35 | Manual testing |
| Insomnia | API client | GUI tool | 33 | Alternative to Postman |
| Burp Suite Pro | Intercepting proxy | GUI tool | 42 | NOT INSTALLED — manual install required |
| mitmproxy | CLI intercepting proxy | mitmproxy -p 8080 | 38 | Open source Burp alternative |

---

## Tier 10 — Browser Automation

| Tool | Purpose | Install | Score | Notes |
|------|---------|---------|-------|-------|
| Playwright (npm) | Full browser automation | npm install playwright | 49 | Session capture, IDOR PoC |
| mcp__playwright | Claude-accessible Playwright | MCP server (PASS) | 42 | Direct from Claude |
| mcp__browser-tools | Browser debugging via Chrome ext | MCP server (PASS) | 39 | Chrome extension required |
| wscat | WebSocket client | npm install -g wscat | 38 | WS endpoint testing |
| websocat | WebSocket client CLI | cargo install websocat | 35 | Alternative to wscat |

---

## Tier 11 — MCP Servers (all PASS per INSTALL_REPORT.md)

| Server | Package | Purpose | Score |
|--------|---------|---------|-------|
| mcp__filesystem | @modelcontextprotocol/server-filesystem | File read/write/list | 42 |
| mcp__memory | @modelcontextprotocol/server-memory | Cross-session finding persistence | 39 |
| mcp__sequential-thinking | @modelcontextprotocol/server-sequential-thinking | Complex chain reasoning | 36 |
| mcp__github | @modelcontextprotocol/server-github | Code search, issue tracking | 46 |
| mcp__brave-search | @modelcontextprotocol/server-brave-search | OSINT, news, disclosure search | 39 |
| mcp__postgres | @modelcontextprotocol/server-postgres | PostgreSQL queries | 34 |
| mcp__sqlite | mcp-server-sqlite | SQLite findings DB queries | 46 |
| mcp__fetch | mcp-server-fetch | HTTP requests from Claude | 46 |
| mcp__playwright | @playwright/mcp | Browser automation from Claude | 42 |
| mcp__browser-tools | @agentdeskai/browser-tools-mcp | Chrome DevTools from Claude | 39 |

Note: BRAVE_API_KEY and GITHUB_PERSONAL_ACCESS_TOKEN must be set in settings.json.
PostgreSQL MCP requires connection string or can be removed if unused.
Browser Tools MCP requires Chrome extension installed manually.

---

## Tier 12 — Python Security Tools (all PASS per INSTALL_REPORT.md)

| Tool | Purpose | Command | Score |
|------|---------|---------|-------|
| dirsearch | Directory/file discovery | python dirsearch.py -u URL | 33 |
| arjun | Parameter discovery | arjun -u URL | 42 |
| wfuzz | Web fuzzer | wfuzz -c -w wordlist.txt URL/FUZZ | 28 |

---

## Tier 13 — Custom Bug Bounty Tools

| Tool | Purpose | Command | Score |
|------|---------|---------|-------|
| bug_hunter_suite.py | 20-vector scanner, 8 tabs | python bug_hunter_suite.py | 44 |
| shadow_hunter.py | Codename fuzzing + shadow APIs | python shadow_hunter.py | 43 |
| scripts/recon.sh | Full passive-to-active pipeline | bash scripts/recon.sh TARGET | 41 |
| scripts/xss-pipeline.sh | XSS automation | bash scripts/xss-pipeline.sh TARGET | 38 |
| scripts/meta_recon.py | Meta recon orchestration | python scripts/meta_recon.py TARGET | 36 |
| scripts/probe_endpoints.py | Endpoint probing | python scripts/probe_endpoints.py | 35 |
| scripts/update-tools.sh | Update all Go/Python tools | bash scripts/update-tools.sh | 30 |
| scripts/content-discovery.sh | Content enumeration | bash scripts/content-discovery.sh TARGET | 32 |

---

## Tier 14 — Wordlists (all present per INSTALL_REPORT.md)

| File | Lines | Use |
|------|-------|-----|
| raft-medium-directories.txt | 29,999 | ffuf/dirsearch directory brute force |
| raft-small-words.txt | 43,007 | ffuf general wordlist |
| subdomains/top-5000.txt | 5,000 | Subdomain brute force |
| content/api-endpoints.txt | 295 | API endpoint discovery |

---

## Tier 15 — Cloud and Infrastructure

| Tool | Purpose | Command | Score |
|------|---------|---------|-------|
| aws cli | S3 bucket testing | aws s3 ls s3://BUCKET --no-sign-request | 38 |
| curl | S3 bucket listing | curl https://BUCKET.s3.amazonaws.com/ | 35 |
| nuclei cloud templates | Cloud misconfiguration scan | nuclei -t cloud/ | 36 |

---

## Tier 16 — Reporting and Documentation

| Tool | Purpose | Command | Score |
|------|---------|---------|-------|
| sqlite3 | Findings database | sqlite3 bug_bounty.db | 46 |
| CVSS calculator | Score calculation | https://www.first.org/cvss/calculator/3.1 | 44 |
| templates/ | Report templates | See templates/ directory | 42 |

---

## Tier 17 — Not Installed (Manual Required per INSTALL_REPORT.md)

| Tool | Reason Not Installed | Install |
|------|---------------------|---------|
| Docker Desktop | Requires GUI admin installer | https://www.docker.com/products/docker-desktop/ |
| PostgreSQL server | Separate DB server | https://www.postgresql.org/download/windows/ |
| Burp Suite Pro | Commercial tool | https://portswigger.net/burp |
| Browser Tools Chrome Extension | Manual Chrome install | Chrome Web Store — search "Browser Tools MCP" |
| findomain | Still building (cargo install in progress) | cargo install findomain |

---

## Tool Scoring Summary — Top 15 by Score

| Rank | Tool | Score | Category |
|------|------|-------|----------|
| 1 | Playwright | 49 | Browser Automation |
| 2 | gau | 48 | URL Discovery |
| 3 | Python 3 | 48 | Environment |
| 4 | WF-12 Source Map Recon | 48 | Workflow |
| 5 | httpx | 46 | Live Hosts |
| 6 | dalfox | 46 | XSS |
| 7 | mcp__github | 46 | MCP |
| 8 | mcp__sqlite | 46 | MCP |
| 9 | mcp__fetch | 46 | MCP |
| 10 | sqlite3 | 46 | Reporting |
| 11 | WF-05 OAuth Registration | 45 | Workflow |
| 12 | katana | 44 | URL Discovery |
| 13 | nuclei | 44 | Vuln Scanning |
| 14 | InQL | 47 | GraphQL |
| 15 | graphql-cop | 46 | GraphQL |
