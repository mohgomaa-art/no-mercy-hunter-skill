# Checklist 01 — Passive Recon

Run before ANY active probing. Zero footprint. No requests to target servers.

## Pre-Flight

- [ ] Target domain confirmed in scope per program scope page
- [ ] Output directory created: recon/TARGET/{subs,live,urls,ports,nuclei,screenshots}
- [ ] SQLite target record created: INSERT INTO targets (domain, program)
- [ ] Scan record created: INSERT INTO scans (target_id, scan_type, status)

## Certificate Transparency

- [ ] Query crt.sh: https://crt.sh/?q=%25.TARGET&output=json | jq -r '.[].name_value'
- [ ] Query Censys (if API key available): search for TARGET in certificate SANs
- [ ] Query Shodan (if API key available): ssl.cert.subject.cn:TARGET
- [ ] Extract all unique hostnames from CT results -> subs/crt.txt
- [ ] Note any interesting subdomains: staging.*, dev.*, internal.*, admin.*, api.*

## Subdomain Enumeration (Passive Only)

- [ ] subfinder -d TARGET -silent -o subs/subfinder.txt
- [ ] assetfinder --subs-only TARGET > subs/assetfinder.txt
- [ ] amass enum -passive -d TARGET -o subs/amass.txt
- [ ] findomain -t TARGET --quiet -u subs/findomain.txt  [NOTE: still BUILDING per INSTALL_REPORT]
- [ ] cat subs/*.txt | sort -u > subs/all.txt
- [ ] Record count: echo "$(wc -l < subs/all.txt) unique subdomains"
- [ ] Highlight: any codename matches in subdomain list?
- [ ] Highlight: staging.*, dev.*, beta.*, test.* subdomains -> Azure AD trigger (Rule 01)

## GitHub and Code Search

- [ ] mcp__github__search_code: query="TARGET api_key OR secret OR password"
- [ ] mcp__github__search_code: query="TARGET /api/internal OR /admin OR /bootstrap"
- [ ] mcp__github__search_code: query="site:github.com TARGET .env OR credentials"
- [ ] mcp__brave-search: query="site:github.com TARGET leaked credentials 2024 2025 2026"
- [ ] Note any leaked secrets, internal endpoints, or employee usernames found

## Wayback Machine and URL History

- [ ] gau --subs TARGET > urls/gau.txt
- [ ] waybackurls TARGET > urls/wayback.txt
- [ ] cat urls/*.txt | sort -u > urls/all.txt
- [ ] Record count: echo "$(wc -l < urls/all.txt) unique historical URLs"
- [ ] Extract parameterized URLs: grep '=' urls/all.txt | sort -u > urls/params.txt
- [ ] Extract API paths: grep -E '/api/|/v[0-9]+/' urls/all.txt | sort -u > urls/api-paths.txt
- [ ] Extract JS files: grep -E '\.js($|\?)' urls/all.txt | sort -u > urls/js-files.txt

## Source Map Discovery

- [ ] Check each JS URL for .map extension: append .map and probe (status 200?)
- [ ] Check each JS file for sourceMappingURL comment in last 200 bytes
- [ ] Download all accessible .map files to js/maps/
- [ ] Extract secrets from maps: grep -riE 'api_key|secret|password|token|bearer|sk-' js/maps/
- [ ] Extract internal API paths: grep -oE '"/[a-zA-Z0-9_/-]{3,}"' js/maps/ | sort -u
- [ ] Extract internal hostnames: grep -oE 'https?://[a-zA-Z0-9.-]+' js/maps/ | sort -u
- [ ] Extract developer emails: grep -oE '[a-zA-Z0-9._%+-]+@TARGET' js/maps/ | sort -u

## Codename Fuzzing (300 URLs — passive generation, no requests yet)

Generate URL matrix. 20 codenames x 15 path patterns. Save to shadow/codename-grid.txt.

Codenames to use as subdomains (CODENAME.TARGET):
- [ ] cortex-admin-gql
- [ ] auth-triton-v2
- [ ] realtime-aries
- [ ] browser-hermes
- [ ] assistant-hub-nest
- [ ] openai-ml-ops
- [ ] deepmind-trainer
- [ ] phoenix-admin-api
- [ ] gizmo-catalog-v3
- [ ] memory-fabric
- [ ] vector-pine
- [ ] chatgpt-staging-omega
- [ ] live-agent-socket
- [ ] action-oauth-gateway
- [ ] npm-openai-internal
- [ ] logs-kibana-2026
- [ ] chat-embed-frame
- [ ] billing-promo-engine
- [ ] frontend-next-2026
- [ ] model-artifacts-prod

Path patterns to append per codename (/):
- [ ] / (root)
- [ ] /api
- [ ] /v1
- [ ] /health
- [ ] /status
- [ ] /config
- [ ] /admin
- [ ] /metrics
- [ ] /graphql
- [ ] /ws
- [ ] /oauth
- [ ] /debug
- [ ] /internal
- [ ] /schema
- [ ] /openapi.json

- [ ] Run shadow_hunter.py Tab 1 (Codename Fuzzer) against TARGET
- [ ] Record all non-404 responses from codename grid

## DNS Passive Analysis

- [ ] Check DNS history for TARGET on SecurityTrails (manual, if access available)
- [ ] Note any historical IPs that may indicate cloud provider (AWS, Azure, GCP)
- [ ] Note any MX records pointing to Microsoft -> Azure AD indicator

## OSINT

- [ ] mcp__brave-search: query="TARGET bug bounty disclosure 2025 2026"
- [ ] mcp__brave-search: query="TARGET CVE vulnerability 2025 2026"
- [ ] mcp__brave-search: query="TARGET data breach OR leak 2024 2025 2026"
- [ ] mcp__brave-search: query="TARGET security researcher disclosed"

## Completion Gate

- [ ] subs/all.txt exists and is non-empty
- [ ] urls/all.txt exists and is non-empty
- [ ] js/maps/ directory scanned (even if empty)
- [ ] All findings logged to SQLite
- [ ] Any staging.* or dev.* subdomains flagged for auth surface phase
- [ ] Any secrets found in source maps -> immediately log as P2 minimum
