# Knowledge Graph — No Mercy Hunter v3.0

## Graph Overview

This is a semantic graph of all concepts, tools, workflows, and methodologies in the
No Mercy Hunter skill. Edges describe relationships. Central nodes (most edges) are
listed first. Orphan nodes (no edges) are listed at the end.

---

## Node Inventory

### Tool Nodes
T01: subfinder
T02: amass
T03: assetfinder
T04: findomain
T05: dnsx
T06: httpx
T07: naabu
T08: gau
T09: waybackurls
T10: katana
T11: ffuf
T12: dirsearch
T13: nuclei
T14: dalfox
T15: arjun
T16: kxss
T17: qsreplace
T18: gf
T19: InQL
T20: GraphCrawler
T21: graphw00f
T22: clairvoyance
T23: batchql
T24: graphql-cop
T25: Playwright
T26: sqlite3
T27: bug_hunter_suite.py
T28: shadow_hunter.py
T29: wscat
T30: curl
T31: python (requests/threading)

### MCP Server Nodes
M01: mcp__filesystem
M02: mcp__memory
M03: mcp__sequential-thinking
M04: mcp__github
M05: mcp__brave-search
M06: mcp__postgres
M07: mcp__playwright
M08: mcp__browser-tools
M09: mcp__fetch
M10: mcp__sqlite

### Methodology Nodes
P01: Passive Recon Phase
P02: Auth Surface Mapping Phase
P03: AI-Specific Attack Phase
P04: Infrastructure Sweep Phase
P05: Race/Timing Phase
P06: Documentation Phase

### Attack Vector Nodes
V01: Source Map Leak
V02: Subdomain Takeover
V03: Codename Fuzzing
V04: JWT Algorithm Confusion
V05: OAuth State Fixation
V06: WebSocket Session Hijack
V07: GraphQL Introspection
V08: Prototype Pollution Client
V09: Prototype Pollution Server
V10: postMessage Validation
V11: DOM Clobbering
V12: CSS Injection
V13: DNS Rebinding
V14: SSRF
V15: Browsing-Tool SSRF
V16: Prompt Injection
V17: Vector DB Poisoning
V18: Memory Poisoning
V19: Memory API IDOR
V20: Vector Store IDOR
V21: S3 Bucket Enum
V22: Elasticsearch/Kibana
V23: npm Registry Confusion
V24: Race Condition
V25: Dependency Confusion
V26: Admin API Discovery
V27: Shadow GPT Catalog
V28: Staging/Debug Endpoints
V29: Forgotten WebSocket
V30: Device ID Header Bypass
V31: Bootstrap Endpoint Leak
V32: OAuth Provider Config Exposure
V33: Routing Cookie RFC1918 Leak
V34: Unauth Feature Flag Dump
V35: Azure AD Tenant Leak
V36: ROPC + Device Code Flow
V37: PowerShell AST Block Bypass
V38: Git Config Driver RCE
V39: Unauthenticated OAuth Registration
V40: CORS Arbitrary Origin Reflection

### Finding Nodes (real)
F01: OAI-Device-Id bypass (P3)
F02: Bootstrap K8s leak (P3)
F03: Unreleased model slugs (P4)
F04: Sidetron OAuth providers (P4)
F05: Routing cookie RFC1918 (P3)
F06: Unauth feature flags (P4)
F07: Realtime WS unauth (P4)
F08: Azure AD tenant leak (P2)
F09: Sentinel token unauth (P4)
F10: ROPC+Device Code (P1)
C01: CODEX-01 begin{} (P2)
C02: CODEX-02 trap{} (P2)
C03: CODEX-03 clean{} (P2)
C04: CODEX-04 git textconv (P2)
H01: HF-01 OAuth ATO (P1)
H02: HF-02 CORS (P3)
A01: AN-01 Anthropic staging CORS (P4)
MI01: MI-01 Ory Kratos config (P3)

### Concept Nodes
C_ATL: Attack Ladder
C_QG: Quality Gate
C_CHAIN: Finding Chain
C_CVSS: CVSS Scoring
C_SCOPE: Program Scope
C_DB: SQLite Findings DB
C_SESS: Playwright Session
C_REPORT: Report Template
C_CODENAME: Codename List
C_AZUREAD: Azure AD

---

## Edge List

### "feeds into" edges (output of A is input to B)

T01 feeds_into P01 (subfinder output → passive recon subdomain list)
T02 feeds_into P01
T03 feeds_into P01
T04 feeds_into P01
T01+T02+T03+T04 feeds_into T05 (subdomain list → dnsx for resolution)
T05 feeds_into T06 (resolved hosts → httpx for live check)
T06 feeds_into T07 (live hosts → naabu port scan)
T06 feeds_into T13 (live hosts → nuclei vuln scan)
T06 feeds_into T10 (live hosts → katana crawl)
T08 feeds_into V01 (gau URLs → JS source map discovery)
T09 feeds_into V01
T08+T09 feeds_into T18 (URL history → gf pattern filter)
T18 feeds_into T16 (gf-filtered URLs → kxss reflection probe)
T17 feeds_into T16 (qsreplace injects XSS → kxss tests reflection)
T16 feeds_into T14 (reflected URLs → dalfox active XSS scan)
T10 feeds_into T15 (katana-crawled URLs → arjun parameter discovery)
T13 feeds_into P04 (nuclei findings → infrastructure sweep)
T25 feeds_into P02 (Playwright session → auth surface mapping)
T25 feeds_into P03 (Playwright → AI attack)
T26 feeds_into P06 (SQLite → documentation)

### "uses" edges (A employs B as component)

P01 uses T01, T02, T03, T04, T08, T09, T05, M05, M04, M09
P02 uses T25, T30, T06
P03 uses T25, T27, T28, T30
P04 uses T06, T07, T13, T30
P05 uses T31
P06 uses T26, C_REPORT, C_CVSS

V03 uses C_CODENAME
V04 uses T30 (curl to fetch JWKS)
V07 uses T19, T20, T21, T22, T23, T24
V14 uses T30, T25
V15 uses T25
V37 uses T25 (Playwright for Codex interaction)
V38 uses T30

C_ATL uses C_CHAIN
C_CHAIN uses C_CVSS
C_QG uses C_SCOPE

### "prerequisite for" edges (A must happen before B)

P01 prerequisite_for P02
P01 prerequisite_for P03
P02 prerequisite_for P03
P04 prerequisite_for P05
P05 prerequisite_for P06

V28 prerequisite_for V35 (staging subdomain → Azure AD recon)
V35 prerequisite_for V36 (Azure AD tenant → ROPC test)
V39 prerequisite_for H01 (unauthenticated register → ATO chain)
F08 prerequisite_for F10 (tenant leak → ROPC exploitation)
V04 prerequisite_for V06 (JWT analysis → WS session hijack)

C_SCOPE prerequisite_for P01 (must know scope before any testing)
C_DB prerequisite_for P06 (DB must be initialized before documentation)

### "produces" edges (A generates B as output)

P01 produces V01, V02, V03, V28, V31
P02 produces V04, V05, V06, V30, V33, V34
P03 produces V15, V16, V17, V18, V19, V20, V27
P04 produces V14, V21, V22, V23, V31, V35
P05 produces V24
P06 produces C_REPORT

T01 produces subs/subfinder.txt
T06 produces live/hosts.txt
T08+T09 produces urls/all.txt
T13 produces nuclei/findings.txt
T14 produces xss/dalfox.txt
T26 produces findings_summary view

### "escalates to" edges (A finding leads to B)

F08 escalates_to F10
V28 escalates_to V35
V35 escalates_to V36
V39 escalates_to H01
C01 escalates_to C02 (AST block enumeration is sequential)
C02 escalates_to C03
V33 escalates_to V14 (RFC1918 IP → SSRF target)
V40 escalates_to V14 (CORS + credential endpoint → data exfil)
V31 escalates_to V14 (K8s bootstrap → internal service SSRF)

---

## Central Nodes (Most Connections)

Ranked by total edge count:

1. **P01 (Passive Recon Phase)** — 12 edges
   Uses: T01, T02, T03, T04, T08, T09, T05, M05, M04, M09
   Prerequisite for: P02, P03
   Produces: V01, V02, V03, V28, V31

2. **T06 (httpx)** — 8 edges
   Fed by: T05 (dnsx output)
   Feeds into: T07, T13, T10
   Used by: P02, P04
   Produces: live/hosts.txt

3. **T25 (Playwright)** — 7 edges
   Used by: P02, P03, V14, V15, V37
   Produces: session cookies, captured responses
   Feeds into: auth surface + AI attack phases

4. **C_ATL (Attack Ladder)** — 7 edges
   Uses: C_CHAIN
   Source: F08→F10, H01, CODEX-01-04
   Referenced by: methodology.md, operator-brain.md, decision-tree.md

5. **T13 (nuclei)** — 6 edges
   Fed by: T06 (live hosts)
   Used by: P04
   Feeds into: infra findings, report queue
   Produces: nuclei/findings.txt

6. **V35 (Azure AD Tenant Leak)** — 6 edges
   Prerequisite: V28 (staging subdomain)
   Escalates to: V36 (ROPC)
   Grounded in: F08, F10
   Used by: pb-06-azure-ad-recon.md

7. **T26 (SQLite)** — 5 edges
   Used by: P06
   Feeds into: reporting, deduplication, findings_summary
   Produces: chain-of-custody records

8. **C_CHAIN (Finding Chain)** — 5 edges
   Uses: C_CVSS
   Used by: C_ATL
   Instances: F08+F10, CODEX-01+02+03+04, HF-01

---

## Duplicate Clusters

These node groups represent the same concept with different names across source skills.
They have been merged in this operator.

**Cluster A — Subdomain Enumeration**
Nodes: T01(subfinder), T02(amass), T03(assetfinder), T04(findomain)
All do the same job. Difference: coverage and speed. Run all four, deduplicate.
Canonical pipeline: subfinder (fast) → assetfinder (tomnomnom sources) → amass (slow, comprehensive) → findomain (Rust, certificate data)

**Cluster B — URL History**
Nodes: T08(gau), T09(waybackurls)
Same function, different data sources. Run both, merge.
gau queries more sources (Common Crawl, OTX, URLScan). waybackurls is Wayback Machine specific.

**Cluster C — Content Discovery**
Nodes: T11(ffuf), T12(dirsearch)
Same function. ffuf is faster and more flexible. dirsearch has better default wordlists for some scenarios.
Canonical: use ffuf. Fall back to dirsearch for recursive crawl.

**Cluster D — GraphQL Tools**
Nodes: T19(InQL), T20(GraphCrawler), T21(graphw00f), T22(clairvoyance), T23(batchql), T24(graphql-cop)
All probe GraphQL. Different strengths:
- graphw00f: fingerprinting only (which GraphQL engine?)
- InQL: full Burp integration, schema dump
- clairvoyance: field suggestion when introspection disabled
- batchql: batching abuse
- graphql-cop: automated security checks
- GraphCrawler: path/field enumeration

**Cluster E — OAuth Registration vs OAuth Client Enum**
Nodes: V05(OAuth State Fixation), V39(Unauthenticated OAuth Registration)
Related but different. V05 is about missing state= parameter. V39 is about open registration endpoint.
Do not conflate. Test both independently.

---

## Orphan Knowledge

Nodes with no inbound edges from main workflow — these are valuable but not yet integrated:

- **wfuzz** (T_WF): installed per INSTALL_REPORT.md, not referenced in any workflow
  Recommendation: use for parameter fuzzing on authenticated endpoints
- **Kiterunner**: mentioned in api-fuzzing skill, not in any workflow
  Recommendation: add to api-testing checklist for route brute force
- **ParamSpider**: mentioned in red-team-tools, not wired into automation framework
  Recommendation: add as step 0 of XSS pipeline before gau
- **DNS Rebinding (V13)**: appears in vector list but no playbook exists
  Recommendation: create pb-08-dns-rebinding.md in next iteration
- **Prototype Pollution (V08, V09)**: vector listed but no playbook
  Recommendation: create pb-09-prototype-pollution.md
- **CSS Injection (V12)**: vector listed but no playbook
  Recommendation: create pb-10-css-injection.md

---

## Visual Adjacency Summary (Text-Based)

```
                    ┌─────────────────────────────────────────┐
                    │           PROGRAM SCOPE (C_SCOPE)         │
                    └──────────────┬──────────────────────────┘
                                   │ prerequisite_for
                    ┌──────────────▼──────────────────────────┐
                    │           PASSIVE RECON (P01)            │
                    │  subfinder amass assetfinder findomain   │
                    │  gau waybackurls crt.sh brave-search     │
                    └──┬──────────────────────────────┬───────┘
        feeds_into     │                              │ feeds_into
           ┌───────────▼──────────┐       ┌──────────▼───────────┐
           │    dnsx (T05)        │       │   URL History         │
           │  DNS resolution      │       │  gau + wayback        │
           └───────────┬──────────┘       └──────────┬───────────┘
                       │ feeds_into                   │ feeds_into
           ┌───────────▼──────────┐       ┌──────────▼───────────┐
           │    httpx (T06)       │       │   gf → kxss → dalfox │
           │   live hosts         │       │   XSS pipeline        │
           └──┬──────┬──────┬─────┘       └──────────────────────┘
              │      │      │
         ┌────▼─┐ ┌──▼──┐ ┌▼─────┐
         │naabu │ │nucl │ │katana│
         │ports │ │ei   │ │crawl │
         └──────┘ └──┬──┘ └──┬───┘
                     │       │ feeds_into
                     │    ┌──▼───────────┐
                     │    │  arjun       │
                     │    │  params      │
                     │    └─────────────┘
                     │
         ┌───────────▼──────────────────────────┐
         │         AUTH SURFACE (P02)            │
         │  Playwright · JWT · OAuth · WS · AD   │
         └──────────────────┬───────────────────┘
                            │ prerequisite_for
         ┌──────────────────▼───────────────────┐
         │         AI-SPECIFIC (P03)             │
         │  Prompt Inj · IDOR · Browsing SSRF   │
         └──────────────────┬───────────────────┘
                            │ feeds_into
         ┌──────────────────▼───────────────────┐
         │         DOCUMENTATION (P06)           │
         │   SQLite DB · CVSS · Report Template  │
         └──────────────────────────────────────┘
```
