# Migration Report — No Mercy Hunter v3.0

Documents all source files analyzed, duplicate clusters merged, unique knowledge retained,
gaps found, and the final architecture rationale.

---

## Source Files Analyzed

| File | Lines | Key Contribution |
|------|-------|-----------------|
| CHEAT_SHEET.md | ~150 | Full ops command reference — subfinder, amass, dnsx, httpx, naabu, gau, waybackurls, katana, ffuf, nuclei, dalfox, arjun, kxss, qsreplace, sqlite3, Playwright, 10 MCP servers |
| SESSION-STATUS.md | ~80 | 18 real findings across 4 platforms — ground truth for all operator rules |
| .claude/bug-bounty.md | ~400 | 40 vectors across 8 tiers, 20 codenames, 7 SSRF prompts, 10 prompt injection payloads |
| .claude/api-fuzzing-bug-bounty skill | ~200 | IDOR bypass techniques, GraphQL attacks, 403 bypass, PDF export attacks, tool list |
| .claude/red-team-tools skill | ~150 | Full recon pipeline, Jason Haddix heat map, XSS pipeline, automated recon script |
| .claude/vulnerability-scanner skill | ~200 | OWASP 2025 Top 10, CVSS scoring, 4-phase methodology, high-risk code patterns |
| .claude/security-bounty-hunter skill | ~100 | Quality gate, reportability criteria, skip list |
| .claude/owasp-security skill | ~300 | TypeScript code examples A01-A10, auth patterns, SSRF prevention |
| scripts/recon.sh | 64 | End-to-end recon pipeline — 7 steps, all tool invocations |
| scripts/xss-pipeline.sh | 27 | XSS automation — gau+waybackurls -> qsreplace -> kxss -> gf -> dalfox |
| _templates/markdown/finding-template.md | 60 | Base finding template with all sections |
| _templates/severity/cvss-rubric.md | 41 | CVSS 3.1 quick reference and common vectors |
| _templates/reporting/disclosure-policy.md | 15 | Pre-submission disclosure checklist |
| INSTALL_REPORT.md | 149 | Validated tool inventory — 15/16 Go tools, 3 Python tools, 10 MCP servers, 4 wordlists |

---

## Duplicate Clusters Merged

### Cluster A — Subdomain Enumeration
Sources: CHEAT_SHEET.md (all 4 tools listed), red-team-tools skill (Subfinder + Amass),
bug-bounty.md (subfinder + amass)
Resolution: All four tools (subfinder, amass, assetfinder, findomain) run together,
output merged and deduplicated. No conflict — additive coverage.

### Cluster B — Live Host Probing
Sources: CHEAT_SHEET.md (httpx), red-team-tools (httprobe/httpx), scripts/recon.sh (httpx)
Resolution: httpx is canonical. httprobe is fallback only. Consistent across all files.

### Cluster C — URL History
Sources: CHEAT_SHEET.md (gau+waybackurls), scripts/recon.sh (gau+waybackurls),
scripts/xss-pipeline.sh (gau+waybackurls), red-team-tools (same)
Resolution: gau + waybackurls run together universally. No conflict.

### Cluster D — XSS Pipeline
Sources: CHEAT_SHEET.md (gau+kxss+dalfox), red-team-tools (ParamSpider+Gxss+Dalfox),
scripts/xss-pipeline.sh (gau+waybackurls+qsreplace+kxss+gf+dalfox)
Resolution: Use scripts/xss-pipeline.sh as canonical. It is the most complete version.
ParamSpider noted as orphan (installed, not wired into pipeline).

### Cluster E — Vulnerability Scanning
Sources: CHEAT_SHEET.md (nuclei), red-team-tools (nuclei), scripts/recon.sh (nuclei)
Resolution: nuclei is canonical. Same tool, same usage across all sources.

### Cluster F — Finding Template
Sources: _templates/markdown/finding-template.md (base template),
bug-bounty.md (report format mentions), api-fuzzing skill (report format)
Resolution: finding-template.md is canonical base. Extended in templates/ directory.

### Cluster G — CVSS Scoring
Sources: _templates/severity/cvss-rubric.md, vulnerability-scanner skill (CVSS + EPSS),
security-bounty-hunter skill (implicit severity ratings)
Resolution: cvss-rubric.md is canonical. EPSS context noted but not required for BB reports.

---

## Unique Knowledge Retained (not duplicated across sources)

| Knowledge | Source | Where Used |
|-----------|--------|------------|
| 18 real findings with endpoints and severities | SESSION-STATUS.md | operator-brain.md, all playbooks |
| Attack Ladder concept | Synthesized from SESSION-STATUS.md | methodology.md, decision-tree.md |
| 20 codenames list | bug-bounty.md | workflows.md WF-02, checklists/01 |
| 7 browsing-tool SSRF prompts | bug-bounty.md | checklists/04, playbook pb-04 |
| 10 prompt injection payloads | bug-bounty.md | checklists/04, playbook pb-04 |
| IDOR bypass technique list (5 methods) | api-fuzzing skill | checklists/03, playbook pb-05 |
| GraphQL tool taxonomy (6 tools) | api-fuzzing skill | tools-catalog.md, playbook pb-07 |
| 403 bypass technique list | api-fuzzing skill | checklists/03 |
| Jason Haddix heat map | red-team-tools skill | operator-brain.md (infused into phases) |
| OWASP 2025 vs 2021 difference | vulnerability-scanner vs owasp-security | conflicts.md |
| Quality gate with skip list | security-bounty-hunter skill | checklists/06 |
| Disclosure policy checklist | _templates/reporting/disclosure-policy.md | checklists/06, reporting-framework.md |
| scripts/recon.sh exact invocations | scripts/recon.sh | automation-framework.md |
| scripts/xss-pipeline.sh exact pipeline | scripts/xss-pipeline.sh | automation-framework.md |
| INSTALL_REPORT.md tool status | INSTALL_REPORT.md | tools-catalog.md (findomain BUILDING noted) |
| Bugcrowd VRT taxonomy | Synthesized from real CODEX submissions | reporting-framework.md |
| HackerOne CWE mapping | Synthesized from real HF-01 submission | reporting-framework.md |
| SQLite schema (6 tables + 1 view) | CHEAT_SHEET.md + synthesis | evidence-framework.md |
| Playwright session capture pattern | CHEAT_SHEET.md + synthesis | automation-framework.md |

---

## Gaps Found

These knowledge areas were referenced but not fully documented in source files.
Each has been given a minimal extendable framework in the operator.

### Gap 1 — DNS Rebinding Playbook
Referenced in: bug-bounty.md (vector #13), tools catalog
Not covered in: no playbook, no step-by-step procedure
Status: Vector listed in checklists/05-infrastructure-checklist.md. Playbook pb-08-dns-rebinding.md
not created in this iteration. Recommended for v3.1.

### Gap 2 — Prototype Pollution Playbook
Referenced in: bug-bounty.md (vectors #8 client, #9 server), red-team-tools
Not covered in: no playbook
Status: Both vectors documented in ontology.md and checklists/03. Playbook pb-09-prototype-pollution.md
not created in this iteration. Recommended for v3.1.

### Gap 3 — Burp Suite Integration
Referenced in: InQL requires Burp Suite for Burp plugin mode
Status: Burp Suite Pro NOT INSTALLED per INSTALL_REPORT.md. InQL standalone mode documented
instead. When Burp Suite Pro is installed, add: InQL Burp plugin workflow.

### Gap 4 — Mobile Application Testing
Not covered in any source skill.
Status: Out of scope for this operator version. No mobile-specific attack vectors included.
Recommended for v4.0 if mobile is in scope for target programs.

### Gap 5 — Docker-based Tools
Several tools (e.g., amass in Docker, various scanners) benefit from Docker.
Status: Docker Desktop NOT INSTALLED per INSTALL_REPORT.md. All tool invocations use
native binaries. When Docker is installed, add containerized tool variants.

### Gap 6 — Automated Chain Escalation
The Attack Ladder concept is documented but no automation exists to:
- Automatically detect when a P4 finding enables a P1 chain
- Suggest chain combinations from the findings database
Status: Manual operator-brain.md rules cover this. Automated chain detector recommended for v3.1.

### Gap 7 — wfuzz Integration
wfuzz is installed (INSTALL_REPORT.md PASS) but not referenced in any workflow.
Status: Listed in tools-catalog.md Tier 5. Not wired into automation pipelines.
Use case: parameter fuzzing on authenticated endpoints where arjun is too slow.

### Gap 8 — ParamSpider Integration
ParamSpider mentioned in red-team-tools skill but not in scripts/xss-pipeline.sh.
Status: Listed as orphan in knowledge-graph.md. Recommended addition to XSS pipeline:
run ParamSpider before gau to capture JS-rendered parameter URLs.

---

## Architecture Rationale

### Why this structure?

The operator is organized around the phases in methodology.md, not around vulnerability types.
This matches how real engagements flow: you do passive recon first regardless of what you find,
then auth surface, then AI-specific, etc. Organizing by vulnerability class (like the source skills)
would mean jumping between phases mid-engagement.

### Why operator-brain.md is separate from methodology.md

methodology.md tells you WHAT to do in order.
operator-brain.md tells you WHEN to deviate from the order based on signals.
These are different cognitive tasks. Mixing them would make both harder to use.

### Why playbooks are separate from checklists

Checklists are verification tools — you run down the list confirming each item is done.
Playbooks are procedural guides — you follow steps to accomplish a specific goal.
A checklist for auth testing tells you what to check. A playbook for OAuth ATO tells you
exactly how to exploit it when you find the right conditions.

### Why the knowledge graph and ontology are separate

The knowledge graph shows connections between concepts (edges between nodes).
The ontology shows the taxonomy of concepts (classification of nodes).
A graph without taxonomy is hard to navigate. A taxonomy without connections is static.
Together they provide both structure and relationships.

### Why findings from SESSION-STATUS.md are embedded everywhere

Every operator rule that doesn't cite a real finding is speculative. Rules 01-10 in
operator-brain.md are all derived from actual findings with known severities and outcomes.
This grounds the operator in evidence rather than theory. When a rule says "test for Azure AD
tenant leak when staging subdomain found," it is because that is exactly how F-08 was discovered.

---

## Final File Count

| Directory | Files | Purpose |
|-----------|-------|---------|
| super-research-operator/ | 12 | Core operator files |
| super-research-operator/checklists/ | 6 | Per-phase ordered checklists |
| super-research-operator/templates/ | 4 | Ready-to-submit report templates |
| super-research-operator/playbooks/ | 7 | Step-by-step attack playbooks |
| Total | 29 | Complete operator |

---

## Version History

v3.0.0 — 2026-06-21
  Initial release. Unified from 6 source skills + 18 real findings.
  29 files. 40 attack vectors. 12 workflows. 7 playbooks. 6 checklists. 4 templates.

v3.1.0 — Planned
  Add: pb-08-dns-rebinding.md
  Add: pb-09-prototype-pollution.md
  Add: ParamSpider to XSS pipeline
  Add: Automated chain escalation detection
  Add: Burp Suite Pro integration (when installed)
  Add: wfuzz workflow for authenticated parameter fuzzing
