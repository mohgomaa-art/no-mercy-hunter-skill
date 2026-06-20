# No Mercy Hunter v3.0 — Master Skill Index

## Identity

Name: No Mercy Hunter v3.0
Version: 3.0.0
Created: 2026-06-21
Unified from: bug-bounty-hunter, red-team-tools, vulnerability-scanner, security-bounty-hunter, owasp-security, api-fuzzing-bug-bounty (6 skills)
Grounded in: 18 real findings across OpenAI, OpenAI Codex, HuggingFace, Anthropic, Mistral (SESSION-STATUS.md)
Toolchain: 15 Go recon tools + 3 Python tools + 10 MCP servers + 2 custom Python suites

## Trigger Phrases

Any of these phrases invoke the full operator:

- "run no mercy on [target]"
- "full recon [target]"
- "hunt [target]"
- "start bug bounty session [target]"
- "passive recon [target]"
- "shadow api hunt [target]"
- "oauth ato test [target]"
- "jwt confusion [target]"
- "graphql enum [target]"
- "ai prompt injection [target]"
- "idor test [target]"
- "azure ad recon [target]"
- "codex bypass test"
- "dependency confusion [target]"

## Invocation Examples

```
Hunt openai.com — full passive recon, shadow API discovery, and AI-specific vectors.
Run OAuth ATO chain against huggingface.co.
JWT confusion test on api.example.com with token: eyJ...
Test memory IDOR between two accounts on chatgpt.com.
Azure AD recon on staging.target.com.
PowerShell AST bypass enumeration against codex.openai.com.
Generate P1 report for OAuth ATO finding on HuggingFace.
```

## Capability Map

### Tier 0 — Setup and Initialization
- Load target scope from bug bounty program rules
- Initialize SQLite findings DB
- Set up output directory structure: recon/$DOMAIN/{subs,live,urls,ports,nuclei,screenshots}
- Configure Playwright session capture

### Tier 1 — Passive Recon (zero footprint)
- Source map discovery and JS secret extraction
- Certificate transparency (crt.sh, Censys, Shodan)
- Subdomain takeover fingerprinting (16 cloud providers)
- Codename fuzzing (20 codenames × 15 path patterns = 300 URLs)
- Wayback Machine / GAU URL archaeology

### Tier 2 — Authentication Surface
- JWT algorithm confusion (HS256 with RSA pubkey)
- OAuth state parameter fixation
- OAuth client registration (unauthenticated endpoint discovery)
- ROPC + Device Code flow enumeration (Azure AD)
- WebSocket session hijack
- Session fixation and cookie analysis

### Tier 3 — API Enumeration
- GraphQL introspection and field suggestion
- REST API version enumeration (/v1, /v2, /v3, /api/v1, /api/internal)
- Swagger/OpenAPI discovery
- IDOR bypass techniques (array wrap, JSON wrap, double ID, wildcard, parameter pollution)
- HTTP method tampering
- 403 bypass techniques

### Tier 4 — AI-Platform Specific
- Prompt injection (10 systematic payloads)
- Vector DB poisoning (5 templates)
- Memory poisoning via API
- Memory API IDOR (two-account methodology)
- Vector Store IDOR
- Browsing-tool SSRF (7 crafted prompts)
- Shadow API discovery using codename list

### Tier 5 — Infrastructure
- S3 bucket enumeration (50+ patterns)
- Elasticsearch/Kibana probing (10 URLs, 6 credential pairs)
- Azure IMDS / GCP IMDS / AWS IMDS access
- Internal npm registry detection
- Azure AD tenant discovery and user enumeration
- Kubernetes API server exposure

### Tier 6 — Client-Side
- Prototype pollution (client + server)
- postMessage origin validation
- DOM clobbering
- CSS injection
- XSS pipeline: GAU → kxss → gf → dalfox

### Tier 7 — Server-Side
- SSRF (11 internal targets)
- DNS rebinding
- Browsing-tool SSRF via LLM
- Path traversal

### Tier 8 — Race Conditions and Supply Chain
- Race condition on billing/coupon endpoints (thread-barrier technique)
- Dependency confusion (PyPI + npm)

## Attack Ladder Concept

Real findings demonstrate that low-severity bugs chain to critical:

```
F-08 (P2): staging.openai.com Azure AD tenant leak
  → user enumeration of 9 employees
  → F-10 (P1): ROPC + Device Code enabled
  → password spray + phishing chain → account takeover

HF-01 (P1): /oauth/register unauthenticated
  → register evil.com OAuth client
  → generate authorization URL with evil.com redirect_uri
  → any user who clicks is redirected with code → ATO

CODEX-01/02/03/04 (P2 × 4): PowerShell AST blocks bypass classifier
  → systematic: begin{} → trap{} → clean{} → git config textconv
  → each is independent P2; together they demonstrate classifier blindspot
```

The operator always looks for P4 findings that are prerequisite for P1 chains.

## Relationship to Sub-Files

| File | Role |
|------|------|
| methodology.md | Ordered attack phases, attack ladder logic |
| operator-brain.md | Decision rules derived from real findings |
| knowledge-graph.md | Semantic map of all concepts and tools |
| ontology.md | Full taxonomy of domains, activities, assets, tools |
| workflows.md | Scored workflow procedures |
| decision-tree.md | What-do-I-have → what-do-I-test navigation |
| evidence-framework.md | Evidence collection and chain-of-custody |
| reporting-framework.md | Bugcrowd/HackerOne format and CVSS procedure |
| automation-framework.md | Script pipelines and MCP integration |
| tools-catalog.md | Every tool scored and categorized |
| conflicts.md | Skill conflicts resolved |
| migration-report.md | Source analysis and architecture rationale |
| checklists/01-06 | Per-phase ordered checklists |
| templates/\* | Ready-to-submit report templates |
| playbooks/pb-01–07 | Full step-by-step attack playbooks |

## The 40 Vectors

### Tier 1 Passive Recon
1. Source Map Leak — JS source maps expose minified code, internal paths, secrets
2. Subdomain Takeover — crt.sh + 16 cloud provider CNAME fingerprints
3. Codename Fuzzing — 20 codenames × 15 path/subdomain patterns

### Tier 2 Auth
4. JWT Algorithm Confusion — HS256 with RSA pubkey as HMAC secret
5. OAuth State Fixation — missing or reused state parameter
6. WebSocket Session Hijack — CSWSH via cross-site WebSocket
7. GraphQL Introspection — schema exposure enabling targeted attacks

### Tier 3 Client-Side
8. Prototype Pollution (client) — __proto__ via query parameter
9. Prototype Pollution (server) — JSON body merge
10. postMessage Validation — missing origin check
11. DOM Clobbering — form/anchor element name collisions
12. CSS Injection — style attribute or @import exfil

### Tier 4 Server-Side
13. DNS Rebinding — localhost bypass via TTL=0 record
14. SSRF — 11 internal targets including IMDS endpoints
15. Browsing-Tool SSRF — LLM-mediated SSRF via 7 prompts

### Tier 5 AI-Specific
16. Prompt Injection — 10 payloads targeting system prompt, tool calls, memory
17. Vector DB Poisoning — malicious embeddings in shared vector stores
18. Memory Poisoning — persistent context manipulation via API
19. Memory API IDOR — cross-account memory read/write
20. Vector Store IDOR — cross-account vector store access

### Tier 6 Infrastructure
21. S3 Bucket Scanner — 50+ naming patterns
22. Elasticsearch/Kibana — unauthenticated cluster access
23. Internal npm Registry — package shadowing

### Tier 7 Race Conditions + Supply Chain
24. Race Condition — billing/coupon parallelism
25. Dependency Confusion — PyPI + npm package squatting

### Tier 8 Shadow APIs
26. Admin API Discovery — /admin, /internal, /ops endpoints
27. Shadow GPT Catalog — unreleased model slugs (F-03 pattern)
28. Staging/Debug Endpoints — staging.*, dev.*, debug.* subdomains
29. Forgotten WebSocket — legacy WS endpoints without auth (F-07 pattern)

### Real Finding Classes (from SESSION-STATUS.md)
30. Device ID Header Bypass — OAI-Device-Id grants unauth backend access
31. Bootstrap Endpoint Info Leak — K8s infrastructure exposure
32. OAuth Provider Config Exposure — Sidetron OAuth providers list
33. Routing Cookie RFC1918 Leak — internal pod IP disclosure
34. Unauth Feature Flag Dump — account config and flag enumeration
35. Azure AD Tenant Leak — tenant ID + user enumeration from staging
36. ROPC + Device Code Enabled — password spray + phishing chain
37. PowerShell AST Block Bypass — begin{}/trap{}/clean{} classifier evasion
38. Git Config Driver RCE — textconv/external-diff under auto-approved commands
39. Unauthenticated OAuth Client Registration — ATO via redirect_uri manipulation
40. CORS Arbitrary Origin Reflection — credentials=include cross-origin read

## Scoring Formula

Composite Score = (Confidence × 2) + (Information Gain × 3) + (Automation Potential × 2) + (Reusability × 2) - Cost

All metrics 1–5 scale. Maximum score = 50. Minimum = 1.

| Score | Interpretation |
|-------|---------------|
| 40–50 | Run first, every engagement |
| 30–39 | High priority, run in first session |
| 20–29 | Run when relevant surface found |
| 10–19 | Situational, run when specific indicator present |
| 1–9   | Specialist, run only when explicitly targeting |
