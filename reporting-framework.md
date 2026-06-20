# Reporting Framework — No Mercy Hunter v3.0

Covers Bugcrowd format, HackerOne format, CVSS procedure, severity mapping, chain reporting,
and what makes reports get triaged vs. duplicated vs. accepted.

---

## Severity Mapping

### P1 — Critical (CVSS 9.0–10.0)
Characteristics:
- Unauthenticated remote code execution
- Full account takeover of any user without interaction
- Mass PII exfiltration
- Authentication bypass at scale
- Production credential leak with confirmed access

Real examples from session:
- F-10: ROPC + Device Code enabled -> password spray + phishing -> any employee ATO
- HF-01: Unauthenticated OAuth registration -> any user ATO via authorization code theft

Typical bounty: $3,000–$25,000+ depending on program

### P2 — High (CVSS 7.0–8.9)
Characteristics:
- Auth bypass for specific sensitive function
- SSRF to metadata service or internal network
- Stored XSS in admin panel
- Significant cross-account data exposure
- Sandbox escape in AI coding environment

Real examples:
- F-08: Azure AD tenant leak + employee user enumeration from staging subdomain
- CODEX-01/02/03: PowerShell classifier bypass enabling arbitrary command execution
- CODEX-04: Git config driver RCE under auto-approved operations

Typical bounty: $500–$5,000

### P3 — Medium (CVSS 4.0–6.9)
Characteristics:
- Info disclosure enabling further attacks
- CORS misconfiguration with credentials
- Limited auth bypass
- Reflected XSS requiring user interaction

Real examples:
- F-01: Device ID header bypasses auth to backend-api
- F-02: Bootstrap endpoint leaks K8s infrastructure data
- F-05: Routing cookie discloses RFC1918 pod IPs
- HF-02: CORS reflects arbitrary origins with ACAC=true
- MI-01: Ory Kratos full config and schema exposed

Typical bounty: $100–$1,000

### P4 — Low/Informational (CVSS 0.0–3.9)
Characteristics:
- Information disclosure without direct exploitability
- Unreleased feature/model exposure
- Unauthenticated access to non-sensitive config
- Missing security headers

Real examples:
- F-03: Unreleased model slugs gpt-5-* accessible
- F-04: Sidetron OAuth provider list exposed
- F-06: Unauth account config + 37 feature flags
- F-07: Realtime WS accepts unauthenticated upgrade
- F-09: Sentinel token issued without auth
- AN-01: api-staging.anthropic.com public + CORS ACAC=true

Typical bounty: $0–$500 or swag

---

## CVSS 3.1 Scoring Procedure

Vector format: AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_

### Step-by-step

1. Attack Vector (AV)
   N (Network) = exploitable remotely over internet — use for web vulnerabilities
   A (Adjacent) = requires network adjacency — rare for web bugs
   L (Local) = requires local access — for local privilege escalation
   P (Physical) = requires physical access — not applicable to web

2. Attack Complexity (AC)
   L (Low) = no special conditions required — most web bugs
   H (High) = requires specific configuration, race condition, or attacker-controlled conditions

3. Privileges Required (PR)
   N (None) = unauthenticated
   L (Low) = regular user account required
   H (High) = admin/privileged account required

4. User Interaction (UI)
   N (None) = no victim action required — SSRF, IDOR, RCE
   R (Required) = victim must click/visit — XSS, CSRF, phishing

5. Scope (S)
   U (Unchanged) = impact confined to vulnerable component
   C (Changed) = impact extends beyond vulnerable component (e.g., SSRF from web to metadata service)

6. Confidentiality (C), Integrity (I), Availability (A)
   H (High) = complete loss
   L (Low) = partial loss
   N (None) = no impact

### Common vectors for session findings

HF-01 (OAuth ATO):
  AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N = 8.1
  Note: UI:R because victim must click authorization link

F-10 (ROPC + Device Code):
  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
  Note: ROPC spray requires no victim interaction; PR:N because endpoint is public

F-08 (Azure AD tenant + user enum):
  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
  Note: Read-only information disclosure, no integrity impact

CODEX-01/02/03 (PowerShell classifier bypass):
  AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N = 9.0
  Note: S:C because sandbox escape affects host; PR:L because requires account

CODEX-04 (git textconv RCE):
  AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N = 8.2
  Note: AC:H because requires specific git operation to be auto-approved

HF-02 (CORS reflection):
  AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N = 6.5
  Note: UI:R because victim must visit attacker page

Calculator: https://www.first.org/cvss/calculator/3.1

---

## Bugcrowd Submission Format

Used for: OpenAI (Codex findings CODEX-01 through CODEX-04), Bugcrowd programs generally.

### Title format
[Component] Vulnerability Class — Brief Impact Description

Examples from session:
  [Codex] PowerShell begin{} block bypasses command safety classifier
  [Codex] git config textconv driver executes arbitrary commands under auto-approved git operations
  [API] Unauthenticated bootstrap endpoint leaks Kubernetes infrastructure data

### VRT (Vulnerability Rating Taxonomy) mapping

| Finding Type | Bugcrowd VRT |
|---|---|
| RCE / Sandbox Escape | Server-Side Injection > Remote Code Execution |
| Auth Bypass | Broken Authentication > Authentication Bypass |
| IDOR | Insecure Direct Object Reference (IDOR) |
| SSRF | Server-Side Request Forgery (SSRF) |
| Info Disclosure (sensitive) | Sensitive Data Exposure |
| OAuth misconfiguration | Broken Authentication > OAuth |
| XSS Stored | Cross-Site Scripting (XSS) > Stored |
| CORS | Cross-Origin Resource Sharing (CORS) |

### Body structure

Summary
Provide a clear, one-paragraph description of the vulnerability, what can be done with it,
and why it is a security issue. Write for a technical triage team who needs to understand
in 30 seconds whether this is real and worth escalating.

Reproduction Steps
Number each step. Be explicit — include exact URLs, exact payloads, exact headers.
Never say "navigate to the vulnerable endpoint" — say "GET https://target.com/exact/path".
Include copy-paste ready curl commands where possible.

Impact
Describe what an attacker can do. Be specific about:
- What data is accessed/modified
- Which users are affected (just the attacker, any user, all users)
- Whether authentication is required

Supporting Material
Attach: screenshots, HTTP captures, PoC scripts

### Bugcrowd-specific rules
- Do not exaggerate severity — Bugcrowd will downgrade overstated reports
- Use their CVSS calculator, not your own
- One vulnerability per report (exception: tightly coupled chain)
- Include remediation guidance — triagers appreciate it
- Avoid vague impact statements like "could lead to data breach"

---

## HackerOne Submission Format

Used for: HuggingFace (HF-01, HF-02), programs on HackerOne generally.

### Title format
Same as Bugcrowd: [Component] Class — Impact

### Weakness (CWE) mapping

| Finding | CWE |
|---|---|
| HF-01 OAuth ATO | CWE-306: Missing Authentication for Critical Function |
| IDOR | CWE-639: Authorization Bypass Through User-Controlled Key |
| SSRF | CWE-918: Server-Side Request Forgery |
| XSS | CWE-79: Cross-site Scripting |
| CORS | CWE-942: Permissive Cross-domain Policy |
| JWT confusion | CWE-327: Use of Broken or Risky Cryptographic Algorithm |
| Open redirect | CWE-601: URL Redirection to Untrusted Site |
| Race condition | CWE-362: Concurrent Execution Using Shared Resource |
| Dependency confusion | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |

### Body structure (HackerOne markdown)

## Summary
[One paragraph technical summary]

## Severity
CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
Severity: Critical / High / Medium / Low

## Steps To Reproduce

1. [Step 1 — exact action with exact URL]
2. [Step 2]
3. [Step N — confirm impact]

## Proof of Concept

[Include curl commands, Python script, or screenshots]

## Impact

[Specific impact: what can attacker do, who is affected, how many users]

## Suggested Remediation

[Specific fix recommendation — not generic]

### HackerOne-specific rules
- Disclose only via H1 — no public disclosure without permission
- Use /dev/null for test data — never use real user data in PoC
- Signal/noise ratio matters — false positives are penalized on reputation
- First blood matters — search for existing reports before submitting
- Use the "Does not qualify" self-check before submitting

---

## Chain Reporting

When multiple findings combine to form a higher-severity chain, submit as ONE report.

### When to chain vs. submit separately

Chain together when:
- Finding B is only exploitable because of Finding A
- The chain demonstrates a qualitatively different impact than either finding alone
- Example: F-08 (Azure AD info) + F-10 (ROPC enabled) = account takeover chain

Submit separately when:
- Findings are independent vulnerabilities in different components
- Each finding has standalone impact
- Example: CODEX-01/02/03/04 — each is an independent classifier bypass, same class
  but each requires different PowerShell construct. Submit each separately for clarity
  (and separate bounties).

### Chain report structure

Title: [Component] Multi-step Account Takeover via Azure AD Tenant Leak and ROPC Authentication

Summary:
"We identified a two-stage attack chain that enables full account takeover of any
organization employee. First, [F-08: staging subdomain exposes Azure AD tenant ID and
enables user enumeration]. Second, [F-10: the tenant has ROPC and device code grant types
enabled, allowing password spray and phishing attacks against enumerated accounts].
The combination allows an unauthenticated attacker to obtain valid credentials for any
enumerated employee."

Steps to Reproduce:
Stage 1: Azure AD Tenant Leak (F-08)
  [steps for F-08]

Stage 2: ROPC Password Spray (F-10)
  [steps for F-10]

Stage 3: Full Chain — Account Takeover
  [combined steps]

Impact:
[Describe combined impact, which is higher than either alone]

---

## What Makes Reports Get Triaged vs. Duplicated vs. Accepted

### Gets ACCEPTED
- Specific: exact URL, exact payload, exact response
- Reproducible: step-by-step that any analyst can follow
- Impactful: clear statement of what attacker gains
- Novel: not a known/patched issue
- In scope: on listed assets
- Quality PoC: working code, not just description
- Correct severity: not inflated, accurate CVSS

### Gets TRIAGED (but may be downgraded)
- Real vulnerability but overstated severity
- Valid but known to be low priority by program
- Real but requires additional preconditions
- Valid chain but one link is already known

### Gets MARKED DUPLICATE
- Same vulnerability class on same endpoint as existing open report
- Prevention: search platform for "endpoint /oauth/register" before submitting
- Search for: vulnerability type + endpoint path + target domain

### Gets MARKED N/A (invalid)
- Self-XSS (only affects attacker's own account)
- Missing headers alone (Content-Security-Policy, HSTS without exploitation)
- Rate limiting on non-sensitive endpoints
- Out of scope assets
- Theoretical vulnerabilities without PoC
- Known accepted risk (program has acknowledged and accepted)
- Works only in old/unsupported browser

### Gets MARKED INFORMATIONAL
- Real finding but program considers it acceptable risk
- Info disclosure of non-sensitive data
- Best practice deviation without direct security impact

---

## Pre-Submission Checklist

From disclosure-policy.md + real submission experience:

- [ ] Target is in scope per program's official scope page
- [ ] Testing performed within program rate limits (no DoS, no mass enumeration)
- [ ] No data exfiltrated beyond what is needed to demonstrate impact
- [ ] No service degradation occurred during testing
- [ ] PoC payload is non-destructive (no DROP TABLE, no rm -rf, no SSRF to write-side APIs)
- [ ] Multi-tenancy bugs tested only against your own test accounts
- [ ] Screenshots and HARs redact other users PII
- [ ] CVSS string calculated and included
- [ ] Remediation guidance is specific
- [ ] Searched platform for existing reports on same endpoint/vulnerability class
- [ ] Report follows platform preferred format
- [ ] Impact statement is concrete (not "could allow an attacker to...")
- [ ] PoC is self-contained and runnable
- [ ] Finding logged in SQLite DB before submission
