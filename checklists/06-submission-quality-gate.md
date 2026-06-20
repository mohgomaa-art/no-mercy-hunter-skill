# Checklist 06 — Submission Quality Gate
# No Mercy Hunter v3.0

Purpose: Every finding must pass this gate before submission. No exceptions.
Grounded in: Real submission outcomes from Bugcrowd (CODEX-01 through CODEX-04),
  HackerOne (HF-01, HF-02), and direct programs (F-01 through F-10, AN-01, MI-01).

---

## Gate 1 — Scope Verification (Hard Stop)

Fail any of these = DO NOT SUBMIT.

- [ ] Confirmed the endpoint/domain is listed in the program's in-scope assets
- [ ] Confirmed the finding type is in scope (some programs exclude DoS, rate limiting, etc.)
- [ ] Confirmed this is not on the out-of-scope list (e.g., *.third-party.com, self-XSS)
- [ ] Confirmed the program is currently accepting submissions (not paused)
- [ ] If found on a subdomain: verified subdomain ownership by target

**Scope source:** [Bugcrowd / HackerOne / direct program URL: ___]

---

## Gate 2 — Duplicate Check (Hard Stop)

Fail = submit only if you have significant new impact angle.

- [ ] Searched platform for same CWE class + same endpoint
- [ ] Searched platform for same vulnerability title keywords
- [ ] Searched platform for recent reports on this specific feature
- [ ] Checked program's disclosed reports for same class

**Platform search query used:** ___
**Similar reports found:** ___
**Decision:** UNIQUE / POTENTIAL DUPLICATE (reason: ___)

---

## Gate 3 — Reproduction Verified (Hard Stop)

Fail = do not submit until verified.

- [ ] Reproduced the vulnerability from scratch (not just documented the first attempt)
- [ ] Reproduced on a fresh browser session / new Playwright session
- [ ] If IDOR: reproduced with two clean test accounts (no shared session cookies)
- [ ] If race condition: race triggered at least 3 times consistently
- [ ] If injection: payload works in current production environment (not just staging)
- [ ] Reproduction steps can be followed by someone with no context

---

## Gate 4 — Evidence Package Complete

### Minimum for P4/P3
- [ ] At least 1 screenshot showing the vulnerability
- [ ] At least 1 HTTP request/response log (curl -v output or HAR)
- [ ] Written reproduction steps (numbered, complete)

### Required for P2
- [ ] 2+ screenshots (showing setup and impact)
- [ ] Full HTTP log with all relevant requests
- [ ] PoC code or curl command that reproduces in one step
- [ ] CVSS score calculated with vector string
- [ ] Impact statement written

### Required for P1
- [ ] Video walkthrough (screen recording MP4)
- [ ] Full attack chain documented
- [ ] Multiple victim accounts tested (to confirm generalizability)
- [ ] Business impact quantified (how many users affected, what data accessible)
- [ ] PoC code is clean, commented, and runs without modification
- [ ] CVSS score calculated
- [ ] Remediation suggestion included

---

## Gate 5 — Severity Calibration

Use this to avoid over-claiming or under-claiming severity.

### Check: Is this actually exploitable by a realistic attacker?
- [ ] Attack requires no special prerequisites → severity stays
- [ ] Attack requires authenticated session → reduce by 1 level if auth is hard to get
- [ ] Attack requires victim interaction → reduce by 1 level (user must click something)
- [ ] Attack requires local network access → reduce by 1 level
- [ ] Attack requires MFA bypass not in scope → note limitation

### Check: Is the impact correctly scoped?
- [ ] Does the finding affect only your own account? → Self-XSS = not reportable
- [ ] Does the finding affect only data you own? → IDOR only worth reporting if cross-account
- [ ] Can any unauthenticated user trigger this? → escalate severity
- [ ] Does the finding expose production customer data? → escalate severity

### Final Severity Assignment
- [ ] P1 (Critical) CVSS 9.0+: Full account takeover, RCE, unauthenticated mass data exposure
- [ ] P2 (High) CVSS 7.0-8.9: Auth bypass, significant data exposure, sandbox escape
- [ ] P3 (Medium) CVSS 4.0-6.9: Limited auth bypass, info disclosure enabling further attack
- [ ] P4 (Low/Info) CVSS 0-3.9: Configuration exposure, no direct exploitability

**Assigned severity:** ___
**CVSS vector string:** ___
**Score:** ___

---

## Gate 6 — Report Quality

### Title
- [ ] Specific (includes affected endpoint or component)
- [ ] Under 100 characters
- [ ] Describes the vulnerability class, not just the symptom
- [ ] Example good: "Unauthenticated OAuth client registration at /oauth/register enables ATO"
- [ ] Example bad: "Security issue in OAuth"

### Summary Section
- [ ] One paragraph: what, where, impact
- [ ] No jargon without explanation
- [ ] States severity with justification

### Steps to Reproduce
- [ ] Numbered list
- [ ] Each step is a single action
- [ ] Starts from "no account" or "free account" — no assumed access
- [ ] Includes exact URLs, exact payloads, exact parameter names
- [ ] Includes expected vs actual result
- [ ] A second person can follow without asking any questions

### Impact Section
- [ ] States the worst-case impact
- [ ] Names the data or capability exposed
- [ ] Mentions affected user population if relevant
- [ ] Does NOT overstate (no "this could lead to death" hyperbole)

### Supporting Material
- [ ] Screenshots are labeled and legible
- [ ] HTTP logs are trimmed to relevant sections (no 2000-line dumps)
- [ ] PoC code is tested and commented
- [ ] Video (if included) is under 5 minutes and narrated

---

## Gate 7 — Chain Analysis

Before submitting individual findings, check:

- [ ] Does this P4 finding enable a P2/P1 finding? → Hold and chain first
- [ ] Does this P3 finding combine with another P3 to create P2? → Combine and submit as chain
- [ ] Is this finding a prerequisite for something I haven't tested yet? → Test prerequisite first
- [ ] Can this finding be combined with an existing open report for higher impact? → Note for escalation

**Chain potential:** YES / NO
**Chain direction:** ___

---

## Gate 8 — Legal and Ethics Check

- [ ] I have authorization to test this target
- [ ] I have not accessed, downloaded, or exfiltrated real user data
- [ ] I have not caused service disruption (rate limit test was bounded)
- [ ] I have not accessed admin functionality beyond confirming existence
- [ ] My PoC uses test accounts only, no real user accounts
- [ ] I have not retained credentials or tokens discovered during testing
- [ ] Disclosure timeline will be: immediate report → wait 90 days before public disclosure

---

## Gate 9 — Platform-Specific Rules

### For Bugcrowd
- [ ] VRT category selected correctly (use VRT taxonomy, not OWASP)
- [ ] Vulnerability Type field matches finding exactly
- [ ] CVSS not required but recommended for P1/P2
- [ ] Attachments: max 50MB per file, .png .jpg .mp4 .txt .py .sh allowed
- [ ] Do not use markdown headers in the report body (plain text preferred)
- [ ] Check program's custom rules tab for exclusions

### For HackerOne
- [ ] CWE field filled in
- [ ] CVSSv3 vector string included for P1/P2
- [ ] Markdown formatting used (HackerOne renders markdown)
- [ ] Asset field filled in (exact domain/wildcard from scope)
- [ ] Weakness field matches CWE

### For Direct Programs
- [ ] Used program's disclosure email or PGP key
- [ ] Subject line matches their preferred format
- [ ] Response deadline requested (usually 7 days to acknowledge, 90 days to fix)

---

## Final Submission Decision

Run through final checklist:

```
SCOPE:        IN SCOPE    / OUT OF SCOPE (stop)
DUPLICATE:    UNIQUE       / DUPLICATE (stop or reconsider)
REPRODUCED:   YES          / NO (stop)
EVIDENCE:     COMPLETE     / INCOMPLETE (stop)
SEVERITY:     P___ CVSS ___
CHAIN:        STANDALONE   / CHAINED WITH ___
LEGAL:        CLEARED      / CONCERN (stop)
PLATFORM:     BUGCROWD / HACKERONE / DIRECT
```

All gates passed: [ ] YES → SUBMIT
Any gate failed: [ ] STOP — resolve before submitting

---

## Post-Submission Actions

- [ ] Log submission in SQLite DB: `INSERT INTO findings (target_id, title, severity, status, platform_report_id) VALUES (...)`
- [ ] Set 7-day follow-up reminder
- [ ] If no response in 14 days: send polite follow-up message
- [ ] If no response in 30 days: escalate to program manager
- [ ] If resolved: update findings DB with resolution + bounty
- [ ] If duplicate: note the original report ID for learning

---

## Common Rejection Reasons (Avoid These)

| Rejection | Root Cause | Prevention |
|-----------|-----------|------------|
| Out of scope | Didn't check scope before testing | Always verify scope first |
| Duplicate | Didn't search platform | Always search before submitting |
| Informational | Overstated impact | Be precise about exploitability |
| Not reproducible | Incomplete steps | Reproduce from scratch before submitting |
| Self-XSS | Payload only works in own session | Confirm victim impact |
| Missing evidence | No screenshots or logs | Evidence package required |
| NA: by design | Feature works as intended | Check docs before claiming vulnerability |
| Needs more info | Vague description | Follow report quality standards above |
