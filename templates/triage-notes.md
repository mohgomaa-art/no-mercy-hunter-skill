# Triage Notes Template
# No Mercy Hunter v3.0

Usage: One file per active investigation. Keep open in a second tab while testing.
Naming: {TARGET}-{DATE}-triage.md  (e.g., openai-2026-06-21-triage.md)
Purpose: Capture raw observations, dead ends, and hypothesis chain in real time.
         NOT for final reports. This is your scratchpad.

---

# Triage: [TARGET] — [DATE]

**Session start:** [HH:MM]
**Session end:** [HH:MM]
**Phase:** [Passive Recon / Auth Surface / AI-Specific / Infrastructure / Race / Documentation]
**Operator state:** [PASSIVE_RECON / AUTH_SURFACE / AI_SPECIFIC / INFRA_SWEEP / RACE_TEST / DOCUMENTATION]

---

## Scope Reference

**Program:** [Bugcrowd / HackerOne / Direct]
**URL:** [Program URL]
**In-scope assets:**
- [asset 1]
- [asset 2]

**Out-of-scope (confirmed):**
- [asset 1]
- [asset 2]

**Special rules:**
- [e.g., "No automated scanning", "No account creation", "Report within 24h if P1"]

---

## Live Hypotheses

(Active attack hypotheses being tested right now. Check off when confirmed or eliminated.)

- [ ] [Hypothesis 1] — [basis for this hypothesis] — Status: TESTING
- [ ] [Hypothesis 2] — [basis for this hypothesis] — Status: QUEUED
- [ ] [Hypothesis 3] — [basis for this hypothesis] — Status: ELIMINATED (reason: ___)

---

## Passive Recon Notes

### Subdomains Found
```
[paste deduplicated subdomain list here]
```

Notable subdomains:
- staging.* → Rule 01: Azure AD check queued
- dev.* → Debug endpoints possible
- api.* → Primary API surface
- realtime.* → WebSocket surface (F-07 pattern)

### Codenames Found
(From source maps, JS bundles, API responses)
```
[list any internal codenames found]
```

### URLs from Wayback/GAU
Notable paths:
- [path] — reason it is interesting
- [path] — reason it is interesting

### Source Map Findings
- Source map URL: ___
- Internal paths found: ___
- Secrets found: ___
- API endpoints found: ___

---

## Auth Surface Notes

### OAuth Endpoints
```
GET /.well-known/openid-configuration → [status: 200/404/redirect]
GET /oauth/register → [status: ___]  ← CRITICAL if 200 without auth
GET /oauth/token → [status: ___]
GET /oauth/authorize → [status: ___]
```

### JWT Analysis
- Token location: [Authorization header / Cookie / Response body]
- Algorithm in header: [HS256 / RS256 / ES256 / none]
- JWKS URL: ___
- Kid value: ___
- Confusion test result: ___

### Azure AD (if applicable)
```
Tenant ID: ___
token_endpoint: ___
grant_types_supported: ___
ROPC enabled: YES / NO
Device code enabled: YES / NO
```

### WebSocket Endpoints
```
wss://[host]/[path] → Unauthenticated upgrade: YES / NO
```

### Cookies Observed
| Cookie Name | Value Pattern | Decoded | RFC1918? |
|-------------|--------------|---------|----------|
| [name] | [base64/JWT/opaque] | [decoded value or N/A] | YES/NO |

### Device Headers
| Header | Value | Bypass Result |
|--------|-------|--------------|
| OAI-Device-Id | [value] | [tested: YES/NO, result: ___] |

---

## Active Probing Notes

### Interesting Endpoints
| URL | Method | Status | Auth | Notes |
|-----|--------|--------|------|-------|
| [url] | GET | 200 | None | Unauthenticated — interesting |
| [url] | POST | 403 | Required | Bypass attempted: ___ |
| [url] | GET | 404 | — | Exists per Wayback, removed |

### Parameters Found (arjun)
```
Endpoint: [url]
Parameters: [list]
```

### GraphQL (if applicable)
```
Endpoint: /graphql
Introspection: ENABLED / DISABLED
Engine: [Apollo / Hasura / Strawberry / other]
Schema dump: [saved to graphql/schema.json: YES/NO]
Interesting types: ___
Interesting mutations: ___
```

---

## Findings Log (Raw)

(One entry per potential finding. Rate these after the session, not during.)

### Potential Finding 1
**Time:** [HH:MM]
**What I found:** [describe]
**URL/Endpoint:** ___
**Request:**
```
[paste request]
```
**Response:**
```
[paste relevant part of response]
```
**Severity estimate:** [P1/P2/P3/P4 / unknown]
**Next step:** [what needs to be confirmed or escalated]
**Status:** [UNCONFIRMED / CONFIRMED / DEAD END]

### Potential Finding 2
**Time:** [HH:MM]
**What I found:** ___
**URL/Endpoint:** ___
**Severity estimate:** ___
**Status:** ___

---

## Dead Ends

(Document these to avoid repeating them and to inform future sessions.)

| Vector | What Was Tried | Why It Failed | Time Spent |
|--------|---------------|--------------|-----------|
| [vector] | [what you tried] | [403 + WAF / rate limited / out of scope / not injectable] | [X min] |
| [vector] | [what you tried] | [reason] | [X min] |

---

## Chain Tracking

(Track potential finding chains as they emerge.)

```
[Finding A] (P[X]) → enables → [Finding B] (P[X]) → chains to → [Finding C] (P[X])

Current chain status:
  Finding A: CONFIRMED
  Finding B: TESTING
  Finding C: NOT STARTED
```

---

## Rate Limit / WAF Status

| Endpoint | Limit Hit | Action Taken |
|----------|-----------|-------------|
| [url] | 429 after [N] requests | Stopped. Logged. Moved on. |
| [url] | 403 with [WAF fingerprint] | Out of scope bypass. Skipped. |

---

## Tool Output References

| Tool | Output File | Status |
|------|------------|--------|
| subfinder | subs/subfinder.txt | DONE |
| amass | subs/amass.txt | RUNNING |
| httpx | live/hosts.txt | QUEUED |
| gau | urls/gau.txt | DONE |
| nuclei | nuclei/findings.txt | QUEUED |

---

## Session Handoff Notes

(Fill this out before ending the session so you can resume without losing context.)

**Last action taken:** ___
**Next action queued:** ___
**Unresolved hypotheses:**
- [hypothesis] — needs [specific test] to confirm or eliminate
- [hypothesis] — needs [specific test]

**Findings to log in DB:**
- [finding description] → [severity estimate]

**Findings to submit:**
- [finding ID] — ready / needs more evidence

**Do not forget:**
- [specific thing to check next session]
- [specific thing to check next session]

---

## Timestamps

| Event | Time |
|-------|------|
| Session start | |
| Phase 1 complete | |
| Phase 2 complete | |
| Phase 3 complete | |
| Phase 4 complete | |
| Phase 5 complete | |
| Documentation start | |
| First submission | |
| Session end | |
