# Decision Tree — No Mercy Hunter v3.0

Meta-framework for navigating from "what do I have" to "what do I test".

---

## Level 0 — What Do I Have?

Start here every session. Identify your access level and attack surface type.

### Branch A: No Authentication (Unauthenticated)
    |
    +-- Web application visible?
    |     YES -> Go to Branch A1 (Passive Recon)
    |     NO  -> Go to Branch A2 (API only)
    |
    +-- A1: Web Application
    |     |
    |     +-- Run WF-12 (Source Map + JS Recon) FIRST
    |     |     Found secrets?     -> Log, test API endpoints with found keys
    |     |     Found internal paths? -> Add to probe list
    |     |
    |     +-- Run WF-01 (Full Passive Recon)
    |     |     Staging subdomain found?  -> Rule 01 -> Azure AD recon
    |     |     *.internal found?         -> Infra sweep
    |     |     Source maps found?        -> Extract all secrets and paths
    |     |
    |     +-- OAuth endpoint found?
    |     |     YES -> WF-05 (OAuth Client Registration Test) IMMEDIATELY
    |     |     /oauth/register returns 200 no auth? -> P1 candidate (HF-01 pattern)
    |     |
    |     +-- GraphQL found?
    |           YES -> WF-04 (GraphQL Full Enumeration) IMMEDIATELY
    |
    +-- A2: API Only
          |
          +-- API docs available? (swagger, openapi, postman collection)
          |     YES -> Import all endpoints, test each for auth bypass
          |
          +-- Test common unauthenticated endpoints:
                /health /status /version /metrics /config /bootstrap
                /api/v1/users /api/v1/config /api/v1/features
                Any 200? -> Log content, check for sensitive data

### Branch B: Session Cookie (Authenticated Web User)
    |
    +-- Capture session in Playwright
    |
    +-- Analyze cookie values
    |     Encoded IP in cookie? -> Rule 07 (RFC1918 disclosure) -> P3
    |     JWT in cookie?        -> WF-03 (JWT Algorithm Confusion)
    |     Device ID header?     -> Rule 05 (Device ID bypass test)
    |
    +-- Enumerate authenticated endpoints via katana crawl
    |
    +-- Test IDOR on all resource IDs found:
    |     User IDs, document IDs, file IDs, memory IDs, store IDs
    |     Two accounts? -> WF-09 (Memory IDOR) + cross-account tests
    |
    +-- Check for feature flags endpoint:
    |     /api/config /account/features /experiments
    |     37+ flags returned? -> P4 (F-06 pattern)
    |
    +-- WebSocket endpoint in JS?
          YES -> Test unauthenticated upgrade (F-07 pattern)
          wscat -c wss://TARGET/ws (no cookies)
          Connected? -> P4-P2 depending on data/commands available

### Branch C: API Key / Bearer Token
    |
    +-- Decode the token
    |     JWT? -> WF-03 (JWT Algorithm Confusion)
    |     Opaque? -> Test scope escalation: add admin=true, role=admin params
    |
    +-- Enumerate API versions:
    |     /v1 /v2 /v3 /api/v1 /api/v2
    |     Older version with fewer restrictions? -> Auth bypass candidate
    |
    +-- Test all HTTP methods on each endpoint:
    |     GET (read), POST (create), PUT (replace), PATCH (update), DELETE
    |     TRACE, OPTIONS, HEAD
    |     Unexpected 200? -> Document, escalate
    |
    +-- GraphQL endpoint?
          YES -> WF-04 immediately
          Check: does API key grant schema access?

### Branch D: Two Accounts (Account A + Account B)
    |
    +-- IDOR testing is now possible
    |     WF-09: Memory IDOR
    |     Create resource as A, access as B
    |     Test: read, write, delete across accounts
    |
    +-- Cross-account data isolation:
    |     Files, documents, conversations, projects
    |     Can B access A's private resources?
    |
    +-- GraphQL IDOR:
          WF-04 step 7: query user(id: A_USER_ID) from B's token

---

## Level 1 — What Attack Surface?

### Surface: Web Application
    |
    +-- Technology stack (from httpx tech-detect)?
    |     React/Next.js  -> Check for client-side routing leaks, API endpoints in bundle
    |     Angular        -> Check for environment.ts in source maps
    |     Vue            -> Check for .env variables in bundle
    |
    +-- Authentication mechanism?
    |     JWT         -> WF-03
    |     OAuth       -> WF-05
    |     Session     -> CSRF test, session fixation
    |     API Key     -> Scope enumeration
    |
    +-- Input fields present?
          File upload  -> SSRF via file content, path traversal, polyglot
          Search       -> SQLi, XSS, SSRF via URL parameter
          URL field    -> SSRF directly
          Markdown/HTML -> XSS, CSS injection

### Surface: API (REST)
    |
    +-- Parameter discovery: arjun on each endpoint
    |
    +-- 403 bypass techniques (try each):
    |     /admin/.json
    |     /admin?
    |     /admin/
    |     /admin??
    |     /admin%20
    |     /admin%09
    |     /admin#
    |     /admin&details
    |     /..;/admin
    |     X-Original-URL: /admin
    |     X-Rewrite-URL: /admin
    |
    +-- IDOR bypass techniques (try each on all IDs):
    |     Original: {"id": 1234}
    |     Array wrap: {"id": [1234]}
    |     JSON wrap: {"id": {"id": 1234}}
    |     Double ID: /resource/1234?id=5678
    |     Wildcard: {"id": "*"}
    |     Param pollution: id=1234&id=5678
    |
    +-- HTTP method tampering:
    |     POST endpoint -> try PUT, PATCH, DELETE
    |     GET endpoint  -> try POST with body
    |
    +-- Version enumeration:
          /api/v1 working? -> try /api/v2, /api/v3, /api/v0, /api/beta

### Surface: WebSocket
    |
    +-- Test unauthenticated upgrade first (F-07 pattern)
    |
    +-- If authenticated: capture handshake headers
    |
    +-- Message injection:
    |     Modify message fields: change user_id, conversation_id
    |     Inject XSS in message content
    |     Test SSRF via URL parameters in messages
    |
    +-- Race condition on WS:
          Send same message simultaneously from two connections

### Surface: AI Tools (LLM platform)
    |
    +-- Run WF-04-AI (Prompt Injection) systematically with all 10 payloads
    |
    +-- Browsing tool present?
    |     YES -> 7-prompt SSRF test (WF-03-AI)
    |
    +-- Memory API present?
    |     YES -> WF-09 (Memory IDOR)
    |
    +-- Vector store API present?
    |     YES -> Cross-account vector store access test
    |
    +-- Model name parameter?
          YES -> Enumerate unreleased slugs (WF-02 step 5)

### Surface: OAuth / Identity
    |
    +-- Registration endpoint?  -> WF-05 (unauth registration test)
    |
    +-- Azure AD / Microsoft?   -> WF-06 (tenant recon)
    |
    +-- JWT issued?             -> WF-03 (algorithm confusion)
    |
    +-- Device code mentioned?  -> Generate phishing URL
    |
    +-- Multiple grant types?
          password + device_code both enabled? -> P1 chain (F-10 pattern)

### Surface: Git Operations (auto-approved)
    |
    +-- Which commands are auto-approved?
    |     git diff, git log, git show -> WF-08 (textconv driver)
    |     git checkout -> filter driver
    |     git merge   -> merge driver
    |
    +-- PowerShell involved?
          YES -> WF-07 (AST block enumeration)

---

## Level 2 — What Information Is Missing?

### Missing: Full API Schema
    Action: GET /openapi.json, /swagger.json, /api-docs, /api/v1/swagger.json
    Action: GraphQL introspection (WF-04 step 2)
    Action: Run arjun on all discovered endpoints

### Missing: Internal Hostnames
    Action: WF-12 step 7 (extract from source maps)
    Action: Decode cookie values (Rule 07)
    Action: Check bootstrap endpoint (Rule 06)
    Action: Nuclei misconfigs scan

### Missing: Authentication Mechanism Details
    Action: GET /.well-known/openid-configuration
    Action: GET /oauth/token endpoint options (check WWW-Authenticate header on 401)
    Action: Decode any JWT in traffic

### Missing: Azure AD Tenant
    Action: Probe https://login.microsoftonline.com/TARGET_DOMAIN/v2.0/.well-known/openid-configuration

### Missing: Subdomain Coverage
    Action: Run full WF-01 if not done
    Action: Check crt.sh for recent certificates

### Missing: JS Source
    Action: WF-12 (source map analysis)
    Action: Check gau history for .map files

---

## Level 3 — Severity Routing

### Finding is unauthenticated data exposure
    Sensitive PII / credentials?   -> P2 minimum
    Infrastructure data (IPs, K8s)?-> P3
    Feature flags / config?        -> P4
    Chainable to higher severity?  -> Re-route to chain path

### Finding is authentication bypass
    Bypasses all auth?             -> P1
    Bypasses for specific function?-> P2
    Partial bypass with conditions?-> P2-P3

### Finding is IDOR
    Cross-account read of sensitive data?  -> P2
    Cross-account write/delete?            -> P1-P2
    Own account, limited impact?           -> P3

### Finding is injection
    RCE (command/code execution)?  -> P1
    SSRF to metadata/internal?     -> P2
    XSS stored in admin view?      -> P2
    XSS reflected, user interaction?-> P3
    Self-XSS only?                 -> Not reportable

### Finding is info disclosure
    Credentials/tokens?            -> P1-P2 depending on what they access
    Internal infra (IPs, K8s)?     -> P3
    Username enumeration?          -> P3-P4 (higher if combined with ROPC)
    Unreleased feature names?      -> P4

---

## Level 4 — Chain Detection

When you have 2+ findings, check for chain potential:

### Chain Template 1: Staging -> ATO
    P4: staging subdomain exists
    P3: staging has debug/verbose errors
    P2: Azure AD tenant and users enumerable
    P1: ROPC or device code enabled -> password spray or phishing
    -> Submit as single P1 report with full chain demonstrated

### Chain Template 2: Unauthenticated Endpoint -> ATO
    P4: /oauth/register returns 200
    P3: redirect_uri validation missing
    P1: any user can be ATO'd via authorization code theft
    -> Submit as single P1 report (HF-01 pattern)

### Chain Template 3: Classifier Bypass -> Sandbox Escape
    P2: One AST block bypasses classifier
    P2: Additional AST blocks bypass classifier
    P2: Git config drivers execute under auto-approved commands
    -> Submit each as individual P2, note pattern in each report
    -> Optional: submit meta-report on classifier architecture flaw

### Chain Template 4: Info Disclosure -> SSRF
    P3: RFC1918 IP found in routing cookie (F-05)
    P3: Bootstrap endpoint reveals K8s service names (F-02)
    P2: SSRF using discovered internal hostnames
    -> Combine P3 findings into SSRF report

---

## Quick Routing Table

| Condition | Immediate Action | Expected Severity |
|-----------|-----------------|-------------------|
| /oauth/register returns 200 | WF-05 step 2 immediately | P1 |
| staging.* subdomain | Azure AD openid-config | P1 via chain |
| JWT with RS256 | WF-03 immediately | P2 |
| GraphQL /graphql 200 | WF-04 immediately | P2-P4 |
| PowerShell accepted | WF-07 all 10 blocks | P2 |
| git diff auto-approved | WF-08 textconv | P2 |
| Cookie has encoded IPs | Decode, document | P3 |
| /bootstrap returns 200 | Check for K8s data | P3 |
| Memory API found | WF-09 two-account test | P2 |
| CORS ACAC=true | Find sensitive endpoint | P2-P3 |
| Unreleased model returns 200 | Document slug | P4 |
| Feature flags unauthenticated | Document all flags | P4 |
