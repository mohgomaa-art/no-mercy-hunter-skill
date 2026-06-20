# Checklist 03 — API Testing

Covers REST API, GraphQL, IDOR, and HTTP-level testing techniques.

## Pre-Flight

- [ ] Live hosts list available: live/hosts.txt
- [ ] Historical URLs available: urls/all.txt
- [ ] Authenticated session ready (at least one account)
- [ ] Second account available for IDOR testing (recommended)

## API Discovery

- [ ] Probe for OpenAPI/Swagger documentation:
  - [ ] /openapi.json
  - [ ] /swagger.json
  - [ ] /api-docs
  - [ ] /api-docs/v1
  - [ ] /api/v1/swagger.json
  - [ ] /v2/api-docs
  - [ ] /docs
- [ ] Import any discovered schema into Postman or Insomnia
- [ ] Run arjun on all discovered endpoints: arjun -u ENDPOINT
- [ ] Enumerate API versions: /v1, /v2, /v3, /api/v1, /api/v2, /api/v0, /api/beta, /api/internal
- [ ] Check for version-specific auth differences (old versions may have weaker auth)

## GraphQL Discovery and Testing

- [ ] Probe: /graphql, /api/graphql, /query, /gql, /graphiql, /playground
- [ ] If found: run WF-04 (GraphQL Full Enumeration) immediately
  - [ ] graphw00f fingerprint
  - [ ] Introspection query
  - [ ] If blocked: clairvoyance field suggestion
  - [ ] graphql-cop automated checks
  - [ ] Batching abuse test
  - [ ] Alias amplification test
  - [ ] IDOR via direct ID parameters
  - [ ] Nested query DoS test (confirm scope allows)

## REST API IDOR Testing (Two Accounts Required)

For every resource ID found in API responses, test the following from Account B:

- [ ] Direct access: GET /api/resource/ACCOUNT_A_RESOURCE_ID
- [ ] Array wrap: {"id": [ACCOUNT_A_ID]}
- [ ] JSON wrap: {"id": {"id": ACCOUNT_A_ID}}
- [ ] Double ID: /resource/ACCOUNT_A_ID?id=ACCOUNT_B_ID (test both orderings)
- [ ] Wildcard: {"id": "*"} or {"id": null}
- [ ] Parameter pollution: id=ACCOUNT_A_ID&id=ACCOUNT_B_ID
- [ ] HTTP method swap: GET works, but does PATCH/DELETE on Account A resource work from Account B?
- [ ] UUID prediction: if IDs are UUIDs, collect 10+ and check for pattern

## 403 Bypass Techniques

For every 403 response, try each of the following:

- [ ] /admin/.json
- [ ] /admin?
- [ ] /admin/
- [ ] /admin??
- [ ] /admin%20
- [ ] /admin%09
- [ ] /admin#
- [ ] /admin&details
- [ ] /..;/admin
- [ ] /./admin
- [ ] X-Original-URL: /admin header
- [ ] X-Rewrite-URL: /admin header
- [ ] X-Custom-IP-Authorization: 127.0.0.1 header
- [ ] X-Forwarded-For: 127.0.0.1 header
- [ ] Host: localhost header

## HTTP Method Tampering

For each discovered endpoint:

- [ ] Test all HTTP methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE
- [ ] POST-only endpoints: does GET expose data?
- [ ] GET-only endpoints: does POST create/modify?
- [ ] Check OPTIONS response for allowed methods
- [ ] TRACE method enabled? -> XST vulnerability

## API Version Enumeration

- [ ] Test /v0 (pre-release, may have fewer restrictions)
- [ ] Test /v1 through /v5
- [ ] Test /api/beta, /api/alpha, /api/internal, /api/dev
- [ ] Compare auth requirements between versions
- [ ] Compare data returned between versions
- [ ] Older version returning more data than current = information disclosure

## Parameter Discovery

- [ ] Run arjun on each interesting endpoint
- [ ] Check URL history for parameter names used historically
- [ ] Test debug parameters: debug=true, verbose=1, admin=true, internal=1
- [ ] Test format parameters: format=json, format=xml, callback=test (JSONP)
- [ ] Test pagination: page, limit, offset, cursor, per_page
- [ ] Test filter bypass: filter[user_id]=ACCOUNT_A_ID

## Content Type Testing

- [ ] JSON endpoint: try application/xml body
- [ ] JSON endpoint: try text/plain body
- [ ] JSON endpoint: try multipart/form-data
- [ ] JSON endpoint: try application/x-www-form-urlencoded
- [ ] Different content types may bypass validation or trigger different code paths

## Rate Limiting and Business Logic

- [ ] Test rate limiting on: login, signup, password reset, coupon redemption, API key generation
- [ ] Race condition candidates (run WF-10): coupon redeem, credit operations, plan upgrades
- [ ] Negative values: amount=-100, quantity=-1 (negative price/amount bypass)
- [ ] Extremely large values: amount=9999999999 (integer overflow)
- [ ] Currency/unit manipulation: price in cents vs dollars confusion

## Mass Assignment

- [ ] POST /api/users (registration): include extra fields (role, admin, isAdmin, plan, credits)
- [ ] PUT/PATCH /api/users/me: include fields that should be read-only (id, created_at, role)
- [ ] Any extra accepted field = mass assignment vulnerability

## Completion Gate

- [ ] All API endpoints documented with auth requirements
- [ ] GraphQL schema dumped (if GraphQL found)
- [ ] IDOR tested on all resource IDs with two accounts
- [ ] 403 bypasses attempted on all restricted endpoints
- [ ] Parameter discovery run on interesting endpoints
- [ ] All findings logged to SQLite
