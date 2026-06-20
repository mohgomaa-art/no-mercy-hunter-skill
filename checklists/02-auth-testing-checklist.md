# Checklist 02 — Auth Testing

Run after passive recon. Requires at least one authenticated session.

## Pre-Flight

- [ ] Passive recon complete (checklist 01 done)
- [ ] At least one test account available
- [ ] Playwright session captured: sessions/TARGET-auth.json
- [ ] HTTP intercepting proxy active (Burp Suite or mitmproxy)

## OAuth Endpoint Discovery

- [ ] GET /.well-known/openid-configuration — capture full response
- [ ] GET /.well-known/oauth-authorization-server
- [ ] Record all fields: issuer, token_endpoint, authorization_endpoint, jwks_uri, registration_endpoint, grant_types_supported, response_types_supported
- [ ] Check grant_types_supported for: password, device_code, implicit
- [ ] Check registration_endpoint field — if present, run WF-05 immediately
- [ ] Probe manually: /oauth/register, /oauth/clients, /oauth/applications, /connect/register, /api/oauth/register

## Unauthenticated OAuth Registration (WF-05 — highest priority)

- [ ] POST /oauth/register with no Authorization header
- [ ] Body: {"client_name":"test","redirect_uris":["https://evil.example.com/cb"],"grant_types":["authorization_code"]}
- [ ] HTTP 201 without auth = P1 candidate (HF-01 pattern) — log immediately
- [ ] If 201: confirm evil.com redirect_uri is accepted in authorization URL
- [ ] If 201: test device_code grant with registered client
- [ ] If 201: test password grant (ROPC) with registered client

## Azure AD Detection and Tenant Recon

- [ ] Check if target uses Microsoft login (login.microsoftonline.com redirect)
- [ ] Check DNS: does TARGET have MX or SPF pointing to Microsoft?
- [ ] Probe: https://login.microsoftonline.com/TARGET_DOMAIN/v2.0/.well-known/openid-configuration
- [ ] Extract tenant_id from issuer field
- [ ] Check grant_types_supported for "password" -> ROPC enabled = P1 chain potential
- [ ] Check grant_types_supported for device_code -> phishing chain potential
- [ ] If ROPC: test user enumeration via AADSTS error codes (AADSTS50034 vs AADSTS50126)
- [ ] If device_code: generate device code URL as PoC
- [ ] See playbooks/pb-06-azure-ad-recon.md for full procedure

## JWT Analysis

- [ ] Capture JWT from authenticated session (Authorization header or cookie)
- [ ] Decode header: check alg field (RS256, ES256, HS256, none)
- [ ] Decode payload: note all claims (sub, iss, aud, exp, iat, role, scope)
- [ ] Fetch JWKS endpoint (from openid-configuration jwks_uri)
- [ ] If RS256 or ES256: run WF-03 (JWT algorithm confusion)
- [ ] Test alg: none (remove signature, add trailing dot)
- [ ] Test HS256 with public key as secret (WF-03)
- [ ] Test expired token: does server reject properly?
- [ ] Test token from different audience: does server validate aud?
- [ ] Test token with modified claims: role, admin, scope fields

## WebSocket Endpoint Testing

- [ ] Search JS bundles for: wss://, new WebSocket, socket.io connect
- [ ] List all WS endpoints found
- [ ] For each WS endpoint: attempt unauthenticated upgrade (no cookies)
  - [ ] wscat -c wss://TARGET/ws (no cookies) — does connection succeed?
  - [ ] If connected: does server send data before any message? (F-07 pattern)
  - [ ] If connected: attempt commands that should require auth
- [ ] Check WS upgrade request for: Origin header validation, CSRF token requirement
- [ ] Test cross-site WebSocket hijack: does server validate Origin?

## Session Cookie Analysis

- [ ] Inspect all cookies: name, value, domain, path, HttpOnly, Secure, SameSite
- [ ] Base64 decode cookie values — look for structured data
- [ ] JSON parse decoded values — look for: user_id, role, IP addresses, hostnames
- [ ] RFC1918 IP in cookie value? -> P3 (F-05 pattern) — log immediately
- [ ] JWT in cookie? -> Run JWT analysis section above
- [ ] Check SameSite=None without Secure flag -> CSRF candidate
- [ ] Check missing HttpOnly on session cookies -> XSS impact amplified

## Special Header Testing (Device ID Bypass — F-01 pattern)

- [ ] Capture authenticated request with all headers
- [ ] Identify any device/session/client headers: OAI-Device-Id, X-Device-Id, CF-Device-Id, X-Client-Id
- [ ] Strip Authorization header, keep device header, resend to authenticated endpoint
- [ ] HTTP 200 without auth = P3 minimum (F-01 pattern) — log immediately
- [ ] Test device header on different account endpoints
- [ ] Test: does same device header work for different users?

## ROPC and Password Grant Testing

- [ ] Is ROPC (password grant) enabled? Check grant_types_supported
- [ ] If enabled: POST /oauth/token grant_type=password with test credentials
- [ ] Test user enumeration via error message differentiation
- [ ] Note: Do NOT run full password spray — demonstrate with single credential pair only
- [ ] Document: ROPC enabled = P1 candidate when combined with user enumeration

## Device Code Flow Testing

- [ ] Is device_code grant enabled? Check grant_types_supported
- [ ] POST /oauth/device_authorization client_id=CLIENT_ID scope=openid+profile
- [ ] Receive: device_code, user_code, verification_uri, expires_in
- [ ] Generate phishing URL: verification_uri + user_code
- [ ] Document: victim visits URL and authenticates -> attacker polls for tokens
- [ ] This is a P1 phishing chain even without ROPC

## MFA Bypass Vectors

- [ ] Test: does ROPC flow bypass MFA requirement?
- [ ] Test: does device code flow bypass MFA?
- [ ] Test: are there any legacy auth endpoints that predate MFA?
- [ ] Test: /api/v1/auth/legacy, /api/v0/login, /oauth/v1/token

## Session Fixation

- [ ] GET login page, note session cookie value
- [ ] Complete authentication
- [ ] Check: did session cookie value change after authentication?
- [ ] Same value pre/post auth = session fixation vulnerability

## Completion Gate

- [ ] All auth endpoints mapped and documented in auth-surface.md
- [ ] JWT algorithm confirmed and confusion test run if RS256/ES256
- [ ] OAuth registration endpoint tested (WF-05)
- [ ] Azure AD probed if Microsoft indicators found
- [ ] WS endpoints tested for unauthenticated upgrade
- [ ] All session cookies decoded and analyzed
- [ ] All findings logged to SQLite findings table
