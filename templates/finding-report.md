# Finding Report Template
# No Mercy Hunter v3.0

Usage: Copy this file. Replace all [BRACKETED] fields. Delete instructions in parentheses.
Naming: {FINDING-ID}-report.md

---

# [FINDING-ID]: [VULNERABILITY TITLE]

**Severity:** [P1 / P2 / P3 / P4]
**CVSS Score:** [0.0 - 10.0]
**CVSS Vector:** CVSS:3.1/AV:[X]/AC:[X]/PR:[X]/UI:[X]/S:[X]/C:[X]/I:[X]/A:[X]
**CWE:** CWE-[ID]: [CWE Name]
**Target:** [domain or subdomain]
**Endpoint:** [full URL path]
**Method:** [GET / POST / PUT / PATCH / DELETE]
**Auth Required:** [None / User / Admin]
**Date Discovered:** [YYYY-MM-DD]
**Date Reproduced:** [YYYY-MM-DD]
**Status:** [Draft / Ready to Submit / Submitted / Triaged / Resolved / Duplicate / N/A]
**Platform:** [Bugcrowd / HackerOne / Direct]
**Program:** [Program name]

---

## Summary

[One paragraph: what is the vulnerability, where does it exist, and what can an attacker do
with it? Be specific. Name the endpoint and the attack class. State the worst-case impact.]

Example (HF-01 pattern):
The /oauth/register endpoint on huggingface.co accepts OAuth 2.0 Dynamic Client
Registration (RFC 7591) requests without authentication. An attacker can register
an arbitrary OAuth client with a redirect_uri pointing to an attacker-controlled
domain, then generate authorization URLs targeting any HuggingFace user. When the
victim clicks the link, their authorization code is delivered to the attacker, who
can exchange it for access and refresh tokens — resulting in full account takeover.

---

## Affected Asset

**URL:** [https://example.com/path]
**Scope entry:** [exact scope line from program rules]
**Asset type:** [Web application / API endpoint / Mobile app / Infrastructure]

---

## Vulnerability Details

### Root Cause
[One sentence: what is the underlying flaw? Missing authentication check? Insecure
algorithm choice? No authorization validation on resource ID?]

### Attack Class
[OWASP 2025 category. E.g., A01:2025 Broken Access Control]

### Technical Description
[Paragraph or two explaining the technical mechanism. Include:
- What the endpoint does normally
- What validation is missing or broken
- How an attacker exploits the gap
- Why this is not intended behavior]

### Affected Parameters
| Parameter | Value | Effect |
|-----------|-------|--------|
| [param] | [value] | [what it does] |

---

## Steps to Reproduce

(Each step must be a single atomic action. No combined steps. Start from an unauthenticated
or basic-user state. Include exact payloads, exact URLs, exact header names.)

**Prerequisites:**
- Account A: [test email A]
- Account B: [test email B] (if IDOR testing)
- Tool: [curl / Playwright / browser / Python script]

**Steps:**

1. Navigate to [URL] in a browser or send the following request:

```http
GET /path HTTP/1.1
Host: target.com
Authorization: Bearer [TOKEN-A]
```

2. [Next action]

3. Observe that the response contains [unexpected data / incorrect behavior]:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "sensitive_data": "value_that_should_not_be_here"
}
```

4. [Continue steps until vulnerability fully demonstrated]

5. Confirm impact: [what the attacker now has access to]

---

## Proof of Concept

### Option A — curl Command
```bash
# Step 1: [describe what this does]
curl -s -X POST "https://target.com/vulnerable/endpoint" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ATTACKER_TOKEN" \
  -d '{"target_id": "VICTIM_RESOURCE_ID"}'

# Expected response demonstrating vulnerability:
# {"data": "victim_data", "owner": "victim_user_id"}
```

### Option B — Python Script
```python
#!/usr/bin/env python3
"""
PoC for [FINDING-ID]: [TITLE]
Author: [handle]
Date: [YYYY-MM-DD]
Target: [program/platform]
"""

import requests

# Configuration
TARGET = "https://target.com"
ATTACKER_TOKEN = "Bearer TOKEN_A"
VICTIM_RESOURCE_ID = "resource_id_from_victim_account"

def exploit():
    # Step 1: Access victim resource using attacker credentials
    resp = requests.get(
        f"{TARGET}/api/v1/resource/{VICTIM_RESOURCE_ID}",
        headers={"Authorization": ATTACKER_TOKEN}
    )
    
    if resp.status_code == 200:
        print(f"[VULNERABLE] Cross-account access confirmed")
        print(f"Response: {resp.json()}")
    else:
        print(f"[NOT VULNERABLE] Status: {resp.status_code}")

if __name__ == "__main__":
    exploit()
```

---

## Evidence

### Screenshots
(List all screenshots with descriptions)

| File | Shows |
|------|-------|
| [FINDING-ID]-01-setup.png | [What is visible] |
| [FINDING-ID]-02-exploit.png | [What is visible] |
| [FINDING-ID]-03-impact.png | [What is visible] |

### HTTP Logs
| File | Request | Response |
|------|---------|----------|
| [FINDING-ID]-01.http | [Brief description] | [Status + key data] |

---

## Impact

### Direct Impact
[What can the attacker do immediately after exploitation?]

### Worst-Case Scenario
[What is the maximum damage if this is fully exploited?]

### Affected Population
[Who is at risk? All users? Authenticated users? Specific role?]

### Data Exposed
[List specific data types: PII, credentials, financial data, API keys, source code, etc.]

### Business Impact
[Revenue impact, regulatory risk (GDPR, SOC2), reputational damage]

---

## Chain Analysis

(Complete this section if this finding is part of a chain)

### Prerequisites (what enables this finding)
| Finding | Severity | Relationship |
|---------|----------|-------------|
| [F-XX] | [P-X] | Required prerequisite |

### What This Enables (what this finding enables)
| Finding | Severity | Relationship |
|---------|----------|-------------|
| [F-XX] | [P-X] | This finding makes it possible |

### Combined Severity
Individual severity: [P-X]
Chain severity: [P-X] because [reason]

---

## Remediation

### Short-Term Fix (1-2 days)
[Immediate mitigation that reduces exposure. E.g., require authentication on /oauth/register]

### Long-Term Fix (1-4 weeks)
[Proper architectural fix. E.g., implement server-side ownership check before returning any
resource, comparing resource.owner_id with authenticated user's ID]

### Code Guidance
```python
# Example: Server-side IDOR fix
def get_resource(resource_id, authenticated_user_id):
    resource = db.get(resource_id)
    if resource is None:
        return 404
    # Add this check:
    if resource.owner_id != authenticated_user_id:
        return 403  # Do not return 404 here (information leak)
    return resource
```

### References
- [CWE-XXX: Name](https://cwe.mitre.org/data/definitions/XXX.html)
- [OWASP: Category Name](https://owasp.org/...)

---

## Timeline

| Event | Date | Notes |
|-------|------|-------|
| Discovered | [YYYY-MM-DD] | During [phase/activity] |
| Reproduced | [YYYY-MM-DD] | From scratch |
| Documented | [YYYY-MM-DD] | |
| Submitted | [YYYY-MM-DD] | Platform report ID: |
| Triaged | [YYYY-MM-DD] | |
| Resolved | [YYYY-MM-DD] | Fix version: |

---

## Notes and Dead Ends

[Optional: what you tried that did not work, alternative angles investigated,
follow-up questions for the vendor, related endpoints that were not vulnerable]
