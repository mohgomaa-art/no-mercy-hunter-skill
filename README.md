# No Mercy Hunter

> Evidence-driven AI Bug Bounty Operator for Claude Code

No Mercy Hunter transforms Claude Code into a structured bug bounty research operator focused on validation, impact analysis, and report-ready findings.

Unlike generic security prompts, No Mercy Hunter is built around evidence collection, hypothesis testing, and vulnerability triage to reduce false positives and maximize high-value discoveries.

---

## What It Does

No Mercy Hunter helps researchers:

- Discover attack surface faster
- Prioritize high-signal findings
- Validate vulnerabilities systematically
- Eliminate weak hypotheses early
- Generate report-ready evidence
- Focus on impact, not noise

Supported research areas include:

- Authentication & Authorization
- OAuth & SSO
- JWT Security
- API Security
- GraphQL
- IDOR
- Business Logic Abuse
- AI / LLM Attack Surface
- Cloud Misconfigurations
- Shadow APIs
- Modern SaaS Applications

---

## Core Philosophy

Most researchers stop at:

```text
Observation
```

No Mercy Hunter forces progression through:

```text
Observation
↓
Signal
↓
Validated Signal
↓
Impact
↓
Report Ready
```

Every investigation is evaluated using:

### Proven

Facts supported by evidence.

### Assumed

Likely but unverified claims.

### Speculation

Ideas requiring validation.

### Next Test

The highest-value action based on:

- Confidence
- Expected Information Gain
- Cost

---

## Research Workflow

```text
Recon
 ↓
Attack Surface Mapping
 ↓
Hypothesis Generation
 ↓
Validation
 ↓
Impact Analysis
 ↓
Evidence Collection
 ↓
Report Generation
```

---

## Skill Components

### Operator Brain

Central decision-making layer.

Responsible for:

- Investigation strategy
- Prioritization
- Signal evaluation
- Dead-end detection

---

### Decision Tree

Guides:

- Authentication testing
- Authorization testing
- API analysis
- Business logic review
- AI security assessment

---

### Evidence Framework

Structures findings into:

```text
Observation
Signal
Validated Signal
Impact
```

Prevents chasing low-value noise.

---

### Reporting Framework

Generates:

- Reproducible reports
- Impact summaries
- Evidence packages
- Submission-ready writeups

---

## Example Investigation Output

### Current Evidence Level

Signal

### Proven

User A can access User B's invoice endpoint.

### Assumed

Additional resources may be exposed.

### Speculation

Cross-tenant data exposure exists.

### Highest Value Next Test

Attempt cross-tenant access against:

- Orders
- Billing
- Payment methods

Confidence: High

Information Gain: High

Cost: Low

---

## Directory Structure

```text
no-mercy-hunter/
├── SKILL.md
├── operator-brain.md
├── decision-tree.md
├── ontology.md
├── knowledge-graph.md
├── evidence-framework.md
├── reporting-framework.md
├── playbooks/
├── checklists/
├── templates/
└── references/
```

---

## Design Goals

### Reduce Hallucinated Findings

Every claim requires evidence.

### Kill Dead Ends Quickly

Weak paths are abandoned early.

### Increase Reportable Findings

Focus on validated impact.

### Improve Research Velocity

Spend more time proving vulnerabilities and less time exploring noise.

---

## Best Used For

- Bug Bounty Programs
- Private Security Assessments
- SaaS Security Reviews
- API Security Research
- AI Security Research
- Red Team Reconnaissance

---

## Not Designed For

- Automated exploitation
- Unauthorized testing
- Mass scanning
- Offensive operations outside scope

Always operate within the rules of the target program.

---

## Recommended Environment

- Claude Code
- Claude Opus
- Local Research Tooling
- Playwright
- Burp Suite
- Custom Recon Pipelines

---

## License

Use responsibly and only against systems you are authorized to test.

---

## Author

**Mohamed Gomaa**

Medical Student • Security Researcher • AI Systems Builder

Focused on:

- Bug Bounties
- AI Security
- Local-First AI Systems
- Research Automation
