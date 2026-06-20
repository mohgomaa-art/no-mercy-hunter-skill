# Checklist 05 — Infrastructure Attack Checklist
# No Mercy Hunter v3.0

Phase: Infrastructure Sweep (Phase 4)
Prerequisite: Passive Recon complete, live hosts list available
Expected duration: 60-90 minutes

---

## Pre-Flight

- [ ] live/hosts.txt populated (httpx output)
- [ ] ports/open.txt populated (naabu output) or about to be generated
- [ ] subs/all.txt populated from Phase 1
- [ ] Target cloud provider identified (AWS / GCP / Azure / unknown): ___
- [ ] Scope confirmed: infrastructure testing permitted

---

## Section A — Port Scanning and Service Discovery

### Priority Ports to Check
Non-standard ports that signal exposed admin/monitoring services:

- [ ] 8080 — alternate HTTP (proxy, admin, dev server)
- [ ] 8443 — alternate HTTPS
- [ ] 9200 — Elasticsearch HTTP API
- [ ] 5601 — Kibana dashboard
- [ ] 6443 — Kubernetes API server
- [ ] 2379 — etcd client
- [ ] 2380 — etcd peer
- [ ] 4444 — Metasploit / misc
- [ ] 8888 — Jupyter Notebook
- [ ] 9090 — Prometheus
- [ ] 3000 — Grafana / Node dev
- [ ] 4000 — misc admin
- [ ] 10250 — kubelet API
- [ ] 10255 — kubelet read-only
- [ ] 27017 — MongoDB
- [ ] 6379 — Redis
- [ ] 5432 — PostgreSQL (externally exposed)
- [ ] 3306 — MySQL (externally exposed)

Run: `naabu -l subs/all.txt -p 8080,8443,9200,5601,6443,2379,10250,10255,9090,3000,4000,8888,27017,6379 -o ports/critical.txt`

---

## Section B — S3 Bucket Enumeration (50+ Patterns)

### Bucket Generation Logic
Generate bucket names from target domain: TARGET = base domain (e.g., "openai" from openai.com)

#### Category 1 — Direct Name
- [ ] TARGET
- [ ] www.TARGET
- [ ] TARGET.com

#### Category 2 — Environment
- [ ] TARGET-prod
- [ ] TARGET-production
- [ ] TARGET-staging
- [ ] TARGET-stage
- [ ] TARGET-dev
- [ ] TARGET-development
- [ ] TARGET-test
- [ ] TARGET-testing
- [ ] TARGET-uat
- [ ] TARGET-qa
- [ ] TARGET-beta
- [ ] TARGET-preview

#### Category 3 — Function
- [ ] TARGET-assets
- [ ] TARGET-static
- [ ] TARGET-media
- [ ] TARGET-uploads
- [ ] TARGET-images
- [ ] TARGET-files
- [ ] TARGET-docs
- [ ] TARGET-documents
- [ ] TARGET-cdn
- [ ] TARGET-resources

#### Category 4 — Data
- [ ] TARGET-data
- [ ] TARGET-database
- [ ] TARGET-db
- [ ] TARGET-backup
- [ ] TARGET-backups
- [ ] TARGET-archive
- [ ] TARGET-logs
- [ ] TARGET-log
- [ ] TARGET-audit

#### Category 5 — Access Level
- [ ] TARGET-private
- [ ] TARGET-public
- [ ] TARGET-internal
- [ ] TARGET-external
- [ ] TARGET-secure
- [ ] TARGET-secrets

#### Category 6 — Infrastructure
- [ ] TARGET-infra
- [ ] TARGET-config
- [ ] TARGET-configs
- [ ] TARGET-terraform
- [ ] TARGET-k8s
- [ ] TARGET-kubernetes
- [ ] TARGET-deploy
- [ ] TARGET-builds
- [ ] TARGET-artifacts
- [ ] TARGET-releases

#### Category 7 — Team/Service
- [ ] TARGET-ml
- [ ] TARGET-ai
- [ ] TARGET-api
- [ ] TARGET-web
- [ ] TARGET-mobile
- [ ] TARGET-reports
- [ ] TARGET-analytics

### S3 Test Commands
For each bucket name, test:
```bash
curl -s "https://{BUCKET}.s3.amazonaws.com/" | grep -i "ListBucketResult\|Access Denied\|NoSuchBucket"
curl -s "https://s3.amazonaws.com/{BUCKET}/" | grep -i "ListBucketResult\|Access Denied\|NoSuchBucket"
```

Result interpretation:
- `ListBucketResult` → Public bucket, readable — CRITICAL
- `Access Denied` → Exists but private — LOW (note it)
- `NoSuchBucket` → Does not exist

Also test GCS (Google Cloud Storage):
```bash
curl -s "https://storage.googleapis.com/{BUCKET}/" | grep -i "ListBucketResult\|Access Denied"
```

### Findings
- [ ] Public buckets found: ___
- [ ] Private buckets found (for reference): ___

---

## Section C — Elasticsearch and Kibana

### Elasticsearch Discovery
For each IP/host in live hosts:

- [ ] GET http://HOST:9200/ — cluster info (unauthenticated = critical)
- [ ] GET http://HOST:9200/_cat/indices — list all indices
- [ ] GET http://HOST:9200/_cluster/health — cluster health
- [ ] GET http://HOST:9200/_cat/nodes — node list
- [ ] GET http://HOST:9200/{index}/_search?size=1 — sample data from index
- [ ] GET http://HOST:9200/_aliases — index aliases
- [ ] GET http://HOST:9200/_snapshot — snapshot repositories

### Kibana Discovery
- [ ] GET http://HOST:5601/api/status — version + status
- [ ] GET http://HOST:5601/app/discover — Kibana UI (unauthenticated = critical)
- [ ] GET http://HOST:5601/api/saved_objects/_find — saved searches/dashboards

### Default Credentials to Test (in order)
1. elastic / elastic
2. elastic / changeme
3. elastic / password
4. kibana / changeme
5. admin / admin
6. admin / password

### Findings
- [ ] Unauthenticated Elasticsearch: ___
- [ ] Kibana exposed: ___
- [ ] Default credentials worked: ___

---

## Section D — Kubernetes API Exposure

### API Server Checks (port 6443 or 443)
- [ ] GET https://HOST:6443/version — server version (no auth)
- [ ] GET https://HOST:6443/api/v1/namespaces — namespace list (no auth)
- [ ] GET https://HOST:6443/api/v1/pods — pod list (no auth)
- [ ] GET https://HOST:6443/api/v1/secrets — secrets list (no auth)
- [ ] GET https://HOST:6443/api/v1/configmaps — configmap list (no auth)

### Kubelet API (port 10250)
- [ ] GET https://HOST:10250/pods — pod list (no auth)
- [ ] POST https://HOST:10250/run/{namespace}/{pod}/{container} — command execution
- [ ] GET http://HOST:10255/pods — read-only kubelet (port 10255, HTTP)

### etcd (port 2379)
- [ ] GET http://HOST:2379/version — etcd version
- [ ] GET http://HOST:2379/v2/keys — key enumeration
- [ ] GET http://HOST:2379/v3/kv/range — v3 key range

### Bootstrap Endpoint Pattern (F-02)
- [ ] GET /bootstrap — K8s bootstrap config (F-02 pattern)
- [ ] GET /k8s-bootstrap
- [ ] GET /init/config
- [ ] GET /cluster-config
- [ ] Response contains serviceAccountToken: ___
- [ ] Response contains cluster URLs: ___
- [ ] Response contains internal IPs: ___

---

## Section E — Internal Metadata Services

Only test if SSRF vector is confirmed or target is a cloud platform.

### AWS IMDS
- [ ] GET http://169.254.169.254/latest/meta-data/
- [ ] GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
- [ ] GET http://169.254.169.254/latest/meta-data/hostname
- [ ] GET http://169.254.169.254/latest/user-data

### GCP IMDS
- [ ] GET http://metadata.google.internal/computeMetadata/v1/ (header: Metadata-Flavor: Google)
- [ ] GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

### Azure IMDS
- [ ] GET http://169.254.169.254/metadata/instance?api-version=2021-02-01 (header: Metadata: true)
- [ ] GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

---

## Section F — Internal npm Registry Detection

### Registry Probing
- [ ] GET https://registry.npmjs.org/{TARGET-PACKAGE-NAME} — public registry
- [ ] GET https://npm.{TARGET}/ — internal npm mirror
- [ ] GET https://registry.{TARGET}/ — internal registry
- [ ] Check package.json .npmrc for private registry URLs

### Dependency Confusion Test
For each internal package name found:
- [ ] Search npmjs.com for the exact package name
- [ ] If not on public registry: vulnerable to dependency confusion
- [ ] Note package names found in internal registry: ___

---

## Section G — Azure AD Tenant Recon (if Azure detected)

Trigger: Any subdomain uses *.microsoft.com, *.azure.com, or Azure AD sign-in

### Step 1 — Tenant Discovery
```bash
curl -s "https://login.microsoftonline.com/{TARGET-DOMAIN}/v2.0/.well-known/openid-configuration"
```
- [ ] tenant_id extracted: ___
- [ ] token_endpoint extracted: ___
- [ ] grant_types_supported extracted: ___

### Step 2 — Flow Detection
- [ ] "password" in grant_types → ROPC enabled (F-10 pattern, P1 candidate)
- [ ] "urn:ietf:params:oauth:grant-type:device_code" → Device code enabled
- [ ] ROPC enabled: YES / NO
- [ ] Device code enabled: YES / NO

### Step 3 — User Enumeration (if ROPC enabled)
```bash
curl -s -X POST "https://login.microsoftonline.com/{TENANT-ID}/oauth2/v2.0/token" \
  -d "client_id={CLIENT_ID}&grant_type=password&username={USER}&password=invalid&scope=openid"
```
Interpret errors:
- AADSTS50126: Invalid password — user EXISTS
- AADSTS50034: User not found — user DOES NOT EXIST
- AADSTS70011: Scope not supported — try different scope

- [ ] Users enumerated: ___

### Step 4 — Device Code Phishing URL
```bash
curl -s -X POST "https://login.microsoftonline.com/{TENANT-ID}/oauth2/v2.0/devicecode" \
  -d "client_id={CLIENT_ID}&scope=openid profile"
```
- [ ] device_code extracted: ___
- [ ] user_code for phishing: ___
- [ ] Verification URL: ___

---

## Section H — Nuclei Scan

### Run Order (by priority)
```bash
# Critical/High severity first
nuclei -l live/hosts.txt -severity critical,high -o nuclei/critical-high.txt

# Exposed panels (admin UIs)
nuclei -l live/hosts.txt -t exposed-panels/ -o nuclei/panels.txt

# Misconfigurations
nuclei -l live/hosts.txt -t misconfiguration/ -o nuclei/misconfigs.txt

# CVEs (known vulnerabilities)
nuclei -l live/hosts.txt -t cves/ -severity critical,high -o nuclei/cves.txt

# Medium severity
nuclei -l live/hosts.txt -severity medium -o nuclei/medium.txt
```

### Custom Templates
Apply custom template for F-01 pattern (device ID bypass):
```bash
nuclei -l live/hosts.txt -t custom-templates/device-id-bypass.yaml -o nuclei/custom.txt
```

### Findings
- [ ] Critical nuclei findings: ___
- [ ] High nuclei findings: ___
- [ ] Exposed panels: ___
- [ ] Custom template hits: ___

---

## Completion Gate

Before moving to Phase 5 (Race Conditions):

- [ ] Port scan complete — all critical ports checked
- [ ] S3 enumeration complete — 50+ patterns tested
- [ ] Elasticsearch/Kibana checked on all discovered IPs
- [ ] Kubernetes API checked on all hosts with port 6443
- [ ] Bootstrap endpoint tested on API hosts
- [ ] Azure AD tenant recon complete (if applicable)
- [ ] Nuclei scan complete
- [ ] All findings logged to SQLite DB
- [ ] infra-findings.md written

---

## Output Files

| File | Contents |
|------|----------|
| infra-findings.md | All infrastructure findings |
| s3-buckets.txt | All bucket names tested + results |
| ports/critical.txt | Open critical ports |
| nuclei/critical-high.txt | Nuclei critical/high findings |
| nuclei/panels.txt | Exposed admin panels |
