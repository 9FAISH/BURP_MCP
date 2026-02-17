# Comprehensive Penetration Test Plan
# MASAR Group — Full Attack Surface Assessment

**Target Scope:**
| Asset | URL/Identifier |
|-------|---------------|
| Admin Portal (Test) | `https://test-admin.masar-group.com` |
| Admin Portal (Prod) | `https://admin.masar-group.com` |
| API (Test) | `https://test-api.masar-group.com` |
| API (Prod) | `https://api.masar-group.com` |
| Legacy API | `https://masar-api.urbansoft.app` |
| Cognito IDP | `cognito-idp.me-south-1.amazonaws.com` |
| Cognito Identity | `cognito-identity.me-south-1.amazonaws.com` |
| Payment Page | `eazypay.html` (Mastercard integration) |
| Ticket Page | `wmqr.html` (public-facing QR tickets) |
| Static Assets | S3 via CloudFront |

**Date:** February 17, 2026
**Prepared By:** Cybersecurity Manager, MASAR Group
**Classification:** INTERNAL — CONFIDENTIAL

---

## Gap Analysis: What Was Tested vs. What Remains

### Phase 1 (Completed) — Authentication Bypass Focus
| Area | Status | Key Findings |
|------|--------|-------------|
| Cognito auth flow bypass | ✅ Done | SRP-only, good |
| JWT forgery (alg:none, fake sig) | ✅ Done | Blocked by API GW |
| User enumeration | ✅ Done | Exploitable, no rate limit |
| Identity Pool unauth creds | ✅ Done | **CRITICAL** — AWS creds issued |
| GraphQL introspection | ✅ Done | Exposed on /unauth |
| Self-registration | ✅ Done | Blocked |

### Phase 2 (This Plan) — 12 Additional Attack Areas
| # | Area | Priority | Status |
|---|------|----------|--------|
| 1 | AWS Cloud Infrastructure Deep-Dive | P0 | **NOT TESTED** |
| 2 | Payment Gateway (eazypay.html) Security | P0 | **NOT TESTED** |
| 3 | DOM XSS Exploitation (wmqr.html) | P0 | **NOT TESTED** |
| 4 | GraphQL API Deep Exploitation | P1 | **PARTIALLY TESTED** |
| 5 | CORS Misconfiguration | P1 | **NOT TESTED** |
| 6 | Security Headers & CSP | P1 | **NOT TESTED** |
| 7 | S3 Bucket & CloudFront Misconfig | P1 | **NOT TESTED** |
| 8 | Supply Chain (CDN/3rd-Party Scripts) | P1 | **NOT TESTED** |
| 9 | Session Management & Token Storage | P2 | **NOT TESTED** |
| 10 | Hidden Endpoints & Path Discovery | P2 | **NOT TESTED** |
| 11 | DNS & Subdomain Enumeration | P2 | **NOT TESTED** |
| 12 | Business Logic Flaws | P3 | **NOT TESTED** |

---

## PHASE 2A: P0 — CRITICAL TESTS

---

### TEST 1: AWS Cloud Infrastructure Deep-Dive
**Time Estimate:** 2-3 hours
**Tool:** Burp Repeater + AWS CLI via unauthenticated Identity Pool credentials

**Background:** Phase 1 confirmed we can obtain unauthenticated AWS credentials (`ASIAVVZOOASAZ264WP5E`). This is the single most dangerous finding — if the IAM role is overpermissive, it's game over.

**Test Steps:**

| # | Test | Method | Expected |
|---|------|--------|----------|
| 1.1 | STS GetCallerIdentity | SigV4-signed request to `sts.me-south-1.amazonaws.com` | Reveals IAM role ARN, account ID |
| 1.2 | S3 ListBuckets | SigV4 signed `GET /` to `s3.me-south-1.amazonaws.com` | Check if we can list all buckets |
| 1.3 | S3 GetObject on known bucket | Try accessing the S3 bucket backing CloudFront | Check if we can read files directly |
| 1.4 | S3 PutObject test | Try uploading a test file to S3 | Check if we have write access |
| 1.5 | Cognito AdminListUsers | SigV4 signed to `cognito-idp.me-south-1.amazonaws.com` with `AdminListUsers` | Check if IAM role can enumerate users |
| 1.6 | Cognito AdminCreateUser | Attempt to create a test admin user | Check if IAM role can create accounts |
| 1.7 | DynamoDB ListTables | SigV4 signed to `dynamodb.me-south-1.amazonaws.com` | Check database access |
| 1.8 | DynamoDB Scan | If tables found, scan for booking/user data | Check data exfiltration risk |
| 1.9 | Lambda ListFunctions | SigV4 signed to `lambda.me-south-1.amazonaws.com` | Check if we can list/invoke functions |
| 1.10 | IAM GetRolePolicy | Try to read our own role's policy | Understand full permissions |
| 1.11 | SSM GetParameters | Try reading SSM Parameter Store | Check for secrets/API keys |
| 1.12 | SecretsManager ListSecrets | Try listing secrets | Check for database passwords, keys |

**Burp Approach:**
- Obtain fresh credentials via `GetId` → `GetCredentialsForIdentity`
- Create Repeater tabs for each AWS service call
- Sign requests using AWS SigV4 (calculate HMAC-SHA256)
- Track all results in Intruder for automated sweeping

**Critical Success Indicators:**
- ⚠️ If `AdminListUsers` works → can enumerate ALL admin accounts
- ⚠️ If `AdminCreateUser` works → **can create admin account** = FULL COMPROMISE
- ⚠️ If `S3 GetObject` works → can access all passenger data, documents, photos
- ⚠️ If `DynamoDB Scan` works → can dump entire database

---

### TEST 2: Payment Gateway (eazypay.html) Security
**Time Estimate:** 1-2 hours
**Tool:** Burp Repeater + Browser Proxy

**Background:** WARD report identified a CRITICAL finding — Mastercard payment script without SRI. Need to test the actual payment flow.

**Test Steps:**

| # | Test | Method | Expected |
|---|------|--------|----------|
| 2.1 | Fetch eazypay.html | GET request to `/eazypay.html` | Confirm script tag has no integrity attribute |
| 2.2 | Analyze payment flow | Extract session_id parameter handling from JS | Identify token exposure risks |
| 2.3 | Parameter tampering | Modify `session_id` query parameter in payment URL | Check for IDOR on payment sessions |
| 2.4 | Checkout callback interception | Intercept `completeCallback`, `errorCallback`, `cancelCallback` | Check if callbacks leak sensitive data |
| 2.5 | Payment session replay | Replay a captured payment session request | Check if sessions are one-time-use |
| 2.6 | SRI bypass confirmation | Verify no integrity/crossorigin attributes on Mastercard script | Confirm supply chain risk |
| 2.7 | Checkout.configure injection | Test if session.id parameter is sanitized | Check for injection in payment config |

**Burp Approach:**
- Fetch and analyze `eazypay.html` via Repeater
- Create Intruder tab for session_id parameter fuzzing
- Monitor all requests to `eazypay.gateway.mastercard.com` in proxy

---

### TEST 3: DOM XSS Exploitation (wmqr.html)
**Time Estimate:** 1-2 hours
**Tool:** Burp Repeater + Unauth GraphQL API

**Background:** WARD report confirmed `innerHTML` injection via passenger names. We already confirmed the unauth GraphQL API at `/unauth/graphql` accepts `getTicket` queries. Now test the full XSS chain.

**Test Steps:**

| # | Test | Method | Expected |
|---|------|--------|----------|
| 3.1 | Confirm innerHTML sink | Fetch wmqr.html, verify `${passenger.given_name}` in innerHTML | Confirm no sanitization |
| 3.2 | Test getTicket with XSS booking | Query `getTicket` with various booking codes | Find a booking with data |
| 3.3 | Test booking code enumeration | Brute-force booking code patterns via Intruder | Enumerate valid bookings |
| 3.4 | Verify XSS fields | Check all fields in innerHTML: `given_name`, `family_name`, `start_location.en`, `end_location.en`, `qr_code_url` | Map all injection points |
| 3.5 | Test reflected params | Test `bc`, `td`, `si` URL parameters for XSS | Check for reflected XSS in URL handling |
| 3.6 | Test error handler XSS | Trigger error states, check if error messages use innerHTML | Check for XSS in error paths |
| 3.7 | Chain: XSS → Token Theft | Craft payload to exfiltrate localStorage Cognito tokens | Prove admin takeover chain |

**Burp Approach:**
- Repeater for `getTicket` query variants
- Intruder for booking code enumeration
- Send crafted payloads through the API to test XSS rendering

---

## PHASE 2B: P1 — HIGH PRIORITY TESTS

---

### TEST 4: GraphQL API Deep Exploitation
**Time Estimate:** 2-3 hours
**Tool:** Burp Repeater + Intruder

**Test Steps:**

| # | Test | Method | Expected |
|---|------|--------|----------|
| 4.1 | Full introspection on /unauth/graphql | `__schema` query with all types, fields, args, directives | Complete API blueprint |
| 4.2 | Full introspection on /admin/graphql | Same with various auth bypass attempts | Should be blocked |
| 4.3 | Query depth attack | Deeply nested query (10+ levels) | Test for DoS via query complexity |
| 4.4 | Batch query attack | Send array of 100+ queries in single request | Test for rate limiting on batched queries |
| 4.5 | Alias-based DoS | Same query aliased 1000 times | Test query alias limits |
| 4.6 | Field suggestion enumeration | Send typo queries, collect "did you mean" suggestions | Enumerate hidden fields |
| 4.7 | IDOR on getTicket | Enumerate booking codes: `BK001`-`BK999`, `MS001`-`MS999` | Access other users' tickets |
| 4.8 | IDOR on all unauth queries | Test `searchTrip`, `getBoat`, `searchLocation` for data leakage | Access internal data without auth |
| 4.9 | Mutation abuse | Test `submitFeedbackResponses`, `addUserItemClick` for injection | Inject malicious data via unauth mutations |
| 4.10 | GraphQL injection | Special chars in variables: `{"id": "1' OR '1'='1"}` | Test for injection in resolvers |
| 4.11 | Type confusion | Send wrong types: string where int expected | Test error handling and info leakage |
| 4.12 | Directive abuse | `@skip`, `@include`, custom directives | Test for authorization bypass |

**Burp Approach:**
- Repeater tabs for each query variant
- Intruder for booking code/ID enumeration
- Monitor response sizes to detect data leakage

---

### TEST 5: CORS Misconfiguration
**Time Estimate:** 30 minutes
**Tool:** Burp Repeater

**Background:** Proxy history shows Cognito returns `Access-Control-Allow-Origin: *` (wildcard). Need to test all endpoints.

**Test Steps:**

| # | Test | Method | Expected |
|---|------|--------|----------|
| 5.1 | Admin API CORS | Send with `Origin: https://evil.com` | Should NOT reflect origin |
| 5.2 | Unauth API CORS | Same test on `/unauth/graphql` | Check if wildcard |
| 5.3 | Cognito CORS | Already confirmed `*` | Document the risk |
| 5.4 | S3/CloudFront CORS | Test frontend origin header | Check for overpermissive CORS |
| 5.5 | Null Origin | `Origin: null` (data: URI, sandboxed iframe) | Check if null origin is accepted |
| 5.6 | Subdomain trust | `Origin: https://evil.masar-group.com` | Check if wildcarding on domain |
| 5.7 | Credential inclusion | CORS + `Access-Control-Allow-Credentials: true` combo | Check if cookies can be stolen cross-origin |

---

### TEST 6: Security Headers & CSP Analysis
**Time Estimate:** 30 minutes
**Tool:** Burp Repeater

**Test Steps:**

| # | Test | Method | Expected |
|---|------|--------|----------|
| 6.1 | CSP header check | All endpoints | Confirm missing CSP |
| 6.2 | X-Frame-Options check | Currently `SAMEORIGIN` on S3 responses | Test on API responses too |
| 6.3 | HSTS check | Currently `max-age=31536000` | Check all subdomains + preload |
| 6.4 | Permissions-Policy | Check for camera, microphone, geolocation restrictions | Should be restrictive |
| 6.5 | Cache-Control on API | Check if API responses cache sensitive data | Auth responses should be no-store |
| 6.6 | Cookie flags | Check Set-Cookie headers for HttpOnly, Secure, SameSite | Should have all flags |
| 6.7 | Server header info leak | Check all `Server`, `X-Powered-By`, `X-Amz-*` headers | Document info disclosure |

---

### TEST 7: S3 Bucket & CloudFront Misconfiguration
**Time Estimate:** 1-2 hours
**Tool:** Burp Repeater + Intruder

**Test Steps:**

| # | Test | Method | Expected |
|---|------|--------|----------|
| 7.1 | S3 bucket name discovery | From CloudFront response headers, guess bucket names | Find the backing S3 bucket |
| 7.2 | S3 directory listing | `GET /` with various Accept headers to S3 | Check for open listing |
| 7.3 | S3 path traversal | `GET /../../etc/passwd`, `GET /..%2f..%2f` | Test path traversal |
| 7.4 | Hidden files discovery | `GET /.env`, `GET /.git/config`, `GET /config.json` | Check for leaked configs |
| 7.5 | Backup files | `GET /index.html.bak`, `GET /main.js.map` | Check for source maps/backups |
| 7.6 | S3 version enumeration | Use `X-Amz-Version-Id` header patterns | Access old versions of files |
| 7.7 | CloudFront cache poisoning | Manipulate `Host`, `X-Forwarded-Host` headers | Test for cache poisoning |
| 7.8 | CloudFront signed URL bypass | Test if signed URLs are required for any paths | Check for unsigned access |

---

### TEST 8: Supply Chain (CDN / Third-Party Script) Analysis
**Time Estimate:** 30 minutes
**Tool:** Burp Repeater

**Test Steps:**

| # | Test | Method | Expected |
|---|------|--------|----------|
| 8.1 | Inventory all external scripts | Parse HTML of index.html, wmqr.html, eazypay.html, privacy_policy.html, terms_and_condition.html | Complete 3rd-party inventory |
| 8.2 | SRI audit | Check every `<script>` and `<link>` tag | Identify missing integrity attributes |
| 8.3 | BrowserPrint-3.1.250.min.js | Analyze this Zebra printer SDK script — local file, not CDN | Check for vulnerabilities in this library |
| 8.4 | Tailwind CDN JIT risk | Confirm cdn.tailwindcss.com is a full JS runtime in production | Document the risk |
| 8.5 | rsms.me/inter font | Test if this could be weaponized via CSS injection | Low risk but document |
| 8.6 | Subresource integrity coverage | Calculate expected SRI hashes for all CDN resources | Provide remediation hashes |

---

## PHASE 2C: P2 — MEDIUM PRIORITY TESTS

---

### TEST 9: Session Management & Token Storage
**Time Estimate:** 1 hour
**Tool:** Burp Proxy + Browser DevTools

**Test Steps:**

| # | Test | Method | Expected |
|---|------|--------|----------|
| 9.1 | Token storage location | Inspect localStorage, sessionStorage, cookies after login | Confirm localStorage (no httpOnly) |
| 9.2 | Token expiry enforcement | Use expired token against API | Should return 401 |
| 9.3 | Token reuse after logout | Capture token, logout, replay token | Should be invalidated |
| 9.4 | Concurrent session handling | Login from two locations | Check for concurrent session limits |
| 9.5 | Token refresh flow | Intercept refresh token usage | Check for refresh token rotation |
| 9.6 | Session fixation | Pre-set a known session token | Check if accepted |
| 9.7 | Token in URL | Check if tokens leak via Referer header | Should never be in URL params |

---

### TEST 10: Hidden Endpoints & Path Discovery
**Time Estimate:** 1-2 hours
**Tool:** Burp Intruder + JS Analysis

**Test Steps:**

| # | Test | Method | Expected |
|---|------|--------|----------|
| 10.1 | React route extraction | Parse `main.df6ea6c2.js` for all route paths | Complete route map |
| 10.2 | API path fuzzing | Intruder on `test-api.masar-group.com` with common paths: `/api/`, `/graphql/`, `/health`, `/metrics`, `/swagger`, `/api-docs`, `/debug` | Discover hidden endpoints |
| 10.3 | Admin portal path fuzzing | Intruder on `test-admin.masar-group.com` with common paths: `/.env`, `/.git`, `/robots.txt`, `/sitemap.xml`, `/manifest.json`, `/static/`, `/admin/`, `/debug/` | Discover exposed files |
| 10.4 | HTTP method fuzzing | Send PUT, DELETE, PATCH, OPTIONS to all known endpoints | Check for unprotected methods |
| 10.5 | API version discovery | `/v1/graphql`, `/v2/graphql`, `/api/v1/`, `/api/v2/` | Find older API versions |
| 10.6 | Legacy endpoint probing | Test `masar-api.urbansoft.app` (found in JS) | Check legacy API security |
| 10.7 | Source map access | `GET /static/js/main.df6ea6c2.js.map` | Check if source maps are exposed |
| 10.8 | Webpack chunk discovery | `GET /static/js/[0-9].*.js` pattern | Find additional JS bundles |

---

### TEST 11: DNS & Subdomain Enumeration
**Time Estimate:** 30 minutes
**Tool:** External DNS tools (passive)

**Test Steps:**

| # | Test | Method | Expected |
|---|------|--------|----------|
| 11.1 | Subdomain enumeration | DNS brute-force on `masar-group.com` | Find additional services |
| 11.2 | Certificate transparency | Search crt.sh for `masar-group.com` certs | Discover subdomains from SSL certs |
| 11.3 | TXT record analysis | DNS TXT records | Find SPF, DMARC, verification records |
| 11.4 | MX record analysis | DNS MX records | Identify email infrastructure |
| 11.5 | urbansoft.app relationship | DNS analysis on `urbansoft.app` | Understand the vendor relationship |
| 11.6 | CNAME dangling check | Check for unclaimed CNAMEs | Subdomain takeover risk |

---

## PHASE 2D: P3 — BUSINESS LOGIC TESTS

---

### TEST 12: Business Logic Flaws
**Time Estimate:** 2-3 hours
**Tool:** Burp Repeater + Intruder

**Test Steps:**

| # | Test | Method | Expected |
|---|------|--------|----------|
| 12.1 | Booking code predictability | Analyze booking code format and generation | Check if sequential/guessable |
| 12.2 | Price manipulation | Modify trip/ticket price in GraphQL mutations | Check server-side validation |
| 12.3 | Seat overbooking | Book same seat concurrently from two sessions | Check for race conditions |
| 12.4 | Date manipulation | Book with past/future dates outside valid range | Check boundary validation |
| 12.5 | Role escalation via GraphQL | Modify `user_roles` field in mutations | Check if role changes are validated |
| 12.6 | Mass data export | Request large page sizes (size: 10000) in pagination | Check for data export limits |
| 12.7 | Feedback injection | Submit XSS/SQL injection via `submitFeedbackResponses` | Check input validation on mutations |
| 12.8 | QR code tampering | Analyze QR code URL structure for IDOR | Check if QR codes are authenticated |
| 12.9 | Negative quantity/price | Submit negative values in booking flow | Check for integer underflow |
| 12.10 | Timezone abuse | Manipulate timezone to get expired tickets | Check timezone validation |

---

## Execution Timeline

```
DAY 1 (4-6 hours):
├── Phase 2A — P0 Critical
│   ├── TEST 1: AWS Infrastructure Deep-Dive (2-3 hrs)   ← HIGHEST PRIORITY
│   ├── TEST 2: Payment Gateway Security (1-2 hrs)
│   └── TEST 3: DOM XSS Exploitation (1-2 hrs)
│
DAY 2 (4-6 hours):
├── Phase 2B — P1 High
│   ├── TEST 4: GraphQL Deep Exploitation (2-3 hrs)
│   ├── TEST 5: CORS Misconfiguration (30 min)
│   ├── TEST 6: Security Headers & CSP (30 min)
│   ├── TEST 7: S3 & CloudFront Misconfig (1-2 hrs)
│   └── TEST 8: Supply Chain Analysis (30 min)
│
DAY 3 (3-5 hours):
├── Phase 2C — P2 Medium
│   ├── TEST 9: Session Management (1 hr)
│   ├── TEST 10: Hidden Endpoints (1-2 hrs)
│   └── TEST 11: DNS & Subdomain Enumeration (30 min)
│
DAY 4 (3-4 hours):
├── Phase 2D — P3 Business Logic
│   └── TEST 12: Business Logic Flaws (2-3 hrs)
│
DAY 5 (2-3 hours):
└── Report Consolidation
    ├── Merge Phase 1 + Phase 2 findings
    ├── Update CVSS scores and risk ratings
    ├── Create remediation roadmap
    └── Executive summary for leadership
```

---

## Burp Suite Setup Requirements

### Repeater Tabs Needed (Pre-Create)
| Tab Name | Purpose |
|----------|---------|
| AWS STS - GetCallerIdentity | Verify IAM role from Identity Pool creds |
| AWS S3 - ListBuckets | S3 enumeration with unauth creds |
| AWS Cognito - AdminListUsers | Cognito admin API with unauth creds |
| AWS DynamoDB - ListTables | Database enumeration |
| Payment - eazypay.html | Payment flow analysis |
| Payment - Session Tampering | Payment session_id manipulation |
| XSS - wmqr Passenger Names | DOM XSS via passenger data |
| GraphQL - Deep Introspection | Full schema extraction |
| GraphQL - Query Depth DoS | Nested query complexity test |
| GraphQL - Batch Attack | Batched query rate limit test |
| CORS - Origin Reflection | Cross-origin testing |
| S3 - Directory Listing | S3 bucket enumeration |
| S3 - Hidden Files | .env, .git config checks |
| Legacy API - urbansoft | Legacy endpoint testing |

### Intruder Configurations Needed
| Config | Payload |
|--------|---------|
| User Enumeration | 500+ common email patterns for @masar-group.com |
| Booking Code Enum | Alphanumeric patterns (BK001-BK999, MS001-MS999) |
| Path Discovery (Admin) | Common web paths wordlist (~2000 entries) |
| Path Discovery (API) | API path wordlist (~500 entries) |
| GraphQL Field Suggestion | Typo'd field names to trigger "did you mean" |

---

## Risk-Based Prioritization Logic

```
IF Test 1 (AWS creds) reveals overpermissive IAM role:
    → STOP everything
    → This is a FULL INFRASTRUCTURE COMPROMISE
    → Escalate to CTO immediately
    → Remediate before continuing other tests

IF Test 1 IAM role is restricted:
    → Continue with remaining tests
    → Still recommend disabling unauth Identity Pool access

IF Test 3 (DOM XSS) confirms exploitable:
    → Combined with missing CSP = Token theft chain
    → Any customer can become admin
    → P0 remediation alongside payment script
```

---

## Deliverables

1. **COMPREHENSIVE-PENTEST-REPORT.md** — Full technical report with all Phase 1 + Phase 2 findings
2. **EXECUTIVE-SUMMARY.md** — 2-page summary for leadership
3. **REMEDIATION-TRACKER.md** — Prioritized action items with owners and deadlines
4. **Burp Project File** — All Repeater/Intruder configs for regression testing
5. **EVIDENCE/** directory — Screenshots, request/response pairs, exploit PoCs

---

*Plan prepared by MASAR Cybersecurity Manager*
*Ready for immediate execution upon approval*
