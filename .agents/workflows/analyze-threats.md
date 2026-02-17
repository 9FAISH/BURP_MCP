---
description: Analyze Burp Suite HTTP history for security threats and generate a full report
---

# Analyze HTTP History for Threats

When the user asks to analyze HTTP history, scan for threats, or review proxy traffic, follow these rules **every time**:

---

## Step 1 — Fetch All HTTP History

// turbo-all

1. Use `mcp_burp_get_proxy_http_history` with a high count (e.g., 100) and offset 0 to fetch all available traffic.
2. If there are more entries, continue fetching with increasing offsets until all history is retrieved.

---

## Step 2 — Analyze BOTH Request AND Response

For **every** history entry, you MUST examine:

### Request Analysis
- HTTP method, URL, path, and query parameters
- Headers: `Authorization`, `Cookie`, `Content-Type`, `Origin`, `Referer`, custom headers
- Body: JSON payloads, form data, GraphQL queries, file uploads
- Look for: tokens, credentials, IDs, user-controllable parameters

### Response Analysis
- Status codes and their security implications
- Headers: `Access-Control-*`, `Set-Cookie`, `X-Powered-By`, `Server`, security headers
- Body: leaked data (PII, tokens, stack traces, internal IPs, error messages)
- Look for: information disclosure, excessive data, missing security headers, verbose errors

### Correlation
- Match request parameters to response data — does changing an ID return different user data?
- Track authentication tokens across requests — are they reused, rotated, or exposed?
- Identify state-changing operations and their protections (CSRF tokens, idempotency keys)

---

## Step 3 — Validate with Repeater & Intruder

When a potential finding is identified, **actively validate** it using Burp tools:

### Use Repeater (`mcp_burp_create_repeater_tab`) when:
- You need to **replay a suspicious request** with modified parameters to confirm a vulnerability
- Testing IDOR by changing user IDs, org IDs, or resource IDs
- Testing auth bypass by removing/modifying Authorization headers
- Testing CORS by changing the Origin header
- Testing for missing rate limiting by replaying the same request
- Verifying if sensitive data changes when manipulating request parameters

### Use Intruder (`mcp_burp_send_to_intruder`) when:
- You need to **fuzz or brute-force** a parameter (e.g., sequential IDs for IDOR enumeration)
- Testing multiple payloads against an injection point
- Enumerating valid usernames, emails, or resource IDs
- Testing rate limiting with rapid concurrent requests

### Use Direct HTTP Requests (`mcp_burp_send_http1_request`) when:
- You need a quick one-off test (e.g., checking if an endpoint responds without auth)
- Verifying SSRF by sending a crafted URL parameter
- Testing HTTP method tampering (GET → PUT/DELETE)

---

## Step 4 — Advanced Threat Analysis Checklist

Systematically check for the following categories (derived from **thousands of real-world HackerOne bug bounty reports**):

### 🔐 Authentication & Session Management
- User Enumeration (different errors for valid/invalid users, e.g., Cognito `UserNotFoundException`)
- Brute Force / No Rate Limiting on login, OTP, password reset
- 2FA Bypass (reusable OTP, session manipulation, race condition)
- Session Fixation/Replay (tokens not rotated, sessions valid after logout)
- Auth Bypass (direct access to endpoints without tokens)
- JWT Issues (`alg: none`, weak HS256 secret, expired tokens accepted)
- OAuth/OIDC Flaws (open redirect, CSRF, token leakage via referrer)

### 🔑 Sensitive Data Exposure
- Tokens/Keys visible in HTTP history (access tokens, AWS keys, session tokens)
- PII in API responses (emails, phones, addresses beyond what's needed)
- Credentials in responses (API keys, DB credentials)
- JWT payload reveals internal info (roles, groups, infrastructure)

### 🆔 IDOR (Insecure Direct Object References)
- Sequential/predictable IDs (`/user/123` → `/user/124`)
- Cross-tenant access (changing `org_id`, `team_id`)
- HTTP method tampering (GET→PUT/DELETE bypasses)
- GraphQL IDOR (mutation parameter manipulation)

### 📊 GraphQL-Specific
- Introspection enabled (`__schema` accessible)
- Batching/alias-based rate limit bypass
- Cross-tenant mutations, nested query DoS
- Deprecated fields with sensitive data

### 🌐 CORS & Cross-Origin
- `Access-Control-Allow-Origin: *` on authenticated endpoints
- Origin reflection, credentials with wildcard
- Null origin allowed

### 🔄 Race Conditions
- No idempotency on financial/state-changing endpoints
- Limit bypass via concurrent requests
- 2FA race, email verification race

### 📨 HTTP Request Smuggling
- CL.TE / TE.CL discrepancies
- HTTP/2 downgrade smuggling
- CRLF injection, chunked encoding anomalies

### 🔗 SSRF
- URL parameters (`url=`, `callback=`, `redirect=`)
- Webhook configurations targeting internal services
- File import via URL (SVG, XML, RSS)
- DNS rebinding, AWS metadata access

### 🔒 Missing Security Headers
- HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy

### 🏗️ Infrastructure Disclosure
- Server version headers, AWS fingerprinting
- Stack traces, debug endpoints, source maps

### 💉 Injection Vectors
- XSS, SQLi, GraphQL injection, header injection

### 📱 API Design Flaws
- Mass assignment, verb tampering, no pagination
- Excessive error detail, API version exposure

### 🏴‍☠️ Business Logic
- Price manipulation, workflow bypass, privilege escalation

---

## Step 5 — Cross-Reference with Bug Bounty Knowledge Base

When a potential finding is identified:
1. Check relevant files in `hackerone-reports/tops_by_bug_type/` for similar reported vulnerabilities
2. Reference patterns from `bugbounty-disclosed-reports/reports/` for attack methodology

Key reference files:
| Finding Category | Reference File |
|---|---|
| GraphQL | `TOPGRAPHQL.md` |
| REST API | `TOPAPI.md` |
| Auth Bypass | `TOPAUTH.md` |
| Authorization | `TOPAUTHORIZATION.md` |
| IDOR | `TOPIDOR.md` |
| SSRF | `TOPSSRF.md` |
| CSRF | `TOPCSRF.md` |
| XSS | `TOPXSS.md` |
| Race Condition | `TOPRACECONDITION.md` |
| Request Smuggling | `TOPREQUESTSMUGGLING.md` |
| Info Disclosure | `TOPINFODISCLOSURE.md` |
| Account Takeover | `TOPACCOUNTTAKEOVER.md` |
| Business Logic | `TOPBUSINESSLOGIC.md` |
| Open Redirect | `TOPOPENREDIRECT.md` |
| File Reading | `TOPFILEREADING.md` |
| OAuth | `TOPOAUTH.md` |
| MFA | `TOPMFA.md` |

---

## Step 6 — Write the Report (HackerOne Style)

Generate a markdown report using the **HackerOne report format**. The overall report is a walkthrough artifact.

### Report Header

```
# 🔍 Security Assessment Report

**Target:** [target domain/application]
**Date:** [date]
**Total Requests Analyzed:** [count]
**Findings:** [X Critical, X High, X Medium, X Low, X Info]
```

### For EACH Finding — Use This Exact HackerOne-Style Format:

```
---

## [Finding Title]

### Report Details
- **Severity**: critical / high / medium / low / informational
- **Category**: [e.g., IDOR, Auth Bypass, CORS Misconfiguration]
- **CWE**: [CWE ID if applicable, e.g., CWE-639: IDOR]
- **CVSS Score**: [estimated score, e.g., 8.6]

### Affected HTTP History Items
| # | History Item | Method | URL | Direction |
|---|---|---|---|---|
| 1 | **#14** | POST | `/api/v1/users/login` | Request & Response |
| 2 | **#27** | GET | `/api/v1/users/profile` | Response |

List the **exact history item numbers** from Burp proxy history.

### Vulnerability Information

[Clear explanation of what the vulnerability is and where it exists]

**Vulnerable Request (History Item #14):**
```
POST /api/v1/users/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"email":"victim@email.com","password":"test123"}
```

**Server Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json

{"error":"UserNotFoundException","message":"User does not exist"}
```

[Explain what's wrong — e.g., "The server returns a different error for non-existent users vs wrong passwords, enabling user enumeration."]

### Steps to Reproduce
1. Open Burp Suite and navigate to the Proxy HTTP History
2. Locate request **#14** — `POST /api/v1/users/login`
3. Send the request to **Repeater**
4. Change the `email` parameter to a known valid user
5. Observe the response changes from `UserNotFoundException` to `PASSWORD_VERIFIER`
6. This confirms user enumeration is possible

### Attack Scenario
A real-world attacker would:
1. **[Step 1]** — [What the attacker does first]
2. **[Step 2]** — [Next action with specific details]
3. **[Step 3]** — [How they escalate or exfiltrate]
4. **[Impact]** — [Business impact: data theft, account takeover, etc.]

> **Similar Real-World Report:** [Title](URL) — $X bounty
> (Reference from hackerone-reports when applicable)

### Impact

[What damage can result from this vulnerability — data breach, account takeover, financial loss, etc.]

### Remediation

> [!CAUTION]
> [Specific, actionable fix]

- [Fix item 1]
- [Fix item 2]
```

### After All Findings

Include:

1. **✅ Positive Security Observations** — Table of things correctly configured
2. **📋 Remediation Priority Matrix** — All findings ranked by severity with one-line fix

---

## Step 7 — Present to User

Present the report as an artifact walkthrough and notify the user with:
- Total findings by severity
- Top 3 most critical items
- Whether Repeater/Intruder were used for validation
