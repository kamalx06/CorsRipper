# CorsRipper — Findings Reference

This document explains all findings produced by **CorsRipper**.

CorsRipper findings represent **failures of cross-origin trust**, not just incorrect HTTP headers.
In modern applications, CORS is frequently (and incorrectly) used as a **security control**, replacing or weakening:

* CSRF protections
* OAuth redirect and token binding
* Session isolation
* API authorization assumptions
* CDN cache separation

Each finding below documents:

* The **security boundary violated**
* The **real-world impact**
* The **typical exploitation path**

---

## Understanding Severity

CorsRipper assigns severity based on **impact and exploitability**, not configuration hygiene.

* **CRITICAL** — Account takeover, cross-user impact, token theft, or confirmed exploitation
* **HIGH** — Sensitive data exposure or reliable exploitation chains
* **MEDIUM** — Limited exposure or control bypass
* **INFO** — Informational or non-exploitable behavior

---

## CORS-WILDCARD-CREDS

**Severity:** CRITICAL
**Security boundary violated:** Same-origin authentication

**Description:**
The server responds with `Access-Control-Allow-Origin: *` while also enabling
`Access-Control-Allow-Credentials: true`.

**Why this matters:**
Browsers explicitly forbid this combination because it completely disables
origin-based authentication isolation.

**Impact:**
Any external website can read authenticated responses, including cookies
and session-protected data.

**Typical exploitation:**
A victim visits an attacker-controlled site while logged in.
The attacker’s JavaScript reads authenticated API responses directly.

---

## CORS-WILDCARD-NO-CREDS

**Severity:** INFO
**Security boundary violated:** Origin isolation (unauthenticated)

**Description:**
The application allows any origin but does not permit credentials.

**Impact:**
Public cross-origin read access. Usually low risk unless sensitive data
is returned without authentication.

**Typical exploitation:**
Unauthenticated scraping or information disclosure.

---

## CORS-CREDENTIAL-REFLECTION

**Severity:** CRITICAL
**Security boundary violated:** Cross-origin authentication trust

**Description:**
The server reflects the incoming `Origin` header in
`Access-Control-Allow-Origin` while allowing credentials.

**Why this matters:**
CORS becomes an **implicit authentication mechanism**.
Any origin becomes trusted if it can control the `Origin` header.

**Impact:**
Authenticated cross-origin data exfiltration.

**Typical exploitation:**
An attacker hosts a malicious site and steals authenticated API responses
from logged-in victims.

---

## CORS-BROWSER-CONFIRMED

**Severity:** CRITICAL
**Security boundary violated:** Verified browser-enforced isolation

**Description:**
CorsRipper successfully confirmed exploitability using a real browser
(Playwright), with credentials enabled.

**Why this matters:**
This eliminates false positives. The issue is exploitable under real
browser security rules.

**Impact:**
Confirmed authenticated data exposure.

**Typical exploitation:**
Same as credential reflection, but proven in a real browser.

---

## CORS-TIMING-SIDE-CHANNEL

**Severity:** CRITICAL
**Security boundary violated:** Cross-origin state confidentiality

**Description:**
Credentialed cross-origin requests produce measurable timing or behavioral
differences between authenticated and unauthenticated states.

**Why this matters:**
Even when browsers block response bodies, side channels can still leak
authentication state or resource existence.

**Impact:**
Cross-origin user tracking, session detection, or account enumeration.

**Typical exploitation:**
An attacker repeatedly issues cross-origin requests and infers authentication
status based on timing differences.

---

## CORS-OPAQUE-NO-SIGNAL

**Severity:** INFO

**Description:**
Credentialed cross-origin requests result in opaque responses with no
observable behavioral differences.

**Impact:**
No practical side-channel or data exposure identified.

---

## CORS-AUTHENTICATED-SESSION-EXPOSED

**Severity:** CRITICAL
**Security boundary violated:** Session confidentiality

**Description:**
Authenticated session data is accessible via CORS when using cookies
from a provided raw HTTP request.

**Impact:**
Full account compromise depending on exposed endpoints.

**Typical exploitation:**
Authenticated API requests are executed cross-origin using victim cookies.

---

## CORS-CACHE-POISONING-POTENTIAL

**Severity:** HIGH
**Security boundary violated:** Cache isolation

**Description:**
Dynamic `Access-Control-Allow-Origin` responses are served without
`Vary: Origin`.

**Why this matters:**
Shared caches (especially CDNs) may serve attacker-controlled CORS headers
to other users.

**Impact:**
Potential cross-user exposure.

**Typical exploitation:**
An attacker poisons a cached ACAO value that affects subsequent users.

---

## CORS-CACHE-POISONING-CONFIRMED

**Severity:** CRITICAL
**Security boundary violated:** Cross-user isolation

**Description:**
Cache poisoning was confirmed by observing attacker-controlled origins
persist across requests.

**Impact:**
Cross-user authenticated data exposure.

**Typical exploitation:**
One attacker request affects all users served from the cache.

---

## CORS-CDN-CACHE-POISONING

**Severity:**

* **CRITICAL** — credentials enabled
* **MEDIUM** — no credentials

**Security boundary violated:** CDN cache integrity

**Description:**
Dynamic ACAO values are cached by a shared CDN without origin variation.

**Impact:**
Large-scale cross-user exposure when credentials are enabled.

---

## CORS-MULTIPLE-ACAO

**Severity:** HIGH
**Security boundary violated:** Header interpretation consistency

**Description:**
Multiple `Access-Control-Allow-Origin` headers are present. Different browsers, proxies, or middleware may select different ACAO values.

**Impact:**
Different components may interpret the CORS policy inconsistently.

**Typical exploitation:**
Bypassing origin validation via parsing ambiguity.

---

## CORS-REDIRECT-ACAO-MISMATCH

Severity: HIGH  
Security boundary violated: Redirect trust and origin consistency

Description:
The value of `Access-Control-Allow-Origin` changes across redirect
responses within a single request chain.

Why this matters:
Many applications perform authorization or trust decisions before
redirecting. If CORS headers change mid-chain, origin validation may be
performed on one response while data is returned on another.

Impact:
CORS confusion that can be chained with open redirects, OAuth flows,
or credentialed requests to bypass origin validation.

Typical exploitation:
An attacker forces a request through a redirect chain where the initial
response validates origin and the final response exposes authenticated
data.

---

## CORS-CREDENTIALS-ACROSS-REDIRECTS

**Severity:** CRITICAL
**Security boundary violated:** Redirect-based session isolation

**Description:**
Credentialed CORS remains active across redirects.

**Impact:**
Authenticated data exposure via redirection abuse.

---

## CORS-ADAPTIVE-ORIGIN-BYPASS

**Severity:** HIGH
**Security boundary violated:** Origin validation logic

**Description:**
Malformed or crafted origins (Unicode, encoding tricks) are accepted.

**Impact:**
Bypass of origin allowlists.

---

## CORS-SENSITIVE-STRUCTURED-DATA

**Severity:** CRITICAL
**Security boundary violated:** API data confidentiality

**Description:**
Structured sensitive data (JSON APIs) is accessible cross-origin.

**Impact:**
Exposure of tokens, identifiers, or account data.

---

## CORS-SENSITIVE-UNSTRUCTURED-DATA

**Severity:** HIGH

**Description:**
Unstructured sensitive data (HTML, text) is accessible cross-origin.

---

## CORS-SENSITIVE-HEADER-CREDS

**Severity:** HIGH
**Security boundary violated:** Request confidentiality

**Description:**
Sensitive request headers are allowed in credentialed CORS requests.

**Impact:**
Token or session leakage.

---

## CORS-DANGEROUS-METHOD

**Severity:** MEDIUM
**Security boundary violated:** State integrity

**Description:**
State-changing HTTP methods are permitted cross-origin, severity escalates when credentials are enabled

---

## CORS-PREFLIGHT-ABUSE

**Severity:** HIGH
**Security boundary violated:** Preflight trust

**Description:**
Preflight responses allow dangerous methods or headers from untrusted origins.

---

## CORS-PREFLIGHT-WILDCARD-CREDS

**Severity:** CRITICAL

**Description:**
Preflight allows credentials with wildcard ACAO.

---

## CORS-JSONP-ENABLED

**Severity:** HIGH
**Security boundary violated:** Script execution isolation

**Description:**
Endpoint supports JSONP with attacker-controlled callback.

---

## CORS-OAUTH-TOKEN-EXPOSURE

**Severity:** CRITICAL
**Security boundary violated:** OAuth client and token binding

**Description:**
OAuth token responses are accessible via credentialed cross-origin requests.

**Impact:**
Immediate account takeover.

---

## CORS-CSRF-CHAIN

**Severity:** CRITICAL
**Security boundary violated:** CSRF protections

**Description:**
Credentialed CORS combined with state-changing methods bypasses CSRF defenses.

---

## CORS-WEBSOCKET-ORIGIN-TRUST

**Severity:** CRITICAL
**Security boundary violated:** WebSocket origin trust

**Description:**
WebSocket handshakes accept attacker-controlled origins while authenticating
via cookies.

**Impact:**
Real-time authenticated data exfiltration.

---

## CORS-POSTMESSAGE-CHAIN

**Severity:** CRITICAL
**Security boundary violated:** Cross-window trust

**Description:**
`postMessage` abuse triggers authenticated CORS requests without proper
origin validation.

---

## TLS-VALIDATION-FAILED

**Severity:** INFO

**Description:**
TLS certificate validation failed and verification was disabled.

---

## CORS-HTTPS-DOWNGRADE

Severity: HIGH  
Security boundary violated: Transport security during CORS enforcement

Description:
A CORS-enabled request is redirected from HTTPS to HTTP while still
returning CORS headers.

Impact:
Exposure of CORS-protected data to man-in-the-middle attackers.

Typical exploitation:
An attacker intercepts downgraded traffic and injects or reads responses.

---

## CORS-GRAPHQL-INTROSPECTION

Severity: CRITICAL  
Security boundary violated: API schema confidentiality

Description:
The GraphQL introspection endpoint is accessible via credentialed
cross-origin requests after a permissive CORS preflight.

Why this matters:
GraphQL schemas expose the complete API surface, including object types,
relationships, mutations, and authorization boundaries. When accessible
cross-origin, attackers can enumerate privileged operations directly
from a victim’s browser.

Impact:
Full API schema disclosure, discovery of sensitive mutations, and
authorization bypass chaining.

Typical exploitation:
An attacker-controlled origin issues an introspection query after a
successful CORS preflight and uses the schema to target privileged
operations.

---
