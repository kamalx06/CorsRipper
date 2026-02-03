# CorsRipper

CorsRipper is a CORS exploitation and impact analysis engine focused on identifying
real-world security issues caused by broken origin trust in modern web applications.

Unlike traditional CORS scanners that only flag header misconfigurations, CorsRipper
actively evaluates exploitability and escalation paths such as account takeover,
CSRF bypass, OAuth token exposure and misbinding, cache poisoning, and cross-user data exposure.

CorsRipper is designed for bug bounty hunters, penetration testers, and AppSec teams
who care about impact not just headers.

---

## What CorsRipper Does Differently

Most tools stop after detecting `Access-Control-Allow-Origin` reflection.

CorsRipper goes further by answering:

- Can attacker-controlled JavaScript read authenticated data?
- Can this CORS issue bypass CSRF protections?
- Can OAuth tokens be exposed or misbound?
- Can WebSocket connections be hijacked via Origin trust?
- Can CDN caching turn this into a cross-user vulnerability?
- Can timing differences leak authentication state?

---

## Threat Model Assumptions

CorsRipper assumes the attacker controls a web origin and can:

- Execute JavaScript in a victim’s browser
- Trigger cross-origin requests
- Leverage browser-enforced CORS behavior

CorsRipper does not assume XSS, network-level access, or direct server compromise.
All findings are derived from standard browser behavior.

---

## Exploit Chains Covered

CorsRipper actively detects and correlates the following chains:

- CORS → CSRF
- CORS → OAuth token exposure
- CORS → OAuth misbinding
- CORS → GraphQL introspection
- CORS → WebSocket Origin hijacking
- CORS → postMessage abuse
- CORS → CDN cache poisoning
- CORS → timing-based side-channel leaks

Where possible, findings are escalated and confirmed using a real browser.

---

## Key Capabilities

- Credentialed CORS misconfiguration detection
- Adaptive Origin mutation and parser confusion testing
- CDN-aware cache poisoning detection (Cloudflare, Akamai, Fastly, CloudFront)
- Preflight abuse analysis (methods and headers)
- OAuth token leakage and misbinding detection
- GraphQL introspection exposure via permissive CORS
- WebSocket Origin trust validation
- postMessage-based exploit chaining
- Timing side-channel analysis for opaque responses
- Optional browser confirmation using Playwright
- Raw HTTP request support (Burp-compatible)
- Structured, low-noise JSON reporting with stable finding IDs

---

## How Findings Are Escalated

CorsRipper does not assign severity based on single headers alone.

Findings are escalated by correlating multiple signals, including:

- Credential usage (`Access-Control-Allow-Credentials`)
- Origin reflection behavior
- Presence of sensitive or structured data
- Preflight permissions (methods and headers)
- Redirect behavior
- CDN involvement
- Browser-confirmed exploitability

This approach significantly reduces false positives and prioritizes
findings with real-world security impact.
 
---

## Installation

### Requirements
- Python 3.9+
- Playwright
- Chromium (Playwright-managed)

### Setup

Install runtime dependencies:

```bash
pip install -r requirements.txt
```
---

### Usage

Scan a single target:

```bash
python corsripper.py example.com
```

Scan multiple targets:

```bash
python corsripper.py -u targets.txt
```

Confirm exploitability with a real browser:

```bash
python corsripper.py example.com --browser-confirm
```

Scan using a raw HTTP request (Burp format):

```bash
python corsripper.py -r request.txt --browser-confirm
```

Save results to JSON:

```bash
python corsripper.py example.com -o results.json
```

---

## Proxy Support

CorsRipper supports HTTP, HTTPS, and SOCKS proxies for all requests.

This is useful for traffic inspection, interception, and anonymization.

### Examples

Route traffic through Burp or ZAP:

```bash
corsripper example.com --proxy http://127.0.0.1:8080
```
---

## Output Format

CorsRipper produces structured JSON output designed for automation,
reporting, and bug bounty submission.

Each finding includes:

* Stable finding ID
* Severity
* Exploitability level
* Impact description
* Evidence
* Origin context
* Confirmation status

### Example Finding

```json
{
  "id": "CORS-CSRF-CHAIN",
  "severity": "CRITICAL",
  "title": "CORS-enabled CSRF attack possible",
  "description": "Credentialed CORS allows cross-origin state-changing requests",
  "impact": "Account takeover or destructive actions",
  "confirmed": false,
  "exploitability": "potential"
}
```

---

## Why CorsRipper

Modern web applications increasingly rely on CORS as a security boundary.
When CORS is misconfigured, it often replaces or weakens authentication,
authorization, CSRF protection, and OAuth trust relationships.

CorsRipper is built to expose those failures and show their real-world impact.

---

## When CorsRipper Is Not Useful

CorsRipper is not intended for:

- Static websites with no authenticated endpoints
- APIs that do not rely on cookies, OAuth, or browser-based authentication
- Applications with fully static, already-audited CORS policies

The tool is designed for modern web applications where CORS acts
as an implicit security boundary.

---

## Findings Reference

A detailed explanation of all finding types and exploit chains is available in:

```
FINDINGS.md
```

---

## Stability and Finding IDs

Finding IDs in CorsRipper are stable across releases.

New findings may be added over time, but existing IDs will not change.
This allows safe automation, integration, and long-term reporting.
