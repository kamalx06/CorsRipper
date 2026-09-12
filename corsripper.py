import requests
import argparse
import random
import json
import re
import socket
import ssl
import base64
import time
import os
import sys
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.sync_api import sync_playwright
from dataclasses import dataclass, asdict
from typing import Optional, Dict


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    description: str
    impact: str
    confirmed: bool
    exploitability: str
    evidence: Dict[str, any]
    origins: set
    reasons: list = None

    def to_dict(self):
        d = asdict(self)
        d["origins"] = sorted(self.origins)
        if self.reasons:
            d["reasons"] = self.reasons
        return d

    def __post_init__(self):
        if self.reasons is None:
            self.reasons = []


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2_1) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
]

ORIGINS = [
    "null",
    "https://evil.com",
    "https://a.evil.com",
    "https://trusted.com.evil.com",
    "https://trusted.com%2eevil.com",
    "https://evil.com@trusted.com",
    "https://localhost:3000",
    "http://127.0.0.1:3000",
    "https://trusted.com.evil.com",
    "https://trusted.com\u0000.evil.com",
    "https://trusted.com ",
    "https://trusted.com\t.evil.com",
    "https://trusted.com。",
    "https://xn--trusted-9k9.com",
]

IPV6_ORIGINS = {
    "http://[::1]",
    "http://[::ffff:127.0.0.1]",
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    "http://[::ffff:7f00:1]",
    "http://[::ffff:127.1]",
}

CDN_HEADERS = {
    "cloudflare": ["cf-ray", "cf-cache-status"],
    "akamai": ["akamai-x-cache-on"],
    "fastly": ["fastly-debug-digest", "x-served-by"],
    "cloudfront": ["x-amz-cf-id", "via"],
}

WAF_PROFILES = {
    "cloudflare": {
        "header_variants": [
            "Origin",
            "ORIGIN",
            "Origin ",
            "Origin\t",
        ],
        "extra_headers": {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        },
        "delay": (0.2, 0.8),
    },
    "akamai": {
        "header_variants": [
            "Origin",
            "ORIGIN",
            "origin",
        ],
        "extra_headers": {
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
        },
        "delay": (0.3, 1.2),
    },
}

PREFLIGHT_SCENARIOS = [
    ("POST", "Authorization"),
    ("PUT", "Authorization"),
    ("POST", "X-API-Key"),
    ("DELETE", "X-API-Key"),
    ("POST", "Content-Type"),
    ("PATCH", "Content-Type"),
    ("POST", "Cookie"),
    ("POST", "X-CSRF-Token"),
]

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-amz-security-token",
}

# ACCURACY: only match real secret material, not generic words such as "email"
# or "password" that appear on every login page. This drops the vast majority
# of "CORS-SENSITIVE-*" false positives while keeping true positives.
SENSITIVE_REGEX = re.compile(
    r"("
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"      # JWT
    r"|\bBearer\s+[A-Za-z0-9\-_.=]{16,}"                                   # Bearer token
    r"|\"(?:access|refresh|id)[_-]?token\"\s*:\s*\"[^\"]{8,}\""            # token JSON
    r"|\"api[_-]?key\"\s*:\s*\"[^\"]{8,}\""
    r"|\"client[_-]?secret\"\s*:\s*\"[^\"]{4,}\""
    r"|\"password\"\s*:\s*\"[^\"]{4,}\""
    r"|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"                # real email
    r")",
    re.I,
)

# ACCURACY: OAuth detection now requires the actual JSON key:value pattern,
# not just the presence of the word "access_token" in the body.
OAUTH_REGEX = re.compile(
    r"\"(access_token|id_token|refresh_token|token_type)\"\s*:\s*\""
    r"|\"expires_in\"\s*:\s*\d+",
    re.I,
)

TIMEOUT = (5, 10)
MAX_THREADS = 50
DEBUG = False


def dbg(*args):
    if DEBUG:
        print("[DEBUG]", *args, flush=True)


def debug_request_response(resp, *args, **kwargs):
    dbg(
        "HTTP",
        f"{resp.request.method} {resp.request.url}",
        f"Status={resp.status_code}",
        f"Origin={resp.request.headers.get('Origin')}",
        f"ACAO={resp.headers.get('Access-Control-Allow-Origin')}",
        f"ACAC={resp.headers.get('Access-Control-Allow-Credentials')}",
        f"Vary={resp.headers.get('Vary')}",
    )
    return resp


def normalize_urls(url):
    if url.startswith("http://") or url.startswith("https://"):
        return [url]
    return [f"https://{url}", f"http://{url}"]


def generate_dynamic_origins(url):
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return []

    parts = host.split(".")
    base = ".".join(parts[-2:]) if len(parts) >= 2 else host

    return {
        f"https://{base}.evil.com",
        f"https://{host}.evil.com",
        f"https://evil.{host}",
        f"https://{host.replace('.', '-')}.evil.com",
        f"https://{host}@evil.com",
        f"https://evil.com@{host}",
        f"https://{host}\u0000.evil.com",
    }


def generate_parser_confusion_origins(host):
    return {
        f"https://{host}..evil.com",
        f"https://{host}/.evil.com",
        f"https://{host}%2f.evil.com",
        f"https://{host}%5c.evil.com",
        f"https://{host}%00.evil.com",
        f"https://{host}@evil.com",
        f"https://{host}:443@evil.com",
        f"https://{host}#@evil.com",
    }


def detect_cdn(headers):
    for cdn, sigs in CDN_HEADERS.items():
        for h in sigs:
            if h in headers:
                return cdn
    return None


# ACCURACY: replaced keyword counting on raw text with a real JSON walk that
# only counts sensitive keys inside structured objects.
_STRUCTURED_SENSITIVE_KEYS = {
    "id", "userid", "user_id", "user", "username", "email",
    "token", "access_token", "refresh_token", "id_token",
    "api_key", "apikey", "role", "roles", "account", "account_id",
    "session", "session_id", "auth", "auth_token", "password",
    "secret", "client_secret",
}


def structured_data_detector(text):
    text = text.strip()
    if not text or text[0] not in "{[":
        return False
    try:
        data = json.loads(text)
    except Exception:
        return False

    found = 0

    def walk(obj):
        nonlocal found
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and k.lower() in _STRUCTURED_SENSITIVE_KEYS:
                    found += 1
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return found >= 3


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def strict_origin_equal(acao, origin):
    """
    Exact origin equivalence matching the browser's CORS rules:
    scheme, hostname and effective port must match byte-for-byte
    (default ports 443/80 are treated as equivalent to explicit ones).
    """
    try:
        a = urlparse(acao.strip())
        o = urlparse(origin.strip())
        if a.scheme != o.scheme:
            return False
        if a.hostname != o.hostname:
            return False
        a_port = a.port if a.port is not None else _default_port(a.scheme)
        o_port = o.port if o.port is not None else _default_port(o.scheme)
        return a_port == o_port
    except Exception:
        return False


def origin_accepted_by_server(acao, origin):
    """
    True only when the server's ACAO would actually be accepted by a
    browser for the given Origin. `null` only matches a literal null
    origin. No subdomain-suffix shortcuts.
    """
    if not acao or not origin:
        return False

    acao = acao.strip()

    if acao == "*":
        return True
    if acao == "null":
        return origin.strip() == "null"

    return strict_origin_equal(acao, origin)


def header_safe(value: str) -> bool:
    try:
        value.encode("latin-1")
        return True
    except UnicodeEncodeError:
        return False


def is_probable_json(resp, max_size=2_000_000):
    # ACCURACY: avoid parsing giant payloads; also require Content-Type to look
    # JSON-ish or the body to start with a JSON token before parsing.
    try:
        content = resp.content or b""
    except Exception:
        content = b""
    if len(content) > max_size:
        return False
    ct = (resp.headers.get("Content-Type") or "").lower()
    stripped = (resp.text or "").lstrip()
    if "json" not in ct and not stripped.startswith(("{", "[")):
        return False
    try:
        json.loads(resp.text)
        return True
    except Exception:
        return False


def _is_real_jsonp(body: str, cb: str) -> bool:
    """
    Validate that a JSONP response is genuine: starts with the callback
    invocation and wraps a payload that actually parses as JSON.
    """
    if not body.startswith(cb + "("):
        return False
    inner = body[len(cb) + 1:].rstrip()
    if inner.endswith(";"):
        inner = inner[:-1].rstrip()
    if inner.endswith(")"):
        inner = inner[:-1]
    try:
        json.loads(inner)
        return True
    except Exception:
        return False


# ACCURACY: new helpers used to avoid reporting cache-poisoning on responses
# that shared caches would never store in the first place.
_CACHE_NO_STORE_TOKENS = ("no-store", "private", "no-cache")


def response_is_cacheable(headers: Dict[str, str]) -> bool:
    h = {k.lower(): (v or "").lower() for k, v in headers.items()}
    cc = h.get("cache-control", "")
    pragma = h.get("pragma", "")
    if any(tok in cc for tok in _CACHE_NO_STORE_TOKENS):
        return False
    if "no-cache" in pragma:
        return False
    # Explicitly cacheable directives
    if any(tok in cc for tok in ("public", "max-age", "s-maxage")):
        return True
    if "expires" in h:
        return True
    # Heuristically cacheable status codes without explicit directives
    return True


def served_from_cache(headers: Dict[str, str]) -> bool:
    h = {k.lower(): (v or "") for k, v in headers.items()}
    xcache = h.get("x-cache", "").lower()
    if "hit" in xcache and "miss" not in xcache:
        return True
    cf = h.get("cf-cache-status", "").lower()
    if cf in {"hit", "revalidated", "stale"}:
        return True
    age = h.get("age")
    if age and age.isdigit() and int(age) > 0:
        return True
    return False


def build_poison_headers(headers, poison_origin):
    poisoned = headers.copy()
    poisoned["Origin"] = poison_origin
    return poisoned


def build_session(proxy=None):
    session = requests.Session()

    adapter = requests.adapters.HTTPAdapter(
        pool_connections=50,
        pool_maxsize=50,
        max_retries=2,
    )

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if proxy:
        session.proxies = {
            "http": proxy,
            "https": proxy,
        }
    session.hooks["response"].append(debug_request_response)
    return session


def send_request(
    session,
    url,
    headers=None,
    method="GET",
    data=None,
    verify=False,
    allow_redirects=False,
    profile=None,
):

    final_headers = {}

    if headers:
        final_headers.update(headers)

    if profile:
        final_headers.update(profile.get("extra_headers", {}))

    if profile and profile.get("delay"):
        time.sleep(random.uniform(*profile["delay"]))

    dbg(
        "REQUEST",
        "method=", method,
        "url=", url,
        "verify=", verify,
        "headers=", final_headers,
    )

    resp = session.request(
        method=method,
        url=url,
        headers=final_headers,
        data=data,
        timeout=TIMEOUT,
        verify=verify,
        allow_redirects=allow_redirects,
    )

    dbg(
        "RESPONSE",
        "status=", resp.status_code,
        "final_url=", resp.url,
        "ACAO=", resp.headers.get("Access-Control-Allow-Origin"),
        "ACAC=", resp.headers.get("Access-Control-Allow-Credentials"),
        "Vary=", resp.headers.get("Vary"),
    )

    return resp


def browser_checker():
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            p.chromium.launch(headless=True)
    except Exception:
        print(
            "\nPlaywright browser not found.\n"
            "    Browser-based confirmation requires Chromium.\n\n"
            "    Run:\n"
            "        playwright install chromium\n"
        )
        sys.exit(2)


def check_cors(url, enable_browser_confirm=False, base_request=None, proxy=None):
    session = build_session(proxy)
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return None
    dynamic_origins = generate_dynamic_origins(url)
    parser_origins = generate_parser_confusion_origins(host)
    all_origins = set(ORIGINS) | dynamic_origins | IPV6_ORIGINS | parser_origins
    findings = []
    skipped_origins = set()
    cache_poisoning_reported = False
    browser_confirmed = False
    browser_attempted = False
    browser = None
    p = None
    method = "GET"
    data = None
    profile = None
    ws_tested = False

    if base_request:
        method = base_request["method"]
        data = base_request.get("body")

    def add(
        fid,
        severity,
        title,
        description,
        impact,
        origin=None,
        confirmed=False,
        exploitability="theoretical",
        evidence=None,
        reason=None,
    ):
        nonlocal findings

        for f in findings:
            if f.id == fid:
                sev_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                if sev_order.index(severity) > sev_order.index(f.severity):
                    f.severity = severity
                f.confirmed = f.confirmed or confirmed
                exp_order = ["theoretical", "potential", "confirmed"]
                if exp_order.index(exploitability) > exp_order.index(f.exploitability):
                    f.exploitability = exploitability
                if origin:
                    f.origins.add(origin)
                if evidence:
                    for k, v in evidence.items():
                        if k not in f.evidence:
                            f.evidence[k] = []
                        if v not in f.evidence[k]:
                            f.evidence[k].append(v)
                if reason:
                    if not f.reasons:
                        f.reasons = []
                    if reason not in f.reasons:
                        f.reasons.append(reason)
                return
        findings.append(
            Finding(
                id=fid,
                severity=severity,
                title=title,
                description=description,
                impact=impact,
                confirmed=confirmed,
                exploitability=exploitability,
                evidence={
                    k: ([v] if not isinstance(v, list) else v)
                    for k, v in (evidence or {}).items()
                },
                origins={origin} if origin else set(),
                reasons=[reason] if reason else [],
            )
        )

    profile = None
    for origin in all_origins:
        if not header_safe(origin):
            skipped_origins.add(origin)
            continue
        time.sleep(random.uniform(0.1, 0.7))
        headers = {"Origin": origin, "User-Agent": random.choice(USER_AGENTS)}

        if base_request:
            for k, v in base_request["headers"].items():
                lk = k.lower()
                if lk not in {"origin", "content-length", "host"}:
                    headers[k] = v

        effective_data = (
            data if method.upper() in {"POST", "PUT", "PATCH"} else None
        )

        try:
            try:
                r = send_request(
                    session, url,
                    headers=headers,
                    method=method,
                    data=effective_data,
                    verify=True,
                    allow_redirects=False,
                    profile=profile,
                )

            except requests.exceptions.SSLError:
                add(
                    fid="TLS-VALIDATION-FAILED",
                    severity="INFO",
                    title="TLS validation failure",
                    description="TLS certificate validation failed, request retried without verification",
                    impact="Possible internal CA or self-signed certificate",
                    confirmed=False,
                    reason=f"TLS certificate validation failed when connecting to '{url}'",
                    exploitability="theoretical",
                )
                r = send_request(
                    session, url,
                    headers=headers,
                    method=method,
                    data=effective_data,
                    verify=False,
                    allow_redirects=False,
                    profile=profile,
                )

            try:
                acao_headers = r.raw.headers.get_all("Access-Control-Allow-Origin")
            except Exception:
                acao_headers = [r.headers.get("Access-Control-Allow-Origin")]

            if acao_headers and len(acao_headers) > 1:
                add(
                    fid="CORS-MULTIPLE-ACAO",
                    severity="HIGH",
                    title="Multiple Access-Control-Allow-Origin headers detected",
                    description="Multiple ACAO headers may enable ambiguity-based CORS bypass",
                    impact="Origin validation confusion",
                    confirmed=False,
                    reason=f"Multiple Access-Control-Allow-Origin headers returned: {acao_headers}",
                    evidence={"acao_headers": str(acao_headers)},
                )

            if (
                url.startswith("https://")
                and r.url.startswith("http://")
                and r.headers.get("Access-Control-Allow-Origin")
            ):
                add(
                    fid="CORS-HTTPS-DOWNGRADE",
                    severity="HIGH",
                    title="HTTPS to HTTP downgrade in CORS flow",
                    description="Request redirected from HTTPS to HTTP",
                    impact="Man-in-the-middle exposure during CORS handling",
                    confirmed=False,
                    reason=f"HTTPS request to '{url}' was redirected to HTTP endpoint '{r.url}' with ACAO present",
                    exploitability="potential",
                    evidence={"final_url": r.url},
                )

            cdn = detect_cdn({k.lower(): v for k, v in r.headers.items()})
            if cdn in WAF_PROFILES:
                profile = WAF_PROFILES[cdn]
            ct = r.headers.get("Content-Type", "").lower()
            acao = r.headers.get("Access-Control-Allow-Origin", "").strip()
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
            acah = r.headers.get("Access-Control-Allow-Headers", "").lower()
            acam = r.headers.get("Access-Control-Allow-Methods", "").lower()
            vary = r.headers.get("Vary", "").lower()
            vary_headers = {v.strip() for v in vary.split(",") if v.strip()}
            cache_control = r.headers.get("Cache-Control", "").lower()
            pragma = r.headers.get("Pragma", "").lower()

            # ACCURACY: gate cache-poisoning "potential" on the response being
            # actually cacheable by a shared cache (respect Cache-Control).
            if (
                not cache_poisoning_reported
                and acao
                and acao != "*"
                and "origin" not in vary_headers
                and response_is_cacheable(r.headers)
                and ("text/html" in ct or "json" in ct)
            ):

                cache_poisoning_reported = True

                add(
                    fid="CORS-CACHE-POISONING-POTENTIAL",
                    severity="HIGH",
                    title="CORS cache poisoning risk",
                    description="Dynamic Access-Control-Allow-Origin without Vary: Origin",
                    impact="Shared caches may serve attacker-controlled ACAO to other users",
                    origin=origin,
                    confirmed=False,
                    reason=f"Dynamic ACAO '{acao}' returned without 'Vary: Origin'",
                    exploitability="theoretical",
                    evidence={
                        "access-control-allow-origin": acao,
                        "vary": r.headers.get("Vary", ""),
                    },
                )

                if cdn and acac == "true":
                    add(
                        fid="CORS-CDN-CACHE-POISONING",
                        severity="CRITICAL",
                        title=f"CORS cache poisoning via {cdn}",
                        description="Dynamic ACAO without Vary: Origin on CDN-backed endpoint",
                        impact="Cross-user credentialed data exposure via shared CDN cache",
                        origin=origin,
                        confirmed=False,
                        reason=f"CDN '{cdn}' served dynamic ACAO '{acao}' without 'Vary: Origin' while ACAC=true",
                        exploitability="potential",
                        evidence={
                            "cdn": cdn,
                            "access-control-allow-origin": acao,
                            "access-control-allow-credentials": acac,
                            "vary": r.headers.get("Vary", ""),
                        },
                    )
                elif cdn:
                    add(
                        fid="CORS-CDN-CACHE-POISONING",
                        severity="MEDIUM",
                        title=f"CORS cache poisoning via {cdn}",
                        description="Dynamic ACAO without Vary: Origin on CDN-backed endpoint (no credentials)",
                        impact="Public or unauthenticated cross-origin data may be cached and reused",
                        origin=origin,
                        confirmed=False,
                        reason=f"CDN '{cdn}' served dynamic ACAO '{acao}' without 'Vary: Origin'",
                        exploitability="theoretical",
                        evidence={
                            "cdn": cdn,
                            "access-control-allow-origin": acao,
                            "vary": r.headers.get("Vary", ""),
                        },
                    )
                if acac == "true":
                    poison_origin = f"https://cache-{random.randint(1000, 9999)}.evil.com"
                    poison_headers = build_poison_headers(headers, poison_origin)
                    try:
                        pr = send_request(
                            session,
                            url,
                            headers=poison_headers,
                            method=method,
                            data=effective_data,
                            verify=False,
                            allow_redirects=False,
                            profile=profile,
                        )

                        poisoned_acao = pr.headers.get("Access-Control-Allow-Origin", "")

                        # ACCURACY: previous logic confirmed "cache poisoning"
                        # on any origin reflection. Now we additionally require
                        # either an actual cache-hit indicator OR that a fresh
                        # benign-Origin request returns the poisoned ACAO.
                        if poison_origin in poisoned_acao:
                            reflected_from_cache = served_from_cache(pr.headers)

                            # Follow-up with a benign Origin to detect a poisoned cache entry.
                            benign_origin = f"https://benign-{random.randint(1000, 9999)}.example.com"
                            benign_headers = build_poison_headers(headers, benign_origin)
                            try:
                                br = send_request(
                                    session,
                                    url,
                                    headers=benign_headers,
                                    method=method,
                                    data=effective_data,
                                    verify=False,
                                    allow_redirects=False,
                                    profile=profile,
                                )
                                benign_acao = br.headers.get("Access-Control-Allow-Origin", "")
                                poisoned_cache_replay = (
                                    poison_origin in benign_acao
                                    and poison_origin not in benign_acao.replace(poison_origin, "")
                                ) and (benign_origin not in benign_acao)
                            except Exception:
                                poisoned_cache_replay = False

                            if reflected_from_cache or poisoned_cache_replay:
                                add(
                                    fid="CORS-CACHE-POISONING-CONFIRMED",
                                    severity="CRITICAL",
                                    title="CORS cache poisoning confirmed",
                                    description="Injected Origin persisted in ACAO response",
                                    impact="Authenticated cross-origin data leakage to arbitrary origins",
                                    origin=poison_origin,
                                    confirmed=True,
                                    reason=f"Injected Origin '{poison_origin}' was persisted in ACAO response",
                                    exploitability="confirmed",
                                    evidence={
                                        "poison_origin": poison_origin,
                                        "access-control-allow-origin": poisoned_acao,
                                        "served_from_cache": str(reflected_from_cache),
                                        "poisoned_cache_replay": str(poisoned_cache_replay),
                                    },
                                )
                    except Exception:
                        pass

            if acao == "*" and acac == "true":
                add(
                    fid="CORS-WILDCARD-CREDS",
                    severity="CRITICAL",
                    title="Wildcard ACAO with credentials enabled",
                    description="Server allows credentials with Access-Control-Allow-Origin: *",
                    impact="Authenticated cross-origin data theft",
                    confirmed=False,
                    reason=(
                        f"ACAO='*' returned together with ACAC=true. Browsers "
                        f"block this by spec, but the server-side config is unsafe "
                        f"and will break if the browser policy changes."
                    ),
                    exploitability="potential",
                    evidence={
                        "access-control-allow-origin": acao,
                        "access-control-allow-credentials": acac,
                    },
                )
            elif acao == "*":
                add(
                    fid="CORS-WILDCARD-NO-CREDS",
                    severity="INFO",
                    title="Wildcard Access-Control-Allow-Origin without credentials",
                    description="Server allows any origin but does not permit credentials",
                    impact="Public cross-origin read access (low risk)",
                    confirmed=False,
                    reason=f"ACAO='*' allows all origins without credential restriction",
                    exploitability="theoretical",
                    evidence={"access-control-allow-origin": "*"},
                )
            sensitive = bool(SENSITIVE_REGEX.search(r.text))
            json_like = is_probable_json(r)
            structured = structured_data_detector(r.text)

            if (
                OAUTH_REGEX.search(r.text)
                and acac == "true"
                and acao
                and acao != "*"
                and origin_accepted_by_server(acao, origin)
                and ("json" in ct or r.text.strip().startswith("{"))
            ):
                add(
                    fid="CORS-OAUTH-TOKEN-EXPOSURE",
                    severity="CRITICAL",
                    title="OAuth token exposed via CORS",
                    description="OAuth token material accessible cross-origin with credentials",
                    impact="Immediate account takeover",
                    origin=origin,
                    confirmed=False,
                    reason=f"OAuth token material returned in credentialed CORS response for Origin '{origin}'",
                    exploitability="potential",
                )

                if "authorization_code" in r.text or "client_id" in r.text:
                    add(
                        fid="OAUTH-MISBINDING",
                        severity="CRITICAL",
                        title="OAuth token misbinding via CORS",
                        description="OAuth token exchange endpoint accessible cross-origin",
                        impact="Attacker can bind victim session to attacker OAuth client",
                        reason=f"OAuth token exchange endpoint accessible cross-origin for Origin '{origin}'",
                        exploitability="potential",
                        origin=origin,
                    )

            if (
                acac == "true"
                and acao
                and acao != "*"
                and origin_accepted_by_server(acao, origin)
            ):
                add(
                    fid="CORS-CREDENTIAL-REFLECTION",
                    severity="CRITICAL",
                    title="Origin reflected with credentials enabled",
                    description="Origin reflected in ACAO while credentials are allowed",
                    impact="Authenticated cross-origin data exfiltration",
                    origin=origin,
                    confirmed=False,
                    reason=f"ACAO '{acao}' accepted attacker Origin '{origin}' while ACAC=true",
                    exploitability="theoretical",
                    evidence={
                        "access-control-allow-origin": acao,
                        "access-control-allow-credentials": acac,
                    },
                )
                try:
                    if not ws_tested and test_websocket_origin(url, origin):
                        add(
                            fid="CORS-WEBSOCKET-ORIGIN-TRUST",
                            severity="CRITICAL",
                            title="WebSocket accepts attacker-controlled Origin",
                            description="WebSocket handshake succeeded with untrusted Origin",
                            impact="Cookie-authenticated real-time data exfiltration",
                            origin=origin,
                            confirmed=True,
                            reason=f"WebSocket handshake accepted attacker Origin '{origin}'",
                            exploitability="confirmed",
                        )
                        ws_tested = True
                except Exception:
                    pass

                state_changing = any(m in acam for m in ["post", "put", "delete", "patch"])
                if state_changing:
                    add(
                        fid="CORS-CSRF-CHAIN",
                        severity="CRITICAL",
                        title="CORS-enabled CSRF attack possible",
                        description="Credentialed CORS allows cross-origin state-changing requests",
                        impact="Account takeover or destructive actions",
                        origin=origin,
                        exploitability="potential",
                        evidence={
                            "methods": acam,
                            "credentials": acac,
                        },
                    )

                if (
                    base_request
                    and "cookie" in {h.lower() for h in base_request["headers"]}
                ):
                    add(
                        fid="CORS-AUTHENTICATED-SESSION-EXPOSED",
                        severity="CRITICAL",
                        title="Authenticated CORS exposure via cookie-based session",
                        description="CORS misconfiguration allows access to authenticated session data",
                        impact="Account compromise via cross-origin requests",
                        origin=origin,
                        confirmed=False,
                        reason=f"Cookie-authenticated session accessible from Origin '{origin}' via CORS",
                        exploitability="theoretical",
                        evidence={"auth": "cookie"},
                    )

            # ---------------------------------------------------------------
            # Browser-based confirmation. Runs only for a per-origin
            # reflection (wildcard is handled by CORS-WILDCARD-CREDS above).
            # ---------------------------------------------------------------
            if (
                enable_browser_confirm
                and not browser_confirmed
                and not browser_attempted
                and acac == "true"
                and acao
                and acao != "*"
                and origin_accepted_by_server(acao, origin)
            ):
                try:
                    browser_attempted = True

                    if browser is None:
                        p = sync_playwright().start()
                        browser = p.chromium.launch(
                            headless=True,
                            proxy={"server": proxy} if proxy else None,
                            args=["--disable-dev-shm-usage", "--no-sandbox"],
                        )
                    browser_result = browser_cors_confirm(browser, url, origin)
                    if browser_result.get("postmessage_leak"):
                        add(
                            fid="CORS-POSTMESSAGE-CHAIN",
                            severity="CRITICAL",
                            title="postMessage + CORS exploit chain",
                            description="postMessage triggers authenticated fetch without origin validation",
                            impact="Cross-origin account data exfiltration",
                            origin=origin,
                            confirmed=True,
                            reason=f"postMessage triggered authenticated cross-origin fetch from '{origin}'",
                            exploitability="confirmed",
                        )

                    if browser_result.get("ok") and browser_result.get("body_readable"):
                        add(
                            fid="CORS-BROWSER-CONFIRMED",
                            severity="CRITICAL",
                            title="Browser-confirmed credentialed CORS exploit",
                            description="Exploit validated via real browser fetch with credentials",
                            impact="Confirmed cross-origin data exfiltration",
                            origin=origin,
                            confirmed=True,
                            reason=f"Browser successfully read authenticated response cross-origin from '{origin}'",
                            exploitability="confirmed",
                            evidence={
                                "browser": "playwright",
                                "escalates": "CORS-CREDENTIAL-REFLECTION",
                            },
                        )
                        browser_confirmed = True

                    elif (
                        browser_result.get("opaque")
                        and browser_result.get("timing_with_creds") is not None
                        and browser_result.get("timing_without_creds") is not None
                    ):
                        t_cred = browser_result["timing_with_creds"]
                        t_no = browser_result["timing_without_creds"]
                        delta = abs(t_cred - t_no)
                        max_t = max(t_cred, t_no, 1.0)
                        ratio = delta / max_t

                        # ACCURACY: require both a large absolute delta AND a
                        # substantial ratio to reduce random-jitter false positives.
                        if delta >= 500 and ratio >= 0.5:
                            add(
                                fid="CORS-TIMING-SIDE-CHANNEL",
                                severity="CRITICAL",
                                title="Timing-based CORS side-channel leak",
                                description="Credentialed and uncredentialed requests show measurable timing differences",
                                impact="Cross-origin inference of authenticated state",
                                origin=origin,
                                confirmed=True,
                                reason=f"Timing difference of {round(delta, 2)}ms observed between credentialed and uncredentialed requests",
                                exploitability="confirmed",
                                evidence={
                                    "timing_with_creds_ms": round(t_cred, 2),
                                    "timing_without_creds_ms": round(t_no, 2),
                                    "timing_delta_ms": round(delta, 2),
                                    "timing_ratio": round(ratio, 3),
                                },
                            )
                        else:
                            add(
                                fid="CORS-OPAQUE-NO-SIGNAL",
                                severity="INFO",
                                title="Opaque CORS response without timing signal",
                                description="No measurable timing difference detected",
                                impact="No observable side-channel leakage",
                                origin=origin,
                                confirmed=False,
                                reason=f"Opaque CORS response observed without measurable timing difference",
                                exploitability="theoretical",
                            )

                except Exception as e:
                    add(
                        fid="CORS-BROWSER-VERIFY-FAILED",
                        severity="INFO",
                        title="Browser-based verification failed",
                        description="Playwright execution failed during CORS verification",
                        impact="Exploitability could not be confirmed via browser automation",
                        confirmed=False,
                        reason=f"Browser-based verification failed with error: {e}",
                        exploitability="theoretical",
                        evidence={"error": str(e)},
                    )

            # Stop scanning further origins once a real browser confirms.
            if browser_confirmed:
                break

            # ---------------------------------------------------------------
            # Sensitive-data disclosure (independent of --browser-confirm).
            # ---------------------------------------------------------------
            if (
                acac == "true"
                and acao
                and acao != "*"
                and origin_accepted_by_server(acao, origin)
                and sensitive
            ):
                if json_like and structured:
                    add(
                        fid="CORS-SENSITIVE-STRUCTURED-DATA",
                        severity="CRITICAL",
                        title="Structured sensitive API data exposed via CORS",
                        description="Response contains structured sensitive data accessible cross-origin",
                        impact="Exposure of user identifiers, tokens, or account data",
                        origin=origin,
                        confirmed=False,
                        reason=f"Structured sensitive data returned cross-origin for Origin '{origin}'",
                        exploitability="potential",
                    )
                else:
                    add(
                        fid="CORS-SENSITIVE-UNSTRUCTURED-DATA",
                        severity="HIGH",
                        title="Sensitive data exposed via CORS",
                        description="Response contains sensitive information accessible cross-origin",
                        impact="Potential leakage of secrets or personal data",
                        origin=origin,
                        confirmed=False,
                        reason=f"Sensitive response content returned cross-origin for Origin '{origin}'",
                        exploitability="potential",
                    )

            if (
                origin_accepted_by_server(acao, origin)
                and acac != "true"
                and (sensitive or structured)
            ):
                add(
                    fid="CORS-ORIGIN-REFLECTION-NO-CREDS",
                    severity="MEDIUM",
                    title="Origin reflected without credentials",
                    description="Origin is reflected in ACAO but credentials are not allowed",
                    impact="Limited cross-origin read access",
                    origin=origin,
                    confirmed=False,
                    reason=f"ACAO '{acao}' accepted attacker Origin '{origin}' without allowing credentials",
                    exploitability="theoretical",
                )
                adaptive_origins = {
                    origin + ".evil.com",
                    origin + "%00.evil.com",
                    origin + "\t.evil.com",
                }
                for a_origin in adaptive_origins:
                    test_headers = dict(headers) if isinstance(headers, list) else headers.copy()
                    test_headers["Origin"] = a_origin

                    try:
                        r2 = send_request(
                            session,
                            url,
                            headers=test_headers,
                            method=method,
                            data=effective_data,
                            verify=False,
                            allow_redirects=False,
                            profile=profile,
                        )
                        a_acao = r2.headers.get("Access-Control-Allow-Origin", "")
                        if origin_accepted_by_server(a_acao, a_origin):
                            add(
                                fid="CORS-ADAPTIVE-ORIGIN-BYPASS",
                                severity="HIGH",
                                title="Adaptive origin bypass confirmed",
                                description="Malformed origin was accepted by CORS validation logic",
                                impact="Bypass of origin validation controls",
                                origin=a_origin,
                                confirmed=True,
                                reason=f"Malformed Origin '{a_origin}' was accepted by ACAO '{a_acao}'",
                                exploitability="confirmed",
                                evidence={"bypass_origin": a_origin},
                            )
                    except Exception:
                        pass

            if acac == "true":
                for h in SENSITIVE_HEADERS:
                    if h in acah:
                        add(
                            fid="CORS-SENSITIVE-HEADER-CREDS",
                            severity="HIGH",
                            title="Sensitive request header allowed with credentials",
                            description="Sensitive request header is permitted in credentialed CORS context",
                            impact="Token or session leakage via cross-origin requests",
                            confirmed=False,
                            reason=f"Sensitive header '{h}' allowed in credentialed CORS request",
                            exploitability="potential",
                            evidence={"header": h},
                        )

            if origin_accepted_by_server(acao, origin):
                for m in ["put", "post", "delete", "patch", "trace", "track"]:
                    if m in acam and (acac == "true" or sensitive):
                        add(
                            fid="CORS-DANGEROUS-METHOD",
                            severity="MEDIUM",
                            title="Dangerous HTTP method allowed via CORS",
                            description=f"HTTP method {m.upper()} is permitted in cross-origin requests",
                            impact="Cross-origin state-changing requests may be possible",
                            confirmed=False,
                            reason=f"HTTP method '{m.upper()}' allowed via CORS for Origin '{origin}'",
                            exploitability="theoretical",
                            evidence={"method": m.upper()},
                        )
        except Exception as e:
            dbg("EXCEPTION", origin, repr(e))
            if DEBUG:
                raise
            else:
                continue

        if not browser_confirmed:
            try:
                r_redirect = send_request(
                    session,
                    url,
                    headers=headers,
                    method=method,
                    data=effective_data,
                    verify=False,
                    allow_redirects=True,
                    profile=profile,
                )

                history = r_redirect.history

                if history:
                    first = history[0]
                    final = r_redirect
                    first_acao = first.headers.get("Access-Control-Allow-Origin", "")
                    final_acao = final.headers.get("Access-Control-Allow-Origin", "")

                    if first_acao != final_acao:
                        add(
                            fid="CORS-REDIRECT-ACAO-MISMATCH",
                            severity="HIGH",
                            title="Access-Control-Allow-Origin changes across redirects",
                            description="ACAO value differs between redirect responses",
                            impact="CORS confusion leading to inconsistent enforcement",
                            confirmed=False,
                            reason=f"ACAO changed from '{first_acao}' to '{final_acao}' across redirects",
                            exploitability="potential",
                        )

                    if acac == "true" and final_acao:
                        add(
                            fid="CORS-CREDENTIALS-ACROSS-REDIRECTS",
                            severity="CRITICAL",
                            title="Credentialed CORS persists across redirects",
                            description="Credentialed CORS policy remains active after redirects",
                            impact="Authenticated data exposure via redirect chains",
                            confirmed=False,
                            reason=f"Credentialed CORS policy persisted across redirect chain",
                        )

            except Exception:
                pass

        if acao:
            for pf_method, req_header in PREFLIGHT_SCENARIOS:
                try:
                    pf_headers = {
                        **headers,
                        "Access-Control-Request-Method": pf_method,
                        "Access-Control-Request-Headers": req_header,
                    }
                    r = session.options(
                        url,
                        headers=pf_headers,
                        timeout=TIMEOUT,
                        verify=False,
                    )
                    pf_status = r.status_code
                    pf_acao = r.headers.get("Access-Control-Allow-Origin", "").strip()
                    pf_acam = r.headers.get("Access-Control-Allow-Methods", "").lower()
                    pf_acah = r.headers.get("Access-Control-Allow-Headers", "").lower()
                    pf_acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

                    # ACCURACY: require a valid 2xx preflight response before
                    # treating the preflight as permissive. Some servers emit
                    # CORS headers even on 4xx, which browsers ignore.
                    preflight_ok = 200 <= pf_status < 300

                    if (
                        preflight_ok
                        and pf_acac == "true"
                        and origin_accepted_by_server(pf_acao, origin)
                        and pf_method.lower() in pf_acam
                        and req_header.lower() in pf_acah
                        and origin_accepted_by_server(acao, origin)
                    ):
                        add(
                            fid="CORS-PREFLIGHT-ABUSE",
                            severity="HIGH",
                            title="Preflight allows dangerous method and header",
                            description=f"Preflight permits {pf_method} with {req_header} from attacker-controlled origin",
                            impact="Cross-origin modification or data exfiltration",
                            origin=origin,
                            confirmed=False,
                            reason=f"Preflight allowed method '{pf_method}' and header '{req_header}' for Origin '{origin}'",
                            exploitability="potential",
                            evidence={
                                "method": pf_method,
                                "header": req_header,
                            },
                        )

                    if (
                        preflight_ok
                        and pf_method == "POST"
                        and req_header.lower() == "content-type"
                        and "post" in pf_acam
                        and "content-type" in pf_acah
                        and origin_accepted_by_server(pf_acao, origin)
                    ):
                        graphql_probe = {
                            "query": "query IntrospectionQuery { __schema { types { name } } }"
                        }

                        try:
                            gql_headers = {
                                **headers,
                                "Content-Type": "application/json",
                            }

                            r_gql = send_request(
                                session,
                                url,
                                headers=gql_headers,
                                method="POST",
                                data=json.dumps(graphql_probe),
                                verify=False,
                                allow_redirects=False,
                                profile=profile,
                            )

                            if "__schema" in r_gql.text:
                                add(
                                    fid="CORS-GRAPHQL-INTROSPECTION",
                                    severity="CRITICAL",
                                    title="GraphQL introspection exposed via CORS",
                                    description="GraphQL schema accessible cross-origin after permissive preflight",
                                    impact="Full API schema disclosure and sensitive operation discovery",
                                    origin=origin,
                                    confirmed=True,
                                    reason=f"GraphQL introspection query succeeded cross-origin for Origin '{origin}'",
                                    exploitability="confirmed",
                                    evidence={
                                        "preflight_methods": pf_acam,
                                        "preflight_headers": pf_acah,
                                    },
                                )
                        except Exception:
                            pass
                    if preflight_ok and pf_acao == "*" and pf_acac == "true":
                        add(
                            fid="CORS-PREFLIGHT-WILDCARD-CREDS",
                            severity="CRITICAL",
                            title="Preflight wildcard ACAO with credentials enabled",
                            description="Preflight response allows credentials with wildcard ACAO",
                            impact="Full authenticated cross-origin request abuse",
                            confirmed=True,
                            reason=f"Preflight ACAO='*' used together with ACAC=true",
                            exploitability="confirmed",
                        )
                except Exception as e:
                    dbg("EXCEPTION", origin, repr(e))
                    if DEBUG:
                        raise
                    else:
                        continue

    try:
        r = send_request(
            session,
            f"{url}?callback=JSONP_TEST123",
            method="GET",
            verify=False,
            profile=profile,
        )
        ct = r.headers.get("Content-Type", "").lower()
        body = r.text.strip()

        if (
            ct.startswith(("application/javascript", "text/javascript"))
            and _is_real_jsonp(body, "JSONP_TEST123")
        ):
            add(
                fid="CORS-JSONP-ENABLED",
                severity="HIGH",
                title="JSONP endpoint enabled",
                description="Endpoint returns executable JavaScript with attacker-controlled callback",
                impact="Cross-origin data exfiltration via JSONP",
                confirmed=False,
                reason=f"JSONP callback parameter allowed attacker-controlled execution",
            )
    except Exception:
        pass

    if browser:
        browser.close()
        if p:
            p.stop()

    if findings:
        return {
            "url": url,
            "findings": [f.to_dict() for f in findings],
            "skipped_origins": sorted(skipped_origins),
        }
    return None


def browser_cors_confirm(browser, url, origin):
    """
    Confirm a credentialed CORS reflection in a real browser.

    Instead of trying to spoof the `Origin` header (which Chromium treats
    as forbidden for programmatic requests), we serve a bootstrap page
    from the attacker origin via a route handler and evaluate the fetch
    from there. The browser then genuinely sends `Origin: <origin>`.
    """
    context = browser.new_context(ignore_https_errors=True)

    def _handler(route):
        route.fulfill(
            status=200,
            content_type="text/html",
            body=f"<html><body>CorsRipper bootstrap for {origin}</body></html>",
        )

    try:
        try:
            context.route(f"{origin}/**", _handler)
        except Exception:
            pass

        page = context.new_page()

        try:
            page.goto(
                f"{origin}/corsripper-bootstrap",
                wait_until="domcontentloaded",
                timeout=8000,
            )
        except Exception:
            pass

        # ACCURACY: sample multiple times and use medians so a single slow
        # request does not produce a false timing-side-channel finding.
        result = page.evaluate(
            """async (url) => {
                try {
                    let postMessageLeak = false;
                    window.addEventListener("message", e => {
                        try {
                            fetch(url, {
                                credentials: "include",
                                mode: "cors"
                            })
                            .then(r => r.text())
                            .then(() => { postMessageLeak = true; });
                        } catch (e) {}
                    });
                    window.postMessage("corsripper-test", "*");
                    await new Promise(r => setTimeout(r, 800));

                    const controller = new AbortController();
                    setTimeout(() => controller.abort(), 15000);

                    const samples = 5;
                    const withCreds = [];
                    const noCreds = [];
                    let firstResp = null;

                    for (let i = 0; i < samples; i++) {
                        const t1 = performance.now();
                        const r1 = await fetch(url, {
                            credentials: "include",
                            mode: "cors",
                            signal: controller.signal
                        });
                        const t2 = performance.now();
                        if (i === 0) firstResp = r1;
                        withCreds.push(t2 - t1);

                        const t3 = performance.now();
                        await fetch(url, {
                            credentials: "omit",
                            mode: "cors"
                        });
                        const t4 = performance.now();
                        noCreds.push(t4 - t3);
                    }

                    const median = arr => {
                        const s = [...arr].sort((a, b) => a - b);
                        const n = s.length;
                        return n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
                    };

                    let text = null;
                    try { text = await firstResp.text(); } catch {}

                    return {
                        ok: firstResp.ok,
                        status: firstResp.status,
                        type: firstResp.type,
                        redirected: firstResp.redirected,
                        body_readable: text !== null,
                        opaque: firstResp.type === "opaque",
                        timing_with_creds: median(withCreds),
                        timing_without_creds: median(noCreds),
                        postmessage_leak: postMessageLeak
                    };
                } catch (e) {
                    return {
                        ok: false,
                        error: e.toString()
                    };
                }
            }""",
            url,
        )
    finally:
        context.close()

    return result


def test_websocket_origin(url, origin):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False

    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
    port = parsed.port or (443 if ws_scheme == "wss" else 80)
    host = parsed.hostname
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    key = base64.b64encode(os.urandom(16)).decode()

    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: {origin}\r\n\r\n"
    )

    sock = socket.create_connection((host, port), timeout=5)
    try:
        if ws_scheme == "wss":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(5)
        sock.send(req.encode())
        try:
            resp = sock.recv(4096).decode(errors="ignore")
        except socket.timeout:
            resp = ""
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return "101 Switching Protocols" in resp


def load_urls(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def parse_burp_request(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [l.rstrip("\n") for l in f]
    request_line = lines[0]
    method, path, _ = request_line.split(" ", 2)
    headers = {}
    body = None
    host = None
    i = 1
    for i, line in enumerate(lines[1:], start=1):
        if not line.strip():
            break
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()
        if k.lower() == "host":
            host = v.strip()
    if i + 1 < len(lines):
        body = "\n".join(lines[i + 1:]).strip() or None
    scheme = "https"
    url = f"{scheme}://{host}{path}"
    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
    }


def main():
    urls = []
    results = []
    vulnerable = 0
    base_request = None
    requests.packages.urllib3.disable_warnings()

    parser = argparse.ArgumentParser(description="CorsRipper")
    parser.add_argument("url", nargs="?", help="URL to scan")
    parser.add_argument("-u", "--urls", help="File with URLs")
    parser.add_argument("-o", "--output", help="JSON output file")
    parser.add_argument("--browser-confirm", action="store_true",
                        help="Confirm exploitable CORS with Playwright")
    parser.add_argument("-r", "--request",
                        help="Load raw HTTP request from file (Burp format)")
    parser.add_argument("--proxy",
                        help="Proxy URL (http://, https://, socks5://, socks5h:// for Tor)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable verbose debugging output for requests")
    args = parser.parse_args()

    global DEBUG
    DEBUG = args.debug

    if args.url:
        urls.extend(normalize_urls(args.url))
    if args.urls:
        urls.extend(load_urls(args.urls))

    if args.browser_confirm:
        browser_checker()

    if not urls:
        parser.print_help()
        sys.exit(1)

    if args.request:
        base_request = parse_burp_request(args.request)
        urls = [base_request["url"]]

    workers = min(len(urls), MAX_THREADS)
    print(f"Scanning {len(urls)} URLs with {workers} threads")
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(check_cors, u, args.browser_confirm, base_request, args.proxy): u
                for u in urls
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    summary = {}
                    if any(f["severity"] in {"CRITICAL", "HIGH", "MEDIUM"} for f in result["findings"]):
                        vulnerable += 1
                    print(f"\n[VULNERABLE] {result['url']}")
                    for f in result["findings"]:
                        fid = f["id"]
                        summary.setdefault(fid, {
                            "severity": f["severity"],
                            "title": f["title"],
                            "count": 0,
                        })
                        summary[fid]["count"] += 1

                    for fid, s in summary.items():
                        count = s["count"]
                        suffix = f" ({count} variants)" if count > 1 else ""
                        print(f"  [{s['severity']}] {s['title']}{suffix}")
                        for f in result["findings"]:
                            if f["id"] == fid:
                                for r in f.get("reasons", []):
                                    print(f"      ↳ {r}")
                    results.append(result)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(130)

    print(f"\n{vulnerable} vulnerable / {len(urls)} total")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(
                {
                    "schema_version": "1.0",
                    "tool": "CorsRipper",
                    "summary": {
                        "targets": len(urls),
                        "vulnerable_targets": vulnerable,
                    },
                    "results": results,
                },
                f,
                indent=4,
            )


if __name__ == "__main__":
    main()