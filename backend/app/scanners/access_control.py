from __future__ import annotations
import asyncio
from urllib.parse import urlparse, urljoin
from .base import BaseScanner, FindingCandidate, Severity, Confidence

# Paths that should require authentication
PROTECTED_PATHS = [
    "/admin", "/admin/", "/admin/dashboard", "/admin/users",
    "/api/admin", "/api/users", "/api/user/list",
    "/dashboard", "/settings", "/profile/edit",
    "/manage", "/console", "/control",
    "/api/v1/admin", "/api/v2/admin",
]

# HTTP methods to test for IDOR-style method abuse
VERB_TAMPER_METHODS = ["DELETE", "PUT", "PATCH"]


class AccessControlScanner(BaseScanner):
    category = "Access Control"

    async def scan(self, url, session, context, auth_token=None):
        findings: list[FindingCandidate] = []
        base = _base_url(url)

        tasks = [
            self._check_admin_exposure(base, session, findings),
            self._check_http_methods(url, session, findings),
            self._check_idor_params(url, session, findings),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return findings

    async def _check_admin_exposure(self, base, session, findings):
        for path in PROTECTED_PATHS:
            target = urljoin(base, path)
            try:
                r = await session.get(target, follow_redirects=False)
                if r.status_code == 200:
                    findings.append(FindingCandidate(
                        vuln_id="ACL-001",
                        title=f"Unauthenticated Access to Protected Path: {path}",
                        description=(
                            f"The path {path} returned HTTP 200 without authentication, "
                            "suggesting missing access controls."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.PROBABLE,
                        category=self.category,
                        evidence=f"GET {target} → {r.status_code}",
                        location=target,
                        remediation=(
                            "Enforce authentication and authorization checks on all admin/protected routes. "
                            "Return 401/403 for unauthenticated requests."
                        ),
                        cvss_score=8.1,
                        cve_ids=["CWE-862"],
                    ))
            except Exception:
                pass

    async def _check_http_methods(self, url, session, findings):
        try:
            r = await session.options(url)
            allow = r.headers.get("allow", r.headers.get("access-control-allow-methods", ""))
            dangerous = [m for m in ["TRACE", "TRACK", "CONNECT"] if m in allow.upper()]
            if dangerous:
                findings.append(FindingCandidate(
                    vuln_id="ACL-002",
                    title=f"Dangerous HTTP Methods Allowed: {', '.join(dangerous)}",
                    description=(
                        f"The server Allow header includes {', '.join(dangerous)}, "
                        "which can be abused for cross-site tracing (XST) or tunneling attacks."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    category=self.category,
                    evidence=f"OPTIONS {url} → Allow: {allow}",
                    location=url,
                    remediation="Disable TRACE, TRACK, and CONNECT methods in the web server configuration.",
                    cvss_score=5.3,
                    cve_ids=["CWE-200"],
                ))
        except Exception:
            pass

    async def _check_idor_params(self, url, session, findings):
        from urllib.parse import parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        id_params = [k for k in qs if k.lower() in ("id", "user_id", "account_id", "uid", "userid")]
        if not id_params:
            return
        try:
            # Try fetching with id=0 and id=999999
            for test_id in ["0", "999999"]:
                mod = dict(qs)
                for k in id_params:
                    mod[k] = [test_id]
                new_qs = urlencode(mod, doseq=True)
                target = urlunparse(parsed._replace(query=new_qs))
                r = await session.get(target)
                if r.status_code == 200 and len(r.content) > 100:
                    findings.append(FindingCandidate(
                        vuln_id="ACL-003",
                        title="Potential IDOR — Arbitrary Object Access via ID Parameter",
                        description=(
                            f"Requesting id={test_id} returned HTTP 200 with content. "
                            "If server-side authorization is not enforced, this may allow IDOR."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.POSSIBLE,
                        category=self.category,
                        evidence=f"GET {target} → {r.status_code}, {len(r.content)} bytes",
                        location=target,
                        remediation=(
                            "Verify object ownership server-side on every request. "
                            "Use indirect object references or UUIDs instead of sequential IDs."
                        ),
                        cvss_score=6.5,
                        cve_ids=["CWE-639"],
                    ))
                    return
        except Exception:
            pass


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
