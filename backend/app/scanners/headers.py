from __future__ import annotations
from .base import BaseScanner, FindingCandidate, Severity, Confidence


REQUIRED_HEADERS = {
    "content-security-policy": {
        "id": "HDR-001",
        "title": "Missing Content-Security-Policy Header",
        "severity": Severity.HIGH,
        "remediation": (
            "Add a strict CSP header: "
            "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"
        ),
        "cvss": 6.1,
        "cve": [],
    },
    "strict-transport-security": {
        "id": "HDR-002",
        "title": "Missing Strict-Transport-Security (HSTS) Header",
        "severity": Severity.HIGH,
        "remediation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
        "cvss": 5.9,
        "cve": [],
    },
    "x-frame-options": {
        "id": "HDR-003",
        "title": "Missing X-Frame-Options Header (Clickjacking Risk)",
        "severity": Severity.MEDIUM,
        "remediation": "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors)",
        "cvss": 4.3,
        "cve": [],
    },
    "x-content-type-options": {
        "id": "HDR-004",
        "title": "Missing X-Content-Type-Options Header",
        "severity": Severity.LOW,
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "cvss": 3.7,
        "cve": [],
    },
    "referrer-policy": {
        "id": "HDR-005",
        "title": "Missing Referrer-Policy Header",
        "severity": Severity.LOW,
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cvss": 3.1,
        "cve": [],
    },
    "permissions-policy": {
        "id": "HDR-006",
        "title": "Missing Permissions-Policy Header",
        "severity": Severity.INFO,
        "remediation": "Add Permissions-Policy to restrict browser feature access.",
        "cvss": None,
        "cve": [],
    },
}

INSECURE_HEADERS = {
    "x-powered-by": {
        "id": "HDR-007",
        "title": "Server Technology Disclosure via X-Powered-By",
        "severity": Severity.LOW,
        "remediation": "Remove the X-Powered-By header to reduce information exposure.",
        "cvss": 3.1,
    },
    "server": {
        "id": "HDR-008",
        "title": "Server Banner Disclosure",
        "severity": Severity.LOW,
        "remediation": "Configure your web server to suppress detailed version strings.",
        "cvss": 3.1,
    },
}


class HeadersScanner(BaseScanner):
    category = "Security Headers"

    async def scan(self, url, session, context, auth_token=None):
        findings: list[FindingCandidate] = []
        try:
            resp = await session.get(url, follow_redirects=True)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            context["response_headers"] = headers
            context["status_code"] = resp.status_code
        except Exception as exc:
            return [FindingCandidate(
                vuln_id="HDR-000",
                title="HTTP Request Failed",
                description=f"Could not fetch target URL: {exc}",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category=self.category,
                location=url,
            )]

        for header_name, meta in REQUIRED_HEADERS.items():
            if header_name not in headers:
                findings.append(FindingCandidate(
                    vuln_id=meta["id"],
                    title=meta["title"],
                    description=f"The HTTP response is missing the {header_name} security header.",
                    severity=meta["severity"],
                    confidence=Confidence.CONFIRMED,
                    category=self.category,
                    evidence=f"Header '{header_name}' not present in response",
                    location=url,
                    remediation=meta["remediation"],
                    cve_ids=meta["cve"],
                    cvss_score=meta["cvss"],
                ))

        # CSP quality check if present
        csp = headers.get("content-security-policy", "")
        if csp:
            if "unsafe-inline" in csp:
                findings.append(FindingCandidate(
                    vuln_id="HDR-009",
                    title="CSP Allows 'unsafe-inline' Scripts",
                    description="'unsafe-inline' in script-src defeats XSS protection provided by CSP.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    category=self.category,
                    evidence=f"CSP: {csp[:300]}",
                    location=url,
                    remediation="Remove 'unsafe-inline' and use nonces or hashes instead.",
                    cvss_score=5.4,
                ))
            if "unsafe-eval" in csp:
                findings.append(FindingCandidate(
                    vuln_id="HDR-010",
                    title="CSP Allows 'unsafe-eval'",
                    description="'unsafe-eval' allows dynamic code evaluation and weakens CSP.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    category=self.category,
                    evidence=f"CSP: {csp[:300]}",
                    location=url,
                    remediation="Remove 'unsafe-eval'. Refactor code that uses eval().",
                    cvss_score=5.4,
                ))

        for header_name, meta in INSECURE_HEADERS.items():
            val = headers.get(header_name)
            if val:
                findings.append(FindingCandidate(
                    vuln_id=meta["id"],
                    title=meta["title"],
                    description=f"The server exposes '{header_name}: {val}' which reveals technology details.",
                    severity=meta["severity"],
                    confidence=Confidence.CONFIRMED,
                    category=self.category,
                    evidence=f"{header_name}: {val}",
                    location=url,
                    remediation=meta["remediation"],
                    cvss_score=meta["cvss"],
                ))

        return findings
