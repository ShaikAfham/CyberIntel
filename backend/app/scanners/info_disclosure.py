from __future__ import annotations
import re
from .base import BaseScanner, FindingCandidate, Severity, Confidence

# (pattern, vuln_id, title, severity, cvss)
DISCLOSURE_PATTERNS: list[tuple] = [
    (r"stack trace", "INF-001", "Stack Trace Leaked in Response", Severity.MEDIUM, 5.3),
    (r"at\s+[\w\.]+\([\w\.]+:\d+\)", "INF-002", "Java/Python Stack Frame in Response", Severity.MEDIUM, 5.3),
    (r"exception in thread", "INF-003", "Java Exception Disclosure", Severity.MEDIUM, 5.3),
    (r"undefined method|no method error", "INF-004", "Ruby Error Disclosure", Severity.MEDIUM, 5.3),
    (r"NameError|ValueError|AttributeError", "INF-005", "Python Error Disclosure", Severity.MEDIUM, 5.3),
    (r"(?i)mysql.*error|mariadb.*error", "INF-006", "MySQL Error in Response", Severity.HIGH, 7.5),
    (r"ORA-\d{5}", "INF-007", "Oracle DB Error in Response", Severity.HIGH, 7.5),
    (r"psql.*error|pg_query", "INF-008", "PostgreSQL Error in Response", Severity.HIGH, 7.5),
    (r"AKIA[0-9A-Z]{16}", "INF-009", "AWS Access Key ID in Response", Severity.CRITICAL, 9.8),
    (r"(?i)password\s*[:=]\s*\S+", "INF-010", "Password in HTTP Response Body", Severity.CRITICAL, 9.8),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "INF-011", "Private Key in Response", Severity.CRITICAL, 9.8),
    (r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9]{16,}", "INF-012", "API Key in Response Body", Severity.HIGH, 8.0),
    (r"(?i)(secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9/+]{16,}", "INF-013", "Secret/Token in Response", Severity.HIGH, 8.0),
    (r"\b(192\.168|10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.)\d+\.\d+\b", "INF-014", "Internal IP Address Leaked", Severity.LOW, 3.7),
    (r"phpinfo\(\)", "INF-015", "phpinfo() Call in Response", Severity.HIGH, 7.5),
    (r"X-Debug-Token|X-Symfony-Token", "INF-016", "Framework Debug Token in Header", Severity.MEDIUM, 4.3),
]


class InfoDisclosureScanner(BaseScanner):
    category = "Information Disclosure"

    async def scan(self, url, session, context, auth_token=None):
        findings: list[FindingCandidate] = []
        try:
            resp = await session.get(url, follow_redirects=True)
            body = resp.text[:50_000]
            all_headers = dict(resp.headers)
        except Exception:
            return []

        seen: set[str] = set()
        for pattern, vuln_id, title, severity, cvss in DISCLOSURE_PATTERNS:
            if vuln_id in seen:
                continue
            # Check body
            m = re.search(pattern, body, re.IGNORECASE)
            # Also check response headers for header-specific patterns
            header_body = " ".join(f"{k}: {v}" for k, v in all_headers.items())
            if not m:
                m = re.search(pattern, header_body, re.IGNORECASE)
            if m:
                seen.add(vuln_id)
                snippet = m.group(0)[:120]
                findings.append(FindingCandidate(
                    vuln_id=vuln_id,
                    title=title,
                    description=f"Sensitive information pattern detected in HTTP response: '{snippet}'",
                    severity=severity,
                    confidence=Confidence.PROBABLE,
                    category=self.category,
                    evidence=snippet,
                    location=url,
                    remediation=(
                        "Ensure error handling suppresses internal details in production. "
                        "Never expose credentials, keys, or stack traces in HTTP responses."
                    ),
                    cvss_score=cvss,
                ))

        return findings
