from __future__ import annotations
import re
from urllib.parse import urlparse
from .base import BaseScanner, FindingCandidate, Severity, Confidence


HTTP_SRC_PATTERN = re.compile(
    r'(?:src|href|action|data-src|poster)\s*=\s*["\']http://([^"\'>\s]+)',
    re.IGNORECASE,
)


class MixedContentScanner(BaseScanner):
    category = "Mixed Content"

    async def scan(self, url, session, context, auth_token=None):
        findings: list[FindingCandidate] = []
        if not url.startswith("https://"):
            return findings  # only relevant for HTTPS pages

        try:
            resp = await session.get(url, follow_redirects=True)
            html = resp.text[:200_000]
        except Exception:
            return findings

        matches = HTTP_SRC_PATTERN.findall(html)
        if matches:
            unique = list(dict.fromkeys(matches))[:10]
            findings.append(FindingCandidate(
                vuln_id="MIX-001",
                title="Mixed Content — HTTP Resources on HTTPS Page",
                description=(
                    f"The HTTPS page loads {len(matches)} resource(s) over HTTP. "
                    "Browsers block or warn on mixed content, and resources can be intercepted."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category=self.category,
                evidence="http:// references: " + ", ".join(f"http://{u[:60]}" for u in unique),
                location=url,
                remediation=(
                    "Update all resource URLs to use https://. "
                    "Set Content-Security-Policy: upgrade-insecure-requests."
                ),
                cvss_score=4.3,
            ))

        return findings
