from __future__ import annotations
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base import BaseScanner, FindingCandidate, Severity, Confidence

# Safe reflection-only payloads — no actual execution
XSS_PROBES = [
    '<script>/*cyberintel*/</script>',
    '"><img src=x onerror=0 /*ci*/>',
    "javascript:/*ci*/",
]

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"ora-\d{5}",
    r"sqlite3?\.operationalerror",
    r"microsoft.*ole db.*sql",
    r"odbc.*driver.*error",
]

SQLI_PROBES = ["'", '"', "1'--", "1\"--", "' OR '1'='1", "1; --"]

SSTI_PATTERNS = {
    "{{7*7}}": "49",
    "${7*7}": "49",
    "<%=7*7%>": "49",
}

CMDI_PATTERNS = [
    r"\broot\b.*\bbash\b",
    r"\buid=\d+\(",
    r"volume serial number",
]
CMDI_PROBES = ["; echo cyberintel_cmdi", "| echo cyberintel_cmdi", "&& echo cyberintel_cmdi"]


def _inject_params(url: str, payload: str) -> list[str]:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return []
    urls = []
    for key in qs:
        mod = dict(qs)
        mod[key] = [payload]
        new_qs = urlencode(mod, doseq=True)
        urls.append(urlunparse(parsed._replace(query=new_qs)))
    return urls


class InjectionScanner(BaseScanner):
    category = "Injection"

    async def scan(self, url, session, context, auth_token=None):
        findings: list[FindingCandidate] = []
        tasks = [
            self._check_reflected_xss(url, session, findings),
            self._check_sqli(url, session, findings),
            self._check_ssti(url, session, findings),
            self._check_open_redirect(url, session, findings),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return findings

    async def _check_reflected_xss(self, url, session, findings):
        for probe in XSS_PROBES:
            for target in _inject_params(url, probe):
                try:
                    r = await session.get(target)
                    if probe in r.text:
                        findings.append(FindingCandidate(
                            vuln_id="INJ-001",
                            title="Reflected XSS — Parameter Reflects Payload",
                            description=(
                                "A URL parameter directly reflects the supplied value into the HTML "
                                "response without encoding, enabling Reflected Cross-Site Scripting."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.PROBABLE,
                            category=self.category,
                            evidence=f"Probe: {probe!r} reflected in response from {target}",
                            location=target,
                            remediation=(
                                "HTML-encode all user-supplied data before rendering. "
                                "Implement a strict Content-Security-Policy."
                            ),
                            cvss_score=6.1,
                            cve_ids=["CWE-79"],
                        ))
                        return  # one finding per URL is enough
                except Exception:
                    pass

    async def _check_sqli(self, url, session, findings):
        compiled = [re.compile(p, re.IGNORECASE) for p in SQLI_ERROR_PATTERNS]
        for probe in SQLI_PROBES:
            for target in _inject_params(url, probe):
                try:
                    r = await session.get(target)
                    text = r.text.lower()
                    for pat in compiled:
                        if pat.search(text):
                            findings.append(FindingCandidate(
                                vuln_id="INJ-002",
                                title="SQL Injection — Error-Based Detection",
                                description=(
                                    "Injecting a SQL metacharacter triggered a database error message, "
                                    "indicating the parameter is not properly parameterized."
                                ),
                                severity=Severity.CRITICAL,
                                confidence=Confidence.PROBABLE,
                                category=self.category,
                                evidence=f"Probe: {probe!r} → DB error pattern matched in response",
                                location=target,
                                remediation=(
                                    "Use parameterized queries / prepared statements. "
                                    "Never concatenate user input into SQL strings."
                                ),
                                cvss_score=9.8,
                                cve_ids=["CWE-89"],
                            ))
                            return
                except Exception:
                    pass

    async def _check_ssti(self, url, session, findings):
        for probe, expected in SSTI_PATTERNS.items():
            for target in _inject_params(url, probe):
                try:
                    r = await session.get(target)
                    if expected in r.text:
                        findings.append(FindingCandidate(
                            vuln_id="INJ-003",
                            title="Server-Side Template Injection (SSTI)",
                            description=(
                                f"The probe {probe!r} was evaluated server-side and returned '{expected}', "
                                "suggesting a template engine is processing user input."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.PROBABLE,
                            category=self.category,
                            evidence=f"Probe: {probe!r} → response contained: {expected}",
                            location=target,
                            remediation=(
                                "Never pass user-controlled strings to template engines. "
                                "Use sandboxed templates or static rendering."
                            ),
                            cvss_score=9.8,
                            cve_ids=["CWE-94"],
                        ))
                        return
                except Exception:
                    pass

    async def _check_open_redirect(self, url, session, findings):
        evil = "https://evil-attacker.com"
        redirect_params = ["redirect", "next", "url", "return", "returnUrl", "goto", "dest"]
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        targets = []
        if qs:
            for key in qs:
                if key.lower() in redirect_params:
                    mod = dict(qs)
                    mod[key] = [evil]
                    new_qs = urlencode(mod, doseq=True)
                    targets.append(urlunparse(parsed._replace(query=new_qs)))
        # Also try injecting common redirect params if none in URL
        if not targets:
            base = urlunparse(parsed._replace(query=""))
            for param in redirect_params[:3]:
                targets.append(f"{base}?{param}={evil}")

        for target in targets:
            try:
                r = await session.get(target, follow_redirects=False)
                loc = r.headers.get("location", "")
                if evil in loc:
                    findings.append(FindingCandidate(
                        vuln_id="INJ-004",
                        title="Open Redirect Vulnerability",
                        description=(
                            "The application redirects to an attacker-controlled URL supplied via a "
                            "query parameter, enabling phishing and session-hijacking attacks."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        category=self.category,
                        evidence=f"GET {target} → Location: {loc}",
                        location=target,
                        remediation=(
                            "Validate redirect targets against an explicit allowlist of trusted URLs. "
                            "Reject or sanitize user-supplied redirect destinations."
                        ),
                        cvss_score=6.1,
                        cve_ids=["CWE-601"],
                    ))
                    return
            except Exception:
                pass
