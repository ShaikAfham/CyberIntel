from __future__ import annotations
from .base import BaseScanner, FindingCandidate, Severity, Confidence


class CORSScanner(BaseScanner):
    category = "CORS / Access Control"

    async def scan(self, url, session, context, auth_token=None):
        findings: list[FindingCandidate] = []
        evil_origin = "https://evil-attacker.com"
        headers_to_send = {
            "Origin": evil_origin,
            "Access-Control-Request-Method": "GET",
        }

        try:
            resp = await session.options(url, headers=headers_to_send)
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()
        except Exception:
            return []

        if acao == "*":
            findings.append(FindingCandidate(
                vuln_id="CRS-001",
                title="CORS Policy Allows Any Origin (*)",
                description=(
                    "The server responds with Access-Control-Allow-Origin: * "
                    "which allows any website to make cross-origin requests."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category=self.category,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                location=url,
                remediation="Restrict ACAO to a whitelist of trusted origins.",
                cvss_score=5.3,
            ))

        if acao == evil_origin:
            sev = Severity.CRITICAL if acac == "true" else Severity.HIGH
            findings.append(FindingCandidate(
                vuln_id="CRS-002",
                title="CORS Reflects Arbitrary Origin" + (" with Credentials" if acac == "true" else ""),
                description=(
                    "The server echoes the caller's Origin header back in ACAO. "
                    + ("Combined with ACAC: true, authenticated cross-site requests are possible." if acac == "true"
                       else "Sensitive data may leak to attacker-controlled sites.")
                ),
                severity=sev,
                confidence=Confidence.CONFIRMED,
                category=self.category,
                evidence=f"ACAO: {acao} | ACAC: {acac}",
                location=url,
                remediation=(
                    "Validate Origin against an explicit allowlist. "
                    "Never combine wildcard/reflected origin with Allow-Credentials: true."
                ),
                cvss_score=9.1 if acac == "true" else 6.5,
                cve_ids=["CWE-942"],
            ))

        if acac == "true" and acao == "*":
            findings.append(FindingCandidate(
                vuln_id="CRS-003",
                title="CORS Wildcard with Allow-Credentials: true (Invalid but Dangerous Intent)",
                description=(
                    "Combining * with Allow-Credentials:true is rejected by browsers, "
                    "but indicates a misconfigured policy that may be exploitable in other ways."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.PROBABLE,
                category=self.category,
                evidence=f"ACAO: {acao} | ACAC: {acac}",
                location=url,
                remediation="Fix CORS policy: use an explicit origin allowlist, not wildcard.",
                cvss_score=5.0,
            ))

        return findings
