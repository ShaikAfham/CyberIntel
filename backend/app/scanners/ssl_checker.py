from __future__ import annotations
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from .base import BaseScanner, FindingCandidate, Severity, Confidence


class SSLScanner(BaseScanner):
    category = "SSL/TLS"

    async def scan(self, url, session, context, auth_token=None):
        findings: list[FindingCandidate] = []
        parsed = urlparse(url)

        if parsed.scheme != "https":
            findings.append(FindingCandidate(
                vuln_id="SSL-001",
                title="Site Not Using HTTPS",
                description="The target URL uses plain HTTP, transmitting data in cleartext.",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category=self.category,
                evidence=f"URL scheme: {parsed.scheme}",
                location=url,
                remediation="Migrate to HTTPS. Obtain a TLS certificate (e.g., Let's Encrypt).",
                cvss_score=7.5,
            ))
            return findings

        host = parsed.hostname
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    context["ssl_cert"] = cert
                    context["ssl_proto"] = proto

            # Check expiry
            not_after_str = cert.get("notAfter")
            if not_after_str:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.utcnow()).days
                if days_left < 0:
                    findings.append(FindingCandidate(
                        vuln_id="SSL-002",
                        title="TLS Certificate Expired",
                        description=f"Certificate expired {abs(days_left)} days ago.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category=self.category,
                        evidence=f"notAfter: {not_after_str}",
                        location=host,
                        remediation="Renew the TLS certificate immediately.",
                        cvss_score=7.5,
                    ))
                elif days_left < 30:
                    findings.append(FindingCandidate(
                        vuln_id="SSL-003",
                        title="TLS Certificate Expiring Soon",
                        description=f"Certificate expires in {days_left} days.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        category=self.category,
                        evidence=f"notAfter: {not_after_str}",
                        location=host,
                        remediation="Renew the TLS certificate before it expires.",
                        cvss_score=4.0,
                    ))

            # Weak protocol check
            if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                findings.append(FindingCandidate(
                    vuln_id="SSL-004",
                    title=f"Weak TLS Protocol in Use: {proto}",
                    description=f"The server negotiated {proto} which is deprecated and insecure.",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    category=self.category,
                    evidence=f"Negotiated protocol: {proto}",
                    location=host,
                    remediation="Disable TLS 1.0 and 1.1. Require TLS 1.2 minimum, prefer TLS 1.3.",
                    cvss_score=6.5,
                    cve_ids=["CVE-2014-3566"],  # POODLE (SSLv3 / TLS 1.0 downgrade)
                ))

        except ssl.SSLCertVerificationError as exc:
            findings.append(FindingCandidate(
                vuln_id="SSL-005",
                title="TLS Certificate Validation Failed",
                description=f"Certificate verification error: {exc}",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category=self.category,
                evidence=str(exc),
                location=host,
                remediation="Use a certificate signed by a trusted CA for the correct hostname.",
                cvss_score=6.8,
            ))
        except Exception:
            findings.append(FindingCandidate(
                vuln_id="SSL-006",
                title="SSL/TLS Check Inconclusive",
                description="Could not complete TLS probe — the host may be unreachable.",
                severity=Severity.INFO,
                confidence=Confidence.BLOCKED,
                category=self.category,
                location=host,
            ))

        return findings
