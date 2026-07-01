from __future__ import annotations
from urllib.parse import urlparse
from .base import BaseScanner, FindingCandidate, Severity, Confidence


class CookiesScanner(BaseScanner):
    category = "Cookie Security"

    async def scan(self, url, session, context, auth_token=None):
        findings: list[FindingCandidate] = []
        is_https = url.startswith("https://")

        try:
            resp = await session.get(url, follow_redirects=True)
            raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
            if not raw_cookies:
                set_cookie = resp.headers.get("set-cookie")
                raw_cookies = [set_cookie] if set_cookie else []
            context["raw_cookies"] = raw_cookies
        except Exception:
            return []

        seen_names: set[str] = set()
        for cookie_str in raw_cookies:
            parts = [p.strip() for p in cookie_str.split(";")]
            if not parts:
                continue
            name_val = parts[0].split("=", 1)
            name = name_val[0].strip()
            attrs = {p.split("=")[0].strip().lower() for p in parts[1:]}
            attr_map = {}
            for p in parts[1:]:
                kv = p.split("=", 1)
                attr_map[kv[0].strip().lower()] = kv[1].strip() if len(kv) > 1 else ""

            # Duplicate cookie names
            if name in seen_names:
                findings.append(FindingCandidate(
                    vuln_id="CKI-001",
                    title=f"Duplicate Cookie Name: {name}",
                    description="Multiple Set-Cookie headers use the same name, which can lead to unpredictable behavior.",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    category=self.category,
                    evidence=cookie_str[:200],
                    location=url,
                    remediation="Ensure each cookie name is unique per response.",
                ))
            seen_names.add(name)

            # HttpOnly missing
            if "httponly" not in attrs:
                findings.append(FindingCandidate(
                    vuln_id="CKI-002",
                    title=f"Cookie Missing HttpOnly Flag: {name}",
                    description="Without HttpOnly, the cookie is accessible to JavaScript and can be stolen via XSS.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    category=self.category,
                    evidence=cookie_str[:200],
                    location=url,
                    remediation=f"Add HttpOnly flag: Set-Cookie: {name}=...; HttpOnly",
                    cvss_score=5.3,
                ))

            # Secure missing on HTTPS
            if is_https and "secure" not in attrs:
                findings.append(FindingCandidate(
                    vuln_id="CKI-003",
                    title=f"Cookie Missing Secure Flag: {name}",
                    description="Without Secure, the cookie may be sent over HTTP and intercepted by MITM.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    category=self.category,
                    evidence=cookie_str[:200],
                    location=url,
                    remediation=f"Add Secure flag: Set-Cookie: {name}=...; Secure",
                    cvss_score=5.3,
                ))

            # SameSite missing or None without Secure
            same_site = attr_map.get("samesite", "").lower()
            if not same_site:
                findings.append(FindingCandidate(
                    vuln_id="CKI-004",
                    title=f"Cookie Missing SameSite Attribute: {name}",
                    description="Without SameSite, the cookie is sent on cross-site requests (CSRF risk).",
                    severity=Severity.LOW,
                    confidence=Confidence.PROBABLE,
                    category=self.category,
                    evidence=cookie_str[:200],
                    location=url,
                    remediation="Add SameSite=Strict or SameSite=Lax.",
                    cvss_score=4.3,
                ))
            elif same_site == "none" and "secure" not in attrs:
                findings.append(FindingCandidate(
                    vuln_id="CKI-005",
                    title=f"SameSite=None Cookie Without Secure Flag: {name}",
                    description="SameSite=None requires the Secure attribute; browsers reject it otherwise.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    category=self.category,
                    evidence=cookie_str[:200],
                    location=url,
                    remediation="Add Secure flag when using SameSite=None.",
                    cvss_score=5.3,
                ))

            # Session tokens without __Host- or __Secure- prefix
            name_lower = name.lower()
            is_session_like = any(k in name_lower for k in ("sess", "auth", "token", "jwt", "id"))
            if is_session_like and not name.startswith(("__Host-", "__Secure-")):
                findings.append(FindingCandidate(
                    vuln_id="CKI-006",
                    title=f"Session Cookie Missing Security Prefix: {name}",
                    description="Session cookies should use __Host- or __Secure- prefix for additional protection.",
                    severity=Severity.LOW,
                    confidence=Confidence.POSSIBLE,
                    category=self.category,
                    evidence=cookie_str[:200],
                    location=url,
                    remediation="Rename to __Host-<name>= and set Path=/; Secure; HttpOnly.",
                ))

        return findings
