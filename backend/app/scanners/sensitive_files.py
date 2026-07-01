from __future__ import annotations
import asyncio
from urllib.parse import urljoin, urlparse
from .base import BaseScanner, FindingCandidate, Severity, Confidence


SENSITIVE_PATHS = [
    # Git / VCS
    ("/.git/HEAD",           "GIT-001", "Git Repository Exposed",         Severity.CRITICAL, 9.8),
    ("/.git/config",         "GIT-002", "Git Config Exposed",              Severity.CRITICAL, 9.8),
    ("/.svn/entries",        "GIT-003", "SVN Repository Exposed",          Severity.HIGH,     8.0),
    # Environment / config
    ("/.env",                "FIL-001", ".env File Exposed",               Severity.CRITICAL, 9.8),
    ("/.env.local",          "FIL-002", ".env.local Exposed",              Severity.CRITICAL, 9.8),
    ("/.env.production",     "FIL-003", ".env.production Exposed",         Severity.CRITICAL, 9.8),
    ("/config.php",          "FIL-004", "config.php Exposed",              Severity.HIGH,     7.5),
    ("/wp-config.php",       "FIL-005", "WordPress Config Exposed",        Severity.CRITICAL, 9.8),
    ("/configuration.php",   "FIL-006", "Joomla Config Exposed",           Severity.HIGH,     7.5),
    # Backup / dump files
    ("/backup.sql",          "FIL-007", "SQL Dump File Exposed",           Severity.CRITICAL, 9.8),
    ("/dump.sql",            "FIL-008", "SQL Dump File Exposed",           Severity.CRITICAL, 9.8),
    ("/db.sql",              "FIL-009", "DB Dump Exposed",                 Severity.CRITICAL, 9.8),
    ("/backup.zip",          "FIL-010", "Backup Archive Exposed",          Severity.HIGH,     8.0),
    ("/site.tar.gz",         "FIL-011", "Site Archive Exposed",            Severity.HIGH,     8.0),
    # Debug / info pages
    ("/phpinfo.php",         "FIL-012", "phpinfo() Page Exposed",          Severity.HIGH,     7.5),
    ("/info.php",            "FIL-013", "PHP Info Page Exposed",           Severity.HIGH,     7.5),
    ("/test.php",            "FIL-014", "Test PHP Page Exposed",           Severity.MEDIUM,   5.3),
    ("/debug.php",           "FIL-015", "Debug Page Exposed",              Severity.MEDIUM,   5.3),
    # Admin panels
    ("/admin",               "FIL-016", "Admin Panel Accessible",          Severity.MEDIUM,   5.3),
    ("/wp-admin/",           "FIL-017", "WordPress Admin Accessible",      Severity.MEDIUM,   5.3),
    ("/phpmyadmin/",         "FIL-018", "phpMyAdmin Accessible",           Severity.HIGH,     7.5),
    ("/adminer.php",         "FIL-019", "Adminer DB UI Exposed",           Severity.HIGH,     7.5),
    # Log files
    ("/error.log",           "FIL-020", "Error Log Exposed",               Severity.MEDIUM,   5.3),
    ("/access.log",          "FIL-021", "Access Log Exposed",              Severity.MEDIUM,   5.3),
    ("/debug.log",           "FIL-022", "Debug Log Exposed",               Severity.MEDIUM,   5.3),
    # API / docs
    ("/api/swagger.json",    "FIL-023", "Swagger API Spec Exposed",        Severity.LOW,      3.7),
    ("/swagger.json",        "FIL-024", "Swagger API Spec Exposed",        Severity.LOW,      3.7),
    ("/openapi.json",        "FIL-025", "OpenAPI Spec Exposed",            Severity.LOW,      3.7),
    ("/graphql",             "FIL-026", "GraphQL Endpoint Accessible",     Severity.INFO,     None),
    # Kubernetes / Docker
    ("/.dockerenv",          "FIL-027", "Docker Environment File Exposed", Severity.MEDIUM,   5.3),
    ("/docker-compose.yml",  "FIL-028", "Docker Compose File Exposed",     Severity.HIGH,     7.0),
    ("/kubernetes.yml",      "FIL-029", "Kubernetes Config Exposed",       Severity.HIGH,     7.0),
]

CONTENT_TRIGGERS = [
    b"DB_PASSWORD", b"DB_USER", b"SECRET_KEY", b"API_KEY",
    b"-----BEGIN", b"AWS_ACCESS", b"root:x:", b"<html>phpinfo",
]


class SensitiveFilesScanner(BaseScanner):
    category = "Sensitive File Exposure"

    async def scan(self, url, session, context, auth_token=None):
        findings: list[FindingCandidate] = []
        base = _base_url(url)

        async def probe(path, vuln_id, title, severity, cvss):
            target = urljoin(base, path)
            try:
                r = await session.get(target, follow_redirects=False)
                if r.status_code in (200, 206):
                    body = r.content[:512]
                    triggered = any(t in body for t in CONTENT_TRIGGERS)
                    confidence = Confidence.CONFIRMED if triggered else Confidence.PROBABLE
                    findings.append(FindingCandidate(
                        vuln_id=vuln_id,
                        title=title,
                        description=f"The path {path} returned HTTP {r.status_code}, exposing potentially sensitive content.",
                        severity=severity,
                        confidence=confidence,
                        category=self.category,
                        evidence=f"GET {target} → {r.status_code} ({len(r.content)} bytes)",
                        location=target,
                        remediation=(
                            f"Deny access to {path} via web server configuration "
                            "(e.g. nginx deny rule or .htaccess). Remove the file if not needed."
                        ),
                        cvss_score=cvss,
                    ))
            except Exception:
                pass

        tasks = [probe(*row) for row in SENSITIVE_PATHS]
        await asyncio.gather(*tasks)
        return findings


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
