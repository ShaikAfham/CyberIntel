"""
CyberINTEL-AI — Optional Flask Backend
==========================================
Provides server-side capabilities the browser extension can't do alone:
  - WHOIS domain lookups
  - Deep ML analysis with heavier models
  - Scan report storage & history API
  - PhishTank, SSLLabs, CVE/NVD API aggregation
  - Threat intelligence feeds

Usage:
  pip install flask flask-cors requests python-whois dnspython
  python app.py

The extension sends requests to this server (default: http://localhost:5000)
only if the backend URL is configured in Settings.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import json
import os
import sqlite3
from datetime import datetime
from typing import Optional

app = Flask(__name__)
CORS(app, origins=["chrome-extension://*", "moz-extension://*"])

DB_PATH = "cyberintel_reports.db"

# ─── Database Setup ───────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_reports (
            id          TEXT PRIMARY KEY,
            url         TEXT NOT NULL,
            domain      TEXT NOT NULL,
            scanned_at  INTEGER NOT NULL,
            score       INTEGER,
            grade       TEXT,
            vuln_count  INTEGER,
            report_json TEXT NOT NULL,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_events (
            id          TEXT PRIMARY KEY,
            type        TEXT,
            severity    TEXT,
            description TEXT,
            url         TEXT,
            timestamp   INTEGER,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
    print("[CyberINTEL-AI Backend] Database initialized")


# ─── Health Check ─────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({ 'status': 'ok', 'service': 'CyberINTEL-AI Backend' })


# ─── WHOIS Lookup ─────────────────────────────────────────
@app.route('/api/whois', methods=['GET'])
def whois_lookup():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({ 'error': 'domain parameter required' }), 400

    try:
        import whois
        w = whois.whois(domain)
        return jsonify({
            'domain':       domain,
            'registrar':    str(w.registrar) if w.registrar else None,
            'creation_date': str(w.creation_date) if w.creation_date else None,
            'expiry_date':  str(w.expiration_date) if w.expiration_date else None,
            'name_servers': list(w.name_servers) if w.name_servers else [],
            'country':      str(w.country) if w.country else None,
        })
    except Exception as e:
        return jsonify({ 'error': str(e), 'domain': domain }), 500


# ─── PhishTank API Proxy ──────────────────────────────────
@app.route('/api/phishtank', methods=['POST'])
def check_phishtank():
    data = request.get_json()
    url  = data.get('url', '') if data else ''
    if not url:
        return jsonify({ 'error': 'url required' }), 400

    try:
        # PhishTank API (get free API key from phishtank.com)
        api_key = os.environ.get('PHISHTANK_API_KEY', '')
        response = requests.post(
            'https://checkurl.phishtank.com/checkurl/',
            data={
                'url':           url,
                'format':        'json',
                'app_key':       api_key,
            },
            timeout=10
        )
        return jsonify(response.json())
    except Exception as e:
        return jsonify({ 'error': str(e) }), 500


# ─── SSL Labs API Proxy ───────────────────────────────────
@app.route('/api/ssllabs', methods=['GET'])
def check_ssllabs():
    host = request.args.get('host', '').strip()
    if not host:
        return jsonify({ 'error': 'host parameter required' }), 400

    try:
        res = requests.get(
            f'https://api.ssllabs.com/api/v3/analyze?host={host}&publish=off&all=done',
            timeout=30
        )
        return jsonify(res.json())
    except Exception as e:
        return jsonify({ 'error': str(e) }), 500


# ─── CVE Lookup ───────────────────────────────────────────
@app.route('/api/cve', methods=['GET'])
def cve_lookup():
    """Search NVD CVE database for a keyword or technology."""
    keyword = request.args.get('keyword', '').strip()
    if not keyword:
        return jsonify({ 'error': 'keyword parameter required' }), 400

    try:
        res = requests.get(
            f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=10',
            headers={ 'apiKey': os.environ.get('NVD_API_KEY', '') },
            timeout=15
        )
        data         = res.json()
        vulnerabilities = data.get('vulnerabilities', [])
        simplified   = [
            {
                'id':          v['cve']['id'],
                'description': v['cve']['descriptions'][0]['value'] if v['cve']['descriptions'] else '',
                'severity':    v['cve'].get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN'),
                'score':       v['cve'].get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', None),
                'published':   v['cve'].get('published', ''),
            }
            for v in vulnerabilities[:10]
        ]
        return jsonify({ 'keyword': keyword, 'cves': simplified })
    except Exception as e:
        return jsonify({ 'error': str(e) }), 500


# ─── Save Scan Report ─────────────────────────────────────
@app.route('/api/reports', methods=['POST'])
def save_report():
    data = request.get_json()
    if not data or 'id' not in data:
        return jsonify({ 'error': 'Invalid scan report' }), 400

    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO scan_reports
            (id, url, domain, scanned_at, score, grade, vuln_count, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data['id'],
            data.get('url', ''),
            data.get('domain', ''),
            data.get('scannedAt', 0),
            data.get('securityScore', 0),
            data.get('grade', 'F'),
            len(data.get('vulnerabilities', [])),
            json.dumps(data),
        ))
        conn.commit()
        conn.close()
        return jsonify({ 'status': 'saved', 'id': data['id'] })
    except Exception as e:
        return jsonify({ 'error': str(e) }), 500


# ─── Get Scan History ─────────────────────────────────────
@app.route('/api/reports', methods=['GET'])
def get_reports():
    domain = request.args.get('domain')
    limit  = int(request.args.get('limit', 20))

    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    if domain:
        c.execute(
            "SELECT report_json FROM scan_reports WHERE domain=? ORDER BY scanned_at DESC LIMIT ?",
            (domain, limit)
        )
    else:
        c.execute(
            "SELECT report_json FROM scan_reports ORDER BY scanned_at DESC LIMIT ?",
            (limit,)
        )

    rows = c.fetchall()
    conn.close()

    reports = [json.loads(row[0]) for row in rows]
    return jsonify({ 'reports': reports, 'count': len(reports) })


# ─── Threat Intelligence Stats ────────────────────────────
@app.route('/api/stats', methods=['GET'])
def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    c.execute("SELECT COUNT(*) FROM scan_reports")
    total_scans = c.fetchone()[0]

    c.execute("SELECT AVG(score) FROM scan_reports")
    avg_score = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM scan_reports WHERE grade='F'")
    failing   = c.fetchone()[0]

    c.execute("SELECT domain, COUNT(*) as cnt FROM scan_reports GROUP BY domain ORDER BY cnt DESC LIMIT 5")
    top_domains = [{ 'domain': r[0], 'scans': r[1] } for r in c.fetchall()]

    conn.close()

    return jsonify({
        'total_scans': total_scans,
        'avg_score':   round(avg_score, 1) if avg_score else 0,
        'failing_sites': failing,
        'top_domains': top_domains,
    })


# ─── Main ─────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    print("=" * 50)
    print("  CyberINTEL-AI — Backend Server")
    print("  Running at: http://localhost:5000")
    print("  Configure the extension: Settings → Backend URL")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)
