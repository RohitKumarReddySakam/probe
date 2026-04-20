"""Tests for PROBE plugins, CVSS calculator, and report generator."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from plugins.web_headers import check as check_headers
from plugins.open_ports import PORT_PROFILES
from core.cvss_calculator import cvss_summary, risk_grade, severity_from_cvss
from core.report_generator import generate_html_report, generate_json_report
import json


# ─── Web Headers ──────────────────────────────────────────────────

def test_missing_all_security_headers():
    findings = check_headers({})
    checks = [f["check"] for f in findings]
    assert any("Strict-Transport-Security" in c for c in checks)
    assert any("Content-Security-Policy" in c for c in checks)
    assert any("X-Content-Type-Options" in c for c in checks)


def test_present_headers_not_flagged():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
    }
    findings = check_headers(headers)
    checks = [f["check"] for f in findings]
    assert not any("Missing Strict-Transport-Security" in c for c in checks)
    assert not any("Missing Content-Security-Policy" in c for c in checks)


def test_server_header_flagged():
    findings = check_headers({"Server": "Apache/2.4.41"})
    assert any("Server" in f["check"] for f in findings)


def test_wildcard_cors_flagged():
    findings = check_headers({"Access-Control-Allow-Origin": "*"})
    assert any("CORS" in f["check"] for f in findings)
    assert findings[0]["severity"] == "MEDIUM"


def test_x_powered_by_flagged():
    findings = check_headers({"X-Powered-By": "PHP/7.4"})
    assert any("X-Powered-By" in f["check"] for f in findings)


# ─── Open Ports ───────────────────────────────────────────────────

def test_port_profile_telnet_critical():
    service, severity, cvss, _, _ = PORT_PROFILES[23]
    assert service == "Telnet"
    assert severity == "CRITICAL"
    assert cvss >= 9.0


def test_port_profile_redis_critical():
    service, severity, cvss, _, _ = PORT_PROFILES[6379]
    assert severity == "CRITICAL"


def test_port_profile_ssh_info():
    service, severity, cvss, _, _ = PORT_PROFILES[22]
    assert severity == "INFO"


# ─── CVSS Calculator ──────────────────────────────────────────────

def test_cvss_summary_empty():
    s = cvss_summary([])
    assert s["score"] == 0.0
    assert s["grade"] == "A+"
    assert s["total"] == 0


def test_cvss_summary_critical():
    findings = [{"severity": "CRITICAL", "cvss": 9.8}]
    s = cvss_summary(findings)
    assert s["score"] >= 9.0
    assert s["grade"] == "F"
    assert s["counts"]["CRITICAL"] == 1


def test_risk_grade_mapping():
    assert risk_grade(0) == "A+"
    assert risk_grade(1.5) == "A"
    assert risk_grade(3.0) == "B"
    assert risk_grade(5.0) == "C"
    assert risk_grade(7.0) == "D"
    assert risk_grade(9.5) == "F"


def test_severity_from_cvss():
    assert severity_from_cvss(9.5) == "CRITICAL"
    assert severity_from_cvss(7.5) == "HIGH"
    assert severity_from_cvss(5.0) == "MEDIUM"
    assert severity_from_cvss(2.0) == "LOW"
    assert severity_from_cvss(0.0) == "INFO"


# ─── Report Generator ─────────────────────────────────────────────

def test_generate_html_report():
    scan = {
        "id": "test-001",
        "target": "https://example.com",
        "status": "completed",
        "summary": {"score": 7.5, "grade": "D", "severity": "HIGH",
                     "counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 0}, "total": 4},
        "findings": [
            {"plugin": "web_headers", "check": "Missing HSTS", "severity": "HIGH",
             "cvss": 6.1, "cwe": "CWE-319", "owasp": "A05:2021", "recommendation": "Add HSTS"},
        ],
    }
    html = generate_html_report(scan)
    assert "example.com" in html
    assert "Missing HSTS" in html
    assert "<!DOCTYPE html>" in html


def test_generate_json_report():
    scan = {
        "id": "test-002",
        "target": "https://test.com",
        "status": "completed",
        "summary": {"score": 0.0, "grade": "A+", "severity": "INFO",
                     "counts": {}, "total": 0},
        "findings": [],
    }
    report_json = generate_json_report(scan)
    data = json.loads(report_json)
    assert data["target"] == "https://test.com"
    assert data["findings"] == []
    assert "report_generated" in data
