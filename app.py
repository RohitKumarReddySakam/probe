"""
PROBE — Web Vulnerability Scanner
Author: Rohit Kumar Reddy Sakam
GitHub: https://github.com/RohitKumarReddySakam
Version: 1.0.0

Passive web vulnerability scanner: security headers, SSL/TLS, open ports,
web crawling, form analysis, and CVSS scoring. No active exploitation.
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from datetime import datetime
from urllib.parse import urlparse
import os
import uuid
import threading
import logging
import json
import io
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
sio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─── Models ───────────────────────────────────────────────────────
class ScanJob(db.Model):
    __tablename__ = "scan_jobs"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url = db.Column(db.String(500))
    hostname = db.Column(db.String(200))
    status = db.Column(db.String(30), default="pending")
    risk_score = db.Column(db.Float)
    risk_grade = db.Column(db.String(5))
    finding_count = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    plugins_run = db.Column(db.Text)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "target_url": self.target_url, "hostname": self.hostname,
            "status": self.status, "risk_score": self.risk_score, "risk_grade": self.risk_grade,
            "finding_count": self.finding_count, "critical_count": self.critical_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class ScanFinding(db.Model):
    __tablename__ = "scan_findings"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.String(36), db.ForeignKey("scan_jobs.id"))
    plugin = db.Column(db.String(50))
    check_name = db.Column(db.String(300))
    severity = db.Column(db.String(20))
    cvss = db.Column(db.Float, default=0.0)
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    cwe = db.Column(db.String(50))
    owasp = db.Column(db.String(100))
    extra = db.Column(db.Text)  # JSON for port, path, etc.

    def to_dict(self):
        return {
            "id": self.id, "scan_id": self.scan_id, "plugin": self.plugin,
            "check": self.check_name, "severity": self.severity, "cvss": self.cvss,
            "description": self.description, "recommendation": self.recommendation,
            "cwe": self.cwe, "owasp": self.owasp,
        }


# ─── Routes — Pages ───────────────────────────────────────────────
@app.route("/")
def dashboard():
    scans = ScanJob.query.order_by(ScanJob.created_at.desc()).limit(20).all()
    total_scans = ScanJob.query.count()
    completed = ScanJob.query.filter_by(status="completed").count()
    critical_findings = db.session.query(db.func.sum(ScanJob.critical_count)).scalar() or 0
    return render_template("index.html",
        scans=scans, total_scans=total_scans,
        completed=completed, critical_findings=critical_findings)


@app.route("/scan/<scan_id>")
def scan_detail(scan_id):
    scan = ScanJob.query.get_or_404(scan_id)
    findings = ScanFinding.query.filter_by(scan_id=scan_id).order_by(
        ScanFinding.cvss.desc()
    ).all()
    return render_template("scan_detail.html", scan=scan, findings=findings)


@app.route("/reports")
def reports_page():
    scans = ScanJob.query.filter_by(status="completed").order_by(
        ScanJob.completed_at.desc()
    ).all()
    return render_template("reports.html", scans=scans)


# ─── Routes — API ─────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    if not data or not data.get("url"):
        return jsonify({"error": "url is required"}), 400

    url = data["url"].strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return jsonify({"error": "Invalid URL"}), 400

    plugins = data.get("plugins", ["web_headers", "ssl_checker", "open_ports",
                                    "web_crawler", "forms_checker"])

    scan = ScanJob(target_url=url, hostname=hostname, status="running",
                   started_at=datetime.utcnow(), plugins_run=",".join(plugins))
    db.session.add(scan)
    db.session.commit()

    thread = threading.Thread(target=_run_scan, args=(scan.id, url, hostname, plugins),
                              daemon=True)
    thread.start()

    return jsonify({"scan_id": scan.id, "status": "running"}), 202


@app.route("/api/scan/<scan_id>")
def get_scan(scan_id):
    scan = ScanJob.query.get_or_404(scan_id)
    findings = ScanFinding.query.filter_by(scan_id=scan_id).order_by(
        ScanFinding.cvss.desc()
    ).all()
    return jsonify({
        "scan": scan.to_dict(),
        "findings": [f.to_dict() for f in findings],
    })


@app.route("/api/report/<scan_id>/html")
def download_html_report(scan_id):
    scan = ScanJob.query.get_or_404(scan_id)
    if scan.status != "completed":
        return jsonify({"error": "Scan not complete"}), 400

    findings = ScanFinding.query.filter_by(scan_id=scan_id).all()
    from core.cvss_calculator import cvss_summary
    from core.report_generator import generate_html_report
    summary = cvss_summary([f.to_dict() for f in findings])
    html = generate_html_report({
        "id": scan.id, "target": scan.target_url, "status": scan.status,
        "summary": summary, "findings": [f.to_dict() for f in findings],
    })
    return send_file(
        io.BytesIO(html.encode()),
        mimetype="text/html",
        as_attachment=True,
        download_name=f"vuln_report_{scan_id[:8]}.html",
    )


@app.route("/api/report/<scan_id>/json")
def download_json_report(scan_id):
    scan = ScanJob.query.get_or_404(scan_id)
    findings = ScanFinding.query.filter_by(scan_id=scan_id).all()
    from core.cvss_calculator import cvss_summary
    from core.report_generator import generate_json_report
    summary = cvss_summary([f.to_dict() for f in findings])
    report_json = generate_json_report({
        "id": scan.id, "target": scan.target_url, "status": scan.status,
        "summary": summary, "findings": [f.to_dict() for f in findings],
    })
    return send_file(
        io.BytesIO(report_json.encode()),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"vuln_report_{scan_id[:8]}.json",
    )


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "version": "1.0.0",
                    "timestamp": datetime.utcnow().isoformat()})


@sio.on("connect")
def on_connect():
    logger.info("Client connected")


# ─── Scan Runner ──────────────────────────────────────────────────
def _run_scan(scan_id: str, url: str, hostname: str, plugins: list[str]):
    import requests as req
    from core.cvss_calculator import cvss_summary

    timeout = app.config.get("SCAN_TIMEOUT", 10)
    all_findings = []
    session = req.Session()
    session.headers["User-Agent"] = "PROBE/1.0 Security Research"

    try:
        response_headers = {}
        try:
            resp = session.get(url, timeout=timeout, verify=False)
            response_headers = dict(resp.headers)
        except req.RequestException:
            pass

        if "web_headers" in plugins:
            from plugins.web_headers import check as check_headers
            all_findings.extend(check_headers(response_headers))

        if "ssl_checker" in plugins and url.startswith("https://"):
            from plugins.ssl_checker import check as check_ssl
            all_findings.extend(check_ssl(hostname, timeout=timeout))

        if "open_ports" in plugins:
            from plugins.open_ports import check as check_ports
            all_findings.extend(check_ports(hostname, timeout=min(timeout, 3)))

        if "web_crawler" in plugins:
            from plugins.web_crawler import crawl
            crawl_result = crawl(url, timeout=timeout, session=session)
            exposed = crawl_result.get("sensitive_paths", [])
            for p in exposed:
                if p.get("accessible"):
                    all_findings.append({
                        "plugin": "web_crawler",
                        "check": f"Sensitive Path Accessible: {p['path']}",
                        "severity": "HIGH",
                        "cvss": 7.5,
                        "description": f"Sensitive file/path {p['path']} returns HTTP 200.",
                        "recommendation": "Restrict access or remove the sensitive file.",
                        "cwe": "CWE-200",
                        "owasp": "A01:2021 Broken Access Control",
                    })

        if "forms_checker" in plugins:
            from plugins.forms_checker import check as check_forms
            all_findings.extend(check_forms(url, timeout=timeout, session=session))

        summary = cvss_summary(all_findings)

        with app.app_context():
            scan = ScanJob.query.get(scan_id)
            for f in all_findings:
                finding = ScanFinding(
                    scan_id=scan_id,
                    plugin=f.get("plugin", ""),
                    check_name=f.get("check", ""),
                    severity=f.get("severity", "INFO"),
                    cvss=float(f.get("cvss", 0.0)),
                    description=f.get("description", ""),
                    recommendation=f.get("recommendation", ""),
                    cwe=f.get("cwe", ""),
                    owasp=f.get("owasp", ""),
                )
                db.session.add(finding)

            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            scan.risk_score = summary["score"]
            scan.risk_grade = summary["grade"]
            scan.finding_count = summary["total"]
            scan.critical_count = summary["counts"].get("CRITICAL", 0)
            db.session.commit()
            sio.emit("scan_complete", {"scan_id": scan_id, "grade": summary["grade"],
                                        "score": summary["score"]})

    except Exception as e:
        logger.exception("Scan failed for %s: %s", url, e)
        with app.app_context():
            scan = ScanJob.query.get(scan_id)
            if scan:
                scan.status = "failed"
                db.session.commit()


def create_app():
    with app.app_context():
        os.makedirs(os.path.join(app.root_path, "instance"), exist_ok=True)
        db.create_all()
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", 5007))
    sio.run(app, host="0.0.0.0", port=port, debug=False)
