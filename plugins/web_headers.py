"""Check HTTP security headers for vulnerabilities."""

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "cvss": 6.1,
        "description": "Missing HSTS header allows downgrade attacks and cookie hijacking.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "cwe": "CWE-319",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "cvss": 6.1,
        "description": "Missing CSP allows cross-site scripting (XSS) attacks.",
        "recommendation": "Add a Content-Security-Policy header restricting script sources.",
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "cvss": 4.3,
        "description": "Missing X-Content-Type-Options allows MIME-type sniffing attacks.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "cvss": 4.3,
        "description": "Missing X-Frame-Options allows clickjacking attacks.",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
        "cwe": "CWE-1021",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "cvss": 3.1,
        "description": "Missing Referrer-Policy may leak sensitive URLs in referrer header.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-200",
        "owasp": "A01:2021 Broken Access Control",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "cvss": 2.6,
        "description": "Missing Permissions-Policy allows unrestricted access to browser features.",
        "recommendation": "Add Permissions-Policy to restrict camera, microphone, geolocation.",
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
    },
}

DANGEROUS_HEADERS = {
    "Server": {
        "severity": "LOW",
        "cvss": 2.6,
        "description": "Server header reveals technology stack, aiding fingerprinting.",
        "recommendation": "Remove or genericize the Server header.",
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    "X-Powered-By": {
        "severity": "LOW",
        "cvss": 2.6,
        "description": "X-Powered-By reveals framework version, aiding targeted attacks.",
        "recommendation": "Remove the X-Powered-By header.",
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    "X-AspNet-Version": {
        "severity": "LOW",
        "cvss": 2.6,
        "description": "Reveals ASP.NET version, aiding targeted attacks.",
        "recommendation": "Disable X-AspNet-Version in configuration.",
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
    },
}


def check(headers: dict) -> list[dict]:
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, meta in REQUIRED_HEADERS.items():
        if header.lower() not in headers_lower:
            findings.append({
                "plugin": "web_headers",
                "check": f"Missing {header}",
                "severity": meta["severity"],
                "cvss": meta["cvss"],
                "description": meta["description"],
                "recommendation": meta["recommendation"],
                "cwe": meta["cwe"],
                "owasp": meta["owasp"],
            })

    for header, meta in DANGEROUS_HEADERS.items():
        if header.lower() in headers_lower:
            findings.append({
                "plugin": "web_headers",
                "check": f"Exposed {header}: {headers_lower[header.lower()]}",
                "severity": meta["severity"],
                "cvss": meta["cvss"],
                "description": meta["description"],
                "recommendation": meta["recommendation"],
                "cwe": meta["cwe"],
                "owasp": meta["owasp"],
            })

    # Check CORS
    if "access-control-allow-origin" in headers_lower:
        val = headers_lower["access-control-allow-origin"]
        if val == "*":
            findings.append({
                "plugin": "web_headers",
                "check": "Wildcard CORS (Access-Control-Allow-Origin: *)",
                "severity": "MEDIUM",
                "cvss": 5.4,
                "description": "Wildcard CORS allows any origin to make cross-origin requests.",
                "recommendation": "Restrict Access-Control-Allow-Origin to trusted domains only.",
                "cwe": "CWE-942",
                "owasp": "A05:2021 Security Misconfiguration",
            })

    return findings
