"""Scan common ports and flag dangerous open services."""
import socket
import concurrent.futures

# Ports to scan and their risk profiles
PORT_PROFILES = {
    21:   ("FTP",        "HIGH",     7.5,  "FTP transmits credentials in cleartext.", "CWE-319"),
    22:   ("SSH",        "INFO",     0.0,  "SSH service detected.", ""),
    23:   ("Telnet",     "CRITICAL", 9.8,  "Telnet transmits all data including passwords in cleartext.", "CWE-319"),
    25:   ("SMTP",       "MEDIUM",   5.3,  "Open SMTP relay may allow spam or enumeration.", "CWE-200"),
    53:   ("DNS",        "MEDIUM",   5.3,  "Open DNS resolver may allow amplification attacks.", "CWE-400"),
    80:   ("HTTP",       "INFO",     0.0,  "HTTP service detected.", ""),
    110:  ("POP3",       "MEDIUM",   4.3,  "POP3 may transmit credentials in cleartext.", "CWE-319"),
    143:  ("IMAP",       "MEDIUM",   4.3,  "IMAP may transmit credentials in cleartext.", "CWE-319"),
    443:  ("HTTPS",      "INFO",     0.0,  "HTTPS service detected.", ""),
    445:  ("SMB",        "HIGH",     8.1,  "SMB exposed to network — EternalBlue risk if unpatched.", "CWE-119"),
    1433: ("MSSQL",      "HIGH",     7.5,  "MSSQL exposed to network allows brute force or exploitation.", "CWE-200"),
    1521: ("Oracle DB",  "HIGH",     7.5,  "Oracle DB exposed to network.", "CWE-200"),
    3306: ("MySQL",      "HIGH",     7.5,  "MySQL exposed to network allows brute force attacks.", "CWE-200"),
    3389: ("RDP",        "HIGH",     8.1,  "RDP exposed to network — BlueKeep risk if unpatched.", "CWE-119"),
    5432: ("PostgreSQL", "HIGH",     7.5,  "PostgreSQL exposed to network.", "CWE-200"),
    5900: ("VNC",        "HIGH",     8.1,  "VNC may use weak authentication or no encryption.", "CWE-319"),
    6379: ("Redis",      "CRITICAL", 9.8,  "Redis with no authentication allows full database access.", "CWE-306"),
    8080: ("HTTP-Alt",   "INFO",     0.0,  "Alternative HTTP port detected.", ""),
    8443: ("HTTPS-Alt",  "INFO",     0.0,  "Alternative HTTPS port detected.", ""),
    9200: ("Elasticsearch", "CRITICAL", 9.8, "Elasticsearch with no auth allows full data access.", "CWE-306"),
    27017:("MongoDB",    "CRITICAL", 9.8,  "MongoDB may allow unauthenticated access.", "CWE-306"),
}

OWASP_MAP = "A05:2021 Security Misconfiguration"


def check(hostname: str, timeout: int = 3) -> list[dict]:
    open_ports = _scan_ports(hostname, list(PORT_PROFILES.keys()), timeout)
    findings = []
    for port in open_ports:
        if port not in PORT_PROFILES:
            continue
        service, severity, cvss, description, cwe = PORT_PROFILES[port]
        if severity == "INFO":
            continue
        findings.append({
            "plugin": "open_ports",
            "check": f"Risky Service Exposed: {service} (port {port})",
            "severity": severity,
            "cvss": cvss,
            "description": description,
            "recommendation": f"Restrict access to port {port} via firewall. Disable if not needed.",
            "cwe": cwe,
            "owasp": OWASP_MAP,
            "port": port,
            "service": service,
        })
    return findings


def _scan_ports(hostname: str, ports: list[int], timeout: int) -> list[int]:
    open_ports = []

    def probe(port):
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                return port
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(probe, ports)

    for result in results:
        if result is not None:
            open_ports.append(result)

    return sorted(open_ports)
