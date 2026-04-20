"""Check SSL/TLS configuration for vulnerabilities."""
import ssl
import socket
from datetime import datetime, timezone


def check(hostname: str, port: int = 443, timeout: int = 10) -> list[dict]:
    findings = []
    try:
        findings.extend(_check_tls_version(hostname, port, timeout))
        findings.extend(_check_cert(hostname, port, timeout))
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return findings


def _check_tls_version(hostname: str, port: int, timeout: int) -> list[dict]:
    findings = []
    weak_protocols = [
        (ssl.PROTOCOL_TLS_CLIENT, "TLSv1", ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3),
        (ssl.PROTOCOL_TLS_CLIENT, "TLSv1.1", ssl.OP_NO_TLSv1_3),
    ]
    for proto_const, proto_name, opts in weak_protocols:
        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.options |= opts
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    findings.append({
                        "plugin": "ssl_checker",
                        "check": f"Weak TLS version supported: {proto_name}",
                        "severity": "HIGH",
                        "cvss": 7.4,
                        "description": f"Server supports deprecated {proto_name} which has known vulnerabilities (POODLE, BEAST).",
                        "recommendation": f"Disable {proto_name} support. Use TLS 1.2+ only.",
                        "cwe": "CWE-326",
                        "owasp": "A02:2021 Cryptographic Failures",
                    })
        except (ssl.SSLError, ConnectionResetError, OSError):
            pass
    return findings


def _check_cert(hostname: str, port: int, timeout: int) -> list[dict]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

        # Check expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append({
                        "plugin": "ssl_checker",
                        "check": "SSL Certificate Expired",
                        "severity": "CRITICAL",
                        "cvss": 9.1,
                        "description": f"SSL certificate expired {abs(days_left)} days ago.",
                        "recommendation": "Renew the SSL certificate immediately.",
                        "cwe": "CWE-298",
                        "owasp": "A02:2021 Cryptographic Failures",
                    })
                elif days_left < 30:
                    findings.append({
                        "plugin": "ssl_checker",
                        "check": f"SSL Certificate Expiring Soon ({days_left} days)",
                        "severity": "MEDIUM",
                        "cvss": 5.3,
                        "description": f"SSL certificate expires in {days_left} days.",
                        "recommendation": "Renew the SSL certificate before expiry.",
                        "cwe": "CWE-298",
                        "owasp": "A02:2021 Cryptographic Failures",
                    })
            except ValueError:
                pass

        # Check weak cipher
        if cipher:
            cipher_name = cipher[0]
            weak_ciphers = ["RC4", "DES", "3DES", "EXPORT", "NULL", "ADH", "AECDH"]
            for weak in weak_ciphers:
                if weak in cipher_name.upper():
                    findings.append({
                        "plugin": "ssl_checker",
                        "check": f"Weak Cipher Suite: {cipher_name}",
                        "severity": "HIGH",
                        "cvss": 7.4,
                        "description": f"Server is using weak cipher {cipher_name}.",
                        "recommendation": "Use only AEAD cipher suites (AES-GCM, ChaCha20-Poly1305).",
                        "cwe": "CWE-326",
                        "owasp": "A02:2021 Cryptographic Failures",
                    })
                    break

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "plugin": "ssl_checker",
            "check": "SSL Certificate Verification Failed",
            "severity": "HIGH",
            "cvss": 7.4,
            "description": f"Certificate cannot be verified: {e}",
            "recommendation": "Use a certificate signed by a trusted CA.",
            "cwe": "CWE-295",
            "owasp": "A02:2021 Cryptographic Failures",
        })
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return findings
