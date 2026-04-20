"""Check HTML forms for security issues: missing CSRF, plaintext passwords, autocomplete."""
import re
import requests

_FORM_RE = re.compile(
    r'<form([^>]*)>(.*?)</form>',
    re.IGNORECASE | re.DOTALL
)
_INPUT_RE = re.compile(r'<input([^>]*)>', re.IGNORECASE)
_ATTR_RE = re.compile(r'(\w[\w-]*)=["\']([^"\']*)["\']', re.IGNORECASE)
_CSRF_NAMES = {"csrf_token", "csrfmiddlewaretoken", "_token", "csrf", "authenticity_token",
               "_csrf_token", "__requestverificationtoken"}


def check(url: str, timeout: int = 8, session: requests.Session = None) -> list[dict]:
    if session is None:
        session = requests.Session()
        session.headers["User-Agent"] = "PROBE/1.0 Security Research"

    findings = []
    try:
        resp = session.get(url, timeout=timeout, verify=False)
        html = resp.text
    except requests.RequestException:
        return findings

    for form_attrs_raw, form_body in _FORM_RE.findall(html):
        form_attrs = dict(_ATTR_RE.findall(form_attrs_raw))
        method = form_attrs.get("method", "get").upper()
        action = form_attrs.get("action", url)

        inputs = []
        for input_raw in _INPUT_RE.findall(form_body):
            attrs = dict(_ATTR_RE.findall(input_raw))
            inputs.append(attrs)

        input_names = {i.get("name", "").lower() for i in inputs}
        input_types = {i.get("type", "text").lower() for i in inputs}

        # CSRF check for POST forms
        if method == "POST":
            has_csrf = bool(_CSRF_NAMES & input_names)
            if not has_csrf:
                findings.append({
                    "plugin": "forms_checker",
                    "check": f"Missing CSRF Token in POST form (action: {action})",
                    "severity": "HIGH",
                    "cvss": 8.0,
                    "description": "POST form lacks a CSRF token, making it vulnerable to Cross-Site Request Forgery.",
                    "recommendation": "Add a CSRF token to all state-changing forms.",
                    "cwe": "CWE-352",
                    "owasp": "A01:2021 Broken Access Control",
                })

        # Password field over HTTP
        if "password" in input_types:
            if url.startswith("http://"):
                findings.append({
                    "plugin": "forms_checker",
                    "check": f"Password Field Over HTTP (action: {action})",
                    "severity": "CRITICAL",
                    "cvss": 9.1,
                    "description": "Password field submitted over unencrypted HTTP allows credential interception.",
                    "recommendation": "Enforce HTTPS for all forms with password inputs.",
                    "cwe": "CWE-319",
                    "owasp": "A02:2021 Cryptographic Failures",
                })

        # Autocomplete on password field
        for inp in inputs:
            if inp.get("type", "").lower() == "password":
                autocomplete = inp.get("autocomplete", "").lower()
                if autocomplete not in ("off", "new-password", "current-password"):
                    findings.append({
                        "plugin": "forms_checker",
                        "check": "Password Field Missing autocomplete=off",
                        "severity": "LOW",
                        "cvss": 2.6,
                        "description": "Password field does not disable browser autocomplete.",
                        "recommendation": 'Add autocomplete="new-password" or autocomplete="off" to password fields.',
                        "cwe": "CWE-522",
                        "owasp": "A07:2021 Identification and Authentication Failures",
                    })

    return findings
