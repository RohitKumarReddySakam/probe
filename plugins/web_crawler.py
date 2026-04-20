"""Crawl web pages and discover URLs, forms, and paths."""
import re
from urllib.parse import urljoin, urlparse
import requests

MAX_PAGES = 20
MAX_DEPTH = 2

_LINK_RE = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)
_FORM_RE = re.compile(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\'](\w+)["\']',
                      re.IGNORECASE)
_INPUT_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/config.php", "/wp-config.php",
    "/admin", "/administrator", "/phpmyadmin", "/backup",
    "/api/v1/users", "/api/users", "/.htaccess", "/server-status",
    "/robots.txt", "/sitemap.xml",
]


def crawl(base_url: str, timeout: int = 8, session: requests.Session = None) -> dict:
    """
    Crawl the target, returning discovered URLs, forms, and probed sensitive paths.
    """
    if session is None:
        session = requests.Session()
        session.headers["User-Agent"] = "PROBE/1.0 Security Research"

    visited = set()
    to_visit = [(base_url, 0)]
    discovered_urls = []
    forms = []
    exposed_paths = []

    parsed_base = urlparse(base_url)
    base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"

    while to_visit and len(visited) < MAX_PAGES:
        url, depth = to_visit.pop(0)
        if url in visited or depth > MAX_DEPTH:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
            discovered_urls.append({"url": url, "status": resp.status_code,
                                    "content_type": resp.headers.get("Content-Type", "")})
            html = resp.text

            # Extract links
            if depth < MAX_DEPTH:
                for link in _LINK_RE.findall(html):
                    absolute = urljoin(url, link)
                    if urlparse(absolute).netloc == parsed_base.netloc:
                        if absolute not in visited:
                            to_visit.append((absolute, depth + 1))

            # Extract forms
            for action, method in _FORM_RE.findall(html):
                inputs = _INPUT_RE.findall(html)
                forms.append({
                    "url": url,
                    "action": urljoin(url, action) if action else url,
                    "method": method.upper(),
                    "inputs": inputs[:20],
                })

        except requests.RequestException:
            pass

    # Probe sensitive paths
    for path in SENSITIVE_PATHS:
        probe_url = base_domain + path
        if probe_url in visited:
            continue
        try:
            resp = session.get(probe_url, timeout=timeout, allow_redirects=False, verify=False)
            if resp.status_code in (200, 301, 302, 403):
                exposed_paths.append({
                    "path": path,
                    "url": probe_url,
                    "status": resp.status_code,
                    "accessible": resp.status_code == 200,
                })
        except requests.RequestException:
            pass

    return {
        "urls": discovered_urls,
        "forms": forms,
        "sensitive_paths": exposed_paths,
        "pages_crawled": len(visited),
    }
