"""
Subdomain Scanner - Backend
Voor het scannen van je eigen domeinen op actieve subdomeinen.
Combineert: crt.sh (Certificate Transparency), DNS brute-force, HTTP status check.
"""

import socket
import threading
import queue
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from flask import Flask, request, jsonify, Response

app = Flask(__name__, static_folder="static", static_url_path="")


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response

# Kleine ingebouwde wordlist voor brute-force. Kan uitgebreid worden door
# de gebruiker via de frontend een eigen lijst te laten plakken.
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "vpn", "remote", "portal", "admin",
    "administrator", "api", "api-dev", "api-staging", "dev", "development",
    "staging", "stage", "test", "testing", "qa", "uat", "demo", "beta",
    "app", "apps", "mobile", "m", "web", "web1", "web2", "cdn", "static",
    "assets", "media", "images", "img", "files", "download", "downloads",
    "docs", "documentation", "help", "support", "kb", "wiki", "blog",
    "news", "shop", "store", "cart", "checkout", "pay", "payment",
    "secure", "login", "auth", "sso", "account", "accounts", "my",
    "dashboard", "panel", "cpanel", "webdisk", "autodiscover", "autoconfig",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "cd", "build",
    "monitor", "monitoring", "status", "stats", "analytics", "grafana",
    "kibana", "elk", "logs", "log", "db", "database", "mysql", "postgres",
    "redis", "mongo", "sql", "backup", "backups", "old", "new", "legacy",
    "internal", "intranet", "extranet", "partner", "partners", "client",
    "clients", "customer", "customers", "crm", "erp", "hr", "jobs",
    "careers", "recruit", "office", "meet", "meeting", "chat", "video",
    "voip", "sip", "proxy", "gateway", "gw", "lb", "loadbalancer",
    "edge", "origin", "cache", "s3", "storage", "upload", "uploads",
    "cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "docker",
    "registry", "repo", "repository", "npm", "pypi", "maven",
]

COMMON_PORTS = [80, 443, 8080, 8443, 3000, 8000]

CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"


def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$"
    return bool(re.match(pattern, domain)) and len(domain) <= 253


def resolve_host(host: str, timeout: float = 2.0):
    """Probeer A-record te resolven met de ingebouwde socket module."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        ips = sorted({info[4][0] for info in infos})
        return ips
    except (socket.gaierror, socket.timeout):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def check_http(host: str, timeout: float = 3.0):
    """Check welke poorten/protocollen leven en haal titel + server header op."""
    results = []
    for scheme, port in (("https", 443), ("http", 80)):
        url = f"{scheme}://{host}"
        try:
            resp = requests.get(
                url, timeout=timeout, allow_redirects=True,
                headers={"User-Agent": "SubdomainScanner/1.0 (own-domain-recon)"},
                verify=False,
            )
            title_match = re.search(
                r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL
            )
            title = title_match.group(1).strip()[:120] if title_match else None
            results.append({
                "scheme": scheme,
                "status_code": resp.status_code,
                "server": resp.headers.get("Server"),
                "title": title,
                "final_url": resp.url,
            })
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.RequestException:
            continue
    return results


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except socket.error:
        return False


def query_crtsh(domain: str, timeout: float = 15.0):
    """Haal subdomeinen op uit Certificate Transparency logs via crt.sh."""
    found = set()
    try:
        resp = requests.get(
            CRTSH_URL.format(domain=domain),
            timeout=timeout,
            headers={"User-Agent": "SubdomainScanner/1.0 (own-domain-recon)"},
        )
        if resp.status_code == 200 and resp.text.strip():
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if name.endswith(domain) and is_valid_domain(name):
                        found.add(name)
    except (requests.exceptions.RequestException, ValueError):
        pass
    return found


def stream_scan(domain: str, wordlist, do_bruteforce, do_ports, max_workers=40):
    """Generator die scanvoortgang als Server-Sent Events yield't."""

    def sse(event, data):
        import json
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    yield sse("status", {"message": f"Start scan voor {domain}..."})

    # Stap 1: crt.sh
    yield sse("status", {"message": "Zoeken in Certificate Transparency logs (crt.sh)..."})
    crt_results = query_crtsh(domain)
    yield sse("status", {"message": f"{len(crt_results)} kandidaten gevonden via crt.sh"})

    candidates = set(crt_results)
    candidates.add(domain)  # apex domain zelf ook checken

    # Stap 2: brute-force (optioneel)
    if do_bruteforce:
        yield sse("status", {"message": f"Brute-force met {len(wordlist)} woorden..."})
        for word in wordlist:
            candidates.add(f"{word}.{domain}")

    total = len(candidates)
    yield sse("status", {"message": f"Totaal {total} kandidaten te verifiëren..."})

    verified = 0
    live_count = 0

    def process(host):
        ips = resolve_host(host)
        if not ips:
            return None
        entry = {"host": host, "ips": ips, "http": [], "open_ports": []}
        entry["http"] = check_http(host)
        if do_ports:
            for port in COMMON_PORTS:
                if scan_port(host, port):
                    entry["open_ports"].append(port)
        return entry

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process, host): host for host in candidates}
        for future in as_completed(futures):
            verified += 1
            result = future.result()
            if result:
                live_count += 1
                yield sse("result", result)
            if verified % 5 == 0 or verified == total:
                yield sse("progress", {"checked": verified, "total": total, "live": live_count})

    yield sse("done", {"total_checked": total, "live_found": live_count})


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/wordlist", methods=["GET"])
def get_wordlist():
    return jsonify({"wordlist": DEFAULT_WORDLIST, "count": len(DEFAULT_WORDLIST)})


@app.route("/api/scan", methods=["GET"])
def scan():
    domain = request.args.get("domain", "").strip().lower()
    do_bruteforce = request.args.get("bruteforce", "true") == "true"
    do_ports = request.args.get("ports", "false") == "true"
    custom_words = request.args.get("wordlist", "")

    if not domain or not is_valid_domain(domain):
        return jsonify({"error": "Ongeldig domein. Gebruik bv. example.com"}), 400

    if custom_words.strip():
        wordlist = [w.strip() for w in custom_words.split(",") if w.strip()]
    else:
        wordlist = DEFAULT_WORDLIST

    return Response(
        stream_scan(domain, wordlist, do_bruteforce, do_ports),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    app.run(host="0.0.0.0", port=5065, debug=False, threaded=True)
