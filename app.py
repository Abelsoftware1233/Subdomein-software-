"""
Subdomain Scanner - Backend
Voor het scannen van je eigen domeinen op actieve subdomeinen.
Combineert: crt.sh (Certificate Transparency), DNS brute-force, wildcard-detectie,
HTTP status check, TCP poortcheck en subdomain takeover detectie.
"""

import json
import re
import socket
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from flask import Flask, request, jsonify, Response

app = Flask(__name__, static_folder="static", static_url_path="")

MAX_CANDIDATES = 5000  # hard cap tegen per ongeluk (of moedwillig) enorme scans


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


# Kleine ingebouwde wordlist voor brute-force. De frontend kan hier woorden
# aan TOEVOEGEN (niet vervangen) via een eigen lijst.
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

# Bekende "dit CNAME-target bestaat niet (meer) -> takeover mogelijk" vingerafdrukken.
TAKEOVER_FINGERPRINTS = [
    {"service": "GitHub Pages", "cname_hint": "github.io",
     "fingerprint": "There isn't a GitHub Pages site here"},
    {"service": "Heroku", "cname_hint": "herokuapp.com",
     "fingerprint": "No such app"},
    {"service": "Amazon S3", "cname_hint": "s3.amazonaws.com",
     "fingerprint": "NoSuchBucket"},
    {"service": "Shopify", "cname_hint": "myshopify.com",
     "fingerprint": "Sorry, this shop is currently unavailable"},
    {"service": "Fastly", "cname_hint": "fastly.net",
     "fingerprint": "Fastly error: unknown domain"},
    {"service": "Unbounce", "cname_hint": "unbouncepages.com",
     "fingerprint": "The requested URL was not found on this server"},
    {"service": "Netlify", "cname_hint": "netlify.app",
     "fingerprint": "Not Found - Request ID"},
    {"service": "Zendesk", "cname_hint": "zendesk.com",
     "fingerprint": "Help Center Closed"},
    {"service": "Tumblr", "cname_hint": "tumblr.com",
     "fingerprint": "There's nothing here"},
    {"service": "WordPress.com", "cname_hint": "wordpress.com",
     "fingerprint": "Do you want to register"},
    {"service": "Cargo", "cname_hint": "cargocollective.com",
     "fingerprint": "404 Not Found"},
    {"service": "Surge.sh", "cname_hint": "surge.sh",
     "fingerprint": "project not found"},
    {"service": "Azure", "cname_hint": "azurewebsites.net",
     "fingerprint": "404 Web Site not found"},
]


def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$"
    return bool(re.match(pattern, domain)) and len(domain) <= 253


def sanitize_word(word: str) -> str:
    """Houd alleen geldige hostname-tekens over uit een user-supplied woord."""
    word = word.strip().lower()
    word = re.sub(r"[^a-z0-9-]", "", word)
    word = word.strip("-")
    return word[:63]


def resolve_host(host: str, timeout: float = 2.0):
    """Probeer A-record te resolven met de ingebouwde socket module."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        ips = sorted({info[4][0] for info in infos})
        return ips
    except (socket.gaierror, socket.timeout, UnicodeError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def get_cname(host: str, timeout: float = 2.0):
    """Benadering van CNAME-lookup zonder dnspython, via alias-lijst van gethostbyname_ex."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        _, aliases, _ = socket.gethostbyname_ex(host)
        return aliases[0] if aliases else None
    except (socket.gaierror, socket.timeout, UnicodeError, IndexError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def detect_wildcard(domain: str):
    """Check of het domein een wildcard DNS-record heeft (elk *.domein resolvt)."""
    probe = f"wildcard-probe-{uuid.uuid4().hex[:12]}.{domain}"
    ips = resolve_host(probe)
    return set(ips) if ips else None


def check_http(host: str, timeout: float = 3.0):
    """Check welke poorten/protocollen leven en haal titel + server header op."""
    results = []
    for scheme in ("https", "http"):
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
                "body_snippet": resp.text[:2000],
            })
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.RequestException:
            continue
    return results


def check_takeover(host: str, http_results):
    """Match HTTP-response-body's en CNAME tegen bekende takeover-fingerprints."""
    cname = get_cname(host)
    for http_entry in http_results:
        body = http_entry.get("body_snippet", "") or ""
        for fp in TAKEOVER_FINGERPRINTS:
            if fp["fingerprint"].lower() in body.lower():
                return {
                    "vulnerable": True,
                    "service": fp["service"],
                    "cname": cname,
                    "reason": f"Response bevat fingerprint van {fp['service']} "
                              f"('{fp['fingerprint']}') — mogelijk dangling CNAME.",
                }
    if cname:
        for fp in TAKEOVER_FINGERPRINTS:
            if fp["cname_hint"] in cname.lower():
                return {
                    "vulnerable": None,
                    "service": fp["service"],
                    "cname": cname,
                    "reason": f"CNAME wijst naar {fp['service']} maar geen duidelijke "
                              f"'niet geclaimd'-fingerprint gevonden. Handmatig checken aangeraden.",
                }
    return None


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


def stream_scan(domain, wordlist, do_bruteforce, do_ports, do_takeover, max_workers=40):
    """Generator die scanvoortgang als Server-Sent Events yield't."""

    def sse(event, data):
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    yield sse("status", {"message": f"Start scan voor {domain}..."})

    yield sse("status", {"message": "Controleren op wildcard DNS..."})
    wildcard_ips = detect_wildcard(domain)
    if wildcard_ips:
        yield sse("status", {
            "message": f"Let op: wildcard DNS gedetecteerd ({', '.join(wildcard_ips)}). "
                       f"Brute-force resultaten met dit IP kunnen ruis zijn."
        })

    yield sse("status", {"message": "Zoeken in Certificate Transparency logs (crt.sh)..."})
    crt_results = query_crtsh(domain)
    yield sse("status", {"message": f"{len(crt_results)} kandidaten gevonden via crt.sh"})

    candidates = set(crt_results)
    candidates.add(domain)

    if do_bruteforce:
        yield sse("status", {"message": f"Brute-force met {len(wordlist)} woorden..."})
        for word in wordlist:
            clean = sanitize_word(word)
            if clean:
                candidates.add(f"{clean}.{domain}")

    if len(candidates) > MAX_CANDIDATES:
        yield sse("status", {
            "message": f"Kandidatenlijst afgekapt van {len(candidates)} naar {MAX_CANDIDATES} "
                       f"om de scan behapbaar te houden."
        })
        candidates = set(list(candidates)[:MAX_CANDIDATES])

    total = len(candidates)
    yield sse("status", {"message": f"Totaal {total} kandidaten te verifiëren..."})

    verified = 0
    live_count = 0
    takeover_count = 0

    def process(host):
        ips = resolve_host(host)
        if not ips:
            return None

        is_wildcard_match = bool(wildcard_ips) and set(ips) == wildcard_ips

        entry = {
            "host": host,
            "ips": ips,
            "http": [],
            "open_ports": [],
            "wildcard_match": is_wildcard_match,
            "takeover": None,
        }
        http_results = check_http(host)
        entry["http"] = [
            {k: v for k, v in h.items() if k != "body_snippet"} for h in http_results
        ]

        if do_ports:
            for port in COMMON_PORTS:
                if scan_port(host, port):
                    entry["open_ports"].append(port)

        if do_takeover:
            entry["takeover"] = check_takeover(host, http_results)

        return entry

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process, host): host for host in candidates}
        for future in as_completed(futures):
            verified += 1
            try:
                result = future.result()
            except Exception:
                result = None
            if result:
                live_count += 1
                if result.get("takeover") and result["takeover"].get("vulnerable"):
                    takeover_count += 1
                yield sse("result", result)
            if verified % 5 == 0 or verified == total:
                yield sse("progress", {
                    "checked": verified, "total": total,
                    "live": live_count, "takeovers": takeover_count,
                })

    yield sse("done", {
        "total_checked": total,
        "live_found": live_count,
        "takeovers_found": takeover_count,
        "wildcard_detected": bool(wildcard_ips),
    })


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/wordlist", methods=["GET"])
def get_wordlist():
    return jsonify({"wordlist": DEFAULT_WORDLIST, "count": len(DEFAULT_WORDLIST)})


@app.route("/api/scan", methods=["GET"])
def scan():
    domain = request.args.get("domain", "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]

    do_bruteforce = request.args.get("bruteforce", "true") == "true"
    do_ports = request.args.get("ports", "false") == "true"
    do_takeover = request.args.get("takeover", "true") == "true"
    custom_words = request.args.get("wordlist", "")

    if not domain or not is_valid_domain(domain):
        return jsonify({"error": "Ongeldig domein. Gebruik bv. example.com"}), 400

    wordlist = list(DEFAULT_WORDLIST)
    if custom_words.strip():
        extra = [w.strip() for w in custom_words.split(",") if w.strip()]
        seen = set(wordlist)
        for w in extra[:2000]:
            if w not in seen:
                wordlist.append(w)
                seen.add(w)

    return Response(
        stream_scan(domain, wordlist, do_bruteforce, do_ports, do_takeover),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    app.run(host="0.0.0.0", port=5065, debug=False, threaded=True)
