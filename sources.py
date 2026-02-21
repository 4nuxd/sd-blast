
import sys
import json
import re
import time
import argparse
import concurrent.futures
import urllib.request
import urllib.error
import urllib.parse

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 g4rxd-scanner/3.0"
TIMEOUT = 20

SEEN = set()

def emit(sub: str, domain: str):
    sub = sub.strip().lower()
    if not sub:
        return
    if not (sub == domain or sub.endswith("." + domain)):
        return
    if not re.match(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$", sub):
        return
    if sub not in SEEN:
        SEEN.add(sub)
        print(sub, flush=True)


def _get(url: str, headers: dict = None, data: bytes = None,
         timeout: int = TIMEOUT) -> str:
    try:
        req = urllib.request.Request(url, data=data,
                                      headers={"User-Agent": UA, **(headers or {})})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[WARN] GET {url[:80]} → {e}", file=sys.stderr)
        return ""


def _get_json(url: str, headers: dict = None, data: bytes = None) -> object:
    raw = _get(url, headers=headers, data=data)
    try:
        return json.loads(raw)
    except Exception:
        return None


def _extract(text: str, domain: str):
    escaped = re.escape(domain)
    for m in re.findall(r"([a-zA-Z0-9_*.-]+\." + escaped + r")", text):
        emit(m.replace("*.", ""), domain)


def src_crtsh(domain):
    d = _get_json(f"https://crt.sh/?q=%25.{domain}&output=json")
    if not d:
        return
    for e in d:
        for n in e.get("name_value", "").split("\n"):
            emit(n.strip().lstrip("*."), domain)


def src_certspotter(domain):
    d = _get_json(
        f"https://certspotter.com/api/v1/issuances"
        f"?domain={domain}&include_subdomains=true&expand=dns_names"
    )
    if not d:
        return
    for e in d:
        for n in e.get("dns_names", []):
            emit(n.lstrip("*."), domain)


def src_hackertarget(domain):
    raw = _get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    for line in raw.splitlines():
        parts = line.split(",")
        if parts:
            emit(parts[0], domain)


def src_alienvault(domain):
    page = 1
    while True:
        d = _get_json(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}"
            f"/passive_dns?page={page}&limit=500"
        )
        if not d:
            break
        records = d.get("passive_dns", [])
        for r in records:
            emit(r.get("hostname", ""), domain)
        if not d.get("has_next"):
            break
        page += 1


def src_rapiddns(domain):
    raw = _get(f"https://rapiddns.io/subdomain/{domain}?full=1")
    _extract(raw, domain)


def src_wayback(domain):
    raw = _get(
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=100000"
    )
    _extract(raw, domain)


def src_urlscan(domain):
    d = _get_json(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000")
    if not d:
        return
    for r in d.get("results", []):
        emit(r.get("page", {}).get("domain", ""), domain)
        emit(r.get("task", {}).get("domain", ""), domain)


def src_anubisdb(domain):
    d = _get_json(f"https://jldc.me/anubis/subdomains/{domain}")
    if isinstance(d, list):
        for s in d:
            emit(s, domain)


def src_threatcrowd(domain):
    d = _get_json(
        f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    )
    if not d:
        return
    for s in d.get("subdomains", []):
        emit(s, domain)


def src_riddler(domain):
    raw = _get(f"https://riddler.io/search/exportcsv?q=pld:{domain}")
    for line in raw.splitlines():
        parts = line.split(",")
        if len(parts) >= 6:
            emit(parts[5], domain)


def src_bufferover(domain):
    d = _get_json(f"https://dns.bufferover.run/dns?q=.{domain}")
    if not d:
        return
    for entry in d.get("FDNS_A", []) + d.get("RDNS", []):
        parts = entry.split(",")
        for p in parts:
            emit(p.strip(), domain)


def src_dnsbufferover(domain):
    raw = _get(f"https://dnsbufferover.run/dns?q=.{domain}")
    _extract(raw, domain)


def src_sitedossier(domain):
    raw = _get(f"http://www.sitedossier.com/parentdomain/{domain}")
    _extract(raw, domain)


def src_threatminer(domain):
    d = _get_json(
        f"https://api.threatminer.org/v2/domain.php?q={domain}&api=True&rt=5"
    )
    if not d:
        return
    for s in d.get("results", []):
        emit(s, domain)


def src_subdomaincenter(domain):
    d = _get_json(f"https://api.subdomain.center/?domain={domain}")
    if isinstance(d, list):
        for s in d:
            emit(s, domain)


def src_recondev(domain):
    d = _get_json(f"https://recon.dev/api/search?key=&domain={domain}")
    if isinstance(d, list):
        for entry in d:
            for s in entry.get("rawDomains", []):
                emit(s, domain)


def src_ctsearch(domain):
    d = _get_json(
        f"https://ctsearch.entrust.com/api/v1/certificates"
        f"?fields=subjectDN&domain={domain}&includeExpired=true&exactMatch=false&limit=5000"
    )
    if not d:
        return
    for c in d.get("certificates", []):
        dn = c.get("subjectDN", "")
        for part in dn.split(","):
            part = part.strip()
            if part.startswith("CN="):
                emit(part[3:].lstrip("*."), domain)


def src_leakix(domain):
    raw = _get(
        f"https://leakix.net/domain/{domain}",
        headers={"Accept": "application/json"}
    )
    _extract(raw, domain)


def src_certstream_web(domain):
    raw = _get(f"https://certstream.calidog.io/domains/{domain}")
    _extract(raw, domain)


def src_securitytrails_scrape(domain):
    raw = _get(
        f"https://securitytrails.com/list/apex_domain/{domain}",
        headers={"Accept": "text/html"}
    )
    _extract(raw, domain)


def src_shodan_scrape(domain):
    raw = _get(
        f"https://www.shodan.io/search?query=hostname%3A{domain}",
        headers={"Accept": "text/html"}
    )
    _extract(raw, domain)


def src_dnsdumpster(domain):
    home = _get("https://dnsdumpster.com/")
    m = re.search(r"csrfmiddlewaretoken.*?value=['\"]([^'\"]+)", home)
    if not m:
        return
    csrf = m.group(1)
    raw = _get(
        "https://dnsdumpster.com/",
        headers={
            "Referer": "https://dnsdumpster.com/",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": f"csrftoken={csrf}",
        },
        data=urllib.parse.urlencode({
            "csrfmiddlewaretoken": csrf,
            "targetip": domain,
            "user": "free",
        }).encode(),
    )
    _extract(raw, domain)


def src_fullhunt_free(domain):
    d = _get_json(
        f"https://fullhunt.io/api/v1/domain/{domain}/subdomains",
        headers={"x-api-key": ""}
    )
    if not d:
        return
    for s in d.get("hosts", []):
        emit(s, domain)


def src_bevigil_free(domain):
    raw = _get(f"https://osint.bevigil.com/api/{domain}/subdomains/")
    _extract(raw, domain)


def src_virustotal(domain, key):
    cursor = ""
    while True:
        url = (
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            f"?limit=40{('&cursor=' + cursor) if cursor else ''}"
        )
        d = _get_json(url, headers={"x-apikey": key})
        if not d:
            break
        for item in d.get("data", []):
            emit(item.get("id", ""), domain)
        meta = d.get("meta", {})
        cursor = meta.get("cursor", "")
        if not cursor:
            break
        time.sleep(0.5)


def src_securitytrails(domain, key):
    d = _get_json(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        f"?children_only=false&include_inactive=true",
        headers={"APIKEY": key}
    )
    if not d:
        return
    for sub in d.get("subdomains", []):
        emit(f"{sub}.{domain}", domain)


def src_binaryedge(domain, key):
    page = 1
    while True:
        d = _get_json(
            f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}?page={page}",
            headers={"X-Key": key}
        )
        if not d:
            break
        for e in d.get("events", []):
            emit(e, domain)
        total = d.get("total", 0)
        pagesize = d.get("pagesize", 100)
        if page * pagesize >= total:
            break
        page += 1
        time.sleep(0.3)


def src_shodan_api(domain, key):
    d = _get_json(
        f"https://api.shodan.io/dns/domain/{domain}?key={key}"
    )
    if not d:
        return
    for sub in d.get("subdomains", []):
        emit(f"{sub}.{domain}", domain)


def src_censys(domain, censys_id, censys_secret):
    import base64
    creds = base64.b64encode(f"{censys_id}:{censys_secret}".encode()).decode()
    cursor = ""
    while True:
        payload = {
            "q": f"parsed.names: {domain}",
            "fields": ["parsed.names"],
            "flatten": True,
            "per_page": 100,
        }
        if cursor:
            payload["cursor"] = cursor
        raw_payload = json.dumps(payload).encode()
        d = _get_json(
            "https://search.censys.io/api/v2/certificates/search",
            headers={
                "Authorization": f"Basic {creds}",
                "Content-Type": "application/json",
            },
            data=raw_payload,
        )
        if not d:
            break
        for hit in d.get("result", {}).get("hits", []):
            for name in hit.get("parsed.names", []):
                emit(name.lstrip("*."), domain)
        cursor = d.get("result", {}).get("links", {}).get("next", "")
        if not cursor:
            break
        time.sleep(0.3)


def src_spyse(domain, key):
    d = _get_json(
        f"https://api.spyse.com/v4/data/domain/subdomain?domain={domain}&limit=100",
        headers={"Authorization": f"Bearer {key}"}
    )
    if not d:
        return
    for item in d.get("data", {}).get("items", []):
        emit(item.get("name", ""), domain)


def src_c99(domain, key):
    d = _get_json(
        f"https://api.c99.nl/subdomainfinder?key={key}&domain={domain}&json"
    )
    if not d:
        return
    for sub in d.get("subdomains", []):
        emit(sub.get("subdomain", ""), domain)


def src_fullhunt_key(domain, key):
    d = _get_json(
        f"https://fullhunt.io/api/v1/domain/{domain}/subdomains",
        headers={"x-api-key": key}
    )
    if not d:
        return
    for s in d.get("hosts", []):
        emit(s, domain)


def src_bevigil_key(domain, key):
    d = _get_json(
        f"https://osint.bevigil.com/api/{domain}/subdomains/",
        headers={"X-Access-Token": key}
    )
    if not d:
        return
    for s in d.get("subdomains", []):
        emit(s, domain)


def src_netlas(domain, key):
    d = _get_json(
        f"https://app.netlas.io/api/domains/?q=*.{domain}&source_type=include&start=0&fields=domain",
        headers={"X-API-Key": key}
    )
    if not d:
        return
    for item in d.get("items", []):
        emit(item.get("data", {}).get("domain", ""), domain)


FREE_SOURCES = [
    src_crtsh, src_certspotter, src_hackertarget, src_alienvault,
    src_rapiddns, src_wayback, src_urlscan, src_anubisdb, src_threatcrowd,
    src_riddler, src_bufferover, src_dnsbufferover, src_sitedossier,
    src_threatminer, src_subdomaincenter, src_recondev, src_ctsearch,
    src_leakix, src_certstream_web, src_securitytrails_scrape,
    src_shodan_scrape, src_dnsdumpster, src_fullhunt_free, src_bevigil_free,
]


def main():
    parser = argparse.ArgumentParser(
        description="g4rxd sources.py — 25+ passive subdomain sources"
    )
    parser.add_argument("domain")
    parser.add_argument("--vt-key",  default="", help="VirusTotal API key")
    parser.add_argument("--st-key",  default="", help="SecurityTrails API key")
    parser.add_argument("--be-key",  default="", help="BinaryEdge API key")
    parser.add_argument("--sh-key",  default="", help="Shodan API key")
    parser.add_argument("--cx-id",   default="", help="Censys App ID")
    parser.add_argument("--cx-sec",  default="", help="Censys App Secret")
    parser.add_argument("--sp-key",  default="", help="Spyse API key")
    parser.add_argument("--c99-key", default="", help="C99.nl API key")
    parser.add_argument("--fh-key",  default="", help="FullHunt API key")
    parser.add_argument("--bv-key",  default="", help="BeVigil API key")
    parser.add_argument("--nl-key",  default="", help="Netlas API key")
    args = parser.parse_args()
    domain = args.domain.lower().strip()

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(fn, domain) for fn in FREE_SOURCES]
        concurrent.futures.wait(futures)

    keyed_tasks = []
    if args.vt_key:
        keyed_tasks.append((src_virustotal, (domain, args.vt_key)))
    if args.st_key:
        keyed_tasks.append((src_securitytrails, (domain, args.st_key)))
    if args.be_key:
        keyed_tasks.append((src_binaryedge, (domain, args.be_key)))
    if args.sh_key:
        keyed_tasks.append((src_shodan_api, (domain, args.sh_key)))
    if args.cx_id and args.cx_sec:
        keyed_tasks.append((src_censys, (domain, args.cx_id, args.cx_sec)))
    if args.sp_key:
        keyed_tasks.append((src_spyse, (domain, args.sp_key)))
    if args.c99_key:
        keyed_tasks.append((src_c99, (domain, args.c99_key)))
    if args.fh_key:
        keyed_tasks.append((src_fullhunt_key, (domain, args.fh_key)))
    if args.bv_key:
        keyed_tasks.append((src_bevigil_key, (domain, args.bv_key)))
    if args.nl_key:
        keyed_tasks.append((src_netlas, (domain, args.nl_key)))

    if keyed_tasks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(keyed_tasks)) as ex:
            futures = [ex.submit(fn, *fargs) for fn, fargs in keyed_tasks]
            concurrent.futures.wait(futures)


if __name__ == "__main__":
    main()
