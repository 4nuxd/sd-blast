import sys
import socket
import concurrent.futures
import random
import string

TIMEOUT = 4

def random_sub(domain, length=16):
    chars = string.ascii_lowercase + string.digits
    label = ''.join(random.choices(chars, k=length))
    return f"{label}.{domain}"

def resolve_ips(host):
    try:
        socket.setdefaulttimeout(TIMEOUT)
        infos = socket.getaddrinfo(host, None)
        return {info[4][0] for info in infos}
    except Exception:
        return set()

def detect_wildcard(domain, probes=3):
    sets = []
    for _ in range(probes):
        ips = resolve_ips(random_sub(domain))
        if ips:
            sets.append(ips)
    if not sets:
        return set()
    wildcard_ips = sets[0]
    for s in sets[1:]:
        wildcard_ips = wildcard_ips & s
    return wildcard_ips

def check(subdomain, wildcard_ips):
    subdomain = subdomain.strip()
    if not subdomain:
        return None
    ips = resolve_ips(subdomain)
    if not ips:
        return None
    if wildcard_ips and ips.issubset(wildcard_ips):
        return None
    return subdomain

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input_file> <threads>", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    threads = int(sys.argv[2])

    with open(input_file) as f:
        subdomains = [l.strip() for l in f if l.strip()]

    if not subdomains:
        sys.exit(0)

    first = subdomains[0]
    parts = first.split('.')
    domain = '.'.join(parts[-2:]) if len(parts) >= 2 else first

    wildcard_ips = detect_wildcard(domain)
    if wildcard_ips:
        print(f"[!] Wildcard DNS detected for *.{domain} → IPs: {', '.join(sorted(wildcard_ips))}", file=sys.stderr)
        print(f"[!] Filtering out false positives...", file=sys.stderr)
    else:
        print(f"[✓] No wildcard DNS detected for {domain}", file=sys.stderr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check, s, wildcard_ips): s for s in subdomains}
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result:
                print(result, flush=True)

if __name__ == "__main__":
    main()
