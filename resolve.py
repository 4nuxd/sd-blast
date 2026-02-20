#!/usr/bin/env python3
"""
resolve.py — Wildcard-aware threaded DNS resolver for g4rxd
Usage: python3 resolve.py <input_file> <threads>

Wildcard detection:
  - Resolves 3 random garbage subdomains to find the wildcard IP set
  - Any real subdomain that resolves ONLY to those wildcard IPs is dropped
  - Subdomains resolving to different IPs are kept as genuine
"""
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
    """Return set of IPs for host, or empty set on failure."""
    try:
        socket.setdefaulttimeout(TIMEOUT)
        infos = socket.getaddrinfo(host, None)
        return {info[4][0] for info in infos}
    except Exception:
        return set()

def detect_wildcard(domain, probes=3):
    """
    Return the wildcard IP set (may be empty if no wildcard exists).
    Uses 3 random garbage subdomains — intersection of their IPs.
    """
    sets = []
    for _ in range(probes):
        ips = resolve_ips(random_sub(domain))
        if ips:
            sets.append(ips)
    if not sets:
        return set()
    # Intersection: IPs that appear in ALL probe results = true wildcard IPs
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
        return None  # doesn't resolve at all
    if wildcard_ips and ips.issubset(wildcard_ips):
        return None  # only wildcard IPs → false positive
    return subdomain

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input_file> <threads>", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    threads = int(sys.argv[2])

    # Extract domain from first line to detect wildcard
    with open(input_file) as f:
        subdomains = [l.strip() for l in f if l.strip()]

    if not subdomains:
        sys.exit(0)

    # Guess base domain from first entry (last two labels)
    first = subdomains[0]
    parts = first.split('.')
    domain = '.'.join(parts[-2:]) if len(parts) >= 2 else first

    # Detect wildcard baseline
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
