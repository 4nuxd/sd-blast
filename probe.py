import sys
import time
import random
import signal
import concurrent.futures
import urllib.request
import urllib.error
import re

TIMEOUT      = 10
SCHEMES      = ["https", "http"]
CF_WAIT      = 5
RL_BASE_WAIT = 5
RL_MAX_TRIES = 3

CF_TITLES    = {"loading page", "just a moment", "attention required", "cloudflare"}
CF_BODY_SIGS = ["cf-browser-verification", "ray id", "checking your browser",
                "enable javascript", "ddos protection by cloudflare"]

_shutdown = False

def _handle_signal(sig, frame):
    global _shutdown
    _shutdown = True

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

def get_title(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:80] if m else ""

def is_cf_challenge(code, title, body=""):
    if code != 503:
        return False
    t = title.lower()
    b = body.lower()
    return (t in CF_TITLES) or any(sig in b for sig in CF_BODY_SIGS)

def fetch(url, extra_headers=None):
    if _shutdown:
        return None
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(8192).decode("utf-8", errors="ignore")
            return resp.getcode(), get_title(body), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(8192).decode("utf-8", errors="ignore")
            title = get_title(body)
        except Exception:
            body, title = "", ""
        return e.code, title, body
    except Exception:
        return None

def interruptible_sleep(seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if _shutdown:
            return
        time.sleep(min(0.25, deadline - time.monotonic()))

def probe(subdomain, no_404=False, cf_wait=False, rate_limit=False):
    if _shutdown:
        return None
    subdomain = subdomain.strip()
    if not subdomain:
        return None

    for scheme in SCHEMES:
        if _shutdown:
            return None
        url = f"{scheme}://{subdomain}"
        result = fetch(url)
        if result is None:
            continue
        code, title, body = result

        if rate_limit and code == 429:
            for attempt in range(1, RL_MAX_TRIES + 1):
                if _shutdown:
                    break
                wait = RL_BASE_WAIT * attempt + random.uniform(0, 3)
                interruptible_sleep(wait)
                if _shutdown:
                    break
                retried = fetch(url)
                if retried is None:
                    break
                code, title, body = retried
                if code != 429:
                    break

        if cf_wait and is_cf_challenge(code, title, body):
            interruptible_sleep(CF_WAIT)
            if _shutdown:
                return None
            retried = fetch(url, extra_headers={"Cache-Control": "no-cache"})
            if retried is None:
                return None
            code, title, body = retried
            if is_cf_challenge(code, title, body):
                return None

        if _shutdown:
            return None
        if no_404 and code == 404:
            return None
        title_str = f" [{title}]" if title else ""
        return f"{url} [{code}]{title_str}"
    return None

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input_file> <threads> [--no-404] [--cf-wait] [--rate-limit]", file=sys.stderr)
        sys.exit(1)

    input_file  = sys.argv[1]
    threads     = int(sys.argv[2])
    no_404      = "--no-404"     in sys.argv
    cf_wait     = "--cf-wait"    in sys.argv
    rate_limit  = "--rate-limit" in sys.argv

    with open(input_file) as f:
        subdomains = [l.strip() for l in f if l.strip()]

    if not subdomains:
        sys.exit(0)

    if cf_wait:
        print(f"[*] CF-wait: Cloudflare 503 challenge pages will be accessed after {CF_WAIT}s delay (parallel)", file=sys.stderr)
    if rate_limit:
        print("[*] Rate-limit: 429 responses will back off and retry up to 3x (parallel)", file=sys.stderr)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
    futures  = {executor.submit(probe, s, no_404, cf_wait, rate_limit): s for s in subdomains}
    try:
        for fut in concurrent.futures.as_completed(futures):
            if _shutdown:
                break
            try:
                result = fut.result()
                if result:
                    print(result, flush=True)
            except Exception:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        if _shutdown:
            print("\n[!] Interrupted — shutting down...", file=sys.stderr)
        executor.shutdown(wait=False, cancel_futures=True)

if __name__ == "__main__":
    main()
