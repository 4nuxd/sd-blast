# SD-Blast

```
 ██████╗ ██╗  ██╗██████╗ ██╗  ██╗██████╗
██╔════╝ ██║  ██║██╔══██╗╚██╗██╔╝██╔══██╗
██║  ███╗███████║██████╔╝ ╚███╔╝ ██║  ██║
██║   ██║╚════██║██╔══██╗ ██╔██╗ ██║  ██║
╚██████╔╝     ██║██║  ██║██╔╝ ██╗██████╔╝
 ╚═════╝      ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

**God-Level Subdomain Enumerator v3.2.0**

> 18 parallel tools · 25+ passive API sources · DNS brute-force (opt-in) · CF/429 bypass · HTTP probe · Full parallel execution

---

## Features

| Category | Details |
|---|---|
| **Passive OSINT** | 25+ free API sources (crt.sh, certspotter, HackerTarget, AlienVault, URLScan, Wayback, ThreatMiner, BufferOver, and more) |
| **Keyed APIs** | VirusTotal, Shodan, Censys, SecurityTrails, BinaryEdge, Spyse, C99, FullHunt, BeVigil, Netlas, GitHub, Chaos |
| **External Tools** | subfinder · amass · assetfinder · findomain · sublist3r · gau · waybackurls · theHarvester · chaos · github-subdomains · knockpy · fierce · cero · tlsx · shosubgo · shuffledns · puredns · dnsx |
| **DNS Brute-Force** | Built-in 5000+ wordlist, threaded Python resolver — **off by default**, enable with `-b` |
| **Zone Transfer** | Auto-attempts AXFR against all NS records |
| **DNS Resolution** | Filter raw results to live-only (`-r` flag) |
| **HTTP Probe** | httpx or Python fallback — returns status codes + page titles |
| **CF Bypass** | `-c` flag: retries Cloudflare 503 challenge pages after delay (parallel) |
| **429 Bypass** | `-rl` flag: backs off and retries rate-limited responses with jitter |
| **Parallel Execution** | Every tool, source, and retry runs simultaneously via background jobs |
| **Output** | Full results saved to `.txt` with ASCII banner header + scan metadata |

---

## Installation

### 1. Clone

```bash
git clone https://github.com/4nuxd/sd-blast.git
cd sd-blast
chmod +x g4rxd.sh
```

### 2. Python Dependencies (required)

```bash
pip3 install dnspython requests
```

### 3. Go Tools (recommended)

Make sure Go is installed first: https://go.dev/doc/install

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/glebarez/cero@latest
go install github.com/gwen001/github-subdomains@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/d3mondev/puredns/v2@latest
```

Add Go binaries to your PATH if not already done:

```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### 4. APT Tools

```bash
sudo apt update
sudo apt install -y amass findomain sublist3r theharvester knockpy fierce
```

### 5. Shosubgo (Shodan subdomain tool)

```bash
go install github.com/incogbyte/shosubgo@latest
```

> SD-Blast auto-detects which tools are installed and skips missing ones silently — nothing crashes if a tool is absent.

---

## Usage

```bash
./g4rxd.sh <domain> [options]
```

### Options

| Flag | Description |
|---|---|
| `-o <file>` | Output file (default: `g4rxd_<domain>.txt`) |
| `-r` | DNS resolve — keep only live subdomains |
| `-p` | HTTP probe — show live web servers + status + title |
| `-4` | Filter 404 responses from HTTP probe results |
| `-b` | Enable DNS brute-force (off by default) |
| `-c` | CF retry — re-probe Cloudflare 503 challenge pages after delay |
| `-rl` | Rate-limit bypass — back off and retry 429 responses with jitter |
| `-t <int>` | Threads for brute/resolve/probe (default: `100`) |
| `-z` | Skip zone transfer attempt |
| `-v` | Verbose — show per-source counts |
| `-k <file>` | API key file (default: `~/.g4rxd_keys`) |
| `-h` | Help |

### Examples

```bash
# Basic passive scan — all sources, no brute-force
./g4rxd.sh example.com

# Full scan — passive + resolve live + HTTP probe
./g4rxd.sh example.com -r -p -v

# Cloudflare domain — filter 404s, retry CF challenges, retry 429s
./g4rxd.sh example.com -p -4 -c -rl

# Full bug bounty mode — everything enabled
./g4rxd.sh example.com -p -4 -c -rl -b -v

# High-thread scan with custom output
./g4rxd.sh example.com -r -p -t 200 -o results.txt

# Use API keys for extra sources
./g4rxd.sh example.com -p -k ~/.g4rxd_keys
```

---

## API Keys (Optional)

Create `~/.g4rxd_keys` to unlock premium sources:

```ini
virustotal=YOUR_KEY
shodan=YOUR_KEY
censys_id=YOUR_APP_ID
censys_secret=YOUR_APP_SECRET
binaryedge=YOUR_KEY
securitytrails=YOUR_KEY
spyse=YOUR_KEY
c99=YOUR_KEY
fullhunt=YOUR_KEY
bevigil=YOUR_KEY
github=YOUR_GITHUB_TOKEN
netlas=YOUR_KEY
chaos=YOUR_KEY
```

All keys are **optional**. 25+ free no-key sources work without any configuration.

**Where to get keys:**

| Key | URL |
|---|---|
| VirusTotal | https://www.virustotal.com/gui/my-apikey |
| Shodan | https://account.shodan.io |
| Censys | https://search.censys.io/account/api |
| SecurityTrails | https://securitytrails.com/app/account/credentials |
| BinaryEdge | https://app.binaryedge.io/account/api |
| FullHunt | https://fullhunt.io/user/api |
| BeVigil | https://bevigil.com/osint-api |
| Netlas | https://app.netlas.io/profile |
| Chaos | https://chaos.projectdiscovery.io |
| GitHub Token | https://github.com/settings/tokens (no scopes needed) |

---

## Passive Sources (No Key Required)

| Source | Method |
|---|---|
| crt.sh | Certificate transparency |
| Certspotter | Certificate transparency |
| HackerTarget | Passive DNS |
| AlienVault OTX | Passive DNS |
| RapidDNS | DNS records |
| Wayback Machine | CDX API |
| URLScan.io | Scan results |
| AnubisDB / JLDC | Passive DNS |
| ThreatCrowd | Threat intel |
| BufferOver | DNS brute data |
| ThreatMiner | Threat intel |
| Subdomain Center | Passive DNS |
| Recon.dev | Aggregated OSINT |
| CT Entrust Search | Certificate transparency |
| LeakIX | Exposed services |
| DNSDumpster | Passive DNS |
| SiteDossier | Web crawl data |
| Netcraft | Passive DNS |
| Riddler.io | Passive DNS |
| FullHunt (free tier) | Attack surface |
| BeVigil (free tier) | Mobile OSINT |
| Shodan (scrape) | Internet-wide scan data |
| SecurityTrails (scrape) | DNS history |
| VirusTotal (free) | Passive DNS |
| PassiveTotal (free) | Passive DNS |

---

## Cloudflare & Rate Limit Bypass

Many targets sit behind Cloudflare which returns:

- **503 + "Loading Page"** — JS challenge page, not real content
- **429** — Rate limit, real backend exists but is blocking requests

SD-Blast handles both:

```bash
# -c  : detect CF 503 challenge → wait 8s → retry (all in parallel)
# -rl : detect 429 → exponential backoff with jitter → retry up to 3x

./g4rxd.sh target.com -p -c -rl
```

Since retries run in parallel across all subdomains, the overhead is the delay of the single slowest host — not delay × number of subdomains.

---

## Output Files

| File | Contents |
|---|---|
| `g4rxd_<domain>.txt` | All unique subdomains (with banner header) |
| `g4rxd_<domain>_live.txt` | DNS-resolved live subdomains (`-r` flag) |
| `g4rxd_<domain>_http.txt` | Live HTTP servers with status + title (`-p` flag) |

---

## Tool Chain (All Parallel, Auto-detected)

```
subfinder · amass · assetfinder · findomain · sublist3r
gau · waybackurls · theHarvester · chaos · github-subdomains
knockpy · fierce · cero · tlsx · shosubgo
shuffledns · puredns · dnsx · sources.py (25+ APIs)
bruteforce (5000+ words) — opt-in with -b
```

All tools launch simultaneously. Results merge and deduplicate after all jobs finish.

---

## Project Structure

```
sd-blast/
├── g4rxd.sh        # Main wrapper — orchestrates everything
├── sources.py      # Python API aggregator (25+ sources, concurrent)
├── brute.py        # DNS brute-forcer (5000+ wordlist, threaded)
├── resolve.py      # DNS resolution filter (threaded dnspython)
└── probe.py        # HTTP/HTTPS prober with CF/429 retry logic
```

---

## Legal Disclaimer

> This tool is intended for **authorized security testing and bug bounty programs only**.
> Do not use against targets you do not own or have explicit written permission to test.
> The author is not responsible for any misuse.

---

## Author

**g4rxd**
GitHub: [https://github.com/4nuxd/sd-blast](https://github.com/4nuxd/sd-blast)

---

## License

MIT License — use freely, credit appreciated.
