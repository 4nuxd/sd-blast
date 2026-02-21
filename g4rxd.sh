#!/bin/bash

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
BLUE="\033[1;34m"
MAGENTA="\033[1;35m"
WHITE="\033[1;37m"
RESET="\033[0m"
BOLD="\033[1m"
DIM="\033[2m"

BANNER_TEXT='
 ██████╗ ██╗  ██╗██████╗ ██╗  ██╗██████╗
██╔════╝ ██║  ██║██╔══██╗╚██╗██╔╝██╔══██╗
██║  ███╗███████║██████╔╝ ╚███╔╝ ██║  ██║
██║   ██║╚════██║██╔══██╗ ██╔██╗ ██║  ██║
╚██████╔╝     ██║██║  ██║██╔╝ ██╗██████╔╝
 ╚═════╝      ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
'

banner() {
  clear
  echo -e "${CYAN}${BOLD}${BANNER_TEXT}${RESET}"
    echo -e "${WHITE}${BOLD}        God-Level Subdomain Enumerator  v3.2.0${RESET}"
  echo -e "${DIM}${CYAN}  ─────────────────────────────────────────────────────${RESET}"
  echo -e "${DIM}  35+ passive sources · 18 tools · zone-xfer · probe · PARALLEL${RESET}"
  echo ""
}

usage() {
  echo -e "${YELLOW}${BOLD}Usage:${RESET}"
  echo -e "  $0 <domain> [options]"
  echo ""
  echo -e "${YELLOW}${BOLD}Options:${RESET}"
  echo -e "  ${GREEN}-o <file>${RESET}    Output file (default: g4rxd_<domain>.txt)"
  echo -e "  ${GREEN}-r${RESET}           DNS resolve  — keep only live subdomains"
  echo -e "  ${GREEN}-p${RESET}           HTTP probe   — show live web servers + status + title"
  echo -e "  ${GREEN}-4${RESET}           Filter 404s  (auto-enables probe)"
  echo -e "  ${GREEN}-c${RESET}           CF-retry     — re-probe Cloudflare 503 challenge pages"
  echo -e "  ${GREEN}-rl${RESET}          Rate-limit   — back off + retry on 429 responses"
  echo -e "  ${GREEN}-b${RESET}           DNS brute-force (off by default, opt-in)"
  echo -e "  ${GREEN}-t <int>${RESET}     Threads for brute/resolve/probe (default: 100)"
  echo -e "  ${GREEN}-z${RESET}           Skip zone transfer attempt"
  echo -e "  ${GREEN}-v${RESET}           Verbose — show per-source counts"
  echo -e "  ${GREEN}-k <file>${RESET}    API key file (default: ~/.g4rxd_keys)"
  echo -e "  ${GREEN}-vh <IP>${RESET}     VHost mode — brute-force virtual hosts on IP (for .htb/.thm)"
  echo -e "  ${GREEN}-h${RESET}           Help"
  echo ""
  echo -e "${YELLOW}${BOLD}API key file format  (~/.g4rxd_keys):${RESET}"
  echo -e "  virustotal=YOUR_KEY"
  echo -e "  shodan=YOUR_KEY"
  echo -e "  censys_id=YOUR_ID"
  echo -e "  censys_secret=YOUR_SECRET"
  echo -e "  binaryedge=YOUR_KEY"
  echo -e "  securitytrails=YOUR_KEY"
  echo -e "  spyse=YOUR_KEY"
  echo -e "  c99=YOUR_KEY"
  echo -e "  fullhunt=YOUR_KEY"
  echo -e "  bevigil=YOUR_KEY"
  echo -e "  github=YOUR_TOKEN"
  echo -e "  netlas=YOUR_KEY"
  echo ""
  echo -e "${YELLOW}${BOLD}Examples:${RESET}"
  echo -e "  $0 example.com"
  echo -e "  $0 example.com -r -p -v"
  echo -e "  $0 example.com -r -p -t 200 -k ~/.g4rxd_keys -o out.txt"
  exit 0
}

log()     { echo -e "${GREEN}[+]${RESET} $*"; }
info()    { echo -e "${CYAN}[i]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
success() { echo -e "${MAGENTA}[✓]${RESET} $*"; }
step()    { echo -e "${BLUE}[→]${RESET} $*"; }
skip()    { [[ "$VERBOSE" == true ]] && echo -e "${DIM}[~] SKIP: $*${RESET}"; }

banner

DOMAIN=""
OUTPUT=""
DO_RESOLVE=false
DO_PROBE=false
THREADS=100
DO_BRUTE=false
VHOST_IP=""
SKIP_ZONETRANSFER=false
VERBOSE=false
KEY_FILE="$HOME/.g4rxd_keys"
NO_404=false
CF_WAIT=false
RATE_LIMIT=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) OUTPUT="$2";        shift 2 ;;
    -r) DO_RESOLVE=true;    shift ;;
    -p) DO_PROBE=true;      shift ;;
    -t) THREADS="$2";       shift 2 ;;
      -b) DO_BRUTE=true;      shift ;;
      -vh) VHOST_IP="$2";     DO_BRUTE=true; shift 2 ;;
        -z) SKIP_ZONETRANSFER=true; shift ;;
      -v) VERBOSE=true;       shift ;;
      -k) KEY_FILE="$2";      shift 2 ;;
        -4) NO_404=true;        shift ;;
        -c) CF_WAIT=true;       shift ;;
        -rl) RATE_LIMIT=true;   shift ;;
    -h|--help) usage ;;
    -*) warn "Unknown option: $1"; shift ;;
    *) DOMAIN="$1"; shift ;;
  esac
done

[[ -z "$DOMAIN" ]] && { echo -e "${RED}[✗] No domain specified.${RESET}"; usage; }

[[ "$NO_404"      == true ]] && DO_PROBE=true
[[ "$CF_WAIT"    == true ]] && DO_PROBE=true
[[ "$RATE_LIMIT"  == true ]] && DO_PROBE=true
[[ -z "$OUTPUT" ]] && OUTPUT="g4rxd_${DOMAIN}.txt"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

declare -A KEYS
if [[ -f "$KEY_FILE" ]]; then
  while IFS='=' read -r k v; do
    [[ -z "$k" || "$k" == \#* ]] && continue
    KEYS["$k"]="${v}"
  done < "$KEY_FILE"
fi

WORKDIR=$(mktemp -d /tmp/g4rxd_XXXXXX)
RAW="$WORKDIR/raw.txt"
LIVE_FILE="$WORKDIR/live.txt"
HTTP_FILE="$WORKDIR/http.txt"
PIDS_FILE="$WORKDIR/pids.txt"
touch "$RAW" "$PIDS_FILE"
trap 'rm -rf "$WORKDIR"' EXIT

log "Target     : ${WHITE}${BOLD}$DOMAIN${RESET}"
log "Output     : ${WHITE}$OUTPUT${RESET}"
log "Threads    : ${WHITE}$THREADS${RESET}"
log "Resolve    : ${WHITE}$DO_RESOLVE${RESET}  |  Probe: ${WHITE}$DO_PROBE${RESET}  |  CF-Wait: ${WHITE}$CF_WAIT${RESET}  |  RateLimit: ${WHITE}$RATE_LIMIT${RESET}  |  Brute: ${WHITE}$DO_BRUTE${RESET}"
echo ""

add_file() {
  local src="$1" file="$2"
  local before after new_count
  before=$(wc -l < "$RAW")
  grep -Eo "([a-zA-Z0-9_*-]+\.)+${DOMAIN//./\\.}" "$file" 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/^\*\.//' \
    >> "$RAW"
  after=$(wc -l < "$RAW")
  new_count=$(( after - before ))
  if [[ "$VERBOSE" == true ]]; then
    printf "${DIM}    %-26s +%d${RESET}\n" "[$src]" "$new_count"
  fi
}

if [[ "$SKIP_ZONETRANSFER" == false ]]; then
  step "Zone transfer attempt..."
  NS_LIST=$(dig +short NS "$DOMAIN" 2>/dev/null | sed 's/\.$//g')
  ZONE_FOUND=false
  ZONE_TMP="$WORKDIR/zone.txt"
  for ns in $NS_LIST; do
    RESULT=$(dig axfr "$DOMAIN" "@$ns" 2>/dev/null)
    if echo "$RESULT" | grep -q "Transfer failed\|SERVFAIL\|connection timed"; then
      continue
    fi
    echo "$RESULT" >> "$ZONE_TMP"
    ZONE_FOUND=true
    [[ "$VERBOSE" == true ]] && info "  Zone transfer OK on $ns"
  done
  [[ -f "$ZONE_TMP" ]] && add_file "zonetransfer" "$ZONE_TMP"
  [[ "$ZONE_FOUND" == false ]] && skip "Zone transfer failed/blocked (normal)"
fi

echo ""
step "${BOLD}Launching all tools in parallel...${RESET}"
echo ""

TOOL_PIDS=()
TOOL_NAMES=()
TOOL_FILES=()

_launch() {
  local name="$1"; shift
  local tmpf="$WORKDIR/tool_${name}.txt"
  touch "$tmpf"
  "$@" > "$tmpf" 2>/dev/null &
  local pid=$!
  TOOL_PIDS+=("$pid")
  TOOL_NAMES+=("$name")
  TOOL_FILES+=("$tmpf")
  echo -e "  ${BLUE}⟳${RESET} ${WHITE}$name${RESET} ${DIM}(pid $pid)${RESET}"
}

if command -v subfinder &>/dev/null; then
  _launch "subfinder" subfinder -silent -all -d "$DOMAIN"
else
  skip "subfinder not installed  (go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)"
fi

if command -v amass &>/dev/null; then
  _launch "amass" amass enum -passive -norecursive -d "$DOMAIN"
else
  skip "amass not installed  (sudo apt install amass)"
fi

if command -v assetfinder &>/dev/null; then
  _launch "assetfinder" assetfinder --subs-only "$DOMAIN"
else
  skip "assetfinder not installed  (go install github.com/tomnomnom/assetfinder@latest)"
fi

if command -v findomain &>/dev/null; then
  _launch "findomain" findomain --quiet -t "$DOMAIN"
else
  skip "findomain not installed  (sudo apt install findomain)"
fi

if command -v sublist3r &>/dev/null; then
  _launch "sublist3r" sublist3r -n -d "$DOMAIN" -o /dev/stdout
elif python3 -c "import sublist3r" 2>/dev/null; then
  _launch "sublist3r" python3 -c "
import sublist3r
subs = sublist3r.main('$DOMAIN', 40, savefile=None, ports=None,
                      silent=True, verbose=False, enable_bruteforce=False, engines=None)
for s in (subs or []):
    print(s)
"
else
  skip "sublist3r not installed  (sudo apt install sublist3r)"
fi

if command -v gau &>/dev/null; then
  _launch "gau" bash -c "echo '$DOMAIN' | gau --subs 2>/dev/null \
    | grep -oE '([a-zA-Z0-9_-]+\.)+${DOMAIN//./\\.}' | sort -u"
else
  skip "gau not installed  (go install github.com/lc/gau/v2/cmd/gau@latest)"
fi

if command -v waybackurls &>/dev/null; then
  _launch "waybackurls" bash -c "echo '$DOMAIN' | waybackurls 2>/dev/null \
    | grep -oE '([a-zA-Z0-9_-]+\.)+${DOMAIN//./\\.}' | sort -u"
else
  skip "waybackurls not installed  (go install github.com/tomnomnom/waybackurls@latest)"
fi

if command -v theHarvester &>/dev/null || command -v theharvester &>/dev/null; then
  BIN_TH=$(command -v theHarvester 2>/dev/null || command -v theharvester)
  _launch "theHarvester" bash -c "$BIN_TH -d '$DOMAIN' -b all -f /dev/null 2>/dev/null \
    | grep -oE '([a-zA-Z0-9_-]+\.)+${DOMAIN//./\\.}' | sort -u"
else
  skip "theHarvester not installed  (sudo apt install theharvester)"
fi

if command -v chaos &>/dev/null && [[ -n "${KEYS[chaos]}" ]]; then
  _launch "chaos" chaos -d "$DOMAIN" -key "${KEYS[chaos]}" -silent
else
  skip "chaos not found / no key  (go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest)"
fi

if command -v github-subdomains &>/dev/null && [[ -n "${KEYS[github]}" ]]; then
  _launch "github-subdomains" github-subdomains -d "$DOMAIN" -t "${KEYS[github]}" -raw
else
  skip "github-subdomains not found / no token  (go install github.com/gwen001/github-subdomains@latest)"
fi

if command -v knockpy &>/dev/null; then
  KNOCK_OUT="$WORKDIR/knock"
  mkdir -p "$KNOCK_OUT"
  _launch "knockpy" bash -c "knockpy '$DOMAIN' --silent -o '$KNOCK_OUT' 2>/dev/null; \
    python3 -c \"
import json, glob
for f in glob.glob('$KNOCK_OUT/*.json'):
    try:
        d = json.load(open(f))
        [print(k) for k in d.keys()]
    except: pass
\""
else
  skip "knockpy not installed  (sudo apt install knockpy)"
fi

if command -v fierce &>/dev/null; then
  _launch "fierce" bash -c "fierce --domain '$DOMAIN' 2>/dev/null \
    | grep -oE '([a-zA-Z0-9_-]+\.)+${DOMAIN//./\\.}' | sort -u"
else
  skip "fierce not installed  (sudo apt install fierce)"
fi

if command -v cero &>/dev/null; then
  _launch "cero" bash -c "cero '$DOMAIN' 2>/dev/null \
    | grep -oE '([a-zA-Z0-9_-]+\.)+${DOMAIN//./\\.}' | sort -u"
else
  skip "cero not installed  (go install github.com/glebarez/cero@latest)"
fi

if command -v tlsx &>/dev/null; then
  _launch "tlsx" bash -c "echo '$DOMAIN' | tlsx -san -cn -silent 2>/dev/null \
    | grep -oE '([a-zA-Z0-9_-]+\.)+${DOMAIN//./\\.}' | sort -u"
else
  skip "tlsx not installed  (go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest)"
fi

if command -v shosubgo &>/dev/null && [[ -n "${KEYS[shodan]}" ]]; then
  _launch "shosubgo" bash -c "shosubgo -d '$DOMAIN' -a '${KEYS[shodan]}' 2>/dev/null \
    | grep -oE '([a-zA-Z0-9_-]+\.)+${DOMAIN//./\\.}' | sort -u"
else
  skip "shosubgo not found / no shodan key  (go install github.com/incogbyte/shosubgo@latest)"
fi

if command -v shuffledns &>/dev/null; then
  _launch "shuffledns" bash -c "shuffledns -d '$DOMAIN' -mode bruteforce \
    -w '$SCRIPT_DIR/wordlist.txt' -r /dev/stdin -silent 2>/dev/null \
    <<< '8.8.8.8' | grep -oE '([a-zA-Z0-9_-]+\.)+${DOMAIN//./\\.}' | sort -u"
else
  skip "shuffledns not installed  (go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest)"
fi

if command -v puredns &>/dev/null; then
  _launch "puredns" bash -c "puredns bruteforce '$SCRIPT_DIR/wordlist.txt' '$DOMAIN' \
    --resolvers <(echo '8.8.8.8') 2>/dev/null \
    | grep -oE '([a-zA-Z0-9_-]+\.)+${DOMAIN//./\\.}' | sort -u"
else
  skip "puredns not installed  (go install github.com/d3mondev/puredns/v2@latest)"
fi

if command -v dnsx &>/dev/null; then
  _launch "dnsx" bash -c "echo '$DOMAIN' | dnsx -silent -a -resp-only \
    -r 8.8.8.8,1.1.1.1,9.9.9.9 -t '$THREADS' 2>/dev/null"
else
  skip "dnsx not installed  (go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest)"
fi

_launch "sources.py" python3 "$SCRIPT_DIR/sources.py" "$DOMAIN" \
  --vt-key  "${KEYS[virustotal]:-}" \
  --st-key  "${KEYS[securitytrails]:-}" \
  --be-key  "${KEYS[binaryedge]:-}" \
  --sh-key  "${KEYS[shodan]:-}" \
  --cx-id   "${KEYS[censys_id]:-}" \
  --cx-sec  "${KEYS[censys_secret]:-}" \
  --sp-key  "${KEYS[spyse]:-}" \
  --c99-key "${KEYS[c99]:-}" \
  --fh-key  "${KEYS[fullhunt]:-}" \
  --bv-key  "${KEYS[bevigil]:-}" \
  --nl-key  "${KEYS[netlas]:-}"

if [[ "$DO_BRUTE" == true ]]; then
  if [[ -n "$VHOST_IP" ]]; then
    info "VHost mode enabled — hitting ${WHITE}$VHOST_IP${RESET} with Host: headers (bypassing DNS)"
    _launch "vhost-brute" python3 "$SCRIPT_DIR/brute.py" "$DOMAIN" "$THREADS" \
      --vhost "$VHOST_IP"
  else
    _launch "bruteforce" python3 "$SCRIPT_DIR/brute.py" "$DOMAIN" "$THREADS"
  fi
else
  skip "DNS brute-force off (use -b for DNS mode, -vh <IP> for VHost mode)"
fi

echo ""
step "${BOLD}Waiting for all parallel jobs to finish...${RESET}"

TOTAL_TOOLS=${
DONE=0
for i in "${!TOOL_PIDS[@]}"; do
  pid="${TOOL_PIDS[$i]}"
  name="${TOOL_NAMES[$i]}"
  file="${TOOL_FILES[$i]}"
  wait "$pid" 2>/dev/null
  DONE=$(( DONE + 1 ))
    count=$(grep -c . "$file" 2>/dev/null); count=$(( ${count:-0} + 0 ))
  printf "  ${GREEN}[%d/%d]${RESET} %-26s ${DIM}→ %d results${RESET}\n" \
    "$DONE" "$TOTAL_TOOLS" "$name" "$count"
  add_file "$name" "$file"
done

sort -u "$RAW" > "$OUTPUT.tmp"
RAW_COUNT=$(wc -l < "$OUTPUT.tmp")

echo ""
echo -e "${MAGENTA}─────────────────────────────────────────────────────────────${RESET}"
success "Raw unique subdomains : ${WHITE}${BOLD}${RAW_COUNT}${RESET}"

LIVE_COUNT=0
LIVE_OUT=""
if [[ "$DO_RESOLVE" == true ]]; then
    echo ""
    step "Resolving DNS ($THREADS threads) with wildcard detection..."
    python3 "$SCRIPT_DIR/resolve.py" "$OUTPUT.tmp" "$THREADS" > "$LIVE_FILE" 2>&1
    grep -v "^\[" "$LIVE_FILE" | sort -u > "$WORKDIR/live_clean.txt" 2>/dev/null || true
    grep "^\[" "$LIVE_FILE" | while read -r line; do
        echo -e "  ${YELLOW}$line${RESET}"
    done
    sort -u "$WORKDIR/live_clean.txt" -o "$WORKDIR/live_clean.txt"
    cp "$WORKDIR/live_clean.txt" "$LIVE_FILE"
    LIVE_COUNT=$(wc -l < "$LIVE_FILE")
    LIVE_OUT="${OUTPUT%.txt}_live.txt"
    cp "$LIVE_FILE" "$LIVE_OUT"
    success "Live (DNS resolved)   : ${WHITE}${BOLD}${LIVE_COUNT}${RESET}  →  ${GREEN}$LIVE_OUT${RESET}"
fi

HTTP_COUNT=0
HTTP_OUT=""
if [[ "$DO_PROBE" == true ]]; then
  echo ""
  PROBE_INPUT="$OUTPUT.tmp"
  [[ "$DO_RESOLVE" == true ]] && PROBE_INPUT="$LIVE_FILE"

      step "HTTP probing ($THREADS threads)..."
      HTTPX_BIN=""
      for _bin in ~/go/bin/httpx /usr/local/bin/httpx /usr/bin/httpx $(which httpx 2>/dev/null); do
        if "$_bin" -version &>/dev/null 2>&1; then
          HTTPX_BIN="$_bin"
          break
        fi
      done
      if [[ -n "$HTTPX_BIN" ]]; then
        HTTPX_ARGS="-l '$PROBE_INPUT' -silent -status-code -title -tech-detect -timeout 10 -threads '$THREADS'"
        [[ "$NO_404" == true ]] && HTTPX_ARGS="$HTTPX_ARGS -mc 200,201,204,301,302,303,307,308,401,403,405,500,503"
        eval "$HTTPX_BIN" $HTTPX_ARGS 2>/dev/null > "$HTTP_FILE"
      else
        PROBE_FLAGS=""
        [[ "$NO_404"     == true ]] && PROBE_FLAGS="$PROBE_FLAGS --no-404"
        [[ "$CF_WAIT"    == true ]] && PROBE_FLAGS="$PROBE_FLAGS --cf-wait"
        [[ "$RATE_LIMIT" == true ]] && PROBE_FLAGS="$PROBE_FLAGS --rate-limit"
        python3 "$SCRIPT_DIR/probe.py" "$PROBE_INPUT" "$THREADS" $PROBE_FLAGS > "$HTTP_FILE"
      fi
  sort -u "$HTTP_FILE" -o "$HTTP_FILE"
  HTTP_COUNT=$(wc -l < "$HTTP_FILE")
  HTTP_OUT="${OUTPUT%.txt}_http.txt"
  cp "$HTTP_FILE" "$HTTP_OUT"
  success "Live HTTP servers     : ${WHITE}${BOLD}${HTTP_COUNT}${RESET}  →  ${GREEN}$HTTP_OUT${RESET}"

  if [[ $HTTP_COUNT -gt 0 ]]; then
    echo ""
    echo -e "${CYAN}  ── Top 30 HTTP Results ──────────────────────────────────${RESET}"
    head -30 "$HTTP_OUT"
  fi
fi

NOW=$(date '+%Y-%m-%d %H:%M:%S')

{
printf '=============================================================\n'
printf ' ██████╗ ██╗  ██╗██████╗ ██╗  ██╗██████╗\n'
printf '██╔════╝ ██║  ██║██╔══██╗╚██╗██╔╝██╔══██╗\n'
printf '██║  ███╗███████║██████╔╝ ╚███╔╝ ██║  ██║\n'
printf '██║   ██║╚════██║██╔══██╗ ██╔██╗ ██║  ██║\n'
printf '╚██████╔╝     ██║██║  ██║██╔╝ ██╗██████╔╝\n'
printf ' ╚═════╝      ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝\n'
printf '=============================================================\n'
printf ' God-Level Subdomain Enumerator v3.2.0\n'
printf '=============================================================\n'
printf ' Target  : %s\n' "$DOMAIN"
printf ' Date    : %s\n' "$NOW"
printf ' Total   : %d unique subdomains\n' "$RAW_COUNT"
[[ "$DO_RESOLVE" == true ]] && printf ' Live DNS: %d\n' "$LIVE_COUNT"
[[ "$DO_PROBE"   == true ]] && printf ' Live HTTP: %d\n' "$HTTP_COUNT"
printf '=============================================================\n'
printf '\n'
cat "$OUTPUT.tmp"
} > "$OUTPUT"
rm -f "$OUTPUT.tmp"

echo ""
echo -e "${MAGENTA}═════════════════════════════════════════════════════════════${RESET}"
echo -e "${CYAN}${BOLD}  G4RXD v3.2.0  —  Scan Complete${RESET}"
echo -e "${MAGENTA}═════════════════════════════════════════════════════════════${RESET}"
echo -e "  ${WHITE}Domain      :${RESET}  ${BOLD}$DOMAIN${RESET}"
echo -e "  ${WHITE}Date        :${RESET}  $NOW"
echo -e "  ${WHITE}All subs    :${RESET}  ${BOLD}${GREEN}$RAW_COUNT${RESET}  →  $OUTPUT"
[[ "$DO_RESOLVE" == true ]] && \
  echo -e "  ${WHITE}Live DNS    :${RESET}  ${BOLD}${GREEN}$LIVE_COUNT${RESET}  →  $LIVE_OUT"
[[ "$DO_PROBE"   == true ]] && \
  echo -e "  ${WHITE}Live HTTP   :${RESET}  ${BOLD}${GREEN}$HTTP_COUNT${RESET}  →  $HTTP_OUT"
echo -e "${MAGENTA}═════════════════════════════════════════════════════════════${RESET}"
echo ""
