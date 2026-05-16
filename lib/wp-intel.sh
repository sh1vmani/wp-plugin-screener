#!/usr/bin/env bash
# lib/wp-intel.sh — unified vuln-intel resolver (ROADMAP ★ B0).
#
# SOURCE THIS, don't exec it:   . "$(dirname "$0")/lib/wp-intel.sh"
#
# One abstraction over every free WP-vuln source. Consumers call intel::*
# and never touch a raw source again. A provider registry + policy engine
# picks the cheapest sufficient source per query and only escalates when a
# free source was inconclusive (this is what "intelligently pick" means).
#
# PROVIDERS (this increment): wf_bulk (free-cached, PRIMARY for cve/advisory/
# fixed_in — Wordfence Intelligence by-slug dump, already cached by the
# finder; B0 only READS + age-guards it, never re-fetches a parallel copy),
# and wporg (free, no quota — wp.org plugin metadata).
#
# Empirically corrected 2026-05-15: OSV.dev has NO WordPress ecosystem, so it
# is NOT a slug→CVE provider (probe: "Invalid ecosystem"). WF-bulk already
# carries per-advisory `patched_versions`, so it is the primary `fixed_in`
# source and WPScan (B1, later) is only a rare quota cross-confirm — that is
# the real WPScan-lock dissolution, not OSV.
#
# Public interface (stable):
#   intel::cves       <slug>            -> JSON array of normalized records
#   intel::fixed_in   <slug>            -> best/latest patched version (text)
#   intel::advisories <slug>            -> TSV: version<TAB>type<TAB>title
#   intel::meta       <slug>            -> JSON {active_installs,last_updated,author,version}
#   intel::source_of  <slug> <qtype>    -> which provider answered (provenance)
#   intel::wf_age_days                  -> staleness of the WF bulk cache
#   intel::health                       -> one-line provider health summary
# Query types for source_of: cves | advisories | fixed_in | meta
#
# Cache + provenance: $HOME/.cache/wp-intel/  (per-slug per-qtype, 24h TTL).

# ---- config ----------------------------------------------------------------
: "${WP_INTEL_WF_INDEX:=$HOME/.cache/wp-target-finder/wordfence-by-slug.json}"
: "${WP_INTEL_CACHE:=$HOME/.cache/wp-intel}"
: "${WP_INTEL_WF_STALE_DAYS:=10}"     # warn if WF bulk older than this
: "${WP_INTEL_TTL:=86400}"            # per-query result cache TTL (24h)
# B1 — WPScan key pool (QUOTA cross-confirm; reached only when wf_bulk is
# inconclusive). Keys from $WPSCAN_API_TOKENS (comma-sep), or $WPSCAN_API_TOKEN
# (single, back-compat), or ~/.config/wp-finder/wpscan-keys (one per line).
: "${WP_INTEL_WPSCAN_KEYFILE:=$HOME/.config/wp-finder/wpscan-keys}"
: "${WP_INTEL_WPSCAN_COOLDOWN:=86400}"   # per-key cooldown on 429/exhaustion
_INTEL_WPSCAN_STATE="$WP_INTEL_CACHE/wpscan-keys.state"   # key<TAB>cooling_until
_INTEL_PYBIN="$(command -v python3.12 || command -v python3.11 || command -v python3)"
mkdir -p "$WP_INTEL_CACHE" 2>/dev/null || true

# Provenance is FILE-based (not an in-memory array): consumers call
# resolvers via $(intel::fixed_in x) which runs in a subshell, so an
# assoc array set inside would be lost. A sidecar .prov file survives.

_intel_warn() { printf '[wp-intel] %s\n' "$*" >&2; }

# ---- staleness / health ----------------------------------------------------
intel::wf_age_days() {
    [ -f "$WP_INTEL_WF_INDEX" ] || { echo -1; return; }
    local mt now
    mt=$(stat -c %Y "$WP_INTEL_WF_INDEX" 2>/dev/null || echo 0)
    now=$(date +%s)
    echo $(( (now - mt) / 86400 ))
}

intel::health() {
    local age wf nkeys live=0 k
    age=$(intel::wf_age_days)
    if   [ "$age" -lt 0 ]; then wf="wf_bulk=MISSING (run wp-target-finder.sh once)"
    elif [ "$age" -gt "$WP_INTEL_WF_STALE_DAYS" ]; then wf="wf_bulk=STALE(${age}d)"
    else wf="wf_bulk=ok(${age}d)"; fi
    nkeys=$(_intel_wpscan_keys | grep -c . || true)
    while IFS= read -r k; do [ -z "$k" ] && continue; _intel_wpscan_cooling "$k" || live=$((live+1)); done < <(_intel_wpscan_keys)
    echo "$wf · wporg=ok · wpscan=${live}/${nkeys} live key(s) (quota cross-confirm)"
}

# ---- internal: cache helpers ----------------------------------------------
_intel_cache_file() { echo "$WP_INTEL_CACHE/${1}.${2}"; }   # <slug> <qtype>
_intel_cache_fresh() {
    local f="$1"
    [ -s "$f" ] || return 1
    local mt now; mt=$(stat -c %Y "$f" 2>/dev/null || echo 0); now=$(date +%s)
    [ $(( now - mt )) -lt "$WP_INTEL_TTL" ]
}

# ---- provider: wf_bulk (PRIMARY; free-cached) ------------------------------
# Reads the existing Wordfence by-slug dump. Never fetches a parallel copy
# (anti-dup constraint: the finder owns fetching; B0 owns reading + freshness).
_intel_wf_query() {
    # args: <slug> <qtype>   stdout: result   rc 0 ok / 1 no-data / 2 no-source
    local slug="$1" qtype="$2"
    [ -f "$WP_INTEL_WF_INDEX" ] || return 2
    "$_INTEL_PYBIN" - "$WP_INTEL_WF_INDEX" "$slug" "$qtype" <<'PY'
import sys, json, re
idx, slug, qtype = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    d = json.load(open(idx))
except Exception:
    sys.exit(2)
advs = d.get(slug) or []
recs = []
for a in advs:
    if a.get("informational"):
        continue
    sw = (a.get("software") or [{}])[0]
    pv = sw.get("patched_versions") or []
    aff = sw.get("affected_versions") or {}
    # derive a compact affected upper bound for display
    ub = ""
    for k, v in (aff.items() if isinstance(aff, dict) else []):
        ub = v.get("to_version") or ub
    t = a.get("title", "") or ""
    recs.append({
        "id": a.get("id", ""),
        "title": t,
        "published": (a.get("published", "") or "")[:10],
        "type": (a.get("cwe", "") or "").strip() or "—",
        "affected_to": ub,
        "fixed_in": pv[0] if pv else "",
        "patched": bool(sw.get("patched")),
    })
if not recs:
    sys.exit(1)
recs.sort(key=lambda r: r["published"], reverse=True)
if qtype == "cves":
    print(json.dumps(recs))
elif qtype == "advisories":
    for r in recs:
        print(f"{r['affected_to'] or '?'}\t{r['type']}\t{r['title'][:140]}")
elif qtype == "fixed_in":
    # primary fixed_in = newest patched advisory's patched version
    fx = next((r["fixed_in"] for r in recs if r["fixed_in"]), "")
    if not fx:
        sys.exit(1)
    print(fx)
else:
    sys.exit(1)
PY
}

# ---- provider: wporg (free, no quota) -------------------------------------
_intel_wporg_meta() {
    local slug="$1" body
    body=$(curl -sS -m 15 -A 'Mozilla/5.0 (wp-intel)' \
        "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=${slug}" 2>/dev/null) || return 2
    printf '%s' "$body" | "$_INTEL_PYBIN" -c '
import sys, json, re
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(d, dict) or d.get("error"):
    sys.exit(1)
print(json.dumps({
    "active_installs": d.get("active_installs", 0) or 0,
    "last_updated": (d.get("last_updated", "") or "")[:10],
    "author": re.sub("<[^>]+>", "", d.get("author", "") or "").strip()[:80],
    "version": d.get("version", ""),
}))' || return 1
}

# ---- provider: wpscan (B1; QUOTA, multi-key rotation, last-resort) --------
# Pool resolution order: $WPSCAN_API_TOKENS, then $WPSCAN_API_TOKEN, then the
# keyfile. Per-key cooldown ledger: a key that 429s / exhausts is parked for
# WP_INTEL_WPSCAN_COOLDOWN; the resolver transparently advances to the next
# live key and only hard-fails (rc 2) when EVERY key is cooling/absent — so
# the free chain always still answers; WPScan never blocks a hunt.
_intel_wpscan_keys() {
    local raw=""
    [ -n "${WPSCAN_API_TOKENS:-}" ] && raw="$WPSCAN_API_TOKENS"
    [ -z "$raw" ] && [ -n "${WPSCAN_API_TOKEN:-}" ] && raw="$WPSCAN_API_TOKEN"
    if [ -z "$raw" ] && [ -f "$WP_INTEL_WPSCAN_KEYFILE" ]; then
        raw=$(grep -vE '^\s*($|#)' "$WP_INTEL_WPSCAN_KEYFILE" | tr '\n' ',')
    fi
    printf '%s' "$raw" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$'
}
_intel_wpscan_cooling() {            # rc 0 = key is currently cooling
    local key="$1" until now
    [ -f "$_INTEL_WPSCAN_STATE" ] || return 1
    until=$(awk -F'\t' -v k="$key" '$1==k{print $2}' "$_INTEL_WPSCAN_STATE" | tail -1)
    [ -z "$until" ] && return 1
    now=$(date +%s); [ "$now" -lt "$until" ]
}
_intel_wpscan_park() {               # mark key cooling
    local key="$1" until; until=$(( $(date +%s) + WP_INTEL_WPSCAN_COOLDOWN ))
    grep -vE "^${key}	" "$_INTEL_WPSCAN_STATE" 2>/dev/null > "$_INTEL_WPSCAN_STATE.tmp" || true
    printf '%s\t%s\n' "$key" "$until" >> "$_INTEL_WPSCAN_STATE.tmp"
    mv "$_INTEL_WPSCAN_STATE.tmp" "$_INTEL_WPSCAN_STATE" 2>/dev/null || true
}
_intel_wpscan_query() {              # <slug> <qtype>  rc 0 ok / 1 no-data / 2 no-live-key
    local slug="$1" qtype="$2" key code body live=0
    while IFS= read -r key; do
        [ -z "$key" ] && continue
        live=1
        _intel_wpscan_cooling "$key" && continue
        body=$(curl -sS -m 20 -H "Authorization: Token token=${key}" \
               -w '\n%{http_code}' "https://wpscan.com/api/v3/plugins/${slug}" 2>/dev/null) || { _intel_wpscan_park "$key"; continue; }
        code="${body##*$'\n'}"; body="${body%$'\n'*}"
        if [ "$code" = "429" ] || printf '%s' "$body" | grep -qiE 'rate limit|exceeded|too many request'; then
            _intel_warn "wpscan key …${key: -6} exhausted/429 → parked ${WP_INTEL_WPSCAN_COOLDOWN}s, advancing"
            _intel_wpscan_park "$key"; continue
        fi
        [ "$code" = "200" ] || { _intel_wpscan_park "$key"; continue; }
        printf '%s' "$body" | "$_INTEL_PYBIN" - "$slug" "$qtype" <<'PY'
import sys, json
slug, qtype = sys.argv[1], sys.argv[2]
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
vs = (d.get(slug) or {}).get("vulnerabilities") or []
recs = []
for v in vs:
    recs.append({
        "id": (v.get("references", {}) or {}).get("cve", [""])[0] if isinstance(v.get("references", {}).get("cve"), list) else "",
        "title": v.get("title", ""),
        "published": (v.get("published_date", "") or "")[:10],
        "type": v.get("vuln_type", "—"),
        "fixed_in": v.get("fixed_in") or "",
        "affected_to": "",
        "patched": bool(v.get("fixed_in")),
    })
if not recs:
    sys.exit(1)
recs.sort(key=lambda r: r["published"], reverse=True)
if qtype == "cves":
    print(json.dumps(recs))
elif qtype == "fixed_in":
    fx = next((r["fixed_in"] for r in recs if r["fixed_in"]), "")
    print(fx) if fx else sys.exit(1)
elif qtype == "advisories":
    for r in recs:
        print(f"?\t{r['type']}\t{r['title'][:140]}")
else:
    sys.exit(1)
PY
        return $?      # answered (0) or no-data (1) from this live key
    done < <(_intel_wpscan_keys)
    [ "$live" = 1 ] && return 2 || return 2   # all cooling, or no keys → no-source
}

# ---- policy engine: ordered provider chain per query type -----------------
# Returns the answer and records provenance. Short-circuits on first
# confident (rc 0) provider. (WPScan/Patchstack/GHSA providers slot in here
# at B1/B3/B5 with cost-class ordering; today: wf_bulk primary, wporg meta.)
_intel_set_prov() { printf '%s' "$2" > "$(_intel_cache_file "$1" "$3").prov" 2>/dev/null || true; }
_intel_resolve() {
    local slug="$1" qtype="$2" cf out rc
    cf=$(_intel_cache_file "$slug" "$qtype")
    if _intel_cache_fresh "$cf"; then
        _intel_set_prov "$slug" cache "$qtype"
        cat "$cf"; return 0
    fi
    case "$qtype" in
        cves|advisories|fixed_in)
            # Tier 1: wf_bulk (free-cached, PRIMARY).
            out=$(_intel_wf_query "$slug" "$qtype"); rc=$?
            if [ "$rc" = 0 ]; then
                printf '%s' "$out" > "$cf"
                _intel_set_prov "$slug" wf_bulk "$qtype"
                printf '%s' "$out"; return 0
            fi
            [ "$rc" = 2 ] && _intel_warn "wf_bulk unavailable ($(intel::health))"
            # Tier 2: WPScan (QUOTA cross-confirm) — only reached because
            # wf_bulk had no data / was unavailable. Multi-key rotation;
            # silently skipped if no live key (free chain already tried).
            out=$(_intel_wpscan_query "$slug" "$qtype"); rc=$?
            if [ "$rc" = 0 ]; then
                printf '%s' "$out" > "$cf"
                _intel_set_prov "$slug" wpscan "$qtype"
                printf '%s' "$out"; return 0
            fi
            _intel_set_prov "$slug" none "$qtype"
            return "$rc"
            ;;
        meta)
            out=$(_intel_wporg_meta "$slug"); rc=$?
            if [ "$rc" = 0 ]; then
                printf '%s' "$out" > "$cf"
                _intel_set_prov "$slug" wporg "$qtype"
                printf '%s' "$out"; return 0
            fi
            _intel_set_prov "$slug" none "$qtype"; return "$rc"
            ;;
        *) _intel_warn "unknown query type: $qtype"; return 3 ;;
    esac
}

# ---- public interface ------------------------------------------------------
intel::cves()       { _intel_resolve "$1" cves; }
intel::advisories() { _intel_resolve "$1" advisories; }
intel::fixed_in()   { _intel_resolve "$1" fixed_in; }
intel::meta()       { _intel_resolve "$1" meta; }
intel::source_of()  { cat "$(_intel_cache_file "$1" "$2").prov" 2>/dev/null || echo unknown; }

# intel::wf_index — for BULK consumers (whole-index discovery scans, e.g.
# wp-cve-hunt). The resolver owns locating + freshness-guarding the WF dump;
# the consumer owns its own filtering. Prints the validated path to stdout,
# emits a staleness/missing warning to stderr. rc 2 if the dump is absent.
# This is the absorb boundary: consumers must NOT hardcode the cache path.
intel::wf_index() {
    if [ ! -f "$WP_INTEL_WF_INDEX" ]; then
        _intel_warn "WF intel dump missing ($WP_INTEL_WF_INDEX) — run wp-target-finder.sh once to populate"
        return 2
    fi
    local age; age=$(intel::wf_age_days)
    if [ "$age" -gt "$WP_INTEL_WF_STALE_DAYS" ]; then
        _intel_warn "WF intel dump is STALE (${age}d > ${WP_INTEL_WF_STALE_DAYS}d) — results may miss recent advisories; refresh recommended"
    fi
    printf '%s\n' "$WP_INTEL_WF_INDEX"
}

# If executed directly (not sourced): act as a CLI smoke harness.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    case "${1:-}" in
        health) intel::health ;;
        cves|advisories|fixed_in|meta)
            q="$1"; shift; "intel::$q" "$1"
            echo "  [provider: $(intel::source_of "$1" "$q")]" >&2 ;;
        *) echo "usage: wp-intel.sh {health|cves|advisories|fixed_in|meta} [slug]" >&2; exit 1 ;;
    esac
fi
