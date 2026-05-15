#!/usr/bin/env bash
# wp-screener-hunt.sh — net-new, CVE-independent hunter (broadens F01-shape).
#
# F01-shape needs a recent narrow CVE to anchor on. THIS tool does not: it
# screens high-value plugins REGARDLESS of CVE history and surfaces the
# actual in-scope server-side (PHP) HIGH sinks to go verify. F01/CVE signal
# is kept as a BONUS (recent narrow CVE => +score), never a requirement.
#
# Same spec/gates as the rest of the kit so all three paths agree:
#   * Universe: wp.org popular plugins (install-sorted, all categories)
#   * Hard floor: >= --min-installs active installs (default 100000)
#   * Pro-vendor exclusion (comprehensive-fixers come up dry)
#   * Swarm gate from the Wordfence intel cache: >=12 advisories/12mo =
#     hard-drop (dup-trap). For net-new, FEW/zero advisories is GOOD
#     (un-hunted) — opposite of the F01 path.
#   * Tiered last-update recency (2-6mo preferred > 1-2mo > 6-12mo >
#     <1mo last-resort > >12mo) — identical tiers to wp-target-finder.
#   * Not in ~/wp-audited-list.txt
# Then screens survivors and ranks by IN-SCOPE PHP HIGH sink richness
# (NOPRIV/SUBSCRIBER/AUTHOR/UNKNOWN; Editor/Admin = OOS dropped; JS
# build-artifact noise excluded by .php-path filter).
#
# Output: ranked plugins + their top in-scope PHP HIGH sink locations
# (file:line, rule, band) -> direct audit targets. Then run the pipeline:
# wp-patchstack-check.sh <slug> --grep '<sink>'  ->  manual verify  -> DAST.
#
# Usage:
#   wp-screener-hunt.sh [--min-installs N] [--pages P] [--screen-top N]
#                       [--limit N] [--include-pro] [--refresh]
#     --pages P       popular-list pages to scan (100/page, default 6)
#     --screen-top N  how many gated candidates to actually screen (default 25)
#     --limit N       rows to print (default 20)

set -euo pipefail

MIN_INSTALLS=100000
PAGES=6
SCREEN_TOP=25
LIMIT=20
INCLUDE_PRO=0
REFRESH=0
while [ $# -gt 0 ]; do
    case "$1" in
        --min-installs) MIN_INSTALLS="$2"; shift 2 ;;
        --pages)        PAGES="$2"; shift 2 ;;
        --screen-top)   SCREEN_TOP="$2"; shift 2 ;;
        --limit)        LIMIT="$2"; shift 2 ;;
        --include-pro)  INCLUDE_PRO=1; shift ;;
        --refresh)      REFRESH=1; shift ;;
        -h|--help)      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

PYBIN="$(command -v python3.12 || command -v python3.11 || command -v python3)"
SCREENER="/mnt/d/wp-security-audit-toolkit/wp-security-audit-toolkit/wp-plugin-screener.sh"
INTEL="$HOME/.cache/wp-target-finder/wordfence-by-slug.json"
AUDITED="$HOME/wp-audited-list.txt"
CACHE="/tmp/.wp-screener-hunt"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
mkdir -p "$CACHE/zip" "$CACHE/scan"
touch "$AUDITED"
[ -x "$SCREENER" ] || { echo "[x] screener not found: $SCREENER" >&2; exit 2; }

# ---- 1) universe: popular plugins (install-sorted) ----
echo "[*] fetching $PAGES page(s) of wp.org popular plugins ..." >&2
ULIST="$CACHE/universe.tsv"; : > "$ULIST"
for p in $(seq 1 "$PAGES"); do
    f="$CACHE/pop-$p.json"
    if [ "$REFRESH" = "1" ] || [ ! -s "$f" ]; then
        curl -sS -m 20 -A "$UA" "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request%5Bbrowse%5D=popular&request%5Bper_page%5D=100&request%5Bpage%5D=$p&request%5Bfields%5D%5Bactive_installs%5D=1&request%5Bfields%5D%5Blast_updated%5D=1" -o "$f" 2>/dev/null || true
    fi
done
"$PYBIN" - "$CACHE" "$PAGES" "$INTEL" "$AUDITED" "$MIN_INSTALLS" "$INCLUDE_PRO" > "$ULIST" <<'PY'
import json, re, sys, os, datetime as dt
cache, pages, intel_p, aud_p, min_inst, inc_pro = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5]), sys.argv[6] == "1"
today = dt.date.today()
PRO = re.compile(r'yith|w3 ?eden|wp ?rocket|rocketgenius|gravity|awesome motive|'
                 r'wpforms|optinmonster|yoast|caseproof|memberpress|stellarwp|'
                 r'sandhills|elementor|automattic|really simple|rank ?math|wpml|'
                 r'10up|brainstorm|wpdeveloper|wpmanageninja|smush|icegram|'
                 r'themeisle|tidio|strangerstudios|servmask|boldgrid|hubspot|'
                 r'wpbeginner|syed balkhi|liquid web|kinsta|aioseo|'
                 r'all[ -]?in[ -]?one[ -]?seo|wp ?engine|nexcess|woocommerce|'
                 r'wordpress\.org|rock lobster|litespeed', re.I)
aud = set(x.strip() for x in open(aud_p) if x.strip())
try:
    intel = json.load(open(intel_p))
except Exception:
    intel = {}
yr = (today - dt.timedelta(days=365)).isoformat()

def recency(age):
    if 60 <= age <= 180: return 10, "2-6mo PREF"
    if 30 <= age <  60:  return 5,  "1-2mo"
    if 180 < age <= 365: return 3,  "6-12mo"
    if 0 <= age < 30:    return round(2*age/30.0), "<1mo last"
    return 0, ">12mo"

seen = set()
for p in range(1, pages + 1):
    fp = os.path.join(cache, f"pop-{p}.json")
    try:
        d = json.load(open(fp))
    except Exception:
        continue
    for pl in d.get("plugins", []):
        slug = pl.get("slug", "")
        if not slug or slug in seen or slug in aud:
            continue
        seen.add(slug)
        ai = pl.get("active_installs", 0) or 0
        if ai < min_inst:
            continue
        au = re.sub("<[^>]+>", "", pl.get("author", "") or "")
        if not inc_pro and (PRO.search(au) or PRO.search(slug)):
            continue
        advs = intel.get(slug, [])
        radv = sum(1 for x in advs
                   if (x.get("published", "") or "")[:10] >= yr
                   and not x.get("informational"))
        if radv >= 12:                       # swarmed dup-trap
            continue
        lu = (pl.get("last_updated", "") or "")[:10]
        try:
            age = (today - dt.date.fromisoformat(lu)).days
        except Exception:
            age = 99999
        rp, rt = recency(age)
        # net-new swarm pts: 0 advisories = un-hunted = best
        if radv == 0:   sw, swl = 4, "unhunted(0)"
        elif radv <= 2: sw, swl = 3, f"indie({radv})"
        elif radv <= 5: sw, swl = 1, f"low({radv})"
        else:           sw, swl = -3, f"hunted({radv})"
        pre = rp + sw
        print(f"{pre}\t{ai}\t{age}\t{rt}\t{swl}\t{slug}\t{au[:24]}")
PY
sort -t$'\t' -k1,1nr -k2,2nr "$ULIST" -o "$ULIST"
NG=$(grep -c . "$ULIST" || true)
echo "[*] $NG plugins passed the gate (>=${MIN_INSTALLS} installs, not pro/swarmed/audited)" >&2

# ---- 2) screen the top SCREEN_TOP gated candidates ----
echo "[*] screening top $SCREEN_TOP (download+screener, cached) ..." >&2
head -n "$SCREEN_TOP" "$ULIST" | while IFS=$'\t' read -r pre ai age rt swl slug au; do
    [ -z "$slug" ] && continue
    sf="$CACHE/scan/$slug.txt"
    if [ "$REFRESH" = "1" ] || [ ! -s "$sf" ]; then
        z="$CACHE/zip/$slug.zip"
        curl -fsSL -m 60 -A "$UA" "https://downloads.wordpress.org/plugin/$slug.latest-stable.zip" -o "$z" 2>/dev/null || { echo "  (dl fail $slug)" >&2; continue; }
        dd="$CACHE/zip/$slug"; rm -rf "$dd"; mkdir -p "$dd"
        unzip -qq "$z" -d "$dd" 2>/dev/null || { echo "  (unzip fail $slug)" >&2; continue; }
        inner="$(find "$dd" -mindepth 1 -maxdepth 1 -type d | head -1)"
        timeout 240 bash "$SCREENER" "${inner:-$dd}" 2>/dev/null | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' > "$sf" || true
        rm -rf "$z" "$dd"
    fi
done

# ---- 3) parse in-scope PHP HIGH sinks + final rank ----
"$PYBIN" - "$CACHE" "$ULIST" "$SCREEN_TOP" "$LIMIT" <<'PY'
import sys, os, re
cache, ulist, screen_top, limit = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
pre = {}
for i, line in enumerate(open(ulist)):
    if i >= screen_top: break
    c = line.rstrip("\n").split("\t")
    if len(c) < 7: continue
    pre[c[5]] = c  # by slug

FIND = re.compile(r'^\s*\[HIGH\]\s*\[(NOPRIV|SUBSCRIBER|AUTHOR|UNKNOWN)\]\s+(.+?)\s{2,}(\S+\.php):(\d+)\s*$')
BANDW = {"NOPRIV": 4, "SUBSCRIBER": 3, "AUTHOR": 2, "UNKNOWN": 1}
# high-signal server-side rule keywords (bounty-relevant); others still count
# but at lower weight
HOT = re.compile(r'superglobal|capab|authoriz|sql|nonce|option|meta|upload|'
                 r'delet|file|include|deserial|unserial|rce|redirect|ssrf|'
                 r'priv|role|callback', re.I)

rows = []
for slug, c in pre.items():
    sf = os.path.join(cache, "scan", slug + ".txt")
    if not os.path.exists(sf) or os.path.getsize(sf) == 0:
        continue
    nopriv = sub = author = unk = 0
    hot = 0
    samples = []
    for ln in open(sf, encoding="utf-8", errors="replace"):
        m = FIND.match(ln)
        if not m:
            continue
        band, rule, path, lineno = m.group(1), m.group(2).strip(), m.group(3), m.group(4)
        if band == "NOPRIV": nopriv += 1
        elif band == "SUBSCRIBER": sub += 1
        elif band == "AUTHOR": author += 1
        else: unk += 1
        if HOT.search(rule):
            hot += 1
            if len(samples) < 4:
                samples.append(f"[{band}] {rule}  {path}:{lineno}")
    inscope = nopriv + sub + author + unk
    if inscope == 0:
        continue
    pre_pts = int(c[0])
    # screener score: weight by band severity + hot-rule density (cap noise)
    sc = (min(nopriv, 12) * 4 + min(sub, 12) * 3 + min(author, 8) * 2
          + min(unk, 10) * 1 + min(hot, 15) * 2)
    total = sc + pre_pts
    rows.append((total, sc, pre_pts, nopriv, sub, author, unk, hot,
                 c[1], c[2], c[3], c[4], slug, c[6], samples))

rows.sort(key=lambda r: (r[0], int(r[8])), reverse=True)
print(f"\n{'TOT':>4} {'SCRN':>4} {'INSTALLS':>9} {'AGE':>5} {'RECEN':<10} {'SWARM':<12} "
      f"{'NP/SU/AU/UN':<13} HOT  SLUG")
print("=" * 120)
for (tot, sc, pp, np_, su, au_, un, hot, ai, age, rt, swl, slug, author, samples) in rows[:limit]:
    print(f"{tot:>4} {sc:>4} {ai:>9} {str(age)+'d':>5} {rt:<10} {swl:<12} "
          f"{f'{np_}/{su}/{au_}/{un}':<13} {hot:>3}  {slug}  [{author}]")
    for s in samples:
        print(f"        - {s}")
if not rows:
    print("(no in-scope PHP HIGH sinks among screened candidates — widen --pages/--screen-top)")
else:
    print(f"\n[{len(rows)} of top {screen_top} screened have in-scope PHP HIGH sinks; showing {min(limit,len(rows))}]")
    print("Next: pick a slug -> wp-patchstack-check.sh <slug> --grep '<rule/sink>' (dup-gate)")
    print("      -> manually verify the sink (auth tier + reachability) -> DAST.")
    print("F01 bonus: if the slug ALSO has a recent narrow CVE, run wp-svn-diff too.")
PY
