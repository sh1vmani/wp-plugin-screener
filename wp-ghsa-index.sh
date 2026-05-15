#!/usr/bin/env bash
# wp-ghsa-index.sh — build a WP-plugin slug → GHSA advisory index from a local
# clone of github/advisory-database. Used as an OFFLINE FALLBACK when the
# Wordfence intel API is unavailable (e.g., 429-locked, token revoked, or
# air-gapped audit). Wordfence intel remains the primary source; this is a
# secondary path that never hits the network.
#
# Setup (once):
#   mkdir -p ~/wp-cve-intel
#   cd ~/wp-cve-intel && git clone --depth 1 https://github.com/github/advisory-database.git
#
# Refresh:
#   cd ~/wp-cve-intel/advisory-database && git pull --ff-only
#
# Build the slug index (writes ~/.cache/wp-target-finder/ghsa-by-slug.json):
#   bash wp-ghsa-index.sh
#
# Lookup (uses the index):
#   bash wp-ghsa-index.sh --slug your-plugin-slug
#
# Notes on coverage:
# - GitHub Advisory Database does NOT have a `WordPress` ecosystem. WP plugin
#   advisories are auto-imported under `unreviewed/` from CVE feeds (NVD, etc).
# - Slugs are not present in the structured `affected.package.name` field for
#   most WP entries — they must be extracted from `references[].url` (look for
#   `wordpress.org/plugins/<slug>/` or `plugins.trac.wordpress.org/browser/<slug>/`).
# - `fixed_in` versions are usually not structured; we regex-parse the
#   `details` text for "through X.Y.Z", "before X.Y.Z", "<= X.Y.Z" patterns.
# - Coverage: github-reviewed has ~12 high-quality WP entries; unreviewed has
#   ~10,556 lower-structured WP entries. By default this script scans
#   `github-reviewed/{2024,2025,2026}` only. To include unreviewed, set
#   GHSA_INCLUDE_UNREVIEWED=1 — but be aware Python 3.13 on WSL2 has been seen
#   to SIGSEGV during the 300K-file walk of `unreviewed/`. Workaround: split
#   the walk year-by-year and accumulate in stages.
# - This is a SECONDARY source. Wordfence intel (cached for 24h via the main
#   finder) remains the primary; it has 36K vulns + 14.5K WP slug index.

set -e

GHSA_ROOT="${GHSA_ROOT:-$HOME/wp-cve-intel/advisory-database/advisories}"
INDEX_FILE="${INDEX_FILE:-$HOME/.cache/wp-target-finder/ghsa-by-slug.json}"

if [ ! -d "$GHSA_ROOT" ]; then
    echo "GHSA clone not found at $GHSA_ROOT" >&2
    echo "Run: mkdir -p ~/wp-cve-intel && cd ~/wp-cve-intel && git clone --depth 1 https://github.com/github/advisory-database.git" >&2
    exit 1
fi

mkdir -p "$(dirname "$INDEX_FILE")"

# --slug <name>: lookup mode
if [ "$1" = "--slug" ] && [ -n "$2" ]; then
    if [ ! -s "$INDEX_FILE" ]; then
        echo "Index not built. Run: bash $0 (no args) first." >&2
        exit 1
    fi
    python3 - "$INDEX_FILE" "$2" <<'PY'
import sys, json
idx_path, slug = sys.argv[1], sys.argv[2]
idx = json.load(open(idx_path))
entries = idx.get(slug, [])
print(f"slug: {slug}  ({len(entries)} advisor(y/ies))")
for e in entries:
    print(f"  {e.get('id')}  cve={','.join(e.get('aliases', []))}  pub={e.get('published','')[:10]}")
    if e.get('fixed_in'):
        print(f"    fixed_in: {e['fixed_in']}")
    if e.get('summary'):
        print(f"    {e['summary'][:140]}")
PY
    exit 0
fi

echo "Building slug index from $GHSA_ROOT ..." >&2

python3 - "$GHSA_ROOT" "$INDEX_FILE" "${GHSA_INCLUDE_UNREVIEWED:-0}" <<'PY'
import sys, os, json, re, collections

root, dst = sys.argv[1], sys.argv[2]
include_unreviewed = sys.argv[3] == "1"
tmp = dst + ".new"

# Default: github-reviewed only + last 3 years. Larger walks crash Py3.13 on WSL2.
branches = ["github-reviewed"]
if include_unreviewed:
    branches.append("unreviewed")
years = ["2024", "2025", "2026"]

# Match wordpress.org/plugins/<slug>/ and plugins.trac.wordpress.org/browser/<slug>/
SLUG_RE = re.compile(
    r"(?:wordpress\.org/plugins|plugins\.trac\.wordpress\.org/browser)/"
    r"([a-z0-9][a-z0-9\-]+)",
    re.IGNORECASE,
)
# Extract "fixed_in" from free-text details
FIXED_RE = re.compile(
    r"(?:fixed\s+in|patched\s+in|update\s+to|upgrade\s+to)\s+(?:version\s+)?(\d+\.\d+(?:\.\d+)*)",
    re.IGNORECASE,
)
# "through X.Y.Z" = last vulnerable version → fixed = next minor (heuristic only)
THROUGH_RE = re.compile(
    r"through\s+(?:version\s+)?(\d+\.\d+(?:\.\d+)*)",
    re.IGNORECASE,
)
BEFORE_RE = re.compile(
    r"(?:before|prior\s+to|<\s*|<=\s*)(\d+\.\d+(?:\.\d+)*)",
    re.IGNORECASE,
)

idx = collections.defaultdict(list)
n_scanned = 0
n_wp = 0

for br in branches:
    for yr in years:
        base = os.path.join(root, br, yr)
        if not os.path.isdir(base):
            continue
        for dirpath, _, filenames in os.walk(base):
            for fn in filenames:
                if not fn.endswith(".json"):
                    continue
                fp = os.path.join(dirpath, fn)
                n_scanned += 1
                try:
                    with open(fp) as fh:
                        d = json.load(fh)
                except Exception:
                    continue

                refs = d.get("references") or []
                refs_str = " ".join((r.get("url") or "") for r in refs)

                # Identify slug(s) from references
                slugs = set(m.group(1).lower() for m in SLUG_RE.finditer(refs_str))
                if not slugs:
                    continue

                n_wp += 1
                details = d.get("details") or ""
                summary = d.get("summary") or ""
                body = details + " " + summary

                fixed_in = None
                m = FIXED_RE.search(body)
                if m:
                    fixed_in = m.group(1)
                else:
                    m = BEFORE_RE.search(body)
                    if m:
                        fixed_in = m.group(1)

                entry = {
                    "id": d.get("id"),
                    "aliases": d.get("aliases") or [],
                    "published": d.get("published") or "",
                    "summary": (summary or details[:200]).strip()[:300],
                    "fixed_in": fixed_in,
                    "refs": [(r.get("url") or "") for r in refs[:5]],
                }
                for slug in slugs:
                    idx[slug].append(entry)
        print(f"  {br}/{yr}: scanned={n_scanned} wp_tagged={n_wp}", file=sys.stderr)

print(f"scanned {n_scanned} advisories, {n_wp} WP-tagged", file=sys.stderr)
print(f"  unique WP-plugin slugs: {len(idx)}", file=sys.stderr)

with open(tmp, "w") as f:
    json.dump(dict(idx), f)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, dst)
print(f"wrote {dst} ({os.path.getsize(dst)} bytes)", file=sys.stderr)
PY

echo "Done. Lookup example: bash $0 --slug your-plugin-slug" >&2
