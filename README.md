# wp-plugin-screener

Two bash scripts plus a calibration harness for finding WordPress plugins worth auditing for vulnerabilities and pre-screening them with static pattern checks.

Built for personal bug-bounty work. Self-contained — no framework, no dependencies beyond bash, curl, grep, awk, and a small Python helper for JSON.

The interesting part isn't the patterns themselves (there are decent open-source alternatives for that). It's the **calibration loop**: every rule change is measured against a corpus of plugins with known yield/clean outcomes before it ships, so we don't silently regress real catches while trying to clean up false positives.

## What's in the box

```
wp-target-finder.sh           # scanner: wp.org → CVE intel → score → top-N
wp-plugin-screener.sh         # static pre-screener: ~15 PHP/JS pattern rules
tools/calibration/
  validate.py                 # runs screener over a corpus, computes P/R
  corpus.example.json         # template for building your own corpus
LICENSE                       # MIT
```

## What each script does

### `wp-target-finder.sh` — the scanner

Answers "which plugin should I audit next?"

- Seeds from wp.org's `query_plugins` API across three browse modes (popular / updated / new) for a diverse seed pool.
- Enriches each candidate slug with CVE data joined from WPScan, Patchstack, Wordfence Intelligence, and NVD. Tokens optional; NVD always on.
- Scores candidates on install-size sweet spot, CVE recency pattern, recurring vuln-type, vague-changelog signals (indicates silent patches), screener HIGH-count, and update staleness.
- Picks the highest-scoring plugin in each of three install buckets (100K–399K, 400K–999K, 1M+) so the output spreads across plugin sizes instead of clustering on the mega-popular.
- Dedups against a personal audit history and an explicit "already audited" list.
- Caches everything for 6h. Optional `--cache-only` mode for offline runs.

### `wp-plugin-screener.sh` — the screener

Answers "is this specific plugin worth my time?"

Static pattern scan of first-party PHP and JS in a plugin (vendored libraries excluded). Current rules:

**PHP:** `sslverify=false`, `eval()`, `unserialize()` (with safe-form skip), `wp_ajax_nopriv` handler registration, file-write/upload sinks, secret leaked to JS via `wp_localize_script`, `$wpdb` query with superglobal, `$wpdb` query with concat (no prepare), unsanitized superglobal use (with comparison/validator skip + sanitizer-wrapper detection + enclosing-function gate downgrade), AJAX handler missing cap/nonce (with array-callback support and nopriv-first dedup).

**JS / Vue / TS:** `v-html`, `innerHTML=`, `dangerouslySetInnerHTML`, hardcoded AWS / Google / GitHub / Slack tokens, generic secret-like assignments.

**Pre-pass:** discovers plugin-defined sanitization wrappers (functions named like `*sanitize*`/`*escape*`/`*kses*`/etc.) and adds them to the rule-9 sanitizer-context regex so superglobals piped through custom wrappers don't get falsely flagged.

**Per-plugin suppression:** drop a `.screener-suppress` file at the plugin root with `file:line:category` lines to silence known-FP findings on subsequent runs.

Output ends with a machine-readable line:

```
SCREENER_SUMMARY  <HIGH>  <MED>  <LOW>  <verdict>
```

Verdicts: `HIGH-VALUE-TARGET` / `INVESTIGATE` / `SKIP`. Use the underlying counts and categories for real decisions — the verdict label is coarse.

### `tools/calibration/validate.py` — the calibration harness

The reason this repo exists separately from "every other WordPress plugin scanner on GitHub."

Static pattern scanners have a precision problem: the dominant rules fire on huge numbers of safe lines. Cleaning them up by tightening regexes usually regresses real catches without anyone noticing. The harness fixes that by measuring every change against a corpus of plugins with known outcomes:

```bash
python3 tools/calibration/validate.py
```

For each plugin in `corpus.json`:

- **Yield plugins** (where you've confirmed a finding) — does the screener flag the expected sink file? The expected rule category?
- **Clean plugins** (where you audited and confirmed no real findings) — every HIGH/MEDIUM is, by definition, a false positive.

Outputs `baseline.json` with per-plugin numbers and a summary you can diff after every rule change.

The corpus format is in `corpus.example.json`. Build your own — the personal corpus that drove the rule fixes in this repo references pre-disclosure bounty findings and stays private until those are publicly resolved.

## Quick start

### Screen one plugin

```bash
./wp-plugin-screener.sh /path/to/unzipped-plugin
./wp-plugin-screener.sh plugin.zip
```

### Find today's top targets

```bash
./wp-target-finder.sh                  # full network run
./wp-target-finder.sh --cache-only     # use 6h cache (faster, offline-friendly)
./wp-target-finder.sh --no-screener    # skip the per-plugin screener pre-pass
./wp-target-finder.sh --help           # full flag list
```

Optional API tokens read from environment or `~/.zshrc`:

```
WPSCAN_API_TOKEN=...     # free tier: 25 req/day
PATCHSTACK_API_TOKEN=...
WORDFENCE_API_TOKEN=...
```

Falls back gracefully when tokens are missing or rate-limited.

### Run the calibration loop

```bash
# 1. Copy the example corpus and add your own audited plugins
cp tools/calibration/corpus.example.json tools/calibration/corpus.json

# 2. Run the harness
python3 tools/calibration/validate.py

# 3. Edit a screener rule
# 4. Re-run validate.py
# 5. Keep the change only if precision improved AND yield-corpus recall didn't regress
```

## Honest limits

What the screener catches well:

- Direct source-to-sink patterns on a single line
- AJAX handlers (including class-method array callbacks) with no auth in body
- `wp_remote_*` with TLS verification disabled
- Hardcoded API keys / tokens in JS bundles
- `dangerouslySetInnerHTML`, `v-html`, `innerHTML=` on the front-end

What it doesn't catch — and probably won't from regex alone:

- Multi-line taint flow: `$x = $_POST['y']; ... sanitize($x);` — the assignment hides the wrapper
- Cross-function reachability: middleware gates auth in a parent hook
- Output-context bugs: `esc_html` used inside a JS template literal
- Sanitizer-body weaknesses: case-fold-then-keep-original, regex-only validators
- Semantic auth flaws: IDOR, IP-allowlist bypass via routing

These require either an AST pass with proper scope tracking or a parsed entry-point/sink index with cross-function reachability. Roadmap below.

## Roadmap

- **v0.2** — entry-point + sink index (parse PHP once into a `(file, class, function, hook, cap_check, nonce_check, sources, sinks)` table; queries replace ad-hoc regex rules)
- **v0.3** — differential mode (`--diff old:new` runs rules only against changed lines between releases — silent-patch / incomplete-fix hunting)
- **v0.4** — Semgrep alongside as a parallel screener; anything it catches that we don't becomes a rule candidate

## License

MIT.
