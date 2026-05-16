"""lib/wp_gates.py — shared hunt-gate spec (ROADMAP ★, the B0-philosophy
applied a second time: one canonical copy of the logic that was duplicated
across wp-cve-hunt / wp-screener-hunt).

Imported by the tools' python heredocs via:
    import os, sys
    sys.path.insert(0, os.environ["WP_GATES_LIB"]); import wp_gates

SCOPE — only genuinely-shared *decision logic* lives here:
  * PRO_VENDOR_RE   — canonical pro-vendor exclusion (was DIVERGENT between
                      the two tools; this is the union/superset, so the
                      consolidation is a correctness fix, not a refactor:
                      cve-hunt previously missed wordpress.org/rock lobster/
                      litespeed; screener-hunt was already the superset).
  * recency_tier/recency_points — last-update recency policy (was IDENTICAL
                      logic in both; only the *display label* differed, so
                      labels stay in each tool and output is byte-identical).
  * IDOR_RE / IDOR_OK_RE — IDOR-auth-tightening (unauth/Subscriber-only).
  * DEFAULT_MIN_INSTALLS — the 100k floor default.

DELIBERATELY NOT here: the swarm-points tiers. Those are INTENTIONALLY
different per tool (net-new screener-hunt rewards 0-advisory `unhunted(+4)`
because un-hunted is good for net-new; cve-hunt has no 0-special-case and
uses different penalties). Merging them would be a real behaviour
regression, not de-duplication. Each tool keeps its own swarm policy.
"""

import re

DEFAULT_MIN_INSTALLS = 100000

# Canonical pro-vendor exclusion (superset of the two former copies).
PRO_VENDOR_RE = re.compile(
    r'yith|w3 ?eden|wp ?rocket|rocketgenius|gravity|awesome motive|'
    r'wpforms|optinmonster|yoast|caseproof|memberpress|stellarwp|'
    r'sandhills|elementor|automattic|really simple|rank ?math|wpml|'
    r'10up|brainstorm|wpdeveloper|wpmanageninja|smush|icegram|'
    r'themeisle|tidio|strangerstudios|servmask|boldgrid|hubspot|'
    r'wpbeginner|syed balkhi|liquid web|kinsta|aioseo|'
    r'all[ -]?in[ -]?one[ -]?seo|wp ?engine|nexcess|woocommerce|'
    r'wordpress\.org|rock lobster|litespeed',
    re.I,
)

# IDOR-auth tightening: IDOR submittable ONLY at unauth/Subscriber-class.
IDOR_RE = re.compile(r'Insecure Direct Object|IDOR', re.I)
IDOR_OK_RE = re.compile(r'Unauthenticated|Subscriber\+', re.I)


def recency_tier(age):
    """Stable tier key for a plugin's days-since-last-update. Presentation
    (label text) is the caller's concern — only the policy lives here."""
    if 60 <= age <= 180:
        return "pref"        # 2-6 mo — preferred window
    if 30 <= age < 60:
        return "ok"          # 1-2 mo — acceptable (>=1 mo)
    if 180 < age <= 365:
        return "older"       # 6-12 mo — acceptable, older
    if 0 <= age < 30:
        return "last"        # <1 mo — last resort, scaled
    return "neglected"       # >12 mo — neglected / picked-over


def recency_points(age):
    """Score delta for the recency tier (identical to both former copies)."""
    t = recency_tier(age)
    if t == "pref":
        return 10
    if t == "ok":
        return 5
    if t == "older":
        return 3
    if t == "last":
        return round(2 * age / 30.0)   # decreasing within <1mo
    return 0
