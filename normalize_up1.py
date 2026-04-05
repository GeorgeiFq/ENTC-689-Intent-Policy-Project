# ============================================================
# normalize.py
# Policy Rule Normalization Layer
# ============================================================
#
# PURPOSE
# -------
# This file converts raw AI-extracted policy rules into a structured,
# deterministic, backend-ready JSON format that the compliance checker
# can safely evaluate.
#
# In other words:
#
#   raw LLM rule output  ->  normalized deterministic rule objects
#
# WHY THIS FILE EXISTS
# --------------------
# The AI extraction stage is useful for reading policy PDFs, but the
# output from an LLM is not guaranteed to be directly usable by the
# checker.
#
# Common problems in raw AI output include:
#   - inconsistent field naming
#   - vague or non-deterministic requirement wording
#   - duplicate rules
#   - wrong or missing scope hints
#   - placeholder text like {server_ip} or <username>
#   - rules that should be manual review rather than automated
#
# This file solves that problem by transforming raw extracted rules
# into a cleaner schema that the deterministic checker can trust.
#
# ARCHITECTURE ROLE
# -----------------
# This file sits between:
#
#   1) the AI extraction stage
#      and
#   2) the deterministic compliance checker
#
# Pipeline position:
#
#   PDF text
#      -> AI extracts candidate JSON rules
#      -> normalize.py standardizes them
#      -> checks_ios.py evaluates them
#
# WHAT THIS FILE DOES
# -------------------
# This module:
#   - standardizes the normalization schema version
#   - cleans text fields
#   - removes duplicate items in lists
#   - canonicalizes vendor labels
#   - canonicalizes rule scope values
#   - canonicalizes check kinds
#   - converts extracted command strings into regex matchers
#   - marks ambiguous rules for human review
#   - splits one multi-scope rule into multiple simpler scoped rules
#   - validates the final normalized rule structure
#   - produces a summary of normalization warnings/errors
#
# NORMALIZED RULE STRUCTURE
# -------------------------
# The output schema is designed for deterministic checking and includes:
#   - rule_id
#   - title
#   - vendor
#   - original requirement text
#   - source metadata
#   - scope
#   - check logic
#   - automation status
#   - review reason
#   - normalization notes
#   - raw original rule
#
# SCOPES
# ------
# The current MVP supports these scope types:
#   - global
#   - line_vty
#   - line_console
#   - line_aux
#   - unknown
#
# A scope tells the checker where the rule should be evaluated:
#   - globally across top-level config lines
#   - inside a VTY block
#   - inside a console block
#   - inside an auxiliary line block
#
# If the scope cannot be determined safely, the rule is downgraded
# to unknown or needs human review rather than pretending to know.
#
# CHECK KINDS
# -----------
# The normalized check logic uses one of these kinds:
#   - requires
#   - forbids
#   - requires_and_forbids
#   - manual_review
#
# This makes the downstream checker simpler and more explainable.
#
# PATTERN NORMALIZATION
# ---------------------
# Raw extracted commands are converted into deterministic line matchers.
# Examples:
#   - exact command lines
#   - anchored regex line patterns
#   - placeholder-based commands converted into prefix matchers
#
# This step is very important because many policy documents describe
# commands abstractly rather than with exact final config syntax.
#
# HUMAN REVIEW LOGIC
# ------------------
# Some rules should not be auto-evaluated even if the AI extracted them.
# This file identifies such cases and marks them as
# "needs_human_review".
#
# Examples include:
#   - vague requirements
#   - interface-scoped rules not modeled by current backend
#   - conditional rules like "if protocol is used"
#   - operational/prerequisite actions that are not stable config lines
#   - rules whose extracted patterns do not fully match the rule title
#
# This is a safety feature, not a weakness.
# It prevents the project from overstating what it can evaluate.
#
# RULE SPLITTING
# --------------
# If one extracted rule applies to multiple scopes, this file may split
# it into multiple normalized rules.
#
# Example:
#   "Require timeout for console and VTY lines"
#
# can become:
#   - rule_id__line_console
#   - rule_id__line_vty
#
# This makes deterministic checking simpler and easier to explain.
#
# DEDUPLICATION
# -------------
# Raw or normalized rules can contain duplicates, especially if the AI
# extracts similar benchmark items from multiple sections or pages.
#
# This file can merge duplicate normalized rules so the final report is
# cleaner and more meaningful.
#
# VALIDATION
# ----------
# Before sending rules to the checker, this file validates that each
# normalized rule has the required fields and a valid structure.
#
# Any issues are captured in the normalization summary rather than
# failing silently.
#
# OUTPUT
# ------
# The final output of this file is a normalized document object with:
#   - schema version
#   - document name
#   - list of normalized rules
#   - normalization summary
#
# This output is what checks_ios.py consumes.
#
# IMPORTANT DESIGN PRINCIPLE
# --------------------------
# This file does NOT decide PASS or FAIL.
#
# It only decides whether a rule can be represented safely in a
# deterministic form.
#
# Final compliance decisions happen later in checks_ios.py.
#
# SUMMARY
# -------
# normalize.py is the bridge between AI-generated policy extraction
# and deterministic config checking.
#
# It turns messy candidate rules into structured, safer, cleaner,
# backend-ready rule objects.
# ============================================================
import json
import re
from copy import deepcopy


SCHEMA_VERSION = "1.0"


ALLOWED_SCOPES = {
    "global",
    "line_vty",
    "line_console",
    "line_aux",
    "unknown"
}

ALLOWED_CHECK_KINDS = {
    "requires",
    "forbids",
    "requires_and_forbids",
    "manual_review"
}


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def clean_text(value):
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def clean_list(values):
    if not values:
        return []
    out = []
    seen = set()
    for v in values:
        t = clean_text(v)
        if not t:
            continue
        key = t.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out


def unique_preserve(seq):
    out = []
    seen = set()
    for item in seq:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def empty_normalized_document(document_name=""):
    return {
        "schema_version": SCHEMA_VERSION,
        "document_name": document_name,
        "rules": [],
        "normalization_summary": {
            "input_rule_count": 0,
            "output_rule_count": 0,
            "automated_rule_count": 0,
            "needs_human_review_count": 0,
            "deduplicated_rule_count": 0,
            "errors": [],
            "warnings": []
        }
    }

def derive_positive_form(negated_cmd: str) -> str:
    t = clean_text(negated_cmd)
    if t.lower().startswith("no "):
        return t[3:].strip()
    return ""

def make_source(raw_rule):
    return {
        "page": raw_rule.get("source_page"),
        "section": raw_rule.get("source_section"),
        "excerpt": raw_rule.get("source_excerpt") or raw_rule.get("requirement_text", "")
    }


def make_scope(scope_type):
    if scope_type not in ALLOWED_SCOPES:
        scope_type = "unknown"

    mapping = {
        "global": {
            "scope_type": "global",
            "block_header_patterns": []
        },
        "line_vty": {
            "scope_type": "line_vty",
            "block_header_patterns": [r"^line\s+vty\b"]
        },
        "line_console": {
            "scope_type": "line_console",
            "block_header_patterns": [r"^line\s+con(?:sole)?\b"]
        },
        "line_aux": {
            "scope_type": "line_aux",
            "block_header_patterns": [r"^line\s+aux\b"]
        },
        "unknown": {
            "scope_type": "unknown",
            "block_header_patterns": []
        }
    }
    return mapping[scope_type]


def make_matcher(pattern, matcher_type="regex_line"):
    return {
        "pattern": pattern,
        "matcher_type": matcher_type,
        "case_sensitive": False
    }


def validate_normalized_rule(rule):
    errors = []

    required_top_fields = [
        "rule_id",
        "title",
        "vendor",
        "original_requirement_text",
        "source",
        "scope",
        "check",
        "automation_status"
    ]

    for field in required_top_fields:
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    scope = rule.get("scope", {})
    if scope.get("scope_type") not in ALLOWED_SCOPES:
        errors.append(f"Invalid scope_type: {scope.get('scope_type')}")

    check = rule.get("check", {})
    if check.get("kind") not in ALLOWED_CHECK_KINDS:
        errors.append(f"Invalid check.kind: {check.get('kind')}")

    for key in ["required", "forbidden"]:
        value = check.get(key, [])
        if not isinstance(value, list):
            errors.append(f"check.{key} must be a list")
            continue
        for i, item in enumerate(value):
            if not isinstance(item, dict):
                errors.append(f"check.{key}[{i}] must be an object")
                continue
            if not item.get("pattern"):
                errors.append(f"check.{key}[{i}] missing pattern")

    return errors


def canonical_vendor(vendor_scope):
    if not vendor_scope:
        return "unknown"
    joined = " ".join([str(v).lower() for v in vendor_scope])
    if "cisco ios" in joined:
        return "cisco_ios"
    return "unknown"


def parse_scope_hint(scope_hint):
    raw = clean_text(scope_hint).lower()
    if not raw:
        return ["unknown"]

    alias_map = {
        "vty": "line_vty",
        "console": "line_console",
        "con": "line_console",
        "aux": "line_aux",
        "line_tty": "unknown",
        "tty": "unknown",
        "interface": "unknown",
        "config_if": "unknown",
    }

    parts = [p.strip() for p in raw.split("|")]
    out = []
    for p in parts:
        p = alias_map.get(p, p)
        if p in ALLOWED_SCOPES:
            out.append(p)

    if not out:
        out = ["unknown"]

    return unique_preserve(out)


def infer_scope_from_text(title, requirement_text, source_excerpt, fallback_scopes):
    """
    Prefer extractor hints when they are specific.
    Only infer scope from text when hints are missing/unknown.
    """
    if fallback_scopes:
        explicit = [s for s in fallback_scopes if s != "unknown"]
        if explicit:
            return unique_preserve(explicit)

    title_l = clean_text(title).lower()
    req_l = clean_text(requirement_text).lower()
    excerpt_l = clean_text(source_excerpt).lower()
    text = " ".join([title_l, req_l, excerpt_l])

    scopes = []

    if "vty" in text and ("line" in text or "config-line" in text or "management lines" in text):
        scopes.append("line_vty")

    if re.search(r"\bline\s+con(?:sole)?\b", text) or "console line" in text:
        scopes.append("line_console")

    if re.search(r"\bline\s+aux\b", text) or "auxiliary port" in text or "aux port" in text:
        scopes.append("line_aux")

    if scopes:
        return unique_preserve(scopes)

    if fallback_scopes:
        return unique_preserve(fallback_scopes)

    return ["global"]


def canonical_check_kind(raw_check_type, required_patterns, forbidden_patterns):
    lowered = clean_text(raw_check_type).lower()

    if required_patterns and forbidden_patterns:
        return "requires_and_forbids"
    if required_patterns and not forbidden_patterns:
        return "requires"
    if forbidden_patterns and not required_patterns:
        return "forbids"

    if lowered == "required":
        return "requires"
    if lowered == "forbidden":
        return "forbids"
    if lowered == "required_and_forbidden":
        return "requires_and_forbids"
    if lowered == "manual_review":
        return "manual_review"

    return "manual_review"


def looks_like_regex(pattern):
    return bool(re.search(r"[\^\$\.\*\+\?\[\]\(\)\|\\]", pattern))


def escape_prefix_regex(prefix):
    """
    Turn plain command text into a prefix matcher that still requires a value.
    Example: 'ntp server' -> '^ntp\\ server(?:\\s+.+)?$'
    """
    prefix = clean_text(prefix)
    if not prefix:
        return None
    return rf"^{re.escape(prefix)}(?:\s+.+)?$"


def normalize_single_pattern(pattern):
    """
    Convert extracted command-like patterns into backend line matchers.

    Important improvements:
    - Preserve already-regex-like patterns.
    - Convert placeholder/trailing-space templates into wildcard prefixes.
    - Avoid collapsing 'logging host ' into '^logging host$'.
    """
    original = clean_text(pattern)
    if not original:
        return None, []

    notes = []
    p = original

    # Strip common CLI prompt prefixes if they slipped through
    p = re.sub(r"^\S+\(config(?:-[^)]+)?\)#\s*", "", p, flags=re.IGNORECASE)

    # If it already looks regex-like, anchor it unless already anchored.
    if looks_like_regex(p):
        anchored = p
        if not anchored.startswith("^"):
            anchored = "^" + anchored
        if not anchored.endswith("$"):
            anchored = anchored + "$"
        return make_matcher(anchored, matcher_type="regex_line"), notes

    # Patterns ending with whitespace almost always mean "command + argument"
    if original.endswith(" "):
        prefix = original.rstrip()
        notes.append(f"Converted trailing-space template into prefix matcher: {original}")
        return make_matcher(escape_prefix_regex(prefix), matcher_type="regex_line"), notes

    # Curly/angle placeholders mean "some value goes here"
    if any(tok in p for tok in ["{", "}", "<", ">"]):
        prefix = re.split(r"[\{\<]", p, maxsplit=1)[0].strip()
        if prefix:
            notes.append(f"Converted placeholder-based command into prefix matcher: {original}")
            return make_matcher(escape_prefix_regex(prefix), matcher_type="regex_line"), notes

    # UPPERCASE token placeholders like LINE_PASSWORD / LOCAL_USERNAME
    if re.search(r"\b[A-Z][A-Z0-9_]{2,}\b", p):
        prefix = re.split(r"\b[A-Z][A-Z0-9_]{2,}\b", p, maxsplit=1)[0].strip()
        if prefix:
            notes.append(f"Converted all-caps placeholder command into prefix matcher: {original}")
            return make_matcher(escape_prefix_regex(prefix), matcher_type="regex_line"), notes

    # Safe fallback: exact whole-line match
    escaped = re.escape(p)
    return make_matcher(rf"^{escaped}$", matcher_type="regex_line"), notes


def normalize_patterns(patterns):
    out = []
    notes = []

    for p in clean_list(patterns):
        matcher, matcher_notes = normalize_single_pattern(p)
        if matcher:
            out.append(matcher)
        notes.extend(matcher_notes)

        lowered = p.lower()

        if any(token in lowered for token in ["{", "}", "<", ">"]):
            notes.append(f"Pattern contains placeholders and was generalized where possible: {p}")

        if "or equivalent" in lowered or "as appropriate" in lowered:
            notes.append(f"Pattern is policy-language-like and may not be directly matchable: {p}")

    # dedupe normalized matcher patterns
    deduped = []
    seen = set()
    for m in out:
        key = (m.get("pattern"), m.get("matcher_type"), m.get("case_sensitive"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(m)

    return deduped, unique_preserve(notes)


def should_treat_as_interface_rule(title, requirement_text, source_excerpt):
    text = " ".join([
        clean_text(title).lower(),
        clean_text(requirement_text).lower(),
        clean_text(source_excerpt).lower()
    ])
    interface_markers = [
        "each interface",
        "per interface",
        "interface-id",
        "config-if",
        "proxy arp",
        "directed broadcast",
        "unicast reverse-path forwarding",
        "reverse-path forwarding",
    ]
    return any(marker in text for marker in interface_markers)


def should_treat_as_conditional_rule(title, requirement_text, source_excerpt):
    text = " ".join([
        clean_text(title).lower(),
        clean_text(requirement_text).lower(),
        clean_text(source_excerpt).lower()
    ])
    conditional_markers = [
        "if protocol is used",
        "if protocol is in use",
        "if used",
        "if not in use",
        "when used",
        "where used",
        "if enabled",
    ]
    return any(marker in text for marker in conditional_markers)


def should_treat_as_operational_rule(title, requirement_text, source_excerpt, required_patterns):
    text = " ".join([
        clean_text(title).lower(),
        clean_text(requirement_text).lower(),
        clean_text(source_excerpt).lower(),
        " ".join(clean_list(required_patterns)).lower()
    ])
    operational_markers = [
        "write mem",
        "copy running-config startup-config",
        "prerequisite",
        "prerequisites",
        "verify manually",
        "review manually",
    ]
    return any(marker in text for marker in operational_markers)


def title_based_review_flags(rule):
    """
    Heuristics for rules that are not fully safe to automate from the
    currently extracted patterns.
    """
    title = clean_text(rule.get("title")).lower()
    requirement_text = clean_text(rule.get("requirement_text")).lower()
    source_excerpt = clean_text(rule.get("source_excerpt")).lower()
    required_patterns = clean_list(rule.get("required_patterns", []))
    forbidden_patterns = clean_list(rule.get("forbidden_patterns", []))

    notes = []
    needs_review = False
    reason = None

    if "require ssh for remote device access" in title:
        needs_review = True
        reason = "Title implies protocol exclusivity, but extracted patterns do not fully encode that logic."
        notes.append("Recommend handling SSH protocol restriction primarily through VTY transport checks.")
        return needs_review, reason, notes

    if should_treat_as_interface_rule(title, requirement_text, source_excerpt):
        needs_review = True
        reason = "Rule appears interface-scoped, but current backend does not model interface blocks yet."
        notes.append("Downgraded to human review instead of forcing an unreliable global check.")
        return needs_review, reason, notes

    if should_treat_as_conditional_rule(title, requirement_text, source_excerpt):
        needs_review = True
        reason = "Rule is conditional ('if used' / 'if not in use') and current backend does not model that condition safely."
        notes.append("Downgraded to human review until conditional logic is added.")
        return needs_review, reason, notes

    if should_treat_as_operational_rule(title, requirement_text, source_excerpt, required_patterns):
        needs_review = True
        reason = "Rule appears operational or prerequisite-oriented rather than a stable running-config assertion."
        notes.append("Downgraded to human review because running-config checking is not the right evaluator for this rule.")
        return needs_review, reason, notes

    vague_phrases = [
        "verify that",
        "ensure",
        "appropriate",
        "sufficient",
        "securely configured"
    ]

    if any(v in requirement_text for v in vague_phrases) and not required_patterns and not forbidden_patterns:
        needs_review = True
        reason = "Requirement text is too vague for deterministic checking."
        notes.append("No concrete command patterns were extracted.")
        return needs_review, reason, notes

    return needs_review, reason, notes


def split_rule_by_scope(base_rule, scopes):
    scopes = unique_preserve(scopes or ["unknown"])

    if len(scopes) <= 1:
        base_rule["scope"] = make_scope(scopes[0])
        return [base_rule]

    out = []
    for scope in scopes:
        cloned = deepcopy(base_rule)
        cloned["rule_id"] = f"{base_rule['rule_id']}__{scope}"
        cloned["title"] = f"{base_rule['title']} ({scope})"
        cloned["scope"] = make_scope(scope)
        cloned["normalization_notes"].append("Split from multi-scope extracted rule.")
        out.append(cloned)

    return out


def drop_scope_header_matchers(variant):
    """
    Inside already-scoped blocks, do not require block-header lines again.
    Example: in line_vty scope, requiring '^line vty$' inside the block is wrong.
    """
    scope_type = variant["scope"]["scope_type"]
    if scope_type not in {"line_vty", "line_console", "line_aux"}:
        return

    filtered_required = []
    dropped = []

    for matcher in variant["check"]["required"]:
        patt = clean_text(matcher.get("pattern"))
        if not patt:
            continue

        line_header_like = (
            patt.startswith("^line ") or
            patt.startswith("^line\\ ") or
            patt.startswith("^line\\s+") or
            patt.startswith("line ")
        )

        if line_header_like:
            dropped.append(patt)
            continue

        filtered_required.append(matcher)

    if dropped:
        variant["check"]["required"] = filtered_required
        variant["normalization_notes"].append(
            "Dropped block-header matcher(s) from scoped rule: " + ", ".join(dropped)
        )


def apply_scope_specific_tuning(variant):
    scope_type = variant["scope"]["scope_type"]
    title_l = variant["title"].lower()

    drop_scope_header_matchers(variant)

    if "transport ssh" in title_l and scope_type == "line_console":
        variant["automation_status"] = "needs_human_review"
        variant["review_reason"] = "Console lines are local; enforcing SSH on console is usually not meaningful."
        variant["normalization_notes"].append("Console variant downgraded to human review.")

    if "transport ssh" in title_l and scope_type == "line_aux":
        variant["automation_status"] = "needs_human_review"
        variant["review_reason"] = "Auxiliary line SSH transport semantics are not reliable for this benchmark rule in current backend."
        variant["normalization_notes"].append("Aux variant downgraded to human review.")

    # If a scoped rule lost all deterministic required patterns after header cleanup,
    # it should not stay automated.
    if (
        variant["automation_status"] == "automated"
        and variant["check"]["kind"] in {"requires", "requires_and_forbids"}
        and len(variant["check"]["required"]) == 0
        and len(variant["check"]["forbidden"]) == 0
    ):
        variant["automation_status"] = "needs_human_review"
        variant["review_reason"] = "No deterministic command patterns remained after scope cleanup."
        variant["normalization_notes"].append("Downgraded to human review after scoped matcher cleanup.")


def normalize_rule(raw_rule, document_name=""):
    rule_id = clean_text(raw_rule.get("rule_id")) or "unknown_rule"
    title = clean_text(raw_rule.get("title")) or rule_id
    requirement_text = clean_text(raw_rule.get("requirement_text"))
    source_excerpt = clean_text(raw_rule.get("source_excerpt"))
    vendor = canonical_vendor(raw_rule.get("vendor_scope", []))

    required_patterns = clean_list(raw_rule.get("required_patterns", []))
    forbidden_patterns = clean_list(raw_rule.get("forbidden_patterns", []))

    check_kind = canonical_check_kind(
        raw_rule.get("check_type", ""),
        required_patterns,
        forbidden_patterns
    )

    hinted_scopes = parse_scope_hint(raw_rule.get("scope_hint", ""))
    scopes = infer_scope_from_text(title, requirement_text, source_excerpt, hinted_scopes)

    required_matchers, required_notes = normalize_patterns(required_patterns)
    forbidden_matchers, forbidden_notes = normalize_patterns(forbidden_patterns)
    review_flag, review_reason, review_notes = title_based_review_flags(raw_rule)
    normalization_notes = []
    normalization_notes.extend(required_notes)
    normalization_notes.extend(forbidden_notes)
    normalization_notes.extend(review_notes)
    # --- Intent-based handling for negations like "no cdp run" ---
    # If the intent is "this must NOT be enabled", it's more robust to FORBID the positive form.
    # This prevents false FAIL when configs omit explicit "no ..." lines.
    if check_kind in {"forbids", "requires_and_forbids"}:
        positive_from_no = []
        for raw in required_patterns:
            pos = derive_positive_form(raw)
            if pos:
                positive_from_no.append(pos)

        if positive_from_no:
            new_forbidden = list(forbidden_matchers)
            for pos in positive_from_no:
                pos_matcher, _ = normalize_single_pattern(pos)
                if pos_matcher:
                    new_forbidden.append(pos_matcher)

            required_matchers = []
            forbidden_matchers = new_forbidden
            check_kind = "forbids"
            normalization_notes.append(
                "Converted required 'no ...' patterns into forbids of the positive form for robustness."
            )






    extractor_review = bool(raw_rule.get("needs_human_review", False))
    no_det_logic = (len(required_matchers) == 0 and len(forbidden_matchers) == 0)

    if check_kind == "manual_review":
        automation_status = "needs_human_review"
        final_review_reason = "Extractor marked this as manual review."
    elif extractor_review:
        automation_status = "needs_human_review"
        final_review_reason = "Extractor marked this rule for human review."
    elif no_det_logic:
        automation_status = "needs_human_review"
        final_review_reason = "No deterministic command patterns available."
    elif review_flag:
        automation_status = "needs_human_review"
        final_review_reason = review_reason
    else:
        automation_status = "automated"
        final_review_reason = None

    normalized = {
        "rule_id": rule_id,
        "title": title,
        "document_name": document_name,
        "vendor": vendor,
        "original_requirement_text": requirement_text,
        "source": make_source(raw_rule),
        "scope": make_scope("unknown"),
        "check": {
            "kind": check_kind,
            "required": required_matchers,
            "forbidden": forbidden_matchers
        },
        "automation_status": automation_status,
        "review_reason": final_review_reason,
        "normalization_notes": unique_preserve(normalization_notes),
        "raw_rule": raw_rule
    }

    variants = split_rule_by_scope(normalized, scopes)

    for v in variants:
        apply_scope_specific_tuning(v)

    return variants


def semantic_rule_key(rule):
    required = tuple(sorted(m.get("pattern", "") for m in rule.get("check", {}).get("required", [])))
    forbidden = tuple(sorted(m.get("pattern", "") for m in rule.get("check", {}).get("forbidden", [])))
    return (
        rule.get("rule_id"),
        rule.get("vendor"),
        rule.get("scope", {}).get("scope_type"),
        rule.get("check", {}).get("kind"),
        required,
        forbidden,
    )


def merge_duplicate_rules(rules, summary):
    merged = []
    by_key = {}

    for rule in rules:
        key = semantic_rule_key(rule)

        if key not in by_key:
            by_key[key] = rule
            merged.append(rule)
            continue

        existing = by_key[key]
        summary["deduplicated_rule_count"] += 1
        summary["warnings"].append(
            f"Merged duplicate normalized rule: {rule.get('rule_id')} ({rule.get('title')})"
        )

        existing_notes = existing.get("normalization_notes", [])
        dup_page = rule.get("source", {}).get("page")
        if dup_page is not None:
            existing_notes.append(f"Merged duplicate instance from source page {dup_page}.")
        existing["normalization_notes"] = unique_preserve(existing_notes + rule.get("normalization_notes", []))

        # Be conservative if duplicates disagree on automation status.
        if existing.get("automation_status") == "automated" and rule.get("automation_status") != "automated":
            existing["automation_status"] = rule.get("automation_status")
            existing["review_reason"] = rule.get("review_reason")

    summary["warnings"] = unique_preserve(summary["warnings"])
    return merged


def normalize_rules(raw_doc):
    output = empty_normalized_document(raw_doc.get("document_name", ""))
    raw_rules = raw_doc.get("rules", [])
    output["normalization_summary"]["input_rule_count"] = len(raw_rules)

    for idx, raw_rule in enumerate(raw_rules):
        try:
            normalized_variants = normalize_rule(raw_rule, document_name=raw_doc.get("document_name", ""))

            for nr in normalized_variants:
                errors = validate_normalized_rule(nr)
                if errors:
                    output["normalization_summary"]["errors"].append({
                        "rule_index": idx,
                        "rule_id": nr.get("rule_id"),
                        "errors": errors
                    })

                output["rules"].append(nr)

        except Exception as exc:
            output["normalization_summary"]["errors"].append({
                "rule_index": idx,
                "rule_id": raw_rule.get("rule_id"),
                "errors": [str(exc)]
            })

    output["rules"] = merge_duplicate_rules(output["rules"], output["normalization_summary"])

    automated_count = sum(1 for r in output["rules"] if r.get("automation_status") == "automated")
    review_count = sum(1 for r in output["rules"] if r.get("automation_status") != "automated")

    output["normalization_summary"]["output_rule_count"] = len(output["rules"])
    output["normalization_summary"]["automated_rule_count"] = automated_count
    output["normalization_summary"]["needs_human_review_count"] = review_count
    output["normalization_summary"]["warnings"] = unique_preserve(
        output["normalization_summary"]["warnings"]
    )

    return output


def main():
    input_path = "extracted_rules_test.json"
    output_path = "normalized_rules.json"

    raw_doc = load_json(input_path)
    normalized = normalize_rules(raw_doc)

    print("\nNORMALIZED RULES:\n")
    print(json.dumps(normalized, indent=2))

    save_json(output_path, normalized)
    print(f"\nSaved to {output_path}")


if __name__ == "__main__":
    main()