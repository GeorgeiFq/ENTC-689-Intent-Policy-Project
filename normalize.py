# ============================================================
# normalize.py
# Policy Rule Normalization Layer
# ============================================================
#
# PURPOSE
# -------
# Converts raw AI-extracted policy rules into a structured,
# deterministic, backend-ready JSON format that checks_ios.py can
# safely evaluate.
#
# DESIGN NOTES
# ------------
# This version keeps the original project schema, but fixes several
# normalization issues that were causing inaccurate reports:
#   1) explicit required "no ..." commands are preserved as REQUIRED
#      commands instead of being rewritten into forbids of the positive
#      form
#   2) common Cisco IOS command families are normalized more flexibly
#      so valid syntax variants are not falsely failed
#   3) duplicate benchmark IDs like CIS_IOS_1_2_1_1 and 1.2.1.1 are
#      canonicalized and merged more cleanly
#   4) some review heuristics are slightly narrower so clearly
#      deterministic rules are not over-downgraded
#
# IMPORTANT
# ---------
# This file does NOT decide PASS/FAIL. It only decides whether a rule
# can be represented safely in deterministic form.
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
    "unknown",
}

ALLOWED_CHECK_KINDS = {
    "requires",
    "forbids",
    "requires_and_forbids",
    "manual_review",
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
            "warnings": [],
        },
    }


def make_source(raw_rule):
    return {
        "page": raw_rule.get("source_page"),
        "section": raw_rule.get("source_section"),
        "excerpt": raw_rule.get("source_excerpt") or raw_rule.get("requirement_text", ""),
    }



def canonical_rule_id(rule_id, title="", source_section=""):
    """
    Normalize benchmark rule ids while trying hard to preserve the full
    dotted CIS section number.

    Priority:
      1) explicit rule_id field
      2) explicit source_section field
      3) title only when it clearly starts with a section number

    This avoids accidentally shortening ids because a title happens to
    contain a partial number like "2.3.1".
    """

    def dotted_from_text(raw, allow_title_fallback=False):
        raw = clean_text(raw)
        if not raw:
            return None

        # Exact dotted ids anywhere in explicit id/section fields.
        m = re.search(r"\b(\d+(?:\.\d+){1,6})\b", raw)
        if m:
            return m.group(1)

        # Convert underscore-separated numeric tails like CIS_IOS_1_2_3_1.
        m = re.search(r"(?:^|[^\d])(\d+(?:_\d+){1,6})(?:$|[^\d])", raw)
        if m:
            return m.group(1).replace("_", ".")

        # Only use the title when the section number is clearly leading.
        if allow_title_fallback:
            m = re.match(r"^\s*(\d+(?:\.\d+){1,6})\b", raw)
            if m:
                return m.group(1)
            m = re.search(r"\bsection\s+(\d+(?:\.\d+){1,6})\b", raw, flags=re.IGNORECASE)
            if m:
                return m.group(1)

        return None

    for raw in [rule_id, source_section]:
        found = dotted_from_text(raw, allow_title_fallback=False)
        if found:
            return found

    found = dotted_from_text(title, allow_title_fallback=True)
    if found:
        return found

    return clean_text(rule_id) or clean_text(source_section) or "unknown_rule"

def make_scope(scope_type):
    if scope_type not in ALLOWED_SCOPES:
        scope_type = "unknown"

    mapping = {
        "global": {
            "scope_type": "global",
            "block_header_patterns": [],
        },
        "line_vty": {
            "scope_type": "line_vty",
            "block_header_patterns": [r"^line\s+vty\b"],
        },
        "line_console": {
            "scope_type": "line_console",
            "block_header_patterns": [r"^line\s+con(?:sole)?\b"],
        },
        "line_aux": {
            "scope_type": "line_aux",
            "block_header_patterns": [r"^line\s+aux\b"],
        },
        "unknown": {
            "scope_type": "unknown",
            "block_header_patterns": [],
        },
    }
    return mapping[scope_type]


def make_matcher(pattern, matcher_type="regex_line"):
    return {
        "pattern": pattern,
        "matcher_type": matcher_type,
        "case_sensitive": False,
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
        "automation_status",
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

    for key in ["required", "required_all", "required_any", "forbidden"]:
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

    text = " ".join([
        clean_text(title).lower(),
        clean_text(requirement_text).lower(),
        clean_text(source_excerpt).lower(),
    ])

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
    Turn plain command text into a prefix matcher that allows values.
    Example: 'ntp server' -> '^ntp\\ server(?:\\s+.+)?$'
    """
    prefix = clean_text(prefix)
    if not prefix:
        return None
    return rf"^{re.escape(prefix)}(?:\s+.+)?$"


def special_case_matcher_for_plain_command(command_text):
    """
    Flexible matchers for common Cisco IOS command families where the
    benchmark remediation line is often only one valid variant.
    """
    p = clean_text(command_text)
    l = p.lower()

    # Accept legitimate timestamp variants such as:
    # service timestamps debug datetime msec localtime show-timezone year
    if l == "service timestamps debug datetime":
        return make_matcher(r"^service\s+timestamps\s+debug\s+datetime(?:\s+\S+)*$"), [
            "Broadened service timestamps debug matcher to allow valid Cisco datetime options."
        ]

    if l == "service timestamps log datetime":
        return make_matcher(r"^service\s+timestamps\s+log\s+datetime(?:\s+\S+)*$"), [
            "Broadened service timestamps log matcher to allow valid Cisco datetime options."
        ]

    # Banner commands frequently include delimiter + message on the same line.
    if re.fullmatch(r"banner\s+(exec|login|motd)", l):
        return make_matcher(rf"^{re.escape(p)}(?:\s+.+)?$"), [
            "Broadened banner matcher to allow inline banner text/delimiters."
        ]

    # Permit loopback suffix values when extractor only gives the stem.
    if l in {"ntp source loopback", "ip tftp source-interface loopback", "snmp-server trap-source loopback", "logging source-interface loopback"}:
        return make_matcher(rf"^{re.escape(p)}(?:\s*\d+)?(?:\s+.+)?$"), [
            "Broadened loopback stem matcher to allow interface suffix values."
        ]

    return None, []


def normalize_single_pattern(pattern):
    """
    Convert extracted command-like patterns into backend line matchers.

    Rules:
    - Preserve already-regex-like patterns.
    - Convert placeholder/trailing-space templates into wildcard prefixes.
    - Broaden a few Cisco command families that commonly have valid
      option/value variants.
    - Keep explicit negated commands like 'no cdp run' as exact REQUIRED
      commands when they are extracted that way.
    """
    original = clean_text(pattern)
    if not original:
        return None, []

    notes = []
    p = original

    # Strip common CLI prompt prefixes if they slipped through.
    p = re.sub(r"^\S+\(config(?:-[^)]+)?\)#\s*", "", p, flags=re.IGNORECASE)

    # If it already looks regex-like, anchor unless already anchored.
    if looks_like_regex(p):
        anchored = p
        if not anchored.startswith("^"):
            anchored = "^" + anchored
        if not anchored.endswith("$"):
            anchored = anchored + "$"
        return make_matcher(anchored, matcher_type="regex_line"), notes

    special_matcher, special_notes = special_case_matcher_for_plain_command(p)
    if special_matcher:
        return special_matcher, special_notes

    # Patterns ending with whitespace usually mean "command + argument".
    if original.endswith(" "):
        prefix = original.rstrip()
        notes.append(f"Converted trailing-space template into prefix matcher: {original}")
        return make_matcher(escape_prefix_regex(prefix), matcher_type="regex_line"), notes

    # Curly/angle placeholders mean "some value goes here".
    if any(tok in p for tok in ["{", "}", "<", ">"]):
        prefix = re.split(r"[\{\<]", p, maxsplit=1)[0].strip()
        if prefix:
            notes.append(f"Converted placeholder-based command into prefix matcher: {original}")
            return make_matcher(escape_prefix_regex(prefix), matcher_type="regex_line"), notes

    # UPPERCASE token placeholders like LINE_PASSWORD / LOCAL_USERNAME.
    if re.search(r"\b[A-Z][A-Z0-9_]{2,}\b", p):
        prefix = re.split(r"\b[A-Z][A-Z0-9_]{2,}\b", p, maxsplit=1)[0].strip()
        if prefix:
            notes.append(f"Converted all-caps placeholder command into prefix matcher: {original}")
            return make_matcher(escape_prefix_regex(prefix), matcher_type="regex_line"), notes

    # Common stems that are usually followed by values even when extractor omits placeholders.
    prefix_stems = (
        "aaa authentication ",
        "aaa authorization ",
        "aaa accounting ",
        "logging host",
        "ntp server",
        "snmp-server host",
        "username",
        "ip access-list",
        "banner ",
    )
    if any(p.lower().startswith(stem) for stem in prefix_stems):
        notes.append(f"Converted command stem into prefix matcher: {original}")
        return make_matcher(escape_prefix_regex(p), matcher_type="regex_line"), notes

    # Safe fallback: exact whole-line match.
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

    # De-duplicate normalized matcher patterns.
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
        clean_text(source_excerpt).lower(),
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
        clean_text(source_excerpt).lower(),
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


def is_safe_conditional_family(title, requirement_text, source_excerpt, required_patterns, forbidden_patterns):
    """
    Some benchmark text says 'if used' but still maps cleanly to a
    stable line assertion. Allow these to remain automated.
    """
    text = " ".join([
        clean_text(title).lower(),
        clean_text(requirement_text).lower(),
        clean_text(source_excerpt).lower(),
        " ".join(clean_list(required_patterns)).lower(),
        " ".join(clean_list(forbidden_patterns)).lower(),
    ])

    safe_markers = [
        "ntp server",
        "ntp source",
        "logging host",
        "logging source-interface",
        "service timestamps",
        "clock timezone",
        "clock summer-time",
        "cdp run",
        "ip http server",
        "ip http secure-server",
        "snmp-server",
        "snmp community",
        "vty transport ssh",
        "transport input ssh",
        "exec-timeout",
        "access-class",
        "ipv6 access-class",
    ]
    return any(marker in text for marker in safe_markers)


def should_treat_as_operational_rule(title, requirement_text, source_excerpt, required_patterns):
    text = " ".join([
        clean_text(title).lower(),
        clean_text(requirement_text).lower(),
        clean_text(source_excerpt).lower(),
        " ".join(clean_list(required_patterns)).lower(),
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




def rule_text_blob(rule):
    return " ".join([
        clean_text(rule.get("title")).lower(),
        clean_text(rule.get("requirement_text")).lower(),
        clean_text(rule.get("source_excerpt")).lower(),
        " ".join(clean_list(rule.get("required_patterns", []))).lower(),
        " ".join(clean_list(rule.get("forbidden_patterns", []))).lower(),
    ])


def is_known_not_scorable_family(rule):
    text = rule_text_blob(rule)
    if "not scorable" in text:
        return True
    if "finger service" in text and "service finger" in text:
        return True
    return False


def is_safe_deterministic_family(rule):
    text = rule_text_blob(rule)

    safe_markers = [
        "clock timezone",
        "clock summer-time",
        "cdp run",
        "ip bootp server",
        "service timestamps debug",
        "service timestamps log",
        "ntp server",
        "require logging",
        "logging host",
        "logging trap",
        "logging buffered",
        "logging console",
        "logging source-interface",
        "transport input ssh",
        "vty transport ssh",
        "ssh for remote device access",
        "timeout for login sessions",
        "exec-timeout",
        "ssh access control",
        "vty acl",
        "access-class",
        "ipv6 access-class",
        "snmp community string public",
        "snmp community string private",
        "snmp read and write access",
        "snmp ifindex persist",
        "snmp-server ifindex persist",
        "ip ssh version",
        "ip ssh authentication-retries",
        "ip ssh time-out",
        "ip ssh timeout",
        "service password-encryption",
        "enable secret",
        "aaa new-model",
    ]
    return any(marker in text for marker in safe_markers)


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

    if is_known_not_scorable_family(rule):
        needs_review = True
        reason = "Benchmark text indicates this control is not safely scorable from running-config alone."
        notes.append("Kept as human review to avoid overclaiming a deterministic result.")
        return needs_review, reason, notes

    if is_safe_deterministic_family(rule):
        return False, None, notes

    if should_treat_as_interface_rule(title, requirement_text, source_excerpt):
        needs_review = True
        reason = "Rule appears interface-scoped, but current backend does not model interface blocks yet."
        notes.append("Downgraded to human review instead of forcing an unreliable interface check.")
        return needs_review, reason, notes

    if should_treat_as_conditional_rule(title, requirement_text, source_excerpt) and not is_safe_conditional_family(
        title,
        requirement_text,
        source_excerpt,
        required_patterns,
        forbidden_patterns,
    ):
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
        "securely configured",
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

    for matcher in variant["check"]["required_all"]:
        patt = clean_text(matcher.get("pattern"))
        if not patt:
            continue

        line_header_like = (
            patt.startswith("^line ")
            or patt.startswith("^line\\ ")
            or patt.startswith("^line\\s+")
            or patt.startswith("line ")
        )

        if line_header_like:
            dropped.append(patt)
            continue

        filtered_required.append(matcher)

    if dropped:
        variant["check"]["required_all"] = filtered_required
        variant["check"]["required"] = list(filtered_required)
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

    if (
        variant["automation_status"] == "automated"
        and variant["check"]["kind"] in {"requires", "requires_and_forbids"}
        and len(variant["check"]["required_all"]) == 0
        and len(variant["check"]["forbidden"]) == 0
    ):
        variant["automation_status"] = "needs_human_review"
        variant["review_reason"] = "No deterministic command patterns remained after scope cleanup."
        variant["normalization_notes"].append("Downgraded to human review after scoped matcher cleanup.")



def normalize_rule(raw_rule, document_name=""):
    rule_id = canonical_rule_id(
        raw_rule.get("rule_id"),
        title=raw_rule.get("title", ""),
        source_section=raw_rule.get("source_section", ""),
    )
    title = clean_text(raw_rule.get("title")) or rule_id
    requirement_text = clean_text(raw_rule.get("requirement_text"))
    source_excerpt = clean_text(raw_rule.get("source_excerpt"))
    vendor = canonical_vendor(raw_rule.get("vendor_scope", []))

    required_patterns = clean_list(raw_rule.get("required_patterns", []))
    forbidden_patterns = clean_list(raw_rule.get("forbidden_patterns", []))

    check_kind = canonical_check_kind(
        raw_rule.get("check_type", ""),
        required_patterns,
        forbidden_patterns,
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

    # Important fix:
    # Keep explicit required negated commands like "no cdp run" or
    # "no clock summer-time" as REQUIRED commands.
    # Do NOT rewrite them into forbids of the positive form.
    if any(p.lower().startswith("no ") for p in required_patterns):
        normalization_notes.append(
            "Preserved explicit required negated command(s) as required matchers; no positive-form rewrite applied."
        )

    extractor_review = bool(raw_rule.get("needs_human_review", False))
    no_det_logic = (len(required_matchers) == 0 and len(forbidden_matchers) == 0)
    safe_family = is_safe_deterministic_family(raw_rule)
    not_scorable_family = is_known_not_scorable_family(raw_rule)

    if not_scorable_family:
        automation_status = "needs_human_review"
        final_review_reason = "Benchmark text indicates this control is not safely scorable from running-config alone."
        normalization_notes.append("Normalization kept this rule as review-only because it appears to be not scorable.")
    elif check_kind == "manual_review" and not safe_family:
        automation_status = "needs_human_review"
        final_review_reason = "Extractor marked this as manual review."
    elif extractor_review and not safe_family:
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
        if extractor_review and safe_family:
            normalization_notes.append("Overrode extractor human-review flag because this rule family is safe for deterministic evaluation.")
        if check_kind == "manual_review" and safe_family:
            normalization_notes.append("Overrode manual-review check kind because concrete patterns and a safe rule family were present.")

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
            # Legacy field for compatibility with existing checker code.
            "required": list(required_matchers),
            # Preferred field used by checks_ios.py when present.
            "required_all": list(required_matchers),
            "required_any": [],
            "forbidden": list(forbidden_matchers),
        },
        "automation_status": automation_status,
        "review_reason": final_review_reason,
        "normalization_notes": unique_preserve(normalization_notes),
        "raw_rule": raw_rule,
    }

    variants = split_rule_by_scope(normalized, scopes)

    for v in variants:
        apply_scope_specific_tuning(v)

    return variants

def semantic_rule_key(rule):
    required_all = tuple(sorted(m.get("pattern", "") for m in rule.get("check", {}).get("required_all", [])))
    required_any = tuple(sorted(m.get("pattern", "") for m in rule.get("check", {}).get("required_any", [])))
    forbidden = tuple(sorted(m.get("pattern", "") for m in rule.get("check", {}).get("forbidden", [])))

    return (
        canonical_rule_id(rule.get("rule_id", ""), title=rule.get("title", ""), source_section=rule.get("source", {}).get("section", "")),
        clean_text(rule.get("title", "")).lower(),
        rule.get("vendor"),
        rule.get("scope", {}).get("scope_type"),
        rule.get("check", {}).get("kind"),
        required_all,
        required_any,
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

        # Merge source excerpt when the existing one is empty.
        if not clean_text(existing.get("source", {}).get("excerpt")) and clean_text(rule.get("source", {}).get("excerpt")):
            existing["source"]["excerpt"] = rule["source"]["excerpt"]

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
                        "errors": errors,
                    })

                output["rules"].append(nr)

        except Exception as exc:
            output["normalization_summary"]["errors"].append({
                "rule_index": idx,
                "rule_id": raw_rule.get("rule_id"),
                "errors": [str(exc)],
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
