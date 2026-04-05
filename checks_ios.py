# ============================================================
# checks_ios.py
# Deterministic Cisco IOS Compliance Evaluation Layer
# ============================================================
#
# PURPOSE
# -------
# This file is the deterministic compliance engine for Cisco IOS
# configuration files.
#
# It is the part of the project that makes the actual compliance
# decision for each normalized rule.
#
# This file is the final judge for:
#   - PASS
#   - FAIL
#   - NEEDS_HUMAN_REVIEW
#
# ARCHITECTURE ROLE
# -----------------
# This module is downstream of normalize.py.
#
# Pipeline position:
#
#   policy PDF
#      -> AI extracts candidate rules
#      -> normalize.py converts them into deterministic rules
#      -> checks_ios.py evaluates those rules against the config
#
# This file does NOT use AI to make compliance decisions.
# All evaluations here are deterministic and explainable.
#
# WHY THIS FILE EXISTS
# --------------------
# The project requirement is that the LLM must not be the final
# compliance judge.
#
# That means after the AI extracts rules, a pure Python backend must:
#   - read the config text
#   - locate the relevant lines or blocks
#   - apply required/forbidden pattern logic
#   - return a traceable result with evidence lines
#
# This file is that backend evaluator.
#
# WHAT THIS FILE DOES
# -------------------
# This module:
#   - reads normalized rule JSON
#   - reads Cisco IOS config text
#   - parses the config into a lightweight internal structure
#   - finds global lines and scoped blocks
#   - evaluates required patterns
#   - evaluates forbidden patterns
#   - handles ambiguous scope cases using strictness logic
#   - produces per-rule results with evidence
#   - builds the final HTML report
#
# IOS CONFIG PARSING MODEL
# ------------------------
# The parser in this file is intentionally lightweight.
# It does not try to fully emulate the Cisco IOS grammar.
#
# Instead, it extracts enough structure for the MVP:
#   - all lines with line numbers
#   - top-level/global lines
#   - parent/child blocks based on indentation
#
# This is sufficient for many practical benchmark checks, especially:
#   - global command checks
#   - line vty checks
#   - line console checks
#   - line aux checks
#
# RULE EVALUATION TYPES
# ---------------------
# The checker supports these rule forms:
#   - requires:
#       one or more required patterns must be found
#   - forbids:
#       forbidden patterns must not be found
#   - requires_and_forbids:
#       both conditions are enforced
#   - manual_review:
#       no deterministic evaluation; report as human review
#
# GLOBAL VS SCOPED RULES
# ----------------------
# A normalized rule can be evaluated in one of two main ways:
#
# 1) Global rule
#    Evaluated against top-level config lines
#    Example:
#      service password-encryption
#      no ip http server
#
# 2) Scoped rule
#    Evaluated inside blocks selected by their headers
#    Example:
#      line vty 0 4
#        transport input ssh
#        exec-timeout 5 0
#
# This file looks up the proper scope and then checks only the
# relevant block contents.
#
# EVIDENCE
# --------
# Every rule result should include evidence lines whenever possible.
#
# Evidence is important because it makes the checker explainable.
# Instead of only saying "PASS" or "FAIL", the report can show:
#   - which config lines satisfied the rule
#   - which forbidden lines were found
#   - which required patterns were missing
#   - which block headers were checked
#
# This is one of the strongest features of the project because it
# makes the result auditable.
#
# STRICTNESS LOGIC
# ----------------
# Some rules cannot be evaluated cleanly in every config.
# For example, a required scope block may not exist at all.
#
# In those cases, this file uses configurable strictness logic:
#
#   strict   -> FAIL
#   balanced -> NEEDS_HUMAN_REVIEW
#   lenient  -> PASS
#
# This lets the user choose how conservative the tool should be
# when the config structure is incomplete or ambiguous.
#
# REPORT GENERATION
# -----------------
# In addition to rule evaluation, this file generates the final
# HTML compliance report.
#
# The report includes:
#   - overall summary counts
#   - rule-by-rule status
#   - PASS / FAIL / NEEDS_HUMAN_REVIEW color coding
#   - evidence lines
#   - missing required patterns
#   - forbidden hits
#   - source/page metadata when available
#
# The HTML report is meant to be readable in a browser and useful
# for demos, grading, and future project expansion.
#
# IMPORTANT DESIGN PRINCIPLE
# --------------------------
# This file is deterministic by design.
#
# It should never ask an LLM whether a rule passed.
# It should only apply explicit logic to the uploaded config text.
#
# This makes the project:
#   - more explainable
#   - more reproducible
#   - safer to defend academically
#
# LIMITATIONS
# -----------
# The parser/checker is currently an MVP, so some advanced rule types
# may still require human review, such as:
#   - interface-scoped rules not yet modeled
#   - conditional routing protocol checks
#   - operational commands that are not persistent config lines
#
# Those limitations are acceptable as long as the system labels such
# cases honestly instead of pretending to automate them.
#
# SUMMARY
# -------
# checks_ios.py is the core enforcement engine of the project.
#
# It takes normalized deterministic rules and a Cisco IOS config,
# evaluates them in a traceable way, and produces the final
# compliance results and HTML report.
# ============================================================
import json
import re
import sys
import html
import webbrowser
from pathlib import Path


VALID_STRICTNESS = {"strict", "balanced", "lenient"}


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def parse_ios_config(config_text):
    """
    Lightweight Cisco IOS parser.

    Produces:
      - all lines with line numbers
      - top-level/global lines
      - simple indented parent/child blocks

    Notes:
      - Primary block extraction still uses indentation.
      - A secondary fallback scanner in find_scope_blocks() handles
        common Cisco line blocks even when child lines are not indented.
    """
    raw_lines = config_text.splitlines()

    lines = []
    for i, raw in enumerate(raw_lines, start=1):
        expanded = raw.expandtabs(4)
        stripped = expanded.strip()
        indent = len(expanded) - len(expanded.lstrip(" "))

        lines.append({
            "lineno": i,
            "raw": raw,
            "text": stripped,
            "indent": indent,
            "is_blank": stripped == "",
            "is_comment": stripped == "!"
        })

    global_lines = []
    blocks = []

    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]

        if line["is_blank"] or line["is_comment"]:
            i += 1
            continue

        if line["indent"] == 0:
            header = line
            global_lines.append(header)

            j = i + 1
            children = []

            while j < n:
                nxt = lines[j]

                if nxt["is_blank"] or nxt["is_comment"]:
                    j += 1
                    continue

                if nxt["indent"] > 0:
                    children.append(nxt)
                    j += 1
                    continue

                break

            if children:
                blocks.append({
                    "header": header,
                    "children": children
                })

            i = j
        else:
            i += 1

    return {
        "lines": lines,
        "global_lines": global_lines,
        "blocks": blocks
    }


def compile_regex(pattern, case_sensitive=False):
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        return re.compile(pattern, flags)
    except re.error:
        return re.compile(re.escape(str(pattern)), flags)


def normalize_cli_text(text):
    return re.sub(r"\s+", " ", str(text or "").strip()).lower()


def base_rule_id(rule_id):
    return str(rule_id or "").split("__", 1)[0].strip()


def rule_title_text(rule):
    return normalize_cli_text(rule.get("title", ""))


def line_matches(line_obj, matcher):
    text = line_obj["text"]
    matcher_type = matcher.get("matcher_type", "regex_line")
    pattern = matcher.get("pattern", "")
    case_sensitive = matcher.get("case_sensitive", False)

    candidate = text if case_sensitive else text.lower()
    target = pattern if case_sensitive else str(pattern).lower()

    if matcher_type == "exact_line":
        return normalize_cli_text(candidate) == normalize_cli_text(target)

    if matcher_type == "prefix_line":
        return normalize_cli_text(candidate).startswith(normalize_cli_text(target))

    if matcher_type == "contains_line":
        return normalize_cli_text(target) in normalize_cli_text(candidate)

    regex = compile_regex(pattern, case_sensitive=case_sensitive)
    return regex.search(text) is not None


def _line_prefix_match(line_obj, prefix):
    return normalize_cli_text(line_obj.get("text", "")).startswith(normalize_cli_text(prefix))


def _find_prefix_lines(line_objs, prefix):
    return [line for line in line_objs if _line_prefix_match(line, prefix)]


def _find_exact_lines(line_objs, exact_text):
    target = normalize_cli_text(exact_text)
    return [line for line in line_objs if normalize_cli_text(line.get("text", "")) == target]


def _find_positive_command_lines(line_objs, command_prefix):
    prefix = normalize_cli_text(command_prefix)
    out = []
    for line in line_objs:
        txt = normalize_cli_text(line.get("text", ""))
        if txt.startswith(prefix) and not txt.startswith("no " + prefix):
            out.append(line)
    return out


def _specialized_match_lines(rule, line_objs, matcher):
    """
    Rule-aware matcher fallback for Cisco command families that commonly
    appear with valid extra tokens beyond the remediation example.
    """
    rule_id = base_rule_id(rule.get("rule_id"))
    title = rule_title_text(rule)
    pattern = str(matcher.get("pattern", ""))

    if rule_id == "1.2.3.6" or "timestamps for debug" in title:
        return _find_prefix_lines(line_objs, "service timestamps debug datetime")

    if rule_id == "1.2.3.7" or "timestamps in log" in title:
        return _find_prefix_lines(line_objs, "service timestamps log datetime")

    if rule_id == "1.2.1.1" or "clock timezone" in title:
        return _find_exact_lines(line_objs, "clock timezone UTC 0")

    if rule_id == "1.2.2.1" or "cdp run globally" in title:
        if "no cdp run" in pattern.lower():
            return _find_exact_lines(line_objs, "no cdp run")
        if re.search(r"(^|\b)cdp\s+run", pattern, flags=re.IGNORECASE):
            return _find_positive_command_lines(line_objs, "cdp run")

    if rule_id == "1.2.1.2" or "summer-time clock" in title:
        if "no clock summer-time" in pattern.lower():
            return _find_exact_lines(line_objs, "no clock summer-time")
        if re.search(r"(^|\b)clock\s+summer-time", pattern, flags=re.IGNORECASE):
            return _find_positive_command_lines(line_objs, "clock summer-time")

    if rule_id == "1.2.2.2" or "finger service" in title:
        if "no service finger" in pattern.lower():
            return _find_exact_lines(line_objs, "no service finger")
        if re.search(r"(^|\b)service\s+finger", pattern, flags=re.IGNORECASE):
            return _find_positive_command_lines(line_objs, "service finger")

    if rule_id == "1.2.2.3" or "bootp server" in title:
        if "no ip bootp server" in pattern.lower():
            return _find_exact_lines(line_objs, "no ip bootp server")
        if re.search(r"(^|\b)ip\s+bootp\s+server", pattern, flags=re.IGNORECASE):
            return _find_positive_command_lines(line_objs, "ip bootp server")

    if rule_id == "2.2.1.2" or "ntp source loopback" in title:
        return [line for line in line_objs if re.search(r"^ntp\s+source\s+loopback\d+\b", line["text"], flags=re.IGNORECASE)]

    if rule_id == "2.2.1.3" or "tftp source loopback" in title:
        return [line for line in line_objs if re.search(r"^ip\s+tftp\s+source-interface\s+loopback\d+\b", line["text"], flags=re.IGNORECASE)]

    return []


def find_matching_lines(line_objs, matcher, rule=None):
    matches = []
    for line in line_objs:
        if line_matches(line, matcher):
            matches.append(line)

    if matches or rule is None:
        return matches

    return _specialized_match_lines(rule, line_objs, matcher)


def serialize_line(line_obj, context=None):
    item = {
        "lineno": line_obj["lineno"],
        "text": line_obj["text"]
    }
    if context is not None:
        item["context"] = context
    return item


def serialize_block_header(block):
    return {
        "lineno": block["header"]["lineno"],
        "text": block["header"]["text"]
    }


def dedupe_evidence_lines(items):
    seen = set()
    out = []
    for item in items:
        key = (item.get("lineno"), item.get("text"), item.get("context"))
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def normalize_strictness(value):
    s = str(value or "balanced").strip().lower()
    if s not in VALID_STRICTNESS:
        return "balanced"
    return s


def resolve_ambiguous_status(strictness):
    """
    Strict   -> FAIL
    Balanced -> NEEDS_HUMAN_REVIEW
    Lenient  -> PASS
    """
    strictness = normalize_strictness(strictness)

    if strictness == "strict":
        return "FAIL"
    if strictness == "lenient":
        return "PASS"
    return "NEEDS_HUMAN_REVIEW"


def _fallback_find_line_scope_blocks(parsed_config, header_patterns):
    """
    Fallback scanner for line console / aux / vty blocks when child lines
    are not indented consistently.
    """
    lines = parsed_config.get("lines", [])
    if not lines:
        return []

    blocks = []
    header_regexes = [compile_regex(p, case_sensitive=False) for p in header_patterns]
    stop_patterns = [
        compile_regex(r"^line\b"),
        compile_regex(r"^interface\b"),
        compile_regex(r"^router\b"),
        compile_regex(r"^control-plane\b"),
        compile_regex(r"^ip access-list\b"),
    ]

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.get("is_blank") or line.get("is_comment"):
            i += 1
            continue

        if any(r.search(line["text"]) for r in header_regexes):
            header = line
            children = []
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if nxt.get("is_comment"):
                    break
                if nxt.get("is_blank"):
                    j += 1
                    continue
                if any(r.search(nxt["text"]) for r in stop_patterns):
                    break
                children.append(nxt)
                j += 1
            blocks.append({"header": header, "children": children})
            i = j
            continue

        i += 1

    return blocks


def find_scope_blocks(parsed_config, scope):
    scope_type = scope.get("scope_type", "unknown")
    header_patterns = scope.get("block_header_patterns", [])

    if scope_type == "global":
        return []

    matched_blocks = []
    for block in parsed_config["blocks"]:
        header_text = block["header"]["text"]
        for pat in header_patterns:
            if re.search(pat, header_text, flags=re.IGNORECASE):
                matched_blocks.append(block)
                break

    if matched_blocks:
        return matched_blocks

    if scope_type in {"line_vty", "line_console", "line_aux"} and header_patterns:
        return _fallback_find_line_scope_blocks(parsed_config, header_patterns)

    return []




def _normalize_title_for_dedupe(title):
    title = normalize_cli_text(title)
    title = re.sub(r"\s*\((global|line_vty|line_console|line_aux)\)$", "", title)
    return title


def _find_global_prefix_lines(parsed_config, prefix):
    return _find_prefix_lines(parsed_config.get("global_lines", []), prefix)


def _find_global_exact_lines(parsed_config, exact_text):
    return _find_exact_lines(parsed_config.get("global_lines", []), exact_text)


def _find_named_acl_blocks(parsed_config, acl_name, family="ip"):
    acl_name = str(acl_name or "").strip()
    if not acl_name:
        return []

    if family == "ipv6":
        header_re = re.compile(rf"^ipv6\s+access-list\s+{re.escape(acl_name)}\b", flags=re.IGNORECASE)
    else:
        header_re = re.compile(rf"^ip\s+access-list\s+(?:standard|extended)\s+{re.escape(acl_name)}\b", flags=re.IGNORECASE)

    return [block for block in parsed_config.get("blocks", []) if header_re.search(block.get("header", {}).get("text", ""))]


def _find_numbered_acl_lines(parsed_config, acl_name):
    acl_name = str(acl_name or "").strip()
    if not acl_name:
        return []
    pat = re.compile(rf"^access-list\s+{re.escape(acl_name)}\b", flags=re.IGNORECASE)
    return [line for line in parsed_config.get("global_lines", []) if pat.search(line.get("text", ""))]


def _collect_acl_entries(parsed_config, acl_name, family="ip"):
    entries = []

    named_blocks = _find_named_acl_blocks(parsed_config, acl_name, family=family)
    for block in named_blocks:
        entries.append(serialize_block_header(block))
        for child in block.get("children", []):
            entries.append(serialize_line(child, context=block.get("header", {}).get("text")))

    if family == "ip":
        for line in _find_numbered_acl_lines(parsed_config, acl_name):
            entries.append(serialize_line(line, context="global"))

    deduped = []
    seen = set()
    for item in entries:
        key = (item.get("lineno"), item.get("text"), item.get("context"))
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def _serialized_acl_is_effectively_open(entries):
    """
    Treat obviously broad management ACLs as insecure for this benchmark.
    This is intentionally simple and demo-friendly: if the ACL eventually
    permits any-any traffic, it is not considered a meaningful restriction.
    """
    for item in entries:
        text = normalize_cli_text(item.get("text", ""))
        if text.startswith("permit ip any any"):
            return True
        if text.startswith("permit ipv6 any any"):
            return True
        if text.startswith("permit any"):
            return True
    return False


def _extract_access_class_refs(block):
    refs = {"ip": [], "ipv6": []}
    for line in block.get("children", []):
        text = line.get("text", "")
        m = re.search(r"^access-class\s+(\S+)\s+(?:in|out)\b", text, flags=re.IGNORECASE)
        if m:
            refs["ip"].append({
                "name": m.group(1),
                "line": line,
                "family": "ip",
            })
        m = re.search(r"^ipv6\s+access-class\s+(\S+)\s+(?:in|out)\b", text, flags=re.IGNORECASE)
        if m:
            refs["ipv6"].append({
                "name": m.group(1),
                "line": line,
                "family": "ipv6",
            })
    return refs


def _build_simple_result(status, evidence_lines=None, missing_required=None, forbidden_hits=None,
                         checked_blocks=None, ambiguous=False, failure_reason=None):
    return {
        "status": status,
        "evidence_lines": dedupe_evidence_lines(evidence_lines or []),
        "missing_required_patterns": missing_required or [],
        "forbidden_hits": dedupe_evidence_lines(forbidden_hits or []),
        "checked_blocks": checked_blocks or [],
        "ambiguous": ambiguous,
        "failure_reason": failure_reason,
    }


def _evaluate_vty_acl_rule(rule, parsed_config, strictness):
    blocks = find_scope_blocks(parsed_config, rule.get("scope", {}))
    if not blocks:
        status = resolve_ambiguous_status(strictness)
        return _build_simple_result(
            status=status,
            ambiguous=True,
            failure_reason="No matching config block found for required scope: line_vty.",
        )

    evidence = []
    forbidden = []
    checked = []
    missing = []

    for block in blocks:
        checked.append(serialize_block_header(block))
        refs = _extract_access_class_refs(block)

        if not refs["ip"] and not refs["ipv6"]:
            missing.append({
                "block_header": serialize_block_header(block),
                "pattern": "access-class / ipv6 access-class",
            })
            continue

        for family in ("ip", "ipv6"):
            for ref in refs[family]:
                evidence.append(serialize_line(ref["line"], context=block["header"]["text"]))
                acl_entries = _collect_acl_entries(parsed_config, ref["name"], family=family)
                if acl_entries:
                    evidence.extend(acl_entries)
                    if _serialized_acl_is_effectively_open(acl_entries):
                        forbidden.extend(acl_entries)
                else:
                    missing.append({
                        "block_header": serialize_block_header(block),
                        "pattern": f"{family} ACL definition for {ref['name']}",
                    })

    status = "FAIL" if missing or forbidden else "PASS"
    return _build_simple_result(
        status=status,
        evidence_lines=evidence,
        missing_required=missing,
        forbidden_hits=forbidden,
        checked_blocks=checked,
    )


def _parse_exec_timeout_from_line(line_text):
    m = re.search(r"^exec-timeout\s+(\d+)(?:\s+(\d+))?\b", str(line_text or ""), flags=re.IGNORECASE)
    if not m:
        return None
    minutes = int(m.group(1))
    seconds = int(m.group(2) or 0)
    return minutes, seconds


def _evaluate_exec_timeout_rule(rule, parsed_config, strictness):
    blocks = find_scope_blocks(parsed_config, rule.get("scope", {}))
    scope_type = rule.get("scope", {}).get("scope_type", "unknown")

    if not blocks:
        status = resolve_ambiguous_status(strictness)
        return _build_simple_result(
            status=status,
            ambiguous=True,
            failure_reason=f"No matching config block found for required scope: {scope_type}.",
        )

    evidence = []
    missing = []
    forbidden = []
    checked = []

    for block in blocks:
        checked.append(serialize_block_header(block))
        timeout_lines = [line for line in block.get("children", []) if re.search(r"^exec-timeout\b", line.get("text", ""), flags=re.IGNORECASE)]

        if not timeout_lines:
            missing.append({
                "block_header": serialize_block_header(block),
                "pattern": "exec-timeout <minutes> <seconds>",
            })
            continue

        for line in timeout_lines:
            parsed_timeout = _parse_exec_timeout_from_line(line.get("text", ""))
            evidence.append(serialize_line(line, context=block["header"]["text"]))
            if parsed_timeout is None:
                forbidden.append(serialize_line(line, context=block["header"]["text"]))
                continue
            minutes, seconds = parsed_timeout
            if minutes == 0 and seconds == 0:
                forbidden.append(serialize_line(line, context=block["header"]["text"]))

    status = "FAIL" if missing or forbidden else "PASS"
    return _build_simple_result(
        status=status,
        evidence_lines=evidence,
        missing_required=missing,
        forbidden_hits=forbidden,
        checked_blocks=checked,
    )


def _evaluate_transport_ssh_rule(rule, parsed_config, strictness):
    blocks = find_scope_blocks(parsed_config, rule.get("scope", {}))
    scope_type = rule.get("scope", {}).get("scope_type", "unknown")

    if not blocks:
        status = resolve_ambiguous_status(strictness)
        return _build_simple_result(
            status=status,
            ambiguous=True,
            failure_reason=f"No matching config block found for required scope: {scope_type}.",
        )

    evidence = []
    missing = []
    forbidden = []
    checked = []

    for block in blocks:
        checked.append(serialize_block_header(block))
        transport_lines = [line for line in block.get("children", []) if re.search(r"^transport\s+input\b", line.get("text", ""), flags=re.IGNORECASE)]

        if not transport_lines:
            missing.append({
                "block_header": serialize_block_header(block),
                "pattern": "transport input ssh",
            })
            continue

        valid_found = False
        for line in transport_lines:
            evidence.append(serialize_line(line, context=block["header"]["text"]))
            text = normalize_cli_text(line.get("text", ""))
            if text == "transport input ssh":
                valid_found = True
            else:
                forbidden.append(serialize_line(line, context=block["header"]["text"]))

        if not valid_found:
            missing.append({
                "block_header": serialize_block_header(block),
                "pattern": "transport input ssh",
            })

    status = "FAIL" if missing or forbidden else "PASS"
    return _build_simple_result(
        status=status,
        evidence_lines=evidence,
        missing_required=missing,
        forbidden_hits=forbidden,
        checked_blocks=checked,
    )


def _evaluate_logging_presence_rule(parsed_config):
    candidate_lines = parsed_config.get("global_lines", [])
    positive_logging = []
    for line in candidate_lines:
        text = normalize_cli_text(line.get("text", ""))
        if text.startswith("logging "):
            if text.startswith("no logging "):
                continue
            positive_logging.append(line)

    if positive_logging:
        return _build_simple_result(
            status="PASS",
            evidence_lines=[serialize_line(line, context="global") for line in positive_logging],
        )

    return _build_simple_result(
        status="FAIL",
        missing_required=["logging on or other positive logging configuration"],
    )


def _snmp_override_result(rule, parsed_config):
    candidate_lines = parsed_config.get("global_lines", [])
    title = rule_title_text(rule)
    excerpt = normalize_cli_text(rule.get("source", {}).get("excerpt", ""))
    snmp_lines = [line for line in candidate_lines if normalize_cli_text(line.get("text", "")).startswith("snmp-server ")]

    if "snmp" not in title and "snmp" not in excerpt:
        return None

    if not snmp_lines:
        # If the benchmark says "if not in use", "disable", or it forbids
        # insecure community usage, absence of SNMP config is a clean PASS.
        if any(marker in title or marker in excerpt for marker in [
            "if not in use",
            "disable snmp",
            "forbid snmp",
            "community string public",
            "community string private",
            "read and write access",
            "snmp v1",
            "snmp v2c",
            "snmp-server",
        ]):
            return _build_simple_result(status="PASS", evidence_lines=[])
        return None

    def line_hits(substr):
        return [line for line in snmp_lines if substr in normalize_cli_text(line.get("text", ""))]

    if "community string public" in title:
        hits = line_hits("snmp-server community public")
        return _build_simple_result(
            status="FAIL" if hits else "PASS",
            evidence_lines=[serialize_line(line, context="global") for line in hits],
            forbidden_hits=[serialize_line(line, context="global") for line in hits] if hits else [],
        )

    if "community string private" in title:
        hits = line_hits("snmp-server community private")
        return _build_simple_result(
            status="FAIL" if hits else "PASS",
            evidence_lines=[serialize_line(line, context="global") for line in hits],
            forbidden_hits=[serialize_line(line, context="global") for line in hits] if hits else [],
        )

    if "read and write access" in title or " rw" in excerpt:
        hits = [line for line in snmp_lines if re.search(r"\bsnmp-server\s+community\b.*\brw\b", line.get("text", ""), flags=re.IGNORECASE)]
        return _build_simple_result(
            status="FAIL" if hits else "PASS",
            evidence_lines=[serialize_line(line, context="global") for line in hits],
            forbidden_hits=[serialize_line(line, context="global") for line in hits] if hits else [],
        )

    return None


def _known_scoped_override_result(rule, parsed_config, strictness):
    title = rule_title_text(rule)
    scope_type = rule.get("scope", {}).get("scope_type")

    if scope_type == "line_vty" and ("vty transport ssh" in title or "ssh for remote device access" in title):
        return _evaluate_transport_ssh_rule(rule, parsed_config, strictness)

    if scope_type in {"line_vty", "line_console"} and ("timeout for login sessions" in title or "exec-timeout" in title):
        return _evaluate_exec_timeout_rule(rule, parsed_config, strictness)

    if scope_type == "line_vty" and ("ssh access control" in title or "vty acl" in title):
        return _evaluate_vty_acl_rule(rule, parsed_config, strictness)

    return None


def evaluate_global_rule(rule, parsed_config):
    """
    Evaluate a global rule against parsed_config["global_lines"].

    Backwards compatibility:
      - If check.required_all not present, uses check.required (legacy) as required_all.
    """
    check = rule.get("check", {})
    required_all = check.get("required_all", check.get("required", []))
    required_any = check.get("required_any", [])
    forbidden = check.get("forbidden", [])

    candidate_lines = parsed_config.get("global_lines", [])

    evidence_lines = []
    missing_required = []
    forbidden_hits = []

    for matcher in required_all:
        matches = find_matching_lines(candidate_lines, matcher, rule=rule)
        if matches:
            for m in matches:
                evidence_lines.append(serialize_line(m, context="global"))
        else:
            missing_required.append(matcher.get("pattern"))

    if required_any:
        any_hit_lines = []
        for matcher in required_any:
            hits = find_matching_lines(candidate_lines, matcher, rule=rule)
            if hits:
                any_hit_lines.extend(hits)

        if any_hit_lines:
            for h in any_hit_lines:
                evidence_lines.append(serialize_line(h, context="global"))
        else:
            missing_required.append({
                "any_of": [m.get("pattern") for m in required_any],
                "scope": "global",
            })

    for matcher in forbidden:
        hits = find_matching_lines(candidate_lines, matcher, rule=rule)
        for h in hits:
            forbidden_hits.append(serialize_line(h, context="global"))

    status = "FAIL" if missing_required or forbidden_hits else "PASS"

    return {
        "status": status,
        "evidence_lines": dedupe_evidence_lines(evidence_lines),
        "missing_required_patterns": missing_required,
        "forbidden_hits": dedupe_evidence_lines(forbidden_hits),
        "checked_blocks": [],
        "ambiguous": False,
        "failure_reason": None,
    }


def evaluate_scoped_rule(rule, parsed_config, strictness):
    """
    Evaluate a scoped rule inside matching config blocks.

    Backwards compatibility:
      - If check.required_all not present, uses check.required (legacy) as required_all.
    """
    check = rule.get("check", {})
    required_all = check.get("required_all", check.get("required", []))
    required_any = check.get("required_any", [])
    forbidden = check.get("forbidden", [])

    scope = rule.get("scope", {})
    scope_type = scope.get("scope_type", "unknown")

    blocks = find_scope_blocks(parsed_config, scope)

    if not blocks:
        status = resolve_ambiguous_status(strictness)

        missing = [m.get("pattern") for m in required_all] if required_all else []
        if required_any:
            missing.append({
                "any_of": [m.get("pattern") for m in required_any],
                "scope": scope_type,
            })

        return {
            "status": status,
            "evidence_lines": [],
            "missing_required_patterns": missing,
            "forbidden_hits": [],
            "checked_blocks": [],
            "ambiguous": True,
            "failure_reason": f"No matching config block found for required scope: {scope_type}.",
        }

    evidence_lines = []
    missing_required = []
    forbidden_hits = []
    checked_blocks = []

    for block in blocks:
        checked_blocks.append(serialize_block_header(block))
        child_lines = block.get("children", [])
        block_context = block["header"]["text"]

        for matcher in required_all:
            matches = find_matching_lines(child_lines, matcher, rule=rule)
            if matches:
                for m in matches:
                    evidence_lines.append(serialize_line(m, context=block_context))
            else:
                missing_required.append({
                    "block_header": serialize_block_header(block),
                    "pattern": matcher.get("pattern"),
                })

        if required_any:
            block_any_hits = []
            for matcher in required_any:
                hits = find_matching_lines(child_lines, matcher, rule=rule)
                if hits:
                    block_any_hits.extend(hits)

            if block_any_hits:
                for h in block_any_hits:
                    evidence_lines.append(serialize_line(h, context=block_context))
            else:
                missing_required.append({
                    "block_header": serialize_block_header(block),
                    "pattern": {"any_of": [m.get("pattern") for m in required_any]},
                })

        for matcher in forbidden:
            hits = find_matching_lines(child_lines, matcher, rule=rule)
            for h in hits:
                forbidden_hits.append(serialize_line(h, context=block_context))

    status = "FAIL" if missing_required or forbidden_hits else "PASS"

    return {
        "status": status,
        "evidence_lines": dedupe_evidence_lines(evidence_lines),
        "missing_required_patterns": missing_required,
        "forbidden_hits": dedupe_evidence_lines(forbidden_hits),
        "checked_blocks": checked_blocks,
        "ambiguous": False,
        "failure_reason": None,
    }


def build_result_summary(rule, result):
    if result["status"] == "PASS":
        if result.get("ambiguous"):
            return "Ambiguous condition resolved as PASS under lenient strictness."
        return "All deterministic rule conditions were satisfied."

    if result["status"] == "NEEDS_HUMAN_REVIEW":
        if result.get("failure_reason"):
            return result["failure_reason"] + " Review required under balanced strictness."
        return "Rule requires human review."

    pieces = []

    if result.get("failure_reason"):
        pieces.append(result["failure_reason"])

    missing = result.get("missing_required_patterns", [])
    if missing:
        if isinstance(missing[0], dict):
            pieces.append("One or more required patterns were missing in at least one matching block.")
        else:
            pieces.append("One or more required patterns were not found.")

    if result.get("forbidden_hits"):
        pieces.append("One or more forbidden patterns were present.")

    if not pieces:
        pieces.append("Rule failed deterministic evaluation.")

    return " ".join(pieces)



def _known_global_override_result(rule, parsed_config):
    """
    Deterministic benchmark-specific evaluators for rule families that are
    safe to score even when the extracted patterns were weak or over-literal.
    """
    candidate_lines = parsed_config.get("global_lines", [])
    rule_id = base_rule_id(rule.get("rule_id"))
    title = rule_title_text(rule)
    excerpt = normalize_cli_text(rule.get("source", {}).get("excerpt", ""))

    def pass_fail(exact_hits=None, forbidden_hits=None, missing_required=None):
        exact_hits = exact_hits or []
        forbidden_hits = forbidden_hits or []
        missing_required = missing_required or []
        status = "FAIL" if forbidden_hits or missing_required else "PASS"
        return {
            "status": status,
            "evidence_lines": dedupe_evidence_lines([serialize_line(x, context="global") for x in exact_hits]),
            "missing_required_patterns": missing_required,
            "forbidden_hits": dedupe_evidence_lines([serialize_line(x, context="global") for x in forbidden_hits]),
            "checked_blocks": [],
            "ambiguous": False,
            "failure_reason": None,
        }

    def review_result(reason):
        return {
            "status": "NEEDS_HUMAN_REVIEW",
            "evidence_lines": [],
            "missing_required_patterns": [],
            "forbidden_hits": [],
            "checked_blocks": [],
            "ambiguous": True,
            "failure_reason": reason,
        }

    if rule.get("scope", {}).get("scope_type") != "global":
        return None

    snmp_override = _snmp_override_result(rule, parsed_config)
    if snmp_override is not None:
        return snmp_override

    if rule_id == "1.2.1.1" or "clock timezone" in title:
        hits = _find_exact_lines(candidate_lines, "clock timezone UTC 0")
        return pass_fail(exact_hits=hits, missing_required=[] if hits else ["^clock timezone UTC 0$"])

    if rule_id == "1.2.1.2" or "summer-time clock" in title:
        bad = _find_positive_command_lines(candidate_lines, "clock summer-time")
        return pass_fail(forbidden_hits=bad)

    if rule_id == "1.2.2.1" or "cdp run globally" in title:
        hits = _find_exact_lines(candidate_lines, "no cdp run")
        bad = _find_positive_command_lines(candidate_lines, "cdp run")
        missing = [] if hits else ["^no cdp run$"]
        return pass_fail(exact_hits=hits, forbidden_hits=bad, missing_required=missing)

    if rule_id == "1.2.2.2" or "finger service" in title:
        return review_result("Finger service is not safely scorable from running-config alone for this benchmark family.")

    if rule_id == "1.2.2.3" or "bootp server" in title:
        hits = _find_exact_lines(candidate_lines, "no ip bootp server")
        bad = _find_positive_command_lines(candidate_lines, "ip bootp server")
        missing = [] if hits else ["^no ip bootp server$"]
        return pass_fail(exact_hits=hits, forbidden_hits=bad, missing_required=missing)

    if "require logging" == title or title.startswith("require logging "):
        return _evaluate_logging_presence_rule(parsed_config)

    if rule_id == "1.2.3.6" or "timestamps for debug" in title:
        hits = _find_prefix_lines(candidate_lines, "service timestamps debug datetime")
        return pass_fail(exact_hits=hits, missing_required=[] if hits else [r"^service timestamps debug datetime(\s+msec)?(\s+show-timezone)?$"])

    if rule_id == "1.2.3.7" or "timestamps in log" in title:
        hits = _find_prefix_lines(candidate_lines, "service timestamps log datetime")
        return pass_fail(exact_hits=hits, missing_required=[] if hits else [r"^service timestamps log datetime(\s+msec)?(\s+show-timezone)?$"])

    if rule_id in {"1.2.4.1", "1.2.4.2", "1.2.4.3"} or "primary ntp server" in title or "secondary ntp server" in title or "tertiary ntp server" in title:
        hits = _find_prefix_lines(candidate_lines, "ntp server")
        required_count = {"1.2.4.1": 1, "1.2.4.2": 2, "1.2.4.3": 3}.get(rule_id, 1)
        missing = [] if len(hits) >= required_count else [f"At least {required_count} 'ntp server' command(s) required."]
        return pass_fail(exact_hits=hits, missing_required=missing)

    if "ssh for remote device access" in title:
        hits = _find_prefix_lines(candidate_lines, "ip ssh ")
        version_hits = _find_exact_lines(candidate_lines, "ip ssh version 2")
        missing = [] if version_hits else ["^ip ssh version 2$"]
        return pass_fail(exact_hits=hits or version_hits, missing_required=missing)

    return None


def dedupe_rules_for_evaluation(rules):
    """
    Remove near-duplicate rules so a shortened/shifted rule id does not
    survive alongside a stronger equivalent rule.
    """
    def rule_score(rule):
        score = 0
        if rule.get("automation_status") == "automated":
            score += 100
        if _known_global_override_result(rule, {"global_lines": [], "lines": [], "blocks": []}) is not None:
            score += 50
        check = rule.get("check", {})
        score += 5 * len(check.get("required_all", check.get("required", [])))
        score += 4 * len(check.get("required_any", []))
        score += 3 * len(check.get("forbidden", []))
        if check.get("kind") != "manual_review":
            score += 10
        return score

    best = {}
    order = []
    for rule in rules:
        check = rule.get("check", {})
        key = (
            _normalize_title_for_dedupe(rule.get("title", "")),
            rule.get("scope", {}).get("scope_type", "unknown"),
            check.get("kind"),
            tuple(sorted(m.get("pattern", "") for m in check.get("required_all", check.get("required", [])))),
            tuple(sorted(m.get("pattern", "") for m in check.get("required_any", []))),
            tuple(sorted(m.get("pattern", "") for m in check.get("forbidden", []))),
        )
        if key not in best:
            best[key] = rule
            order.append(key)
            continue
        if rule_score(rule) > rule_score(best[key]):
            best[key] = rule

    return [best[k] for k in order]


def evaluate_rule(rule, parsed_config, strictness="balanced"):
    override_result = _known_global_override_result(rule, parsed_config)
    scoped_override = None

    if override_result is None and rule.get("scope", {}).get("scope_type") != "global":
        scoped_override = _known_scoped_override_result(rule, parsed_config, strictness)

    if rule.get("automation_status") != "automated" and override_result is None and scoped_override is None:
        return {
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "status": "NEEDS_HUMAN_REVIEW",
            "scope_type": rule["scope"]["scope_type"],
            "automation_status": rule["automation_status"],
            "review_reason": rule.get("review_reason"),
            "source": rule.get("source", {}),
            "check_kind": rule["check"]["kind"],
            "evidence_lines": [],
            "missing_required_patterns": [],
            "forbidden_hits": [],
            "checked_blocks": [],
            "summary": "Rule not auto-evaluated because normalization marked it for human review.",
            "ambiguous": False
        }

    scope_type = rule["scope"]["scope_type"]

    if override_result is not None:
        result = override_result
        effective_automation_status = "automated_override"
    elif scoped_override is not None:
        result = scoped_override
        effective_automation_status = "automated_override"
    elif scope_type == "global":
        result = evaluate_global_rule(rule, parsed_config)
        effective_automation_status = rule["automation_status"]
    else:
        result = evaluate_scoped_rule(rule, parsed_config, strictness)
        effective_automation_status = rule["automation_status"]

    summary = build_result_summary(rule, result)

    return {
        "rule_id": rule["rule_id"],
        "title": rule["title"],
        "status": result["status"],
        "scope_type": scope_type,
        "automation_status": effective_automation_status,
        "review_reason": rule.get("review_reason"),
        "source": rule.get("source", {}),
        "check_kind": rule["check"]["kind"],
        "evidence_lines": result["evidence_lines"],
        "missing_required_patterns": result["missing_required_patterns"],
        "forbidden_hits": result["forbidden_hits"],
        "checked_blocks": result["checked_blocks"],
        "summary": summary,
        "ambiguous": result.get("ambiguous", False)
    }

def evaluate_all_rules(normalized_doc, config_text, strictness="balanced"):
    strictness = normalize_strictness(strictness)
    parsed = parse_ios_config(config_text)
    results = []

    rules = dedupe_rules_for_evaluation(normalized_doc.get("rules", []))

    for rule in rules:
        result = evaluate_rule(rule, parsed_config=parsed, strictness=strictness)
        results.append(result)

    pass_count = sum(1 for r in results if r["status"] == "PASS")
    fail_count = sum(1 for r in results if r["status"] == "FAIL")
    review_count = sum(1 for r in results if r["status"] == "NEEDS_HUMAN_REVIEW")

    overall = {
        "document_name": normalized_doc.get("document_name"),
        "strictness": strictness.title(),
        "total_rules": len(results),
        "pass_count": pass_count,
        "fail_count": fail_count,
        "needs_human_review_count": review_count,
        "results": results
    }

    return overall


def esc(text):
    if text is None:
        return ""
    return html.escape(str(text))


def status_class(status):
    if status == "PASS":
        return "pass"
    if status == "FAIL":
        return "fail"
    return "review"


def render_evidence_list(items, mode="normal"):
    if not items:
        return "<p class='empty'>None</p>"

    out = ["<ul class='evidence-list'>"]
    for item in items:
        if isinstance(item, dict) and "block_header" in item:
            hdr = item["block_header"]
            out.append(
                "<li>"
                f"<code>{esc(item['pattern'])}</code> missing under block "
                f"<code>Line {hdr['lineno']}: {esc(hdr['text'])}</code>"
                "</li>"
            )
        else:
            if isinstance(item, dict):
                line_no = item.get("lineno", "")
                text = item.get("text", "")
                ctx = item.get("context")
                ctx_html = f" <span class='context'>({esc(ctx)})</span>" if ctx else ""
                out.append(
                    "<li>"
                    f"<code>Line {esc(line_no)}: {esc(text)}</code>{ctx_html}"
                    "</li>"
                )
            else:
                out.append(f"<li><code>{esc(item)}</code></li>")
    out.append("</ul>")
    return "\n".join(out)


def build_html_report(report, config_name=None):
    rows = []
    cards = []

    for r in report["results"]:
        badge_class = status_class(r["status"])

        rows.append(f"""
        <tr>
            <td><span class="badge {badge_class}">{esc(r['status'])}</span></td>
            <td>{esc(r['rule_id'])}</td>
            <td>{esc(r['title'])}</td>
            <td>{esc(r['scope_type'])}</td>
            <td>{esc(r['summary'])}</td>
        </tr>
        """)

        checked_blocks_html = "<p class='empty'>None</p>"
        if r["checked_blocks"]:
            checked_blocks_html = "<ul class='evidence-list'>" + "".join(
                f"<li><code>Line {esc(b['lineno'])}: {esc(b['text'])}</code></li>"
                for b in r["checked_blocks"]
            ) + "</ul>"

        source = r.get("source", {})
        cards.append(f"""
        <div class="rule-card">
            <div class="rule-header">
                <div>
                    <h2>{esc(r['rule_id'])} — {esc(r['title'])}</h2>
                    <div class="meta">
                        <span><strong>Scope:</strong> {esc(r['scope_type'])}</span>
                        <span><strong>Check kind:</strong> {esc(r['check_kind'])}</span>
                        <span><strong>Source page:</strong> {esc(source.get('page'))}</span>
                    </div>
                </div>
                <span class="badge {badge_class}">{esc(r['status'])}</span>
            </div>

            <p class="summary">{esc(r['summary'])}</p>

            <details>
                <summary>Show details</summary>

                <div class="detail-grid">
                    <div class="detail-box">
                        <h3>Source grounding</h3>
                        <p><strong>Section:</strong> {esc(source.get('section'))}</p>
                        <p><strong>Excerpt:</strong></p>
                        <pre>{esc(source.get('excerpt'))}</pre>
                    </div>

                    <div class="detail-box">
                        <h3>Checked blocks</h3>
                        {checked_blocks_html}
                    </div>

                    <div class="detail-box">
                        <h3>Evidence lines</h3>
                        {render_evidence_list(r["evidence_lines"])}
                    </div>

                    <div class="detail-box">
                        <h3>Missing required patterns</h3>
                        {render_evidence_list(r["missing_required_patterns"])}
                    </div>

                    <div class="detail-box">
                        <h3>Forbidden hits</h3>
                        {render_evidence_list(r["forbidden_hits"])}
                    </div>

                    <div class="detail-box">
                        <h3>Review info</h3>
                        <p><strong>Automation status:</strong> {esc(r['automation_status'])}</p>
                        <p><strong>Review reason:</strong> {esc(r.get('review_reason') or 'None')}</p>
                    </div>
                </div>
            </details>
        </div>
        """)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Check Report</title>
    <style>
        :root {{
            --bg: #f6f8fb;
            --card: #ffffff;
            --text: #1f2937;
            --muted: #6b7280;
            --border: #dbe2ea;
            --pass-bg: #dcfce7;
            --pass-text: #166534;
            --fail-bg: #fee2e2;
            --fail-text: #991b1b;
            --review-bg: #ffedd5;
            --review-text: #9a3412;
            --accent: #2563eb;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.45;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 24px;
        }}

        .hero {{
            background: linear-gradient(135deg, #1d4ed8, #2563eb);
            color: white;
            border-radius: 18px;
            padding: 28px;
            margin-bottom: 24px;
            box-shadow: 0 10px 30px rgba(37, 99, 235, 0.18);
        }}

        .hero h1 {{
            margin: 0 0 10px 0;
            font-size: 32px;
        }}

        .hero p {{
            margin: 6px 0;
            opacity: 0.96;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin: 24px 0;
        }}

        .summary-card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 20px;
            box-shadow: 0 4px 18px rgba(0,0,0,0.04);
        }}

        .summary-card h3 {{
            margin: 0 0 8px 0;
            font-size: 14px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}

        .summary-card .value {{
            font-size: 32px;
            font-weight: 700;
        }}

        .table-card, .rule-card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 18px rgba(0,0,0,0.04);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}

        th, td {{
            text-align: left;
            padding: 12px 10px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}

        th {{
            color: var(--muted);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}

        .badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 999px;
            font-weight: 700;
            font-size: 12px;
            letter-spacing: 0.02em;
        }}

        .badge.pass {{
            background: var(--pass-bg);
            color: var(--pass-text);
        }}

        .badge.fail {{
            background: var(--fail-bg);
            color: var(--fail-text);
        }}

        .badge.review {{
            background: var(--review-bg);
            color: var(--review-text);
        }}

        .rule-header {{
            display: flex;
            justify-content: space-between;
            gap: 16px;
            align-items: flex-start;
            margin-bottom: 14px;
        }}

        .rule-header h2 {{
            margin: 0 0 8px 0;
            font-size: 22px;
        }}

        .meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            color: var(--muted);
            font-size: 14px;
        }}

        .summary {{
            font-size: 15px;
            margin-bottom: 12px;
        }}

        details {{
            margin-top: 10px;
        }}

        summary {{
            cursor: pointer;
            font-weight: 700;
            color: var(--accent);
            margin-bottom: 12px;
        }}

        .detail-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-top: 14px;
        }}

        .detail-box {{
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 14px;
            background: #fbfcfe;
        }}

        .detail-box h3 {{
            margin-top: 0;
            font-size: 16px;
        }}

        pre {{
            white-space: pre-wrap;
            word-break: break-word;
            background: #f3f4f6;
            padding: 12px;
            border-radius: 10px;
            overflow-x: auto;
            font-size: 13px;
        }}

        code {{
            background: #f3f4f6;
            padding: 2px 6px;
            border-radius: 6px;
            font-family: Consolas, monospace;
            font-size: 13px;
        }}

        .evidence-list {{
            margin: 0;
            padding-left: 18px;
        }}

        .evidence-list li {{
            margin-bottom: 8px;
        }}

        .context {{
            color: var(--muted);
            font-size: 13px;
        }}

        .empty {{
            color: var(--muted);
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <h1>Compliance Check Report</h1>
            <p><strong>Document:</strong> {esc(report.get('document_name', 'Unknown'))}</p>
            <p><strong>Config file:</strong> {esc(config_name or 'Unknown')}</p>
            <p><strong>Strictness:</strong> {esc(report.get('strictness', 'Balanced'))}</p>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Rules</h3>
                <div class="value">{esc(report['total_rules'])}</div>
            </div>
            <div class="summary-card">
                <h3>PASS</h3>
                <div class="value" style="color:#166534;">{esc(report['pass_count'])}</div>
            </div>
            <div class="summary-card">
                <h3>FAIL</h3>
                <div class="value" style="color:#991b1b;">{esc(report['fail_count'])}</div>
            </div>
            <div class="summary-card">
                <h3>Needs Review</h3>
                <div class="value" style="color:#9a3412;">{esc(report['needs_human_review_count'])}</div>
            </div>
        </div>

        <div class="table-card">
            <h2>Rule Summary</h2>
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Rule ID</th>
                        <th>Title</th>
                        <th>Scope</th>
                        <th>Summary</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>

        {''.join(cards)}
    </div>
</body>
</html>
"""
    return html_doc




# -----------------------------------------------------------------
# AI second-pass compatibility helpers used by UserInterface.py
# -----------------------------------------------------------------



def unique_preserve(seq):
    out = []
    seen = set()
    for item in seq:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out

def _rule_map_by_id(normalized_doc):
    return {str(rule.get("rule_id")): rule for rule in normalized_doc.get("rules", [])}


def _serialize_matcher_patterns(matchers):
    out = []
    for item in matchers or []:
        if isinstance(item, dict):
            pattern = item.get("pattern")
            if pattern:
                out.append(str(pattern))
        elif item:
            out.append(str(item))
    return out


def _pattern_to_search_stem(pattern):
    text = str(pattern or "").strip()
    if not text:
        return ""

    if "#" in text:
        text = text.split("#", 1)[1].strip()

    text = text.replace(r"\s+", " ")
    text = text.replace(r"\s*", " ")
    text = text.replace(r"\b", " ")
    text = text.replace("\\", " ")
    text = re.sub(r"[\^\$\[\]\(\)\{\}\|\?\*\+]", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\{[^}]+\}", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    tokens = []
    for token in re.findall(r"[A-Za-z0-9_./:-]+", text):
        if token.isupper() and len(token) > 1:
            break
        lowered = token.lower()
        if lowered in {"config", "config-line", "line-number", "ending-line-number", "timeout_in_minutes", "timeout_in_seconds", "banner-text", "aaa_list_name", "local_password", "local_username", "enable_secret", "vty_acl_number", "vty_acl_block_with_mask", "vty_acl_host"}:
            break
        tokens.append(token)
        if len(tokens) >= 4:
            break

    if not tokens:
        return ""

    return normalize_cli_text(" ".join(tokens))


def _collect_search_stems_for_rule(rule):
    check = rule.get("check", {})
    raw_rule = rule.get("raw_rule", {})

    pattern_strings = []
    pattern_strings.extend(_serialize_matcher_patterns(check.get("required_all", check.get("required", []))))
    pattern_strings.extend(_serialize_matcher_patterns(check.get("required_any", [])))
    pattern_strings.extend(_serialize_matcher_patterns(check.get("forbidden", [])))

    for key in ("required_patterns", "forbidden_patterns"):
        for value in raw_rule.get(key, []) or []:
            if value:
                pattern_strings.append(str(value))

    stems = []
    for pattern in pattern_strings:
        stem = _pattern_to_search_stem(pattern)
        if stem:
            stems.append(stem)

    title = normalize_cli_text(rule.get("title", ""))
    if "local user" in title:
        stems.extend(["username", "secret", "password"])
    if "enable secret" in title:
        stems.append("enable secret")
    if "banner" in title:
        for token in ("banner exec", "banner login", "banner motd"):
            if token.split()[1] in title:
                stems.append(token)
    if "timeout for login sessions" in title:
        stems.append("exec-timeout")
    if "ssh access control" in title or "vty acl" in title:
        stems.extend(["access-class", "access-list"])
    if "aaa authentication for local console and vty lines" in title:
        stems.append("login authentication")
    if "ssh for remote device access" in title:
        stems.extend(["ip ssh", "transport input ssh"])

    return unique_preserve([s for s in stems if s])


def _limit_serialized_lines(line_objs, limit=30, context=None):
    items = []
    for line in line_objs[:limit]:
        items.append(serialize_line(line, context=context))
    return items


def build_rule_context_for_ai(rule, parsed_config, deterministic_result=None, max_lines=40):
    deterministic_result = deterministic_result or {}
    scope = rule.get("scope", {})
    scope_type = scope.get("scope_type", "unknown")

    context = {
        "scope_type": scope_type,
        "matched_scope_blocks": [],
        "global_lines": [],
        "available_line_headers": [],
        "note": None,
    }

    if scope_type == "global":
        stems = _collect_search_stems_for_rule(rule)
        selected = []

        for line in parsed_config.get("global_lines", []):
            text_norm = normalize_cli_text(line.get("text", ""))
            if any(text_norm.startswith(stem) or stem in text_norm for stem in stems):
                selected.append(line)

        evidence_line_numbers = {item.get("lineno") for item in deterministic_result.get("evidence_lines", []) if isinstance(item, dict)}
        forbidden_line_numbers = {item.get("lineno") for item in deterministic_result.get("forbidden_hits", []) if isinstance(item, dict)}
        wanted_lines = evidence_line_numbers | forbidden_line_numbers
        if wanted_lines:
            for line in parsed_config.get("global_lines", []):
                if line.get("lineno") in wanted_lines:
                    selected.append(line)

        # fall back to known-override safe command families if no stems matched
        if not selected:
            title = rule_title_text(rule)
            fallback_prefixes = []
            if "clock timezone" in title:
                fallback_prefixes.append("clock timezone")
            if "summer-time" in title:
                fallback_prefixes.append("clock summer-time")
            if "cdp run" in title:
                fallback_prefixes.extend(["cdp run", "no cdp run"])
            if "finger" in title:
                fallback_prefixes.extend(["service finger", "no service finger"])
            if "bootp" in title:
                fallback_prefixes.extend(["ip bootp server", "no ip bootp server"])
            if "timestamps for debug" in title:
                fallback_prefixes.append("service timestamps debug datetime")
            if "timestamps in log" in title:
                fallback_prefixes.append("service timestamps log datetime")
            if "ntp server" in title:
                fallback_prefixes.append("ntp server")

            for prefix in fallback_prefixes:
                selected.extend(_find_prefix_lines(parsed_config.get("global_lines", []), prefix))

        context["global_lines"] = dedupe_evidence_lines(_limit_serialized_lines(selected, limit=max_lines, context="global"))
        if not context["global_lines"]:
            context["note"] = "No obvious matching global command lines were found for this rule in the current config snippet search."
        return context

    blocks = find_scope_blocks(parsed_config, scope)
    if blocks:
        for block in blocks[:3]:
            children = block.get("children", [])[:max_lines]
            context["matched_scope_blocks"].append({
                "header": serialize_block_header(block),
                "lines": [serialize_line(line, context=block["header"]["text"]) for line in children],
            })
    else:
        context["note"] = f"No matching scope blocks were found for scope '{scope_type}'."

    all_line_headers = []
    for block in parsed_config.get("blocks", []):
        header_text = normalize_cli_text(block.get("header", {}).get("text", ""))
        if header_text.startswith("line "):
            all_line_headers.append(serialize_block_header(block))
    context["available_line_headers"] = all_line_headers[:12]

    return context


def build_ai_review_items(normalized_doc, deterministic_report, config_text, max_lines_per_item=40):
    parsed = parse_ios_config(config_text)
    rule_map = _rule_map_by_id(normalized_doc)
    items = []

    for result in deterministic_report.get("results", []):
        if result.get("status") != "NEEDS_HUMAN_REVIEW":
            continue

        rule = rule_map.get(str(result.get("rule_id")))
        if not rule:
            continue

        raw_rule = rule.get("raw_rule", {})
        check = rule.get("check", {})

        items.append({
            "rule_id": rule.get("rule_id"),
            "title": rule.get("title"),
            "scope_type": rule.get("scope", {}).get("scope_type"),
            "deterministic_status": result.get("status"),
            "deterministic_summary": result.get("summary"),
            "review_reason": result.get("review_reason") or rule.get("review_reason"),
            "source": {
                "page": rule.get("source", {}).get("page"),
                "section": rule.get("source", {}).get("section"),
                "excerpt": rule.get("source", {}).get("excerpt"),
            },
            "original_requirement_text": rule.get("original_requirement_text"),
            "normalized_rule": {
                "check_kind": check.get("kind"),
                "automation_status": rule.get("automation_status"),
                "required_all": _serialize_matcher_patterns(check.get("required_all", check.get("required", []))),
                "required_any": _serialize_matcher_patterns(check.get("required_any", [])),
                "forbidden": _serialize_matcher_patterns(check.get("forbidden", [])),
            },
            "raw_extracted_rule": {
                "scope_hint": raw_rule.get("scope_hint"),
                "check_type": raw_rule.get("check_type"),
                "required_patterns": raw_rule.get("required_patterns", []),
                "forbidden_patterns": raw_rule.get("forbidden_patterns", []),
                "needs_human_review": raw_rule.get("needs_human_review"),
            },
            "deterministic_context": {
                "checked_blocks": result.get("checked_blocks", []),
                "evidence_lines": result.get("evidence_lines", []),
                "missing_required_patterns": result.get("missing_required_patterns", []),
                "forbidden_hits": result.get("forbidden_hits", []),
            },
            "relevant_config": build_rule_context_for_ai(rule, parsed, deterministic_result=result, max_lines=max_lines_per_item),
        })

    return items


def build_final_result_summary(result):
    deterministic_status = result.get("deterministic_status", result.get("status"))
    final_status = result.get("final_status", result.get("status"))
    decision_source = result.get("decision_source", "Deterministic")
    base_summary = result.get("summary", "")
    ai_review = result.get("ai_review") or {}

    if decision_source == "Deterministic":
        return base_summary

    if decision_source == "AI Suggested":
        confidence = ai_review.get("confidence") or "unspecified"
        explanation = ai_review.get("explanation") or "No explanation provided."
        return (
            f"Deterministic pipeline left this rule as {deterministic_status}. "
            f"AI suggested {final_status} (confidence: {confidence}). {explanation}"
        )

    if ai_review.get("ai_suggested_status") == "UNSURE":
        confidence = ai_review.get("confidence") or "unspecified"
        explanation = ai_review.get("explanation") or "AI could not confidently score this rule."
        return (
            f"Deterministic pipeline left this rule as {deterministic_status}. "
            f"AI remained UNSURE (confidence: {confidence}). {explanation}"
        )

    return base_summary or "Rule still requires human review."


def merge_ai_review_suggestions(deterministic_report, ai_review_payload):
    final_report = json.loads(json.dumps(deterministic_report))
    reviews = ai_review_payload.get("reviews", []) if isinstance(ai_review_payload, dict) else []
    review_map = {}
    for item in reviews:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("rule_id") or "").strip()
        if rule_id:
            review_map[rule_id] = item

    final_pass_count = 0
    final_fail_count = 0
    final_review_count = 0
    ai_pass_count = 0
    ai_fail_count = 0
    ai_unsure_count = 0

    for result in final_report.get("results", []):
        deterministic_status = result.get("status")
        ai_review = review_map.get(str(result.get("rule_id")))

        result["deterministic_status"] = deterministic_status
        result["ai_review"] = ai_review

        if deterministic_status != "NEEDS_HUMAN_REVIEW":
            result["final_status"] = deterministic_status
            result["decision_source"] = "Deterministic"
        else:
            ai_status = str((ai_review or {}).get("ai_suggested_status") or "").strip().upper()
            if ai_status in {"PASS", "FAIL"}:
                result["final_status"] = ai_status
                result["decision_source"] = "AI Suggested"
                if ai_status == "PASS":
                    ai_pass_count += 1
                else:
                    ai_fail_count += 1
            else:
                result["final_status"] = "NEEDS_HUMAN_REVIEW"
                result["decision_source"] = "Needs Human Review"
                if ai_status == "UNSURE":
                    ai_unsure_count += 1

        result["final_summary"] = build_final_result_summary(result)

        if result["final_status"] == "PASS":
            final_pass_count += 1
        elif result["final_status"] == "FAIL":
            final_fail_count += 1
        else:
            final_review_count += 1

    final_report["ai_second_pass"] = {
        "enabled": True,
        "reviewed_rule_count": sum(1 for r in deterministic_report.get("results", []) if r.get("status") == "NEEDS_HUMAN_REVIEW"),
        "ai_suggested_pass_count": ai_pass_count,
        "ai_suggested_fail_count": ai_fail_count,
        "ai_unsure_count": ai_unsure_count,
        "final_pass_count": final_pass_count,
        "final_fail_count": final_fail_count,
        "final_needs_human_review_count": final_review_count,
        "error": ai_review_payload.get("error") if isinstance(ai_review_payload, dict) else None,
    }

    return final_report



def build_html_report(report, config_name=None):
    ai_info = report.get("ai_second_pass", {}) or {}
    ai_enabled = bool(ai_info.get("enabled"))

    displayed_total = report.get("total_rules", 0)
    displayed_pass = ai_info.get("final_pass_count", report.get("pass_count", 0)) if ai_enabled else report.get("pass_count", 0)
    displayed_fail = ai_info.get("final_fail_count", report.get("fail_count", 0)) if ai_enabled else report.get("fail_count", 0)
    displayed_review = ai_info.get("final_needs_human_review_count", report.get("needs_human_review_count", 0)) if ai_enabled else report.get("needs_human_review_count", 0)

    rows = []
    cards = []

    for r in report["results"]:
        shown_status = r.get("final_status", r.get("status"))
        shown_summary = r.get("final_summary", r.get("summary", ""))
        decision_source = r.get("decision_source", "Deterministic" if r.get("status") != "NEEDS_HUMAN_REVIEW" else "Needs Human Review")
        badge_class = status_class(shown_status)

        rows.append(f"""
        <tr>
            <td><span class="badge {badge_class}">{esc(shown_status)}</span></td>
            <td>{esc(decision_source)}</td>
            <td>{esc(r.get('deterministic_status', r.get('status')))}</td>
            <td>{esc(r['rule_id'])}</td>
            <td>{esc(r['title'])}</td>
            <td>{esc(r['scope_type'])}</td>
            <td>{esc(shown_summary)}</td>
        </tr>
        """)

        checked_blocks_html = "<p class='empty'>None</p>"
        if r["checked_blocks"]:
            checked_blocks_html = "<ul class='evidence-list'>" + "".join(
                f"<li><code>Line {esc(b['lineno'])}: {esc(b['text'])}</code></li>"
                for b in r["checked_blocks"]
            ) + "</ul>"

        source = r.get("source", {})
        ai_review = r.get("ai_review") or {}
        ai_review_html = "<p class='empty'>No AI suggestion for this rule.</p>"
        if ai_review:
            ai_review_html = f"""
                <p><strong>AI suggested status:</strong> {esc(ai_review.get('ai_suggested_status'))}</p>
                <p><strong>Confidence:</strong> {esc(ai_review.get('confidence'))}</p>
                <p><strong>Explanation:</strong> {esc(ai_review.get('explanation'))}</p>
                <div style="margin-top:10px;">
                    <strong>AI evidence lines</strong>
                    {render_evidence_list(ai_review.get('evidence_lines', []))}
                </div>
            """

        cards.append(f"""
        <div class="rule-card">
            <div class="rule-header">
                <div>
                    <h2>{esc(r['rule_id'])} — {esc(r['title'])}</h2>
                    <div class="meta">
                        <span><strong>Scope:</strong> {esc(r['scope_type'])}</span>
                        <span><strong>Check kind:</strong> {esc(r['check_kind'])}</span>
                        <span><strong>Source page:</strong> {esc(source.get('page'))}</span>
                        <span><strong>Deterministic status:</strong> {esc(r.get('deterministic_status', r.get('status')))}</span>
                        <span><strong>Decision source:</strong> {esc(decision_source)}</span>
                    </div>
                </div>
                <span class="badge {badge_class}">{esc(shown_status)}</span>
            </div>

            <p class="summary">{esc(shown_summary)}</p>

            <details>
                <summary>Show details</summary>

                <div class="detail-grid">
                    <div class="detail-box">
                        <h3>Source grounding</h3>
                        <p><strong>Section:</strong> {esc(source.get('section'))}</p>
                        <p><strong>Excerpt:</strong></p>
                        <pre>{esc(source.get('excerpt'))}</pre>
                    </div>

                    <div class="detail-box">
                        <h3>Checked blocks</h3>
                        {checked_blocks_html}
                    </div>

                    <div class="detail-box">
                        <h3>Evidence lines</h3>
                        {render_evidence_list(r["evidence_lines"])}
                    </div>

                    <div class="detail-box">
                        <h3>Missing required patterns</h3>
                        {render_evidence_list(r["missing_required_patterns"])}
                    </div>

                    <div class="detail-box">
                        <h3>Forbidden hits</h3>
                        {render_evidence_list(r["forbidden_hits"])}
                    </div>

                    <div class="detail-box">
                        <h3>Review info</h3>
                        <p><strong>Automation status:</strong> {esc(r['automation_status'])}</p>
                        <p><strong>Review reason:</strong> {esc(r.get('review_reason') or 'None')}</p>
                    </div>

                    <div class="detail-box">
                        <h3>AI suggestion</h3>
                        {ai_review_html}
                    </div>
                </div>
            </details>
        </div>
        """)

    ai_summary_cards = ""
    ai_note_html = ""
    if ai_enabled:
        ai_summary_cards = f"""
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Deterministic PASS</h3>
                <div class="value" style="color:#166534;">{esc(report.get('pass_count', 0))}</div>
            </div>
            <div class="summary-card">
                <h3>Deterministic FAIL</h3>
                <div class="value" style="color:#991b1b;">{esc(report.get('fail_count', 0))}</div>
            </div>
            <div class="summary-card">
                <h3>Deterministic Review</h3>
                <div class="value" style="color:#9a3412;">{esc(report.get('needs_human_review_count', 0))}</div>
            </div>
            <div class="summary-card">
                <h3>AI Suggested PASS</h3>
                <div class="value" style="color:#166534;">{esc(ai_info.get('ai_suggested_pass_count', 0))}</div>
            </div>
            <div class="summary-card">
                <h3>AI Suggested FAIL</h3>
                <div class="value" style="color:#991b1b;">{esc(ai_info.get('ai_suggested_fail_count', 0))}</div>
            </div>
            <div class="summary-card">
                <h3>AI Unsure</h3>
                <div class="value" style="color:#9a3412;">{esc(ai_info.get('ai_unsure_count', 0))}</div>
            </div>
        </div>
        """
        ai_note_html = f"""
            <p><strong>AI second pass:</strong> Review-only items were sent to the model for a suggested PASS / FAIL / UNSURE. Deterministic results were kept intact for all rules the Python checker could score.</p>
            <p><strong>Human review note:</strong> AI suggestions are advisory only and human review may still be necessary.</p>
        """
        if ai_info.get("error"):
            ai_note_html += f"<p><strong>AI stage error:</strong> {esc(ai_info.get('error'))}</p>"

    report_title = "Compliance Check Report" if not ai_enabled else "Compliance Check Report (Final)"

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{esc(report_title)}</title>
    <style>
        :root {{
            --bg: #f6f8fb;
            --card: #ffffff;
            --text: #1f2937;
            --muted: #6b7280;
            --border: #dbe2ea;
            --pass-bg: #dcfce7;
            --pass-text: #166534;
            --fail-bg: #fee2e2;
            --fail-text: #991b1b;
            --review-bg: #ffedd5;
            --review-text: #9a3412;
            --accent: #2563eb;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.45;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 24px;
        }}

        .hero {{
            background: linear-gradient(135deg, #1d4ed8, #2563eb);
            color: white;
            border-radius: 18px;
            padding: 28px;
            margin-bottom: 24px;
            box-shadow: 0 10px 30px rgba(37, 99, 235, 0.18);
        }}

        .hero h1 {{
            margin: 0 0 10px 0;
            font-size: 32px;
        }}

        .hero p {{
            margin: 6px 0;
            opacity: 0.96;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin: 24px 0;
        }}

        .summary-card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 20px;
            box-shadow: 0 4px 18px rgba(0,0,0,0.04);
        }}

        .summary-card h3 {{
            margin: 0 0 8px 0;
            font-size: 14px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}

        .summary-card .value {{
            font-size: 32px;
            font-weight: 700;
        }}

        .table-card, .rule-card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 18px rgba(0,0,0,0.04);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}

        th, td {{
            text-align: left;
            padding: 12px 10px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}

        th {{
            color: var(--muted);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}

        .badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 999px;
            font-weight: 700;
            font-size: 12px;
            letter-spacing: 0.02em;
        }}

        .badge.pass {{
            background: var(--pass-bg);
            color: var(--pass-text);
        }}

        .badge.fail {{
            background: var(--fail-bg);
            color: var(--fail-text);
        }}

        .badge.review {{
            background: var(--review-bg);
            color: var(--review-text);
        }}

        .rule-header {{
            display: flex;
            justify-content: space-between;
            gap: 16px;
            align-items: flex-start;
            margin-bottom: 14px;
        }}

        .rule-header h2 {{
            margin: 0 0 8px 0;
            font-size: 22px;
        }}

        .meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            color: var(--muted);
            font-size: 14px;
        }}

        .summary {{
            font-size: 15px;
            margin-bottom: 12px;
        }}

        details {{
            margin-top: 10px;
        }}

        summary {{
            cursor: pointer;
            font-weight: 700;
            color: var(--accent);
            margin-bottom: 12px;
        }}

        .detail-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-top: 14px;
        }}

        .detail-box {{
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 14px;
            background: #fbfcfe;
        }}

        .detail-box h3 {{
            margin-top: 0;
            font-size: 16px;
        }}

        pre {{
            white-space: pre-wrap;
            word-break: break-word;
            background: #f3f4f6;
            padding: 12px;
            border-radius: 10px;
            overflow-x: auto;
            font-size: 13px;
        }}

        code {{
            background: #f3f4f6;
            padding: 2px 6px;
            border-radius: 6px;
            font-family: Consolas, monospace;
            font-size: 13px;
        }}

        .evidence-list {{
            margin: 0;
            padding-left: 18px;
        }}

        .evidence-list li {{
            margin-bottom: 8px;
        }}

        .context {{
            color: var(--muted);
            font-size: 13px;
        }}

        .empty {{
            color: var(--muted);
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <h1>{esc(report_title)}</h1>
            <p><strong>Document:</strong> {esc(report.get('document_name', 'Unknown'))}</p>
            <p><strong>Config file:</strong> {esc(config_name or 'Unknown')}</p>
            <p><strong>Strictness:</strong> {esc(report.get('strictness', 'Balanced'))}</p>
            {ai_note_html}
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Rules</h3>
                <div class="value">{esc(displayed_total)}</div>
            </div>
            <div class="summary-card">
                <h3>PASS</h3>
                <div class="value" style="color:#166534;">{esc(displayed_pass)}</div>
            </div>
            <div class="summary-card">
                <h3>FAIL</h3>
                <div class="value" style="color:#991b1b;">{esc(displayed_fail)}</div>
            </div>
            <div class="summary-card">
                <h3>Needs Review</h3>
                <div class="value" style="color:#9a3412;">{esc(displayed_review)}</div>
            </div>
        </div>

        {ai_summary_cards}

        <div class="table-card">
            <h2>Rule Summary</h2>
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Decision Source</th>
                        <th>Deterministic Status</th>
                        <th>Rule ID</th>
                        <th>Title</th>
                        <th>Scope</th>
                        <th>Summary</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>

        {''.join(cards)}
    </div>
</body>
</html>
"""
    return html_doc



def print_console_summary(report):
    print("\nCHECK RESULTS SUMMARY\n")
    print(f"Document: {report.get('document_name')}")
    print(f"Strictness: {report.get('strictness')}")
    print(f"Total rules: {report['total_rules']}")
    print(f"PASS: {report['pass_count']}")
    print(f"FAIL: {report['fail_count']}")
    print(f"NEEDS_HUMAN_REVIEW: {report['needs_human_review_count']}")
    print()

    for r in report["results"]:
        print(f"[{r['status']}] {r['rule_id']} - {r['title']}")
        print(f"  Scope: {r['scope_type']}")
        print(f"  Summary: {r['summary']}")
        print()


def main():
    """
    Usage:
        python checks_ios.py normalized_rules.json running_config.txt [Strict|Balanced|Lenient]

    Defaults:
        normalized_rules.json
        basic-cisco-router-config.txt
        Balanced
    """
    if len(sys.argv) >= 3:
        normalized_rules_path = Path(sys.argv[1])
        config_path = Path(sys.argv[2])
        strictness = sys.argv[3] if len(sys.argv) >= 4 else "Balanced"
    else:
        normalized_rules_path = Path("normalized_rules.json")
        config_path = Path("basic-cisco-router-config.txt")
        strictness = "Balanced"

    strictness = normalize_strictness(strictness)

    if not normalized_rules_path.exists():
        raise FileNotFoundError(f"Normalized rules file not found: {normalized_rules_path}")

    if not config_path.exists():
        raise FileNotFoundError(
            f"Config file not found: {config_path}\n"
            f"Run as: python checks_ios.py normalized_rules.json your_running_config.txt [Strict|Balanced|Lenient]"
        )

    normalized_doc = load_json(normalized_rules_path)
    config_text = read_text(config_path)

    report = evaluate_all_rules(normalized_doc, config_text, strictness=strictness)

    json_output_path = Path("check_results.json")
    html_output_path = Path("check_report.html")

    save_json(json_output_path, report)

    html_report = build_html_report(report, config_name=config_path.name)
    with open(html_output_path, "w", encoding="utf-8") as f:
        f.write(html_report)

    print_console_summary(report)
    print(f"Saved to {json_output_path}")
    print(f"Saved to {html_output_path}")

    # Open in default browser (often Chrome on Windows if set as default)
    try:
        webbrowser.open(html_output_path.resolve().as_uri())
        print("Opened HTML report in your default browser.")
    except Exception as e:
        print(f"Could not auto-open browser: {e}")


if __name__ == "__main__":
    main()
