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
    return re.compile(pattern, flags)


def line_matches(line_obj, matcher):
    regex = compile_regex(
        matcher["pattern"],
        case_sensitive=matcher.get("case_sensitive", False)
    )
    return regex.search(line_obj["text"]) is not None


def find_matching_lines(line_objs, matcher):
    matches = []
    for line in line_objs:
        if line_matches(line, matcher):
            matches.append(line)
    return matches


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

    return matched_blocks


def evaluate_global_rule(rule, parsed_config):
    required = rule["check"].get("required", [])
    forbidden = rule["check"].get("forbidden", [])

    evidence_lines = []
    missing_required = []
    forbidden_hits = []

    candidate_lines = parsed_config["global_lines"]

    for matcher in required:
        matches = find_matching_lines(candidate_lines, matcher)
        if matches:
            for m in matches:
                evidence_lines.append(serialize_line(m, context="global"))
        else:
            missing_required.append(matcher["pattern"])

    for matcher in forbidden:
        hits = find_matching_lines(candidate_lines, matcher)
        for h in hits:
            forbidden_hits.append(serialize_line(h, context="global"))

    if missing_required or forbidden_hits:
        status = "FAIL"
    else:
        status = "PASS"

    return {
        "status": status,
        "evidence_lines": dedupe_evidence_lines(evidence_lines),
        "missing_required_patterns": missing_required,
        "forbidden_hits": dedupe_evidence_lines(forbidden_hits),
        "checked_blocks": [],
        "ambiguous": False,
        "failure_reason": None
    }


def evaluate_scoped_rule(rule, parsed_config, strictness):
    required = rule["check"].get("required", [])
    forbidden = rule["check"].get("forbidden", [])
    scope_type = rule["scope"].get("scope_type", "unknown")

    blocks = find_scope_blocks(parsed_config, rule["scope"])

    if not blocks:
        status = resolve_ambiguous_status(strictness)

        return {
            "status": status,
            "evidence_lines": [],
            "missing_required_patterns": [m["pattern"] for m in required] if required else [],
            "forbidden_hits": [],
            "checked_blocks": [],
            "ambiguous": True,
            "failure_reason": f"No matching config block found for required scope: {scope_type}."
        }

    evidence_lines = []
    missing_required = []
    forbidden_hits = []
    checked_blocks = []

    for block in blocks:
        checked_blocks.append(serialize_block_header(block))
        child_lines = block["children"]
        block_context = block["header"]["text"]

        for matcher in required:
            matches = find_matching_lines(child_lines, matcher)
            if matches:
                for m in matches:
                    evidence_lines.append(serialize_line(m, context=block_context))
            else:
                missing_required.append({
                    "block_header": serialize_block_header(block),
                    "pattern": matcher["pattern"]
                })

        for matcher in forbidden:
            hits = find_matching_lines(child_lines, matcher)
            for h in hits:
                forbidden_hits.append(serialize_line(h, context=block_context))

    if missing_required or forbidden_hits:
        status = "FAIL"
    else:
        status = "PASS"

    return {
        "status": status,
        "evidence_lines": dedupe_evidence_lines(evidence_lines),
        "missing_required_patterns": missing_required,
        "forbidden_hits": dedupe_evidence_lines(forbidden_hits),
        "checked_blocks": checked_blocks,
        "ambiguous": False,
        "failure_reason": None
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


def evaluate_rule(rule, parsed_config, strictness="balanced"):
    if rule.get("automation_status") != "automated":
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

    if scope_type == "global":
        result = evaluate_global_rule(rule, parsed_config)
    else:
        result = evaluate_scoped_rule(rule, parsed_config, strictness)

    summary = build_result_summary(rule, result)

    return {
        "rule_id": rule["rule_id"],
        "title": rule["title"],
        "status": result["status"],
        "scope_type": scope_type,
        "automation_status": rule["automation_status"],
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

    for rule in normalized_doc.get("rules", []):
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