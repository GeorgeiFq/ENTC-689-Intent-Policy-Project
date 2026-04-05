from dotenv import load_dotenv
load_dotenv("env.txt")   # or just load_dotenv() if you rename to .env
# ============================================================
# UserInterface.py
# Policy / Intent Compliance Assistant - Gradio UI Layer
# ============================================================
#
# PURPOSE
# -------
# This file provides the user-facing web interface for the semester
# project. It is responsible for collecting inputs, calling the
# backend pipeline, and returning the final compliance report to
# the user in a simple local web app.
#
# This file does NOT make the final compliance decision itself.
# Its role is orchestration and presentation.
#
# ARCHITECTURE ROLE
# -----------------
# This file is the UI/orchestrator layer only:
#
#   User uploads:
#     1) Policy / intent PDF
#     2) Device configuration TXT / CFG
#
#   Then this file:
#     - validates the inputs
#     - extracts text from the PDF
#     - calls the TAMU AI Chat API to extract candidate rules
#     - parses the AI output JSON
#     - sends the raw extracted rules into normalize.py
#     - sends the normalized rules and config text into checks_ios.py
#     - generates the final HTML report
#     - returns that report to Gradio for download/viewing
#
# HIGH-LEVEL FLOW
# ---------------
# 1) User launches the Gradio app locally.
# 2) User uploads a policy PDF and a config file.
# 3) User selects vendor mode and strictness mode.
# 4) User clicks "Run Compliance Check".
# 5) Gradio calls the submit() function in this file.
# 6) submit() runs the end-to-end pipeline:
#
#       PDF -> extracted text
#       extracted text -> TAMU AI rule extraction
#       AI rule JSON -> normalize_rules(...)
#       normalized rules + config -> evaluate_all_rules(...)
#       evaluation results -> build_html_report(...)
#
# 7) The final HTML report is saved to the run folder and returned
#    as a downloadable artifact in the UI.
#
# WHY THIS FILE EXISTS
# --------------------
# The semester project needs a simple, demo-friendly interface.
# Gradio is used because it allows a lightweight Python-only web app
# without requiring a separate frontend framework.
#
# This file makes the system usable by:
#   - instructors
#   - classmates
#   - project reviewers
# who may not want to run backend scripts manually.
#
# IMPORTANT DESIGN RULE
# ---------------------
# AI is NOT the final compliance judge.
#
# The AI is only used to read the benchmark/policy PDF and extract
# structured candidate rules in JSON form.
#
# The actual PASS / FAIL / NEEDS_HUMAN_REVIEW decision is made later
# by deterministic Python logic in checks_ios.py.
#
# That separation is one of the most important design principles
# in this project.
#
# TYPICAL INPUTS
# --------------
# - PDF:
#     CIS benchmark, NIST guidance, or similar policy/intent document
#
# - Config file:
#     Cisco IOS running-config text file (.txt / .cfg)
#
# - Vendor mode:
#     For the current MVP, the real supported path is Cisco IOS
#
# - Strictness:
#     Controls how ambiguous cases are scored
#       strict   -> FAIL
#       balanced -> NEEDS_HUMAN_REVIEW
#       lenient  -> PASS
#
# TYPICAL OUTPUTS
# ---------------
# - raw extracted rules JSON
# - normalized deterministic rules JSON
# - evaluation results JSON
# - final HTML compliance report
#
# RUN FOLDER CONTENTS
# -------------------
# Each execution can create a timestamped run folder containing:
#   - copied input files
#   - extracted PDF text
#   - raw LLM-extracted rules
#   - normalized rules
#   - evaluation results
#   - final HTML report
#   - optional debug/error files if something fails
#
# WHY DEBUG SAVING IS IMPORTANT
# -----------------------------
# This project has multiple stages:
#   PDF extraction
#   AI extraction
#   normalization
#   deterministic checking
#   report generation
#
# Saving intermediate artifacts makes it much easier to:
#   - debug failures
#   - inspect what the AI extracted
#   - show project progress
#   - explain the architecture during demos
#
# TAMU AI API ROLE
# ----------------
# This file communicates with the TAMU AI Chat API using:
#   - Bearer token authentication
#   - configured base URL from .env
#   - the protected.gpt-4.1 model
#
# The prompt asks the model to return structured JSON containing
# candidate compliance rules with fields such as:
#   - rule_id
#   - title
#   - requirement_text
#   - source_page
#   - source_section
#   - source_excerpt
#   - scope_hint
#   - check_type
#   - required_patterns
#   - forbidden_patterns
#   - needs_human_review
#
# The UI/orchestrator then passes that raw JSON into normalize.py.
#
# ERROR HANDLING
# --------------
# This file should be defensive because several things can fail:
#   - invalid uploads
#   - unreadable PDF
#   - bad API key or endpoint
#   - model returns malformed JSON
#   - normalization failure
#   - deterministic checker failure
#
# For that reason, this file should catch exceptions and write
# useful debug files to the run folder instead of only crashing.
#
# SUMMARY
# -------
# UserInterface.py is the entry point of the project.
# It connects the three major layers:
#
#   Gradio UI  ->  AI extraction  ->  deterministic checker
#
# It is not the policy engine and not the compliance judge.
# It is the pipeline coordinator and demo interface.
# ============================================================
import json
import os
import shutil
import threading
import webbrowser
from datetime import datetime
from pathlib import Path

import gradio as gr
import requests
from pypdf import PdfReader

from normalize import normalize_rules
from checks_ios import evaluate_all_rules, build_html_report


SUPPORTED_VENDOR = "Cisco IOS"
DEFAULT_MODEL = "protected.gpt-5.2"
RUNS_DIR = Path("runs")


# ------------------------------------------------------------
# Environment / file helpers
# ------------------------------------------------------------
def load_local_env(env_path: str = ".env"):
    """
    Lightweight .env loader so this file does not depend on python-dotenv.
    Existing environment variables are not overwritten.
    """
    path = Path(env_path)
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def read_text_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def extract_pdf_pages(pdf_path: str):
    """
    Returns a list of dicts:
      [{"page_number": 1, "text": "..."}, ...]
    """
    reader = PdfReader(pdf_path)
    pages = []

    for i, page in enumerate(reader.pages, start=1):
        text = (page.extract_text() or "").strip()
        if text:
            pages.append({
                "page_number": i,
                "text": text
            })

    return pages


def build_pdf_chunks(pages, max_chars: int = 12000):
    """
    Groups extracted PDF pages into moderately sized LLM chunks.
    """
    chunks = []
    current_pages = []
    current_text_parts = []
    current_len = 0

    for page in pages:
        block = f"\n\n--- PAGE {page['page_number']} ---\n{page['text']}"
        if current_pages and current_len + len(block) > max_chars:
            chunks.append({
                "start_page": current_pages[0],
                "end_page": current_pages[-1],
                "text": "".join(current_text_parts).strip()
            })
            current_pages = []
            current_text_parts = []
            current_len = 0

        current_pages.append(page["page_number"])
        current_text_parts.append(block)
        current_len += len(block)

    if current_pages:
        chunks.append({
            "start_page": current_pages[0],
            "end_page": current_pages[-1],
            "text": "".join(current_text_parts).strip()
        })

    return chunks


def strip_code_fences(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 2:
            lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()
    return text


def parse_json_from_model_text(text: str):
    cleaned = strip_code_fences(text)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return json.loads(cleaned[start:end + 1])

    raise ValueError("Model response did not contain valid JSON.")


def dedupe_rules(rules):
    out = []
    seen = set()

    for rule in rules:
        key = (
            str(rule.get("title", "")).strip().lower(),
            str(rule.get("requirement_text", "")).strip().lower(),
            tuple(x.strip().lower() for x in rule.get("required_patterns", []) if str(x).strip()),
            tuple(x.strip().lower() for x in rule.get("forbidden_patterns", []) if str(x).strip()),
            str(rule.get("scope_hint", "")).strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(rule)

    return out


# ------------------------------------------------------------
# TAMU AI extraction helpers
# ------------------------------------------------------------
def _preview_text(value, max_len: int = 500):
    text = str(value or "")
    text = text.replace(chr(13), " ").replace(chr(10), "\n")
    return text[:max_len]


def _extract_content_from_chat_response(data):
    if not isinstance(data, dict):
        raise RuntimeError(f"TAMU response root was not a JSON object: {type(data).__name__}")

    if isinstance(data.get("_assistant_text"), str) and data.get("_assistant_text").strip():
        return data["_assistant_text"]

    if data.get("error"):
        raise RuntimeError(f"TAMU API error payload: {data['error']}")

    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise RuntimeError(f"TAMU JSON did not contain choices[]. Keys: {list(data.keys())[:20]}")

    message = choices[0].get("message", {})
    content = message.get("content")

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        text_parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text_parts.append(item.get("text", ""))
        joined = "".join(text_parts).strip()
        if joined:
            return joined

    if isinstance(data.get("output_text"), str) and data.get("output_text").strip():
        return data["output_text"]

    raise RuntimeError(
        "TAMU JSON response was valid, but no assistant text content was found. "
        f"Top-level keys: {list(data.keys())[:20]}"
    )


def _extract_text_from_sse_body(body_text: str) -> str:
    """
    Parse text/event-stream chat chunk output and reconstruct assistant text
    from choices[*].delta.content fragments.
    """
    text_parts = []
    event_count = 0

    for raw_line in body_text.splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("data:"):
            continue

        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue

        event_count += 1

        try:
            event = json.loads(payload)
        except Exception:
            continue

        if isinstance(event, dict) and event.get("error"):
            raise RuntimeError(f"TAMU SSE error payload: {event['error']}")

        choices = event.get("choices", [])
        if not isinstance(choices, list):
            continue

        for choice in choices:
            if not isinstance(choice, dict):
                continue

            delta = choice.get("delta", {})
            if isinstance(delta, dict):
                content = delta.get("content")
                if isinstance(content, str):
                    text_parts.append(content)

            message = choice.get("message", {})
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    text_parts.append(content)

            content = choice.get("content")
            if isinstance(content, str):
                text_parts.append(content)

    joined = "".join(text_parts).strip()
    if joined:
        return joined

    raise RuntimeError(
        "TAMU returned text/event-stream, but no assistant content could be reconstructed. "
        f"Body preview: {_preview_text(body_text)} | Parsed events: {event_count}"
    )


def _post_tamu_chat(url: str, headers: dict, payload: dict):
    response = requests.post(url, headers=headers, json=payload, timeout=180)
    content_type = response.headers.get("content-type", "")
    body_text = response.text or ""

    if not response.ok:
        raise RuntimeError(
            f"TAMU HTTP error {response.status_code}. "
            f"Content-Type: {content_type or 'unknown'}. "
            f"Body preview: {_preview_text(body_text)}"
        )

    if not body_text.strip():
        raise RuntimeError(f"TAMU returned an empty HTTP body with status {response.status_code}.")

    lowered_type = content_type.lower()

    if "text/event-stream" in lowered_type or body_text.lstrip().startswith("data:"):
        return {
            "_transport": "sse",
            "_assistant_text": _extract_text_from_sse_body(body_text),
        }

    try:
        return response.json()
    except Exception as exc:
        raise RuntimeError(
            "TAMU returned a non-JSON HTTP body. "
            f"Content-Type: {content_type or 'unknown'}. "
            f"Body preview: {_preview_text(body_text)}"
        ) from exc


def call_tamu_chat(messages, model: str = DEFAULT_MODEL):
    load_local_env()

    api_key = os.getenv("TAMU_AI_API_KEY")
    base_url = (os.getenv("TAMU_AI_BASE_URL") or "https://chat-api.tamu.ai").rstrip("/")
    url = f"{base_url}/openai/chat/completions"

    if not api_key:
        raise RuntimeError("TAMU_AI_API_KEY is missing. Add it to your .env file.")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }

    payload = {
        "model": model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": messages,
    }

    try:
        data = _post_tamu_chat(url, headers, payload)
        return _extract_content_from_chat_response(data)
    except Exception as first_exc:
        fallback_payload = {
            "model": model,
            "temperature": 0,
            "messages": messages,
        }
        try:
            data = _post_tamu_chat(url, headers, fallback_payload)
            return _extract_content_from_chat_response(data)
        except Exception as second_exc:
            raise RuntimeError(
                "TAMU chat call failed in both modes. "
                f"First attempt error: {first_exc} | Fallback attempt error: {second_exc}"
            ) from second_exc

def make_extraction_messages(document_name: str, chunk_text: str, chunk_index: int, total_chunks: int):
    system_prompt = (
        "You extract deterministic Cisco IOS compliance rules from policy text. "
        "Return ONLY valid JSON. Do not include markdown or commentary. "
        "Only include rules grounded in the provided text. Do not invent commands. "
        "This JSON will be normalized and then checked by deterministic Python logic; "
        "the model is not the final compliance judge. Again RETURN ONLY VALID JSON"
    )

    user_prompt = f"""
Extract candidate compliance rules from this Cisco IOS policy chunk.

Document name: {document_name}
Chunk: {chunk_index} of {total_chunks}

Return exactly this JSON shape:
{{
  "rules": [
    {{
      "rule_id": "string",
      "title": "string",
      "requirement_text": "string",
      "source_page": 1,
      "source_section": "string",
      "source_excerpt": "string",
      "scope_hint": "global|line_vty|line_console|line_aux|unknown or pipe-delimited multi-scope",
      "check_type": "required|forbidden|required_and_forbidden|manual_review",
      "required_patterns": ["exact Cisco IOS command or regex-like pattern"],
      "forbidden_patterns": ["exact Cisco IOS command or regex-like pattern"],
      "needs_human_review": false,
      "vendor_scope": ["Cisco IOS"]
    }}
  ]
}}

Rules:
- Focus only on Cisco IOS-style checks that are realistically automatable for this MVP.
- If a requirement is ambiguous or not safely machine-checkable, set needs_human_review=true.
- Prefer exact IOS commands when the text clearly supports them.
- Use required_patterns for commands that must be present.
- Use forbidden_patterns for commands or states that must not be present.
- If the rule is purely manual/ambiguous, use check_type="manual_review" and leave pattern lists empty.
- source_page must be the actual page number shown in the provided chunk markers.
- source_excerpt must be short and grounded in the text.
- Do not duplicate near-identical rules inside one chunk.

Policy text chunk:
{chunk_text}
""".strip()

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def extract_rules_from_pdf_with_tamu(pdf_path: str, model: str = DEFAULT_MODEL):
    pages = extract_pdf_pages(pdf_path)
    if not pages:
        raise ValueError("No readable text was extracted from the PDF.")

    chunks = build_pdf_chunks(pages, max_chars=12000)
    all_rules = []
    raw_chunk_outputs = []
    document_name = Path(pdf_path).name

    for idx, chunk in enumerate(chunks, start=1):
        messages = make_extraction_messages(
            document_name=document_name,
            chunk_text=chunk["text"],
            chunk_index=idx,
            total_chunks=len(chunks),
        )
        content = call_tamu_chat(messages, model=model)
        parsed = parse_json_from_model_text(content)

        chunk_rules = parsed.get("rules", [])
        if not isinstance(chunk_rules, list):
            raise ValueError(f"Chunk {idx} returned invalid JSON: 'rules' must be a list.")

        raw_chunk_outputs.append({
            "chunk_index": idx,
            "page_range": [chunk["start_page"], chunk["end_page"]],
            "model_output": parsed,
        })
        all_rules.extend(chunk_rules)

    deduped_rules = dedupe_rules(all_rules)

    extracted_doc = {
        "document_name": document_name,
        "rules": deduped_rules,
    }

    return extracted_doc, raw_chunk_outputs, pages, chunks


# ------------------------------------------------------------
# submit() is the UI's real orchestration callback.
# ------------------------------------------------------------
def submit(intent_pdf_path: str, config_txt_path: str, vendor: str, strictness: str):
    if not intent_pdf_path or not config_txt_path:
        return (
            "❌ Please upload **both** the Policy/Intent PDF and the Config TXT before submitting.",
            gr.update(visible=False, value=None),
        )

    if vendor != SUPPORTED_VENDOR:
        return (
            "❌ This MVP is currently wired only for **Cisco IOS** inputs. "
            "Please select **Cisco IOS** and upload a Cisco IOS-style benchmark PDF and running-config file.",
            gr.update(visible=False, value=None),
        )

    try:
        now = datetime.now()
        run_stamp = now.strftime("%Y%m%d_%H%M%S")
        run_dir = RUNS_DIR / f"run_{run_stamp}"
        run_dir.mkdir(parents=True, exist_ok=True)

        pdf_name = os.path.basename(intent_pdf_path)
        cfg_name = os.path.basename(config_txt_path)

        shutil.copy2(intent_pdf_path, run_dir / pdf_name)
        shutil.copy2(config_txt_path, run_dir / cfg_name)

        extracted_doc, chunk_outputs, pages, chunks = extract_rules_from_pdf_with_tamu(intent_pdf_path)
        config_text = read_text_file(config_txt_path)
        normalized_doc = normalize_rules(extracted_doc)
        report = evaluate_all_rules(normalized_doc, config_text, strictness=strictness)
        html_report = build_html_report(report, config_name=cfg_name)

        (run_dir / "policy_text.txt").write_text(
            "\n\n".join(
                f"--- PAGE {p['page_number']} ---\n{p['text']}" for p in pages
            ),
            encoding="utf-8",
        )
        (run_dir / "chunk_debug.json").write_text(
            json.dumps({
                "document_name": extracted_doc["document_name"],
                "chunk_count": len(chunks),
                "chunks": chunks,
            }, indent=2),
            encoding="utf-8",
        )
        (run_dir / "extracted_rules_raw.json").write_text(
            json.dumps(extracted_doc, indent=2),
            encoding="utf-8",
        )
        (run_dir / "extraction_chunk_outputs.json").write_text(
            json.dumps(chunk_outputs, indent=2),
            encoding="utf-8",
        )
        (run_dir / "normalized_rules.json").write_text(
            json.dumps(normalized_doc, indent=2),
            encoding="utf-8",
        )
        (run_dir / "check_results.json").write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

        html_path = run_dir / "check_report.html"
        html_path.write_text(html_report, encoding="utf-8")

        try:
            webbrowser.open(html_path.resolve().as_uri())
        except Exception:
            pass

        norm_summary = normalized_doc.get("normalization_summary", {})
        md = f"""
### ✅ Compliance run complete

- **Policy / Intent (PDF):** `{pdf_name}`
- **Device Config (TXT/CFG):** `{cfg_name}`
- **Vendor Mode:** `{vendor}`
- **Strictness:** `{strictness}`
- **Run folder:** `{run_dir}`

### Extraction summary
- **PDF pages with readable text:** `{len(pages)}`
- **LLM extraction chunks:** `{len(chunks)}`
- **Extracted candidate rules:** `{len(extracted_doc.get('rules', []))}`
- **Normalized rules:** `{norm_summary.get('output_rule_count', 0)}`
- **Auto-evaluable rules:** `{norm_summary.get('automated_rule_count', 0)}`
- **Normalization review-only rules:** `{norm_summary.get('needs_human_review_count', 0)}`

### Check results
- **PASS:** `{report['pass_count']}`
- **FAIL:** `{report['fail_count']}`
- **NEEDS HUMAN REVIEW:** `{report['needs_human_review_count']}`
- **Total rules:** `{report['total_rules']}`

The downloadable artifact is the generated HTML report.
""".strip()

        return md, gr.update(visible=True, value=str(html_path))

    except Exception as exc:
        fail_dir = None
        try:
            RUNS_DIR.mkdir(parents=True, exist_ok=True)
            fail_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            fail_dir = RUNS_DIR / f"run_failed_{fail_stamp}"
            fail_dir.mkdir(parents=True, exist_ok=True)
            (fail_dir / "ui_error.txt").write_text(
                f"{type(exc).__name__}: {exc}\n",
                encoding="utf-8",
            )
        except Exception:
            pass

        extra = f"\n5. Inspect the saved debug folder: `{fail_dir}`" if fail_dir else ""
        err_md = f"""
### ❌ Run failed

**Error:** `{type(exc).__name__}: {exc}`

Check these first:
1. The PDF contains selectable text (not only scanned images).
2. `.env` contains a valid TAMU API key and base URL.
3. Required packages are installed: `gradio`, `requests`, `pypdf`.
4. You selected **Cisco IOS** as vendor mode.{extra}
""".strip()
        return err_md, gr.update(visible=False, value=None)


# ------------------------------------------------------------
# begin_shutdown() is called when the user clicks "Exit"
# ------------------------------------------------------------
def begin_shutdown():
    def _kill():
        os._exit(0)
    threading.Timer(0.9, _kill).start()
    return (
        gr.update(visible=False),
        gr.update(visible=True),
    )


# ------------------------------------------------------------
# Design tokens — Texas A&M maroon + clean light theme
# ------------------------------------------------------------
MAROON      = "#500000"
MAROON_DARK = "#3A0000"
MAROON_MID  = "#6B0000"
OFF_WHITE   = "#F5F3F0"
CARD_BG     = "#FFFFFF"
INPUT_BG    = "#FAFAFA"
BORDER      = "#E2DDD8"
BORDER_SOFT = "rgba(80,0,0,0.12)"
TEXT        = "#1A1A1A"
TEXT_MUTED  = "#5A5A5A"
ACCENT_BLUE = "#1D4E8F"


css = f"""
/* ── Google Fonts ─────────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Source+Serif+4:ital,opsz,wght@0,8..60,400;0,8..60,700;1,8..60,400&family=DM+Sans:wght@400;500;600;700&display=swap');

/* ── CSS custom-property overrides (kills Gradio dark mode) ── */
:root, .dark, [data-theme="dark"] {{
  --body-background-fill:         {OFF_WHITE} !important;
  --background-fill-primary:      {CARD_BG}   !important;
  --background-fill-secondary:    {INPUT_BG}  !important;
  --border-color-primary:         {BORDER}    !important;
  --border-color-accent:          {MAROON}    !important;
  --color-accent:                 {MAROON}    !important;
  --button-primary-background-fill:       {MAROON}      !important;
  --button-primary-background-fill-hover: {MAROON_DARK} !important;
  --button-primary-text-color:            #fff          !important;
  --input-background-fill:        {INPUT_BG}  !important;
  --panel-background-fill:        {CARD_BG}   !important;
  --block-background-fill:        {CARD_BG}   !important;
  --block-label-background-fill:  {CARD_BG}   !important;
  --block-label-text-color:       {TEXT_MUTED}!important;
  --body-text-color:              {TEXT}      !important;
  --body-text-color-subdued:      {TEXT_MUTED}!important;
  --prose-text-color:             {TEXT}      !important;
  --color-accent-soft:            rgba(80,0,0,0.08) !important;
  --shadow-drop:                  0 2px 12px rgba(0,0,0,0.06) !important;
  --shadow-drop-lg:               0 4px 24px rgba(0,0,0,0.10) !important;
}}

html, body {{
  background: {OFF_WHITE} !important;
  font-family: 'DM Sans', sans-serif !important;
  color: {TEXT} !important;
}}

.gradio-container {{
  background: {OFF_WHITE} !important;
  max-width: 1340px !important;
  margin: 0 auto !important;
  padding: 0 16px 32px !important;
  font-family: 'DM Sans', sans-serif !important;
}}

footer {{ display: none !important; }}

#topbar {{
  background: linear-gradient(135deg, {MAROON} 0%, {MAROON_MID} 60%, {MAROON_DARK} 100%);
  border-radius: 18px;
  padding: 20px 24px;
  margin: 16px 0 18px;
  box-shadow: 0 4px 20px rgba(80,0,0,0.30), 0 1px 0 rgba(255,255,255,0.08) inset;
  position: relative;
  overflow: hidden;
}}
#topbar > div,
#topbar > div > div,
#topbar .gap,
#topbar .block,
#topbar .svelte-1tcem6n,
#topbar [class*="wrap"],
#topbar [class*="col"],
#topbar [class*="row"] {{
  background: transparent !important;
  border: none !important;
  box-shadow: none !important;
  color: #fff !important;
}}
#topbar::after {{
  content: '';
  position: absolute;
  inset: 0;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.04'/%3E%3C/svg%3E");
  pointer-events: none;
  border-radius: 18px;
}}
#topbar h1 {{
  margin: 0;
  font-family: 'Source Serif 4', serif !important;
  font-size: 1.55rem;
  font-weight: 700;
  color: #fff;
  letter-spacing: -0.01em;
  line-height: 1.15;
}}
#topbar p {{
  margin: 7px 0 0;
  color: rgba(255,255,255,0.82);
  font-size: 0.93rem;
  font-family: 'DM Sans', sans-serif;
  font-weight: 400;
}}

#exitbtn button {{
  background: rgba(255,255,255,0.12) !important;
  color: #fff !important;
  border: 1px solid rgba(255,255,255,0.35) !important;
  border-radius: 10px !important;
  font-family: 'DM Sans', sans-serif !important;
  font-weight: 600 !important;
  font-size: 0.88rem !important;
  padding: 8px 20px !important;
  letter-spacing: 0.02em;
  backdrop-filter: blur(4px);
  transition: background 0.18s, border-color 0.18s;
}}
#exitbtn button:hover {{
  background: rgba(255,255,255,0.22) !important;
  border-color: rgba(255,255,255,0.60) !important;
}}

.card {{
  background: {CARD_BG} !important;
  border-radius: 18px !important;
  border: 1px solid {BORDER} !important;
  padding: 22px !important;
  box-shadow: 0 2px 12px rgba(0,0,0,0.05) !important;
}}

.card-title {{
  font-family: 'Source Serif 4', serif;
  font-size: 1.10rem;
  font-weight: 700;
  color: {MAROON_DARK};
  margin: 0 0 16px 0;
  padding-bottom: 10px;
  border-bottom: 2px solid {MAROON};
  letter-spacing: -0.01em;
}}

.helpbox {{
  background: #FDFCFB;
  border: 1px solid {BORDER};
  border-left: 4px solid {MAROON};
  border-radius: 12px;
  padding: 11px 14px;
  font-family: 'DM Sans', sans-serif;
  font-size: 0.89rem;
  line-height: 1.5;
  color: {TEXT};
  height: 100%;
  box-sizing: border-box;
}}
.helpbox strong {{
  color: {MAROON_DARK};
  font-weight: 700;
  display: block;
  margin-bottom: 3px;
}}
.helpbox .muted {{
  color: {TEXT_MUTED};
}}

.upload-container,
[data-testid="file"] .upload-container,
.svelte-file-uploader,
.file-uploader,
.file-preview,
[class*="upload"],
div[data-testid="file"],
div[data-testid="file"] > div,
div[data-testid="file"] > div > div {{
  background: {INPUT_BG} !important;
  color: {TEXT} !important;
}}
.file-drop-zone,
[class*="file-drop"],
.upload-container > label,
[data-testid="file"] label,
[data-testid="file"] .file-preview-holder {{
  background: {INPUT_BG} !important;
  color: {TEXT} !important;
  border: 1.5px dashed {BORDER_SOFT} !important;
  border-radius: 14px !important;
}}
.block.svelte-1tcem6n,
.wrap.svelte-1tcem6n {{
  background: {INPUT_BG} !important;
}}
[data-testid="file"] * {{
  background-color: transparent !important;
  color: {TEXT} !important;
}}
[data-testid="file"] .upload-container {{
  background: {INPUT_BG} !important;
  border: 1.5px dashed rgba(80,0,0,0.25) !important;
  border-radius: 14px !important;
  min-height: 120px !important;
  transition: border-color 0.2s, background 0.2s;
}}
[data-testid="file"] .upload-container:hover {{
  border-color: {MAROON} !important;
  background: rgba(80,0,0,0.025) !important;
}}
[data-testid="file"] svg {{
  color: {MAROON} !important;
  fill: none !important;
  stroke: {MAROON} !important;
}}
[data-testid="file"] .upload-container span,
[data-testid="file"] .upload-container p {{
  color: {TEXT_MUTED} !important;
  font-family: 'DM Sans', sans-serif !important;
  font-size: 0.90rem !important;
}}
.block, .panel, .gap {{
  background: {CARD_BG} !important;
}}
.block.padded {{
  background: {CARD_BG} !important;
}}

.accordion,
details,
details > summary {{
  background: {INPUT_BG} !important;
  color: {TEXT} !important;
  border-radius: 12px !important;
  border: 1px solid {BORDER} !important;
}}
details > summary {{
  font-family: 'DM Sans', sans-serif !important;
  font-weight: 600 !important;
  font-size: 0.93rem !important;
  color: {TEXT} !important;
  padding: 10px 14px !important;
  cursor: pointer;
}}
details[open] > summary {{
  border-bottom: 1px solid {BORDER} !important;
  border-radius: 12px 12px 0 0 !important;
}}
details > div {{
  background: {INPUT_BG} !important;
  padding: 14px !important;
}}

select, .gr-dropdown, [data-testid="dropdown"] {{
  background: {INPUT_BG} !important;
  color: {TEXT} !important;
  border: 1px solid {BORDER} !important;
  border-radius: 10px !important;
  font-family: 'DM Sans', sans-serif !important;
}}

.gr-radio label, .radio-group label {{
  color: {TEXT} !important;
  font-family: 'DM Sans', sans-serif !important;
}}

#runbtn button,
button.primary,
.gr-button-primary {{
  background: linear-gradient(135deg, {MAROON} 0%, {MAROON_DARK} 100%) !important;
  border: none !important;
  border-radius: 12px !important;
  font-family: 'DM Sans', sans-serif !important;
  font-weight: 700 !important;
  font-size: 0.97rem !important;
  letter-spacing: 0.02em;
  color: #fff !important;
  padding: 12px 0 !important;
  box-shadow: 0 3px 12px rgba(80,0,0,0.30) !important;
  transition: transform 0.15s, box-shadow 0.15s !important;
}}
#runbtn button:hover,
button.primary:hover {{
  transform: translateY(-1px) !important;
  box-shadow: 0 6px 20px rgba(80,0,0,0.35) !important;
  background: linear-gradient(135deg, {MAROON_MID} 0%, {MAROON} 100%) !important;
}}
#runbtn button:active {{
  transform: translateY(0) !important;
}}

.gr-download button,
[data-testid="download-btn"] button {{
  background: {INPUT_BG} !important;
  color: {MAROON} !important;
  border: 1.5px solid {MAROON} !important;
  border-radius: 10px !important;
  font-family: 'DM Sans', sans-serif !important;
  font-weight: 600 !important;
}}
.gr-download button:hover {{
  background: rgba(80,0,0,0.06) !important;
}}

#statusbox {{
  background: {INPUT_BG};
  border: 1px solid {BORDER};
  border-radius: 14px;
  padding: 16px 18px;
  min-height: 160px;
  font-family: 'DM Sans', sans-serif;
}}
#statusbox p, #statusbox li, #statusbox span {{
  color: {TEXT} !important;
  font-family: 'DM Sans', sans-serif !important;
}}
#statusbox code {{
  background: rgba(80,0,0,0.07) !important;
  color: {MAROON_DARK} !important;
  padding: 2px 6px;
  border-radius: 5px;
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.85em;
}}
#statusbox h3 {{
  font-family: 'Source Serif 4', serif !important;
  color: {MAROON_DARK} !important;
  font-size: 1.05rem;
  margin-top: 0;
}}

.input-row {{
  margin-bottom: 16px;
}}

#shutdown-wrap {{
  background: {CARD_BG};
  border: 1px solid {BORDER};
  border-radius: 18px;
  padding: 40px 32px;
  text-align: center;
  box-shadow: 0 2px 12px rgba(0,0,0,0.06);
}}
#shutdown-wrap h2 {{
  font-family: 'Source Serif 4', serif;
  color: {MAROON};
  font-size: 1.5rem;
  margin: 0 0 8px 0;
}}
#shutdown-wrap p {{
  color: {TEXT_MUTED};
  font-family: 'DM Sans', sans-serif;
  font-size: 0.95rem;
  margin: 6px 0;
}}

label span, .block-title, .label-wrap {{
  color: {TEXT} !important;
  font-family: 'DM Sans', sans-serif !important;
  font-weight: 600 !important;
}}

:not(#topbar):not(#topbar *) {{
  --background-fill-primary: {CARD_BG} !important;
}}
"""


theme = gr.themes.Base(
    primary_hue=gr.themes.Color(
        c50="#fdf2f2", c100="#fce8e8", c200="#f9d0d0", c300="#f5a8a8",
        c400="#ed7070", c500="#c53030", c600="#500000", c700="#3A0000",
        c800="#2c0000", c900="#1e0000", c950="#140000",
    ),
    font=[gr.themes.GoogleFont("DM Sans"), "sans-serif"],
    font_mono=[gr.themes.GoogleFont("IBM Plex Mono"), "monospace"],
)

with gr.Blocks(title="Policy Intent Compliance Assistant", theme=theme, css=css) as demo:
    with gr.Row(elem_id="topbar"):
        with gr.Column(scale=8):
            gr.HTML("""
                <h1>Policy Intent Compliance Assistant</h1>
                <p>Upload a policy/intent PDF and a device configuration file — get a PASS/FAIL/NEEDS REVIEW compliance report with evidence.</p>
            """)
        with gr.Column(scale=2, min_width=130):
            exit_btn = gr.Button("⏻  Exit", elem_id="exitbtn")

    with gr.Column(visible=True) as main_ui:
        with gr.Row(equal_height=True):
            with gr.Column(scale=6, elem_classes=["card"]):
                gr.HTML('<div class="card-title">📂 Inputs</div>')

                with gr.Row(elem_classes=["input-row"]):
                    with gr.Column(scale=6):
                        intent_pdf = gr.File(
                            label="Policy / Intent Document (PDF)",
                            file_types=[".pdf"],
                            type="filepath",
                        )
                    with gr.Column(scale=6):
                        gr.HTML("""
                            <div class="helpbox">
                              <strong>📄 Policy PDF</strong>
                              Source-of-truth document (CIS Benchmarks, NIST, etc.).<br/>
                              <span class="muted">The AI layer extracts structured, testable compliance rules from this PDF before any checking occurs.</span>
                            </div>
                        """)

                with gr.Row(elem_classes=["input-row"]):
                    with gr.Column(scale=6):
                        config_txt = gr.File(
                            label="Device Configuration (TXT / CFG)",
                            file_types=[".txt", ".cfg"],
                            type="filepath",
                        )
                    with gr.Column(scale=6):
                        gr.HTML("""
                            <div class="helpbox">
                              <strong>⚙️ Device Config</strong>
                              Running-config or equivalent exported from the device.<br/>
                              <span class="muted">The backend runs deterministic regex / TextFSM checks — the LLM never decides PASS or FAIL.</span>
                            </div>
                        """)

                with gr.Accordion("⚙️  Settings", open=False):
                    with gr.Row():
                        with gr.Column(scale=6):
                            vendor = gr.Dropdown(
                                ["Cisco IOS", "NX-OS", "JunOS", "Other"],
                                value="Cisco IOS",
                                label="Vendor / Parser Mode",
                            )
                        with gr.Column(scale=6):
                            gr.HTML("""
                                <div class="helpbox">
                                  <strong>Vendor Mode</strong>
                                  Selects the config parser and syntax rules that match your device's output format.
                                </div>
                            """)
                    with gr.Row():
                        with gr.Column(scale=6):
                            strictness = gr.Radio(
                                ["Strict", "Balanced", "Lenient"],
                                value="Balanced",
                                label="Check Strictness",
                            )
                        with gr.Column(scale=6):
                            gr.HTML("""
                                <div class="helpbox">
                                  <strong>Strictness</strong>
                                  Controls scoring of missing or ambiguous items:<br/>
                                  <span class="muted"><b>Strict</b> → FAIL &nbsp;|&nbsp; <b>Balanced</b> → NEEDS REVIEW &nbsp;|&nbsp; <b>Lenient</b> → PASS</span>
                                </div>
                            """)

                run_btn = gr.Button(
                    "▶  Run Compliance Check",
                    variant="primary",
                    elem_id="runbtn",
                )

            with gr.Column(scale=6, elem_classes=["card"]):
                gr.HTML('<div class="card-title">📊 Outputs</div>')

                status_md = gr.Markdown(
                    "Waiting for inputs…",
                    elem_id="statusbox",
                )

                download_btn = gr.DownloadButton(
                    label="⬇  Download Report",
                    value=None,
                    visible=False,
                    variant="primary",
                )

                gr.HTML("""
                    <div class="helpbox" style="margin-top:14px;">
                      <strong>📦 Artifacts</strong>
                      Download the generated HTML report after each run.<br/>
                      <span class="muted">The app also saves extracted rules, normalized rules, and JSON check results in a timestamped <code>runs/</code> folder.</span>
                    </div>
                """)

    with gr.Column(visible=False) as shutdown_ui:
        gr.HTML("""
            <div id="shutdown-wrap">
              <h2>Shutting down…</h2>
              <p>The local server is stopping. You can safely close this browser tab.</p>
              <p style="margin-top:8px;">If you briefly see "connection lost", that's expected — the server has closed.</p>
            </div>
        """)

    run_btn.click(
        fn=submit,
        inputs=[intent_pdf, config_txt, vendor, strictness],
        outputs=[status_md, download_btn],
    )

    exit_btn.click(
        fn=begin_shutdown,
        inputs=None,
        outputs=[main_ui, shutdown_ui],
    )


if __name__ == "__main__":
    RUNS_DIR.mkdir(exist_ok=True)
    demo.queue()
    demo.launch(inbrowser=True)
