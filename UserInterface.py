# UserInterface.py
#
# ============================================================
# Policy Intent Compliance Assistant (Gradio UI)
# ============================================================
#
# PROJECT CONTEXT (big picture)
# -----------------------------
# This semester project builds a "Compliance Assistant" for network devices:
#
#   Inputs:
#     1) A policy/intent document (PDF) — e.g., CIS Benchmarks / NIST guidance
#     2) A device configuration file (TXT/CFG) — e.g., Cisco IOS running-config
#
#   Goal:
#     - Extract testable compliance rules from the policy PDF using an AI model.
#     - Run deterministic, explainable checks against the config text.
#       (IMPORTANT: The AI does NOT decide PASS/FAIL. It only produces structured rules.)
#     - Produce a report with PASS/FAIL/NEEDS_REVIEW per rule, including exact evidence lines.
#
# TEAM DIVISION (how this file fits)
# ---------------------------------
#  - You (this file): Build the web UI in Gradio
#       * upload PDF + config
#       * let the user set options
#       * trigger the pipeline
#       * display results + provide downloadable artifacts
#
#  - Backend teammate: Deterministic parsing + checks + report generator
#       * parse config file format (Cisco IOS / NX-OS / JunOS / etc.)
#       * run checks (regex / CiscoConfParse / TextFSM / etc.)
#       * generate report artifacts (HTML/MD) + JSON results
#
#  - AI teammate: Policy-to-rules extraction layer
#       * read policy text (PDF extraction)
#       * call LLM to produce structured rules (schema-validated JSON)
#
# HOW THE UI WORKS (runtime flow)
# ------------------------------
# 1) User opens the local Gradio webpage (served by this Python process).
# 2) User uploads policy PDF + config TXT and selects settings.
# 3) User clicks "Run Compliance Check".
# 4) Gradio calls a Python callback function (submit()) with file paths + settings.
# 5) In the final version, submit() will call the orchestrator pipeline:
#
#        rules = ai.extract_rules_from_pdf(pdf_path)
#        cfg   = backend.parse_config(cfg_path, vendor=...)
#        res   = backend.run_checks(cfg, rules, strictness=...)
#        report_paths = backend.build_report(res)
#        return report preview + downloadable artifacts
#
# For now, this UI includes a stub submit() to prove the wiring and downloads work.
#
# EXIT BUTTON BEHAVIOR
# --------------------
# This app runs as a local server process. The user typically stops it with Ctrl+C
# in the terminal. To make it easier for non-technical users, we provide an "Exit"
# button that shows a shutdown screen and then terminates the server process.
#
# ============================================================

import os
import threading
from datetime import datetime
import gradio as gr


# ------------------------------------------------------------
# submit() is the UI's "Run" callback.
#
# Today: stub behavior (no real AI or backend integration)
# Final: will call your pipeline module and return real artifacts
# ------------------------------------------------------------
def submit(intent_pdf_path: str, config_txt_path: str, vendor: str, strictness: str):
    """
    This function is invoked when the user clicks 'Run Compliance Check'.

    Inputs come from Gradio components:
      - intent_pdf_path: local temp path to uploaded PDF
      - config_txt_path: local temp path to uploaded config file
      - vendor: dropdown selection (used by backend parser/checkers)
      - strictness: scoring preference for ambiguous/missing items

    Outputs returned to Gradio:
      - status markdown to display in the Outputs panel
      - a downloadable file (stub now; report artifact later)
    """

    # Basic validation: don't run the pipeline without both required files
    if not intent_pdf_path or not config_txt_path:
        return (
            "❌ Please upload **both** the Policy/Intent PDF and the Config TXT before submitting.",
            gr.update(visible=False, value=None),
        )

    # In a real pipeline, these file paths get passed to downstream modules
    pdf_name = os.path.basename(intent_pdf_path)
    cfg_name = os.path.basename(config_txt_path)

    # This is what you'll display after the pipeline runs.
    # Later, you will replace this with:
    #   - pass/fail counts
    #   - severity breakdown
    #   - links to real report artifacts (HTML/JSON)
    md = f"""
### ✅ Run created

- **Policy / Intent (PDF):** `{pdf_name}`
- **Device Config (TXT/CFG):** `{cfg_name}`
- **Vendor Mode:** `{vendor}`
- **Strictness:** `{strictness}`

**Next (when backend is connected):**
1. Extract structured rules from policy (LLM)
2. Run deterministic checks on config
3. Generate PASS/FAIL/REVIEW report with evidence
""".strip()

    # Stub artifact to prove downloads work.
    out_name = f"run_stub_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(out_name, "w", encoding="utf-8") as f:
        f.write("Compliance Assistant (UI Wiring Test)\n\n")
        f.write(f"Policy PDF: {pdf_name}\n")
        f.write(f"Config TXT: {cfg_name}\n")
        f.write(f"Vendor: {vendor}\n")
        f.write(f"Strictness: {strictness}\n")

    return md, gr.update(visible=True, value=out_name)


# ------------------------------------------------------------
# begin_shutdown() is called when the user clicks "Exit"
# ------------------------------------------------------------
def begin_shutdown():
    def _kill():
        os._exit(0)
    threading.Timer(0.9, _kill).start()
    return (
        gr.update(visible=False),  # main_ui
        gr.update(visible=True),   # shutdown_ui
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
ACCENT_BLUE = "#1D4E8F"   # small accent for contrast (TAMU secondary)


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

/* ── Base ───────────────────────────────────────────────── */
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

/* ── Top header bar ─────────────────────────────────────── */
#topbar {{
  background: linear-gradient(135deg, {MAROON} 0%, {MAROON_MID} 60%, {MAROON_DARK} 100%);
  border-radius: 18px;
  padding: 20px 24px;
  margin: 16px 0 18px;
  box-shadow: 0 4px 20px rgba(80,0,0,0.30), 0 1px 0 rgba(255,255,255,0.08) inset;
  position: relative;
  overflow: hidden;
}}
/* Force all children of topbar to inherit the maroon bg */
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

/* subtle grain texture on header */
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

/* ── Exit button ─────────────────────────────────────────── */
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

/* ── Cards ───────────────────────────────────────────────── */
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

/* ── Help / hint boxes ───────────────────────────────────── */
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

/* ── File upload dropzones — force light ─────────────────── */
/* Target all possible Gradio upload-area elements */
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

/* The dashed drop area */
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

/* Gradio 4/5 upload component internals */
.block.svelte-1tcem6n,
.wrap.svelte-1tcem6n {{
  background: {INPUT_BG} !important;
}}

/* Override any dark-themed child elements in file widgets */
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

/* Upload icon color */
[data-testid="file"] svg {{
  color: {MAROON} !important;
  fill: none !important;
  stroke: {MAROON} !important;
}}

/* "Drop File Here" text */
[data-testid="file"] .upload-container span,
[data-testid="file"] .upload-container p {{
  color: {TEXT_MUTED} !important;
  font-family: 'DM Sans', sans-serif !important;
  font-size: 0.90rem !important;
}}

/* Gradio block backgrounds (panels, etc.) */
.block, .panel, .gap {{
  background: {CARD_BG} !important;
}}
.block.padded {{
  background: {CARD_BG} !important;
}}

/* ── Accordion / Settings ────────────────────────────────── */
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

/* ── Dropdown ────────────────────────────────────────────── */
select, .gr-dropdown, [data-testid="dropdown"] {{
  background: {INPUT_BG} !important;
  color: {TEXT} !important;
  border: 1px solid {BORDER} !important;
  border-radius: 10px !important;
  font-family: 'DM Sans', sans-serif !important;
}}

/* ── Radio buttons ───────────────────────────────────────── */
.gr-radio label, .radio-group label {{
  color: {TEXT} !important;
  font-family: 'DM Sans', sans-serif !important;
}}

/* ── Run Compliance Check button ─────────────────────────── */
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

/* ── Download button ─────────────────────────────────────── */
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

/* ── Status / output markdown box ────────────────────────── */
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

/* ── Section dividers between file+helpbox rows ──────────── */
.input-row {{
  margin-bottom: 16px;
}}

/* ── Shutdown screen ─────────────────────────────────────── */
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

/* ── Generic label & block title overrides ───────────────── */
label span, .block-title, .label-wrap {{
  color: {TEXT} !important;
  font-family: 'DM Sans', sans-serif !important;
  font-weight: 600 !important;
}}

/* Ensure nothing is dark-mode tinted — but NOT inside topbar */
:not(#topbar):not(#topbar *) {{
  --background-fill-primary: {CARD_BG} !important;
}}
"""


# ------------------------------------------------------------
# Build the Gradio layout
# NOTE: In Gradio 4+, pass theme + css to gr.Blocks(), not launch()
# ------------------------------------------------------------
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

    # ── Header ────────────────────────────────────────────────
    with gr.Row(elem_id="topbar"):
        with gr.Column(scale=8):
            gr.HTML("""
                <h1>Policy Intent Compliance Assistant</h1>
                <p>Upload a policy/intent PDF and a device configuration file — get a PASS/FAIL/NEEDS REVIEW compliance report with evidence.</p>
            """)
        with gr.Column(scale=2, min_width=130):
            exit_btn = gr.Button("⏻  Exit", elem_id="exitbtn")

    # ── Main app view ──────────────────────────────────────────
    with gr.Column(visible=True) as main_ui:
        with gr.Row(equal_height=True):

            # ── LEFT: Inputs card ──────────────────────────────
            with gr.Column(scale=6, elem_classes=["card"]):
                gr.HTML('<div class="card-title">📂 Inputs</div>')

                # Policy PDF
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

                # Config TXT
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

                # Settings accordion
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

            # ── RIGHT: Outputs card ────────────────────────────
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
                      Download the generated report after each run.<br/>
                      <span class="muted">Stub .txt now — full HTML + JSON evidence report once the backend is connected.</span>
                    </div>
                """)

    # ── Shutdown view ──────────────────────────────────────────
    with gr.Column(visible=False) as shutdown_ui:
        gr.HTML("""
            <div id="shutdown-wrap">
              <h2>Shutting down…</h2>
              <p>The local server is stopping. You can safely close this browser tab.</p>
              <p style="margin-top:8px;">If you briefly see "connection lost", that's expected — the server has closed.</p>
            </div>
        """)

    # ── Event wiring ───────────────────────────────────────────
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


# ------------------------------------------------------------
# Launch
# ------------------------------------------------------------
if __name__ == "__main__":
    demo.queue()
    demo.launch(inbrowser=True)
