content = """Policy / Intent Compliance Assistant

Project overview

This project is a prototype compliance assistant for Cisco IOS configurations. Its purpose is to take a policy or intent PDF and a Cisco IOS configuration file, extract candidate compliance rules from the policy, normalize them into a structured form, run deterministic checks against the config, and generate an HTML report showing which controls appear to pass, fail, or still require review.

The current prototype is intentionally tuned for the CIS Cisco IOS benchmark and Cisco IOS style intent documents, rather than supporting arbitrary policy frameworks on the fly. The goal of the project is to demonstrate a practical workflow for semi automated compliance checking, not to claim universal policy support or final compliance certification.

A key design choice in this project is that the system uses two layers of judgment.

First, deterministic checking.
The software tries to make rule decisions using code based logic wherever possible.

Second, AI review.
Only items that the deterministic checker cannot confidently resolve are sent to a second AI pass, which produces an AI suggested judgment.

This means the AI is not replacing the checker. The AI is only being used as an advisory layer for ambiguous items.

What the software does

Given two inputs

Input 1
Policy or intent PDF

Input 2
Cisco IOS config TXT file

the software attempts to do the following.

Extract candidate compliance rules from the PDF using AI

Normalize those rules into a structured schema

Run deterministic checks on the config

Generate an HTML report with PASS, FAIL, and NEEDS HUMAN REVIEW

Send only the review only items to a second AI prompt

Generate a final report that clearly separates deterministic decisions, AI suggested decisions, and cases where human review may still be needed

Demo framing

This project should be presented as a prototype demo for Cisco IOS and CIS style policy checking, not as a production grade compliance certification tool.

A good way to describe the demo is this.

The tool is currently specialized for Cisco IOS.

It demonstrates a full pipeline from policy PDF and config file to structured compliance report.

It uses deterministic logic first, then AI suggestions only for unresolved cases.

It can show how a real config contains hardening issues and how a revised config can improve the report outcome.

Remaining FAIL and NEEDS HUMAN REVIEW items should be described as known prototype limitations and future work, not as proof that the software is fully complete.

A safe demo claim is the following.

This prototype demonstrates that policy text can be transformed into structured checks, applied to Cisco IOS configurations, and reported in a way that combines deterministic validation with AI assisted review for ambiguous items.

A claim to avoid is the following.

This tool automatically proves full compliance for any policy and any configuration.

File by file project flow

UserInterface.py

This is the main entry point and the user facing web app.

It is responsible for launching the Gradio interface, accepting the uploaded PDF and config file, reading environment variables and API settings, extracting text from the PDF, sending the PDF content to the AI for candidate rule extraction, calling the normalization stage, calling the deterministic checking stage, calling the second AI review stage for unresolved items, generating and saving the final report files, and presenting the outputs to the user in the UI.

Flow style description

User uploads PDF and config

PDF text is extracted

AI extracts candidate rules

normalize.py is called

checks_ios.py is called for deterministic evaluation

Review only items are sent to the second AI pass

Final HTML report is generated

Report is returned in the UI

You can think of UserInterface.py as the orchestrator of the entire pipeline.

normalize.py

This file is the rule cleaning and rule structuring layer.

The AI extraction step can return rules in a messy or inconsistent format. normalize.py takes those extracted rule objects and tries to convert them into a cleaner internal structure that the checker can actually use.

It is responsible for cleaning rule titles and text, standardizing rule IDs, inferring scope such as global, line vty, line console, line aux, or interface, converting extracted rule descriptions into structured fields like required patterns, forbidden patterns, check type, and human review flag, reducing duplicates, and making the rule set more consistent before checking.

Flow style description

Raw AI extracted rules

Clean titles, IDs, and text

Infer rule scope and check type

Build structured normalized rules

Send normalized rules to checker

You can think of normalize.py as the translator between AI output and deterministic checking logic.

checks_ios.py

This file is the deterministic compliance engine and report builder.

It receives the normalized rule set and the Cisco IOS config text, then evaluates the config against the rules.

It is responsible for parsing the config in a scope aware way, checking global commands, checking line con, line vty, and line aux blocks, evaluating whether required commands are present, evaluating whether forbidden commands are present, returning per rule outcomes such as PASS, FAIL, and NEEDS HUMAN REVIEW, collecting config evidence lines, building the structured results used in the final report, merging AI suggested judgments for unresolved items, and generating the final HTML report.

Flow style description

Normalized rules and Cisco IOS config

Deterministic config evaluation

Collect evidence and status per rule

Flag unresolved items

Merge second pass AI suggestions

Generate final HTML report

You can think of checks_ios.py as the judge and report writer for the config.

End to end pipeline summary

A simple way to visualize the whole project is this.

Policy PDF plus Cisco IOS config TXT

UserInterface.py

PDF text extraction

AI candidate rule extraction

normalize.py

Structured rules

checks_ios.py

Deterministic PASS, FAIL, and NEEDS HUMAN REVIEW

Second AI pass for unresolved items

Final HTML report

Why the project uses both deterministic logic and AI

The project is built this way because pure AI judgment is flexible, but not always transparent or repeatable. Pure deterministic checking is transparent, but only works well when rules are clearly scorable and well structured.

This prototype combines both approaches.

Deterministic logic is used for rules that can be safely checked with code.

AI suggestions are used for rules that remain ambiguous after the deterministic pass.

This gives the project a stronger demo story. It is not AI guessing compliance. It is AI assisted compliance analysis with deterministic checking first.

Current scope and limitations

This project is currently best understood as a Cisco IOS prototype with the following limits.

It is tuned for Cisco IOS and CIS style policy content.

It is not intended to switch cleanly across many unrelated policy frameworks in real time.

It may still produce duplicate controls, overly conservative review items, and false positives or false negatives on complex rules.

Some controls require deeper semantic understanding of the config than simple pattern matching can provide.

The second AI pass is advisory, not authoritative.

Because of that, the output should be described as a prototype compliance assessment report, not a final compliance certification.

How to describe the demo results

For the demo, the intended story is the following.

Start with a real Cisco IOS config taken from an example or GitHub style source.

Show that the tool identifies multiple hardening issues and review items.

Then show a revised demo config with many of those issues addressed.

Show that the report improves significantly.

Explain that remaining unresolved items reflect prototype limitations and future refinement work, especially in rules that are harder to evaluate deterministically.

This framing shows meaningful progress and a working system without overclaiming that the tool is already a finished compliance product.

Recommended README summary sentence

This project is a prototype Cisco IOS compliance assistant that uses AI to extract candidate rules from a policy PDF, normalizes them into structured checks, applies deterministic validation to a router configuration, and uses a second AI pass only for unresolved items to generate an explainable HTML compliance report.
"""

path = "/mnt/data/policy_intent_compliance_assistant_readme_text.txt"
with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print(path)
