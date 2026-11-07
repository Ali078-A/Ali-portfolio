from __future__ import annotations

import html
import json
from typing import Any


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def render_text(report: dict[str, Any]) -> str:
    headers = report["headers"]
    lines = [
        f"File: {report['file']['path']}",
        f"SHA-256: {report['file']['sha256']}",
        f"Format: {headers['bitness']}-bit {headers['machine']}",
        f"Entry point RVA: {headers['entry_point_rva']}",
        f"Sections: {headers['section_count']}",
        f"Mitigations: ASLR={'on' if report['mitigations']['aslr'] else 'off'}, "
        f"DEP={'on' if report['mitigations']['dep'] else 'off'}, "
        f"CFG={'on' if report['mitigations']['cfg'] else 'off'}",
        "",
        "Sections:",
    ]
    for section in report["sections"]:
        perms = "".join(letter for name, letter in (("read", "R"), ("write", "W"), ("execute", "X"))
                        if name in section["permissions"])
        lines.append(
            f"  {section['name'] or '(unnamed)':<8} RVA 0x{section['virtual_address']:08x}  "
            f"raw {section['raw_size']:>8} bytes  {perms or '-'}"
        )
    lines.extend(["", "Imports:"])
    if report["imports"]:
        for library in report["imports"]:
            symbols = [
                symbol["name"] if symbol["kind"] == "name" else f"ordinal #{symbol['ordinal']}"
                for symbol in library["symbols"]
            ]
            rendered_symbols = ", ".join(symbols) if symbols else "(no symbols)"
            lines.append(f"  {library['dll']}: {rendered_symbols}")
    else:
        lines.append("  (none found)")
    lines.extend(["", "Potential findings:"])
    if report["findings"]:
        for finding in report["findings"]:
            lines.append(
                f"  [{finding['severity'].upper()}] {finding['title']} "
                f"(confidence: {finding['confidence']})"
            )
            lines.append(f"    Evidence: {finding['evidence']}")
    else:
        lines.append("  None from the checks performed.")
    lines.extend(["", "Scope: static metadata only; this report does not determine exploitability or intent."])
    return "\n".join(lines) + "\n"


def render_html(report: dict[str, Any]) -> str:
    safe_json = html.escape(json.dumps(report, indent=2, sort_keys=True))
    title = html.escape(report["file"]["path"])
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>PE analysis: {title}</title>"
        "<style>body{font:16px system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f4;padding:1rem}"
        "h1{font-size:1.5rem}</style></head><body>"
        f"<h1>Static PE analysis: {title}</h1>"
        "<p>Read-only static metadata report. The input was not executed.</p>"
        f"<pre>{safe_json}</pre></body></html>\n"
    )
