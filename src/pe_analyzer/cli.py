from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pe import PEFormatError, analyze_pe
from .report import render_html, render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pe-analyze",
        description="Inspect Windows PE metadata without executing the input.",
    )
    parser.add_argument("input", type=Path, help="path to a Windows PE file")
    parser.add_argument(
        "--format",
        choices=("text", "json", "html"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument("--output", type=Path, help="write the report to this path instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.output is not None and (
            args.input.resolve() == args.output.resolve()
            or (args.output.exists() and args.input.samefile(args.output))
        ):
            parser.error("output path must not overwrite the input file")
        report = analyze_pe(args.input)
        renderers = {"text": render_text, "json": render_json, "html": render_html}
        output = renderers[args.format](report)
        if args.output is None:
            sys.stdout.write(output)
        else:
            args.output.write_text(output, encoding="utf-8")
    except (OSError, PEFormatError) as error:
        parser.exit(2, f"{parser.prog}: error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
