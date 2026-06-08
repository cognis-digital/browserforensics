"""Command-line interface for BROWSERFORENSICS.

Subcommands:
  scan   Analyze exported history and/or downloads for IOCs / exfil signs.

Output formats: table (default), json (pipelines), html (shareable report).
Exit code is non-zero when findings are present or on failure.
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Finding, Severity, analyze, summarize

_SEV_COLOR = {
    "critical": "#7c1d1d",
    "high": "#b91c1c",
    "medium": "#c2410c",
    "low": "#a16207",
    "info": "#1d4ed8",
}
_SEV_BG = {
    "critical": "#fee2e2",
    "high": "#fee2e2",
    "medium": "#ffedd5",
    "low": "#fef9c3",
    "info": "#dbeafe",
}


def _render_table(findings: List[Finding]) -> str:
    counts = summarize(findings)
    lines: List[str] = []
    lines.append(f"{TOOL_NAME} {TOOL_VERSION} - browser DFIR triage")
    lines.append("=" * 60)
    lines.append(
        "Summary: {total} finding(s)  "
        "CRIT={critical} HIGH={high} MED={medium} LOW={low} INFO={info}".format(**counts)
    )
    lines.append("-" * 60)
    if not findings:
        lines.append("No indicators detected.")
        return "\n".join(lines)
    for i, f in enumerate(findings, 1):
        lines.append(f"[{i}] {f.severity.upper():8} {f.title}")
        lines.append(f"     rule    : {f.rule}  ({f.artifact})")
        if f.indicator:
            lines.append(f"     indicator: {f.indicator}")
        lines.append(f"     detail  : {f.detail}")
    return "\n".join(lines)


def _render_json(findings: List[Finding]) -> str:
    doc = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2, default=str)


def _render_html(findings: List[Finding]) -> str:
    counts = summarize(findings)
    esc = html.escape
    rows = []
    for i, f in enumerate(findings, 1):
        color = _SEV_COLOR.get(f.severity, "#374151")
        bg = _SEV_BG.get(f.severity, "#f3f4f6")
        rows.append(f"""
      <tr style="background:{bg}">
        <td class="num">{i}</td>
        <td><span class="badge" style="background:{color}">{esc(f.severity.upper())}</span></td>
        <td><strong>{esc(f.title)}</strong><div class="detail">{esc(f.detail)}</div></td>
        <td><code>{esc(f.rule)}</code><div class="meta">{esc(f.artifact)}</div></td>
        <td><code>{esc(f.indicator)}</code></td>
      </tr>""")
    if not rows:
        rows.append('<tr><td colspan="5" class="empty">No indicators detected.</td></tr>')

    chips = "".join(
        f'<span class="chip" style="background:{_SEV_BG.get(s,"#eee")};color:{_SEV_COLOR.get(s,"#333")}">'
        f'{s.upper()}: {counts.get(s,0)}</span>'
        for s in ("critical", "high", "medium", "low", "info")
    )
    gen = datetime.now().isoformat(timespec="seconds")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL_NAME} report</title>
<style>
  *{{box-sizing:border-box}}
  body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
    margin:0;background:#0f172a;color:#0f172a}}
  .wrap{{max-width:1000px;margin:0 auto;padding:24px}}
  header{{background:#111827;color:#f9fafb;padding:20px 24px;border-radius:10px}}
  header h1{{margin:0;font-size:20px}}
  header .sub{{color:#9ca3af;font-size:13px;margin-top:4px}}
  .chips{{margin:16px 0}}
  .chip{{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;
    font-weight:600;margin-right:8px}}
  table{{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;
    overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.2)}}
  th{{text-align:left;background:#1f2937;color:#f9fafb;padding:10px 12px;font-size:12px;
    text-transform:uppercase;letter-spacing:.04em}}
  td{{padding:10px 12px;border-top:1px solid #e5e7eb;font-size:14px;vertical-align:top}}
  td.num{{color:#6b7280;font-variant-numeric:tabular-nums}}
  .badge{{color:#fff;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:700}}
  .detail{{color:#374151;font-size:13px;margin-top:4px}}
  .meta{{color:#6b7280;font-size:11px;margin-top:2px}}
  code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
    word-break:break-all}}
  .empty{{text-align:center;color:#6b7280;padding:24px}}
  footer{{color:#94a3b8;font-size:12px;margin-top:16px;text-align:center}}
</style></head>
<body><div class="wrap">
  <header>
    <h1>{TOOL_NAME} &mdash; Browser DFIR Report</h1>
    <div class="sub">{TOOL_NAME} {TOOL_VERSION} &middot; generated {esc(gen)} &middot;
      {counts['total']} finding(s) &middot; defensive analysis of owned artifacts</div>
  </header>
  <div class="chips">{chips}</div>
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Rule</th><th>Indicator</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <footer>Heuristic triage only &mdash; corroborate findings before acting.</footer>
</div></body></html>"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="browserforensics",
        description=f"{TOOL_NAME} - defensive browser history/downloads IOC & exfil triage.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Analyze exported history/downloads.")
    scan.add_argument("--history", help="Path to exported history (CSV or JSON).")
    scan.add_argument("--downloads", help="Path to exported downloads (CSV or JSON).")
    scan.add_argument("--format", choices=["table", "json", "html"],
                      default="table", help="Output format (default: table).")
    scan.add_argument("-o", "--output", help="Write report to file instead of stdout.")
    scan.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"],
                      default="low",
                      help="Minimum severity that triggers a non-zero exit (default: low).")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command != "scan":
        build_parser().print_help()
        return 2

    if not args.history and not args.downloads:
        sys.stderr.write("error: provide --history and/or --downloads\n")
        return 2

    try:
        findings = analyze(args.history, args.downloads)
    except FileNotFoundError as e:
        sys.stderr.write(f"error: file not found: {e.filename}\n")
        return 2
    except OSError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2

    if args.format == "json":
        report = _render_json(findings)
    elif args.format == "html":
        report = _render_html(findings)
    else:
        report = _render_table(findings)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
            sys.stderr.write(f"wrote {args.format} report to {args.output}\n")
        except OSError as e:
            sys.stderr.write(f"error: cannot write output: {e}\n")
            return 2
    else:
        print(report)

    threshold = Severity.rank(args.fail_on)
    if any(Severity.rank(f.severity) >= threshold for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
