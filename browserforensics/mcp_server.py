"""BROWSERFORENSICS MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import sys

from browserforensics.cli import _render_json
from browserforensics.core import analyze


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-browserforensics[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print(
            "Install the MCP extra: pip install 'cognis-browserforensics[mcp]'",
            file=sys.stderr,
        )
        return 1
    app = FastMCP("browserforensics")

    @app.tool()
    def browserforensics_scan(
        history_path: str = "",
        downloads_path: str = "",
    ) -> str:
        """Analyze exported browser history/downloads for IOCs and exfil signs.

        Provide at least one of history_path or downloads_path (local file paths
        to CSV or JSON browser exports). Returns a JSON findings report.
        """
        if not history_path and not downloads_path:
            return '{"error": "provide history_path and/or downloads_path"}'
        try:
            findings = analyze(
                history_path=history_path or None,
                downloads_path=downloads_path or None,
            )
        except (OSError, ValueError) as exc:
            return f'{{"error": {str(exc)!r}}}'
        return _render_json(findings)

    app.run()
    return 0
