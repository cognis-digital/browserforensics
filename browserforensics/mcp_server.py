"""BROWSERFORENSICS MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from browserforensics.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-browserforensics[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-browserforensics[mcp]'")
        return 1
    app = FastMCP("browserforensics")

    @app.tool()
    def browserforensics_scan(target: str) -> str:
        """Analyze exported browser history/downloads for IOCs and exfil signs. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
