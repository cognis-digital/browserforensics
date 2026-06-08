"""BROWSERFORENSICS - defensive browser DFIR triage for exported history & downloads.

Analyze browser-exported artifacts (history CSV/JSON, downloads CSV/JSON) for
indicators of compromise and data-exfiltration signs. Standard library only.

This is a DEFENSIVE / analysis tool: it operates on artifacts you already own
(exports from your own browser profiles). It performs no network access and
no attack capability.
"""
from .core import (
    Finding,
    Severity,
    analyze_history,
    analyze_downloads,
    analyze,
    load_records,
)

TOOL_NAME = "BROWSERFORENSICS"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "Severity",
    "analyze_history",
    "analyze_downloads",
    "analyze",
    "load_records",
]
