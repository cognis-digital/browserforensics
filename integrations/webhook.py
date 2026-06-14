#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="POST browserforensics JSON findings to a webhook URL."
    )
    ap.add_argument("--url", required=True, help="Destination URL (http/https).")
    ap.add_argument("--header", action="append", default=[], help="Extra header as 'Key: Value'.")
    ap.add_argument("--timeout", type=float, default=15.0,
                    help="HTTP timeout in seconds (default: 15).")
    args = ap.parse_args()

    # Validate URL is non-empty and looks like http(s).
    url = args.url.strip()
    if not url:
        sys.stderr.write("error: --url must not be empty\n")
        return 2
    if not url.startswith(("http://", "https://")):
        sys.stderr.write(f"error: --url must start with http:// or https://: {url!r}\n")
        return 2

    # Validate timeout is a positive number.
    if args.timeout <= 0:
        sys.stderr.write("error: --timeout must be a positive number\n")
        return 2

    payload = sys.stdin.read().encode("utf-8")
    if not payload.strip():
        sys.stderr.write("error: no input on stdin; pipe JSON findings to this command\n")
        return 2

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        if ":" not in h:
            sys.stderr.write(f"warning: skipping malformed --header (missing ':'): {h!r}\n")
            continue
        k, _, v = h.partition(":")
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as e:
        sys.stderr.write(f"webhook error: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
