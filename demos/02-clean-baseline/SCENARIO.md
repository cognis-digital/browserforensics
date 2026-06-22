# Demo 02 - Clean baseline (no findings expected)

## Background

Before chasing alerts, an IR team establishes what a *normal* browser profile
looks like for a given role. This is an export from a software-engineer
workstation during a routine, uneventful day. It is included so you can confirm
the tool does **not** cry wolf on ordinary corporate browsing.

## What's in the data

`history.json` (Chrome/Firefox-style export: `url`, `title`, `visit_time`,
`visit_count`) containing only well-known, reputable destinations: the corporate
intranet, Gmail, GitHub, Hacker News, Wikipedia, Stack Overflow, the Python
docs, and BBC News. No anonymous file-shares, no raw IPs, no abused TLDs, no
encoded query blobs.

## Run it

```sh
python -m browserforensics scan --history demos/02-clean-baseline/history.json
```

## What to expect

`Summary: 0 finding(s)` and **exit code 0**. Use this as your regression
baseline: if a future scan of similar traffic suddenly produces findings, the
delta is what deserves attention.

## How to act

Nothing to do. Archive the export as a known-good reference for this user/role.
