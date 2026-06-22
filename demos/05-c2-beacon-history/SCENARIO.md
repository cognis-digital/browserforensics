# Demo 05 - Command-and-control beaconing in browser history

## Background

A workstation showed regular, low-jitter outbound connections roughly every ten
minutes - the signature of a C2 beacon. Because the implant rode the browser's
network stack, the callbacks landed in browser history. This export captures
that pattern: repeated GETs to a raw-IP `gate.php` endpoint, each carrying a
long encoded `id` parameter (the beacon check-in / tasking channel), plus a
fake CDN on an abused TLD delivering a payload disguised as `jquery.min.js`.

The base64-looking blobs here are synthetic placeholders, not captured malware
indicators.

## What's in the data

`history.json` (Chrome/Firefox-style export):

- three visits to **`http://193.42.33.18/gate.php?id=<long-encoded-blob>`** -
  raw IP host + 80+ char encoded query parameter
- one fake-CDN request to **`cdn-update.work`** (`.work` abused TLD) also
  carrying a long encoded query blob
- benign Hacker News and intranet visits as noise

## Run it

```sh
python -m browserforensics scan --history demos/05-c2-beacon-history/history.json --format json
```

## What to expect

Findings include `history.ip_literal_host` (HIGH), `history.encoded_query`
(MEDIUM), and `history.suspicious_tld` (MEDIUM). Exit code non-zero.

## How to act

Treat `193.42.33.18` and `cdn-update.work` as C2 indicators: block at the
perimeter, sweep the fleet for other hosts contacting them, and image this
workstation for memory forensics before the implant rotates infrastructure.
