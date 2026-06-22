# Demo 07 - Malvertising redirect chain (CSV history)

## Background

A user clicked a "you won a prize" web ad and got bounced through a redirect
chain: several URL shorteners, then landing pages on abused TLDs, then a raw-IP
"setup" download host. This is the standard malvertising funnel - shorteners
hide the destination and the cheap throwaway TLDs host the actual lure. The
export is a **CSV** with Chrome's `last_visit_time` column name, exercising both
the CSV loader and the history-alias normalization.

## What's in the data

`history.csv`:

- benign weather and a Wikipedia article (must NOT fire)
- shorteners **`tinyurl.com`, `bit.ly`, `cutt.ly`**
- abused-TLD landings **`flash-prize.top`** (`.top`) and
  **`secure-login.click`** (`.click`)
- a raw-IP install host **`45.155.205.233`**

## Run it

```sh
python -m browserforensics scan --history demos/07-malvertising-shortener/history.csv
```

## What to expect

`history.url_shortener` (x3, MEDIUM), `history.suspicious_tld` (x2, MEDIUM), and
`history.ip_literal_host` (HIGH). The weather and Wikipedia rows produce
nothing. Exit code non-zero.

## How to act

Expand the shortened links in a sandbox to recover the full redirect chain,
block the `.top`/`.click` landings and the raw IP, and check whether the
`/install/setup` payload was actually fetched (cross-reference the downloads
export for this host).
