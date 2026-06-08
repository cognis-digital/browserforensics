# Demo 01 - Suspected workstation compromise triage

## Background

An analyst pulled exports from a user's Chrome profile after the EDR flagged
outbound traffic to an anonymous file-share host. Two artifacts were exported
from the **owned** corporate workstation:

- `history.json` - browsing history (url, title, visit_time, visit_count)
- `downloads.csv` - download records (url, target_path, received_bytes, ...)

The goal is a fast IOC / exfiltration triage before deeper disk forensics.

## What's in the data

The history contains a mix of benign corporate browsing plus several IOCs:

- a visit to a **raw IP** address (phishing/C2 landing page)
- visits to **multiple anonymous paste/file-share sites** (`pastebin`,
  `anonfiles`, `transfer.sh`) - the multi-exfil pattern
- a **URL shortener** redirect
- a **.zip TLD** host
- a query string carrying a long **base64-like blob**

The downloads contain:

- a **double-extension** lure (`invoice.pdf.exe`)
- a payload pulled **from a raw IP**
- a record the browser itself flagged as **dangerous**
- a large archive download

## Run it

```sh
# Human-readable triage
python -m browserforensics scan --history demos/01-basic/history.json \
    --downloads demos/01-basic/downloads.csv

# Shareable HTML report (the "UI")
python -m browserforensics scan --history demos/01-basic/history.json \
    --downloads demos/01-basic/downloads.csv --format html -o report.html

# JSON for pipelines
python -m browserforensics scan --downloads demos/01-basic/downloads.csv --format json
```

Expect a non-zero exit code because high/critical findings are present.

## Note

Heuristics are triage aids, not verdicts. Corroborate each indicator (e.g.
confirm a flagged host's reputation, inspect the actual downloaded file) before
taking action.
