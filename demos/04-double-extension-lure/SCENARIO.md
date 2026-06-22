# Demo 04 - Double-extension lures from a phishing campaign

## Background

The finance team received a wave of phishing emails impersonating invoices,
resumes, and forecasts. A few users clicked through and downloaded the
"documents." This export is from one such workstation. Double-extension files
(`invoice.pdf.exe`) are a classic social-engineering trick: Windows hides the
real extension, so the icon and the leading `.pdf`/`.docx`/`.xlsx` fool the
user while the trailing `.exe`/`.scr`/`.js` is what actually executes.

## What's in the data

`downloads.csv` (Chrome-style export):

- `Invoice_4471.pdf.exe` - PDF lure, real type EXE
- `Resume_Candidate.docx.scr` - Word lure, real type screensaver-executable
- `Q3_Forecast.xlsx.js` - Excel lure, real type JavaScript
- a genuine JPEG and a genuine intranet PDF (must NOT fire)

Note the browser did **not** flag any of these (`danger_type=not_dangerous`) -
the structural double-extension heuristic catches what the browser missed.

## Run it

```sh
python -m browserforensics scan --downloads demos/04-double-extension-lure/downloads.csv
```

To hand the result to GitHub code-scanning or an IDE SARIF viewer:

```sh
python -m browserforensics scan --downloads demos/04-double-extension-lure/downloads.csv \
    --format sarif -o downloads.sarif
```

## What to expect

Three `download.double_extension` findings (CRITICAL) for the three lures, and
zero findings for the JPEG and the intranet PDF. Exit code non-zero.

## How to act

Isolate the host, collect and hash the three files for sandbox detonation, and
search mail/proxy logs for other recipients of the same campaign.
