# Demo 03 - Firefox CSV download export with alternate column names

## Background

Not every export looks like Chrome's. This is a downloads list exported from a
Firefox profile via an add-on that uses different column headers
(`filename`, `size`, `time`, `mimetype` instead of `target_path`,
`received_bytes`, `start_time`, `mime_type`). The demo proves the loader's
column-alias normalization works on real-world variant schemas, and surfaces a
payload hiding among legitimate installer downloads.

## What's in the data

`downloads.csv` with Firefox-style headers:

- two legitimate installers (`setup.exe`, `installer.msi`) from reputable hosts
- a benign PDF report
- **`keylogger_build.exe` pulled from `gofile.io`** (anonymous file-share) and
  flagged `dangerous_file` by the browser
- **`dump.7z` from `mega.nz`** (anonymous file-share) - a possible staged archive

## Run it

```sh
python -m browserforensics scan --downloads demos/03-firefox-csv/downloads.csv
```

## What to expect

Findings include `download.executable`, `download.from_exfil_host`,
`download.browser_flagged`, and `download.archive`. Exit code is non-zero.

## How to act

Quarantine `keylogger_build.exe` and `dump.7z`, hash both and check reputation,
and pivot on the `gofile.io` / `mega.nz` connections in proxy/egress logs.
