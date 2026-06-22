# Demo 06 - Insider bulk export to anonymous file-shares

## Background

A departing salesperson, in their final week, pulled large data exports from the
internal CRM and then visited a series of anonymous one-click file-transfer
sites within the same hour. This is the textbook insider-exfiltration timeline:
**stage** (bulk export to local disk), then **transfer** (upload to an
off-corporate channel). Correlating the history and the downloads together is
what makes the story legible.

## What's in the data

`history.json`:

- CRM "export all customers" and a `payroll_2026.csv` view (sensitive keyword
  `payroll`)
- back-to-back visits to **`file.io`, `transfer.sh`, and `wetransfer.com`** -
  three distinct anonymous file-share services in minutes
- a `db_credential_backup` page (sensitive keywords `credential`, `backup`,
  `secret`)

`downloads.csv`:

- a **500 MB** `customer_dump.csv`
- a `payroll_2026.csv`
- a **200 MB** `db_credential_backup.zip`

## Run it

Scan both artifacts together so the staging and transfer signals line up:

```sh
python -m browserforensics scan \
    --history demos/06-cloud-bulk-exfil/history.json \
    --downloads demos/06-cloud-bulk-exfil/downloads.csv
```

## What to expect

The cross-record `history.multi_exfil_pattern` rule fires **CRITICAL** (three
distinct exfil hosts), alongside `history.exfil_site_visit`,
`history.sensitive_keyword`, `download.large_transfer`, and `download.archive`.
Exit code non-zero.

## How to act

Engage HR/legal per insider-threat policy, preserve the workstation and the
CRM audit log, and check the file-share destinations' egress sizes against the
500 MB / 200 MB local downloads to confirm the upload actually completed.
