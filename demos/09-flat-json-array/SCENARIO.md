# Demo 09 - Linux dev box, downloads as a flat JSON array

## Background

A Linux developer workstation was implicated in a multi-stage compromise. The
download records were dumped as a **flat top-level JSON array** (no `downloads`
wrapper object) - a common shape when records are pulled straight out of a
SQLite query or a jq one-liner. This demo confirms the loader handles a bare
array, and walks a small staged-payload chain: a shell dropper from a paste
host, a raw-IP loader, and a second-stage Python script from another anonymous
file-share.

## What's in the data

`downloads.json` (flat array):

- **`aBcD.sh`** from **`0x0.st`** - shell script (dangerous ext) + anonymous host
- **`loader`** from raw IP **`104.21.5.99`**
- **`stage2.py`** from **`catbox.moe`** - Python script (dangerous ext) +
  anonymous host
- a legitimate `requests.whl` from `pypi.org` (must NOT fire)

## Run it

```sh
python -m browserforensics scan --downloads demos/09-flat-json-array/downloads.json --format json
```

## What to expect

`download.executable` for the `.sh` and `.py`, `download.from_exfil_host` for
`0x0.st` and `catbox.moe`, and `download.from_ip` for the raw-IP loader. The
PyPI wheel stays clean. Exit code non-zero.

## How to act

Reconstruct the kill chain in order (dropper -> loader -> stage2), pull the
three files for analysis, and review shell/bash history and cron/systemd for
persistence the scripts may have installed.
