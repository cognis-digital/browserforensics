# Demo 08 - The .zip / .mov TLD confusion trick

## Background

When Google made the `.zip` and `.mov` TLDs publicly registerable, attackers
seized the obvious confusion: a string like `microsoft-update.zip` reads to a
human as a *file* but is actually a *domain* the browser will happily navigate
to. This export is from a user who clicked links in a phishing email that
leaned on exactly that ambiguity - "security-patch", "invoice", "welcome video"
- each hosted on a `.zip` or `.mov` domain.

## What's in the data

`history.json`:

- legitimate Google Drive and Outlook sessions (must NOT fire)
- **`microsoft-update.zip`** and **`invoice-archive.zip`** - `.zip` TLD domains
- **`hr-onboarding.mov`** - `.mov` TLD domain

## Run it

```sh
python -m browserforensics scan --history demos/08-zip-tld-phish/history.json --format html -o zip-tld.html
```

## What to expect

Three `history.suspicious_tld` (MEDIUM) findings for the `.zip`/`.mov` hosts.
Drive and Outlook stay clean. Exit code non-zero. The HTML report is handy for
walking a non-technical user through *why* `microsoft-update.zip` was never a
file at all.

## How to act

User-awareness teaching moment plus a perimeter block on the three domains.
Confirm whether any payload was downloaded from them by scanning the matching
downloads export.
