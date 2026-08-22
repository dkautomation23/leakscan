# leakscan

Checks what leaves with a file before you send it: tracked changes still in the
document, comments from the internal review, hidden worksheets, GPS coordinates
in photos, and personal data in the text.

```bash
leakscan ./to-client
```

Runs entirely offline. The files you would not want to upload to a web scanner
to find out whether they are safe to upload are exactly the files this is for.

## Why

The expensive mistakes are not typos, they are the parts of a file nobody looks
at:

- a proposal where **the deleted price is still readable** in tracked changes —
  turning markup off hides it on screen, not in the file;
- the internal comment "we can go lower, they refused 4k last quarter", sent to
  the customer who refused 4k last quarter;
- a `veryHidden` worksheet with margins per client, which Excel will not even
  list in the unhide dialog;
- a PDF exported with `Title: offer-v3-FINAL-cheap.docx`;
- a product photo carrying **the coordinates of the flat it was shot in**;
- a customer export sent "for testing" with card numbers and IBANs in it.

Every one of those has cost somebody a deal, a fine, or a headline.

## What it inspects

| Format | What it looks at |
| --- | --- |
| `.docx` `.xlsx` `.pptx` (+ macro variants) | tracked insertions and deletions with the deleted text quoted, review comments and their authors, hidden and `veryHidden` sheets, links to network paths, author / last-editor / company / editing time |
| `.pdf` | annotations, embedded attachments, JavaScript and auto-actions, Info metadata, and whether there is a text layer at all |
| `.jpg` `.tif` `.heic` | GPS coordinates, camera model and body serial number, owner name, capture time, editing software |
| `.txt` `.csv` `.json` `.xml` `.html` `.log` `.sql` | the personal-data pass below |

**Personal data is validated, not guessed.** Card numbers must pass the Luhn
check, IBANs must pass ISO 7064 mod-97 — a 16-digit order number and an invoice
reference do not become findings. Detected values are counted and masked in the
report (`42************42`), never printed in full, so the report itself is safe
to forward.

Two details that took a second pass to get right: an IBAN contains a digit run
that the phone-number pattern also matches, so validated matches are consumed
from the text before the weaker patterns run; and deleted text is fed into the
personal-data check too, because a name someone "removed" is still in the file.

## Sample output

```console
$ leakscan samples

4 file(s) checked in 0.0s - 6 critical, 8 warning(s), 1 note(s) across 3 file(s)

samples\budget-hidden-sheets.xlsx
  [!] 2 hidden worksheet(s)
      Cost breakdown (hidden), Margins per client (veryHidden)
      fix: Unhide and check the contents - 'veryHidden' sheets do not appear in Excel's unhide list.
  [!] 1 x IBAN
      example: DE******************00
  [~] Links to external workbooks or network paths
      file:///\\fileserver01\finance\master-pricing-2026.xlsx
  [~] Document metadata identifies people and the organisation
      author: Anna Weber, last edited by: finance@northgate

samples\customer-export.csv
  [!] 3 x IBAN
  [!] 2 x payment card number
      example: 42************42
  [~] 3 x e-mail address
  [~] 3 x phone number

samples\offer-with-tracked-changes.docx
  [!] Tracked changes are still in the document
      1 insertion(s), 1 deletion(s). Deleted text still readable, e.g.:
      "4,000 EUR (we can go to 3,200 if they push back)"
      fix: Review > Accept All Changes, then save. Turning markup off only hides it on screen.
  [!] 2 comment(s) left in the file
      t.baker (legal): Anna - do not send the old number, they already refused 4k l | ...
  [~] Document metadata identifies people and the organisation
      author: Anna Weber, last edited by: t.baker (legal), company: Northgate Automation Ltd
  [.] Total editing time is recorded
      212 minute(s) - visible to the recipient

Do not send these files as they are.
```

The sample files in `samples/` are built to contain exactly these problems —
open them in Word and Excel and you will not see any of it.

## Build and use

```bash
git clone https://github.com/dkautomation23/leakscan.git
cd leakscan
cargo build --release
./target/release/leakscan ./folder-you-are-about-to-send
```

Rust 1.75+, single binary, no network access at any point.

```bash
cargo test        # 38 tests: Luhn, mod-97, XML parsing, EXIF maths, severities
```

| Flag | Meaning |
| --- | --- |
| `--quiet` | only critical findings |
| `--no-pii` | metadata checks only, skip the personal-data pass |
| `--flat` | do not descend into sub-folders |
| `--json FILE` | full report as JSON |
| `--max-mb` | largest file to open, default 200 |

Exit code is `1` when something critical was found — enough to gate a send:

```bash
leakscan ./outbox && zip -r package.zip outbox
```

## Honest limits

- **Luhn is one check digit.** Roughly one random 16-digit number in ten passes
  it, so a long numeric ID can still show up as a card. It removes most false
  positives, not all.
- **National ID numbers are only flagged when labelled** ("Steuer-ID: …"). A
  bare number is indistinguishable from a reference.
- **No OCR.** A scanned PDF has no text layer, and the tool says so rather than
  reporting the file as clean — but it cannot read the scan.
- **No redaction check.** Text hidden behind a black rectangle is still text;
  detecting that reliably needs the layout, which this does not parse.
- **Strict EXIF reader.** Some files with malformed metadata are reported as
  unreadable instead of being silently skipped. That is deliberate: a file that
  was not checked must never be counted as clean, and the summary line says so.
- **It finds, it does not fix.** Removing metadata safely depends on the app
  that produced the file; the fix line tells you where to click.
- Legacy `.doc` / `.xls` (the pre-2007 binary formats) are not supported.

## License

MIT
