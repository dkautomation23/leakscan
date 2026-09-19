# Security Policy

leakscan opens files you are about to send to someone else — office
documents, PDFs, photos, text exports — and it runs entirely offline. That
makes two things security-relevant: the file parsers have to survive input
they were never handed by a well-behaved editor, and the tool must never be
the thing that sends data anywhere.

## What counts as a vulnerability here

A file that, when scanned, makes leakscan do one of the following:

- read or write anything outside the folder you pointed it at (for example a
  zip entry in a `.docx`/`.xlsx`/`.pptx` that escapes the extraction path —
  "zip-slip");
- execute code, corrupt memory, or otherwise misbehave beyond a clean error
  when parsing a malformed `.docx`/`.xlsx`/`.pptx`/`.pdf`/`.jpg`/`.tif`/`.heic`;
- make an outbound network connection of any kind (the entire point of the
  tool is that it never does this);
- cause the report to print more of a detected value than the masking rule
  allows (card numbers and IBANs are meant to show only the first/last
  digits, never the full number);
- consume unbounded memory or CPU on a small input (a decompression-bomb
  style `.docx`/`.xlsx`/`.pptx`, for instance).

Report these.

## What is not a vulnerability

- A file type, hidden sheet, tracked-change shape, or PII pattern that
  leakscan fails to detect. Missed detection is a false negative — file it
  as a normal bug, with the file (or a redacted reproduction) attached.
- A legitimate value flagged as a finding (false positive), or a `.doc`/`.xls`
  legacy file being unsupported — both are documented limits, not security
  issues.
- Crashes on input that is simply corrupted (not crafted) — still worth a bug
  report, just not through this process unless you can show it is exploitable
  beyond a panic.

If you are unsure which bucket something falls into, report it through the
private channel below and let us sort it out — that costs us little and
costs you nothing.

## Reporting a vulnerability

Preferred: open a report through
[GitHub Private vulnerability reporting](https://github.com/dkautomation23/leakscan/security/advisories/new)
on this repository. It reaches the maintainer directly and is not visible to
anyone else.

Alternative: email **hello@dkautomation.dev** with `leakscan` in the subject
line. If the report itself needs to include sensitive material (a real file
that triggers the bug), say so and we'll arrange a way to send it that isn't
a public issue.

Please include:
- the leakscan version (`leakscan --version`) and OS,
- the exact command you ran,
- a minimal file that reproduces the problem, or a precise description of
  how to build one — a redacted or synthetic file is preferred over a real
  client document.

**First response within 3 business days.** After triage we'll tell you the
expected timeline for a fix and credit you in the release notes, if you want
that.

## Supported versions

Only the latest release is supported. If you're on an older tag, please
upgrade before reporting — the issue may already be fixed.
