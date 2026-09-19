# Contributing

## Build and test

```bash
cargo build --release
cargo test
```

CI runs the same steps against a pinned toolchain and fails the build on any
warning:

```bash
rustup toolchain install 1.98.0 --profile minimal --component clippy
cargo build --release --locked
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

Run `cargo clippy --all-targets -- -D warnings` locally before opening a PR —
it is the step most likely to fail on a clean submission. `Cargo.lock` is
committed and CI builds with `--locked`, so add new dependencies with
`cargo add` (or edit `Cargo.toml` and run `cargo build` once) rather than
hand-editing the lockfile.

## Where tests live

There is no `tests/` directory — each module carries its own `#[cfg(test)]
mod tests` block next to the code it covers: `src/finding.rs`, `src/media.rs`
(EXIF), `src/office.rs` (docx/xlsx/pptx), `src/pdfdoc.rs`, `src/pii.rs` (Luhn,
IBAN mod-97, and the rest of the personal-data checks). Put a new test next
to the code it exercises, not in a new top-level file.

`samples/` holds fixture files built to contain specific problems (tracked
changes, hidden sheets, IBANs, GPS coordinates). They're for manual sanity
checks (`cargo run -- samples`) and as a source of realistic fixtures for
new tests — they are not run automatically by `cargo test`.

## Adding a new check

Every detector (a new PII pattern, a new metadata field, a new
hidden-content check) starts with a failing test that encodes the exact case
it should catch — a literal string or a small fixture — before any detection
code is written. Make the test pass, then check it against a plausible
false-positive (an order number that looks like a card number, a reference
that looks like an IBAN) so the detector doesn't overreach.

If the change affects what gets masked in output (card numbers, IBANs),
double-check the masking still hides the full value — leakscan's report is
meant to be safe to forward, and a detector that prints the full match
defeats that.

## Commit style

Match the existing log (`git log --oneline`): `Area: what changed`, lower
case after the colon, imperative, no trailing period, no conventional-commit
prefixes (`feat:`, `fix:`, etc.). Examples from this repository:

```
Run the tests in CI on every push
README: state the Rust version CI actually proves
Release workflow: build a binary for Linux, macOS and Windows on a tag
```

## Pull requests

Keep the "Honest limits" section in the README honest — if a PR changes what
leakscan does or does not catch, update it in the same PR. Small, focused
PRs over large ones; describe what you tested it against.
