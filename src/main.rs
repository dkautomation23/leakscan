//! leakscan - check what leaves with a file before you send it.
//!
//!     leakscan ./to-client
//!     leakscan ./to-client --json report.json
//!     leakscan contract.docx --quiet
//!
//! Offline by design: the files it reads are exactly the files you would not
//! want uploaded to somebody's web scanner to find out whether they are safe
//! to upload.

mod finding;
mod media;
mod office;
mod pdfdoc;
mod pii;

use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Parser;
use rayon::prelude::*;
use walkdir::WalkDir;

use finding::{Finding, Report, Severity};

#[derive(Parser, Debug)]
#[command(name = "leakscan", about = "Find hidden metadata, tracked changes and personal data before sending files")]
struct Args {
    /// File or folder to check
    path: PathBuf,

    /// Do not descend into sub-folders
    #[arg(long)]
    flat: bool,

    /// Write the full report as JSON
    #[arg(long)]
    json: Option<PathBuf>,

    /// Overwrite --json if it already exists
    #[arg(long)]
    force: bool,

    /// Only print critical findings
    #[arg(long)]
    quiet: bool,

    /// Skip the personal-data pass (metadata checks only)
    #[arg(long)]
    no_pii: bool,

    /// Largest file to open, in megabytes
    #[arg(long, default_value_t = 200)]
    max_mb: u64,
}

const OFFICE: [&str; 6] = ["docx", "xlsx", "pptx", "docm", "xlsm", "pptm"];
const IMAGES: [&str; 5] = ["jpg", "jpeg", "tif", "tiff", "heic"];
const PLAIN: [&str; 8] = ["txt", "csv", "md", "json", "xml", "html", "log", "sql"];

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default()
}

fn is_supported(path: &Path) -> bool {
    let extension = extension(path);
    OFFICE.contains(&extension.as_str())
        || IMAGES.contains(&extension.as_str())
        || PLAIN.contains(&extension.as_str())
        || extension == "pdf"
}

/// Inspect one file. Text that came out of it is returned for the PII pass.
fn inspect(path: &Path, max_bytes: u64) -> Result<(Vec<Finding>, String), String> {
    let display = path.display().to_string();
    let metadata = std::fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() > max_bytes {
        return Err(format!("skipped, {} MB is over the limit", metadata.len() / 1_048_576));
    }

    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let extension = extension(path);

    if OFFICE.contains(&extension.as_str()) {
        let facts = office::inspect(&bytes)?;
        let mut text = facts.text.clone();
        // Deleted text counts as content for the personal-data pass: a name
        // someone "removed" is still in the file.
        text.push_str(&facts.deleted_text.join(" "));
        for (_, comment) in &facts.comments {
            text.push(' ');
            text.push_str(comment);
        }
        return Ok((office::findings(&display, &facts), text));
    }

    if extension == "pdf" {
        let facts = pdfdoc::inspect(&bytes)?;
        let text = facts.text.clone();
        return Ok((pdfdoc::findings(&display, &facts), text));
    }

    if IMAGES.contains(&extension.as_str()) {
        // "No EXIF at all" is the good case and not an error; anything else
        // (a truncated file, an unsupported container) has to be reported,
        // otherwise a file that was never really checked looks clean.
        return match media::inspect(&bytes) {
            Ok(facts) => Ok((media::findings(&display, &facts), String::new())),
            Err(error) if error.contains("not found") || error.contains("No Exif") => {
                Ok((Vec::new(), String::new()))
            }
            Err(error) => Err(format!("image metadata unreadable: {error}")),
        };
    }

    Ok((Vec::new(), String::from_utf8_lossy(&bytes).to_string()))
}

fn pii_findings(detector: &pii::Detector, path: &str, text: &str) -> Vec<Finding> {
    detector
        .scan(text)
        .into_iter()
        .map(|hit| {
            let severity = if hit.kind.is_critical() { Severity::Critical } else { Severity::Warning };
            Finding::new(
                path,
                severity,
                format!("{} x {}", hit.count, hit.kind.label()),
                format!("example: {}", hit.sample),
                match hit.kind {
                    pii::Kind::CardNumber => "Card numbers must not sit in a document you e-mail. Remove or truncate to the last four digits.",
                    pii::Kind::PrivateKey | pii::Kind::ApiKey => "Rotate the credential - assume it is already compromised - then remove it from the file.",
                    pii::Kind::Iban => "Bank details in a shared file are the classic invoice-fraud vector. Send them separately, or confirm by phone.",
                    _ => "Check the recipient is entitled to this personal data, and remove what they do not need.",
                },
            )
        })
        .collect()
}

fn collect(args: &Args) -> Vec<PathBuf> {
    if args.path.is_file() {
        return vec![args.path.clone()];
    }
    let walker = if args.flat { WalkDir::new(&args.path).max_depth(1) } else { WalkDir::new(&args.path) };
    walker
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| is_supported(path))
        .collect()
}

fn main() {
    let args = Args::parse();
    if !args.path.exists() {
        eprintln!("not found: {}", args.path.display());
        std::process::exit(2);
    }

    let started = Instant::now();
    let files = collect(&args);
    if files.is_empty() {
        println!("nothing to check in {} (looked for office, pdf, image and text files)", args.path.display());
        return;
    }

    let detector = pii::Detector::new();
    let max_bytes = args.max_mb * 1_048_576;

    let results: Vec<(String, Result<Vec<Finding>, String>)> = files
        .par_iter()
        .map(|path| {
            let display = path.display().to_string();
            match inspect(path, max_bytes) {
                Ok((mut findings, text)) => {
                    if !args.no_pii && !text.trim().is_empty() {
                        findings.extend(pii_findings(&detector, &display, &text));
                    }
                    (display, Ok(findings))
                }
                Err(error) => (display, Err(error)),
            }
        })
        .collect();

    let mut report = Report { files_scanned: files.len(), ..Default::default() };
    for (path, result) in results {
        match result {
            Ok(findings) => report.findings.extend(findings),
            Err(error) => report.unreadable.push((path, error)),
        }
    }

    print_report(&report, &args, started);

    if let Some(path) = &args.json {
        if let Err(error) = write_json(path, &report, args.force) {
            eprintln!("could not write {}: {error}", path.display());
        } else {
            println!("full report -> {}", path.display());
        }
    }

    std::process::exit(if report.should_block() { 1 } else { 0 });
}

fn print_report(report: &Report, args: &Args, started: Instant) {
    let critical = report.count(Severity::Critical);
    let warnings = report.count(Severity::Warning);
    let notes = report.count(Severity::Note);

    println!(
        "\n{} file(s) checked in {:.1}s - {critical} critical, {warnings} warning(s), {notes} note(s) across {} file(s)\n",
        report.files_scanned,
        started.elapsed().as_secs_f32(),
        report.files_with_findings(),
    );

    // Grouped by file, worst first inside each file, and files with a critical
    // finding listed before the rest. One file, one block.
    let mut files: Vec<&str> = report.findings.iter().map(|f| f.file.as_str()).collect();
    files.sort_unstable();
    files.dedup();
    files.sort_by_key(|file| {
        report
            .findings
            .iter()
            .filter(|finding| finding.file == *file)
            .map(|finding| finding.severity)
            .min()
            .unwrap_or(Severity::Note)
    });

    for file in files {
        let mut for_file: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|finding| finding.file == file)
            .filter(|finding| !args.quiet || finding.severity == Severity::Critical)
            .collect();
        if for_file.is_empty() {
            continue;
        }
        for_file.sort_by_key(|finding| finding.severity);

        println!("{file}");
        for finding in for_file {
            println!("  {} {}", finding.severity.marker(), finding.what);
            if !finding.detail.is_empty() {
                println!("      {}", finding.detail);
            }
            if !finding.fix.is_empty() && finding.severity != Severity::Note {
                println!("      fix: {}", finding.fix);
            }
        }
        println!();
    }

    if !report.unreadable.is_empty() {
        println!("\n{} file(s) could not be read:", report.unreadable.len());
        for (path, error) in report.unreadable.iter().take(5) {
            println!("  {path} - {error}");
        }
    }

    println!(
        "\n{}",
        if critical > 0 {
            "Do not send these files as they are.".to_string()
        } else if warnings > 0 {
            "Nothing critical, but metadata identifies you and your organisation.".to_string()
        } else if !report.unreadable.is_empty() {
            // Never say "clean" about files that were never actually read.
            format!("Nothing found, but {} file(s) could not be checked.", report.unreadable.len())
        } else {
            "Clean.".to_string()
        }
    );
}

fn write_json(path: &Path, report: &Report, force: bool) -> std::io::Result<()> {
    use std::io::Write;

    // A rerun must never quietly eat an earlier report - refuse instead of
    // overwriting unless the caller explicitly asked for that.
    if !force && path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} already exists; overwrite only with --force", path.display()),
        ));
    }

    fn escape(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace(['\n', '\r', '\t'], " ")
    }

    let mut file = std::fs::File::create(path)?;
    writeln!(file, "{{")?;
    writeln!(file, "  \"files_scanned\": {},", report.files_scanned)?;
    writeln!(file, "  \"critical\": {},", report.count(Severity::Critical))?;
    writeln!(file, "  \"warnings\": {},", report.count(Severity::Warning))?;
    writeln!(file, "  \"findings\": [")?;
    let findings = report.sorted();
    for (index, finding) in findings.iter().enumerate() {
        writeln!(
            file,
            "    {{\"file\": \"{}\", \"severity\": \"{}\", \"what\": \"{}\", \"detail\": \"{}\", \"fix\": \"{}\"}}{}",
            escape(&finding.file),
            finding.severity,
            escape(&finding.what),
            escape(&finding.detail),
            escape(&finding.fix),
            if index + 1 == findings.len() { "" } else { "," },
        )?;
    }
    writeln!(file, "  ]")?;
    writeln!(file, "}}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_types_are_recognised_case_insensitively() {
        assert!(is_supported(Path::new("Offer.DOCX")));
        assert!(is_supported(Path::new("photo.JPG")));
        assert!(is_supported(Path::new("contract.pdf")));
        assert!(is_supported(Path::new("export.csv")));
        assert!(!is_supported(Path::new("archive.zip")));
        assert!(!is_supported(Path::new("video.mp4")));
    }

    #[test]
    fn payment_data_is_critical_and_other_personal_data_is_a_warning() {
        let detector = pii::Detector::new();
        let findings = pii_findings(&detector, "export.csv", "card 4242 4242 4242 4242, mail a@example.com");
        let severities: Vec<Severity> = findings.iter().map(|f| f.severity).collect();
        assert!(severities.contains(&Severity::Critical));
        assert!(severities.contains(&Severity::Warning));
    }

    #[test]
    fn the_report_never_prints_the_value_itself() {
        let detector = pii::Detector::new();
        let findings = pii_findings(&detector, "export.csv", "card 4242 4242 4242 4242");
        assert!(findings.iter().all(|f| !f.detail.contains("4242 4242 4242 4242")));
    }
}
