//! What the scanner reports, and how bad it is.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Someone's data or credentials leave with the file.
    Critical,
    /// Content the sender believes is not in the file, or identifying metadata.
    Warning,
    /// Worth knowing, not worth blocking a send over.
    Note,
}

impl Severity {
    pub fn marker(self) -> &'static str {
        match self {
            Severity::Critical => "[!]",
            Severity::Warning => "[~]",
            Severity::Note => "[.]",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Note => "note",
        };
        f.write_str(text)
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub file: String,
    pub severity: Severity,
    pub what: String,
    pub detail: String,
    /// What to do before sending the file.
    pub fix: String,
}

impl Finding {
    pub fn new(
        file: impl Into<String>,
        severity: Severity,
        what: impl Into<String>,
        detail: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Self {
            file: file.into(),
            severity,
            what: what.into(),
            detail: detail.into(),
            fix: fix.into(),
        }
    }
}

/// Everything found in one scan, plus what could not be read.
#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub unreadable: Vec<(String, String)>,
}

impl Report {
    pub fn count(&self, severity: Severity) -> usize {
        self.findings.iter().filter(|finding| finding.severity == severity).count()
    }

    pub fn files_with_findings(&self) -> usize {
        let mut files: Vec<&str> = self.findings.iter().map(|f| f.file.as_str()).collect();
        files.sort_unstable();
        files.dedup();
        files.len()
    }

    /// Non-zero exit when something genuinely should not be sent.
    pub fn should_block(&self) -> bool {
        self.count(Severity::Critical) > 0
    }

    pub fn sorted(&self) -> Vec<&Finding> {
        let mut findings: Vec<&Finding> = self.findings.iter().collect();
        findings.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.file.cmp(&b.file)));
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(file: &str, severity: Severity) -> Finding {
        Finding::new(file, severity, "something", "detail", "fix it")
    }

    #[test]
    fn critical_sorts_before_warning_and_note() {
        let mut report = Report::default();
        report.findings.push(finding("b.docx", Severity::Note));
        report.findings.push(finding("c.pdf", Severity::Critical));
        report.findings.push(finding("a.xlsx", Severity::Warning));

        let order: Vec<Severity> = report.sorted().iter().map(|f| f.severity).collect();
        assert_eq!(order, vec![Severity::Critical, Severity::Warning, Severity::Note]);
    }

    #[test]
    fn only_critical_findings_block() {
        let mut report = Report::default();
        report.findings.push(finding("a.docx", Severity::Warning));
        assert!(!report.should_block());

        report.findings.push(finding("b.docx", Severity::Critical));
        assert!(report.should_block());
    }

    #[test]
    fn files_are_counted_once_however_many_findings_they_have() {
        let mut report = Report::default();
        report.findings.push(finding("a.docx", Severity::Warning));
        report.findings.push(finding("a.docx", Severity::Critical));
        report.findings.push(finding("b.pdf", Severity::Note));
        assert_eq!(report.files_with_findings(), 2);
        assert_eq!(report.count(Severity::Warning), 1);
    }
}
