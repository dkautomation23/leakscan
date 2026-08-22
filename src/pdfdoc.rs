//! PDFs: metadata, annotations, attachments, scripts, and the text itself.
//!
//! The dangerous belief about PDF is that it is a picture of a document. It is
//! not - it is a container. Comments from review, whole files attached by
//! accident, JavaScript, and the author's name from whatever produced it all
//! travel inside.

use lopdf::{Document, Object};

use crate::finding::{Finding, Severity};

#[derive(Debug, Default)]
pub struct PdfFacts {
    pub author: String,
    pub creator: String,
    pub producer: String,
    pub title: String,
    pub pages: usize,
    pub annotations: usize,
    pub attachments: Vec<String>,
    pub has_javascript: bool,
    pub encrypted: bool,
    pub text: String,
}

fn string_field(document: &Document, key: &[u8]) -> String {
    document
        .trailer
        .get(b"Info")
        .and_then(|info| match info {
            Object::Reference(id) => document.get_object(*id),
            other => Ok(other),
        })
        .and_then(|info| info.as_dict())
        .and_then(|dict| dict.get(key))
        .and_then(|value| value.as_str())
        .map(|bytes| String::from_utf8_lossy(bytes).trim().to_string())
        .unwrap_or_default()
}

pub fn inspect(bytes: &[u8]) -> Result<PdfFacts, String> {
    let document = Document::load_mem(bytes).map_err(|error| error.to_string())?;
    let mut facts = PdfFacts {
        author: string_field(&document, b"Author"),
        creator: string_field(&document, b"Creator"),
        producer: string_field(&document, b"Producer"),
        title: string_field(&document, b"Title"),
        encrypted: document.is_encrypted(),
        ..Default::default()
    };

    let pages = document.get_pages();
    facts.pages = pages.len();

    for (_, page_id) in &pages {
        if let Ok(page) = document.get_dictionary(*page_id) {
            if let Ok(annotations) = page.get(b"Annots") {
                match annotations {
                    Object::Array(items) => facts.annotations += items.len(),
                    Object::Reference(id) => {
                        if let Ok(Object::Array(items)) = document.get_object(*id) {
                            facts.annotations += items.len();
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Attachments and scripts live under the catalog's Names tree.
    if let Ok(catalog) = document.catalog() {
        if catalog.get(b"OpenAction").is_ok() || catalog.get(b"AA").is_ok() {
            facts.has_javascript = true;
        }
        if let Ok(names) = catalog.get(b"Names").and_then(|value| match value {
            Object::Reference(id) => document.get_object(*id),
            other => Ok(other),
        }) {
            if let Ok(dict) = names.as_dict() {
                if dict.get(b"JavaScript").is_ok() {
                    facts.has_javascript = true;
                }
                if dict.get(b"EmbeddedFiles").is_ok() {
                    facts.attachments.push("embedded file(s) present".to_string());
                }
            }
        }
    }

    // Text extraction is best-effort: a scanned PDF has no text layer, and
    // saying "no personal data found" about an image would be a lie, so the
    // caller is told how much text there was.
    let page_numbers: Vec<u32> = pages.keys().copied().collect();
    if let Ok(text) = document.extract_text(&page_numbers) {
        facts.text = text;
    }

    Ok(facts)
}

pub fn findings(path: &str, facts: &PdfFacts) -> Vec<Finding> {
    let mut findings = Vec::new();

    if facts.annotations > 0 {
        findings.push(Finding::new(
            path,
            Severity::Critical,
            format!("{} annotation(s) in the PDF", facts.annotations),
            "Comments, highlights and sticky notes stay in the file and open in any reader.",
            "Flatten the PDF (print to PDF) or remove comments before sending.",
        ));
    }

    if !facts.attachments.is_empty() {
        findings.push(Finding::new(
            path,
            Severity::Critical,
            "The PDF carries attached files",
            facts.attachments.join(", "),
            "Open the attachments panel and check what is in there - spreadsheets get attached by accident.",
        ));
    }

    if facts.has_javascript {
        findings.push(Finding::new(
            path,
            Severity::Warning,
            "The PDF contains JavaScript or an automatic action",
            "Recipients' readers may block it, and security teams will ask about it.",
            "Re-export without scripting unless the form genuinely needs it.",
        ));
    }

    let identity: Vec<String> = [
        ("author", &facts.author),
        ("creator", &facts.creator),
        ("producer", &facts.producer),
        ("title", &facts.title),
    ]
    .into_iter()
    .filter(|(_, value)| !value.is_empty())
    .map(|(label, value)| format!("{label}: {value}"))
    .collect();

    if !identity.is_empty() {
        // The Title field is the one that catches people out: it keeps the
        // name of the Word file it was exported from, "offer-v3-FINAL-cheap".
        findings.push(Finding::new(
            path,
            Severity::Warning,
            "PDF metadata identifies the author or the source file",
            identity.join(", "),
            "Clear document properties on export, or run a PDF metadata cleaner.",
        ));
    }

    if facts.pages > 0 && facts.text.trim().len() < 20 {
        findings.push(Finding::new(
            path,
            Severity::Note,
            "No text layer - the personal-data check could not run",
            format!("{} page(s), scanned or image-only", facts.pages),
            "Run OCR first if this document is supposed to be searchable or redacted.",
        ));
    }

    if facts.encrypted {
        findings.push(Finding::new(
            path,
            Severity::Note,
            "The PDF is encrypted",
            "Inspection was limited to what could be read without the password.",
            "",
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annotations_are_critical() {
        let facts = PdfFacts { annotations: 3, pages: 2, text: "x".repeat(50), ..Default::default() };
        let findings = findings("contract.pdf", &facts);
        let annotation = findings.iter().find(|f| f.what.contains("annotation")).unwrap();
        assert_eq!(annotation.severity, Severity::Critical);
        assert!(annotation.what.contains('3'));
    }

    #[test]
    fn the_source_file_name_in_the_title_is_reported() {
        let facts = PdfFacts {
            title: "offer-v3-FINAL-cheap.docx".into(),
            pages: 1,
            text: "x".repeat(50),
            ..Default::default()
        };
        let findings = findings("offer.pdf", &facts);
        assert!(findings.iter().any(|f| f.detail.contains("offer-v3-FINAL-cheap.docx")));
    }

    #[test]
    fn a_scan_is_reported_as_unchecked_rather_than_clean() {
        let facts = PdfFacts { pages: 12, text: String::new(), ..Default::default() };
        let findings = findings("scan.pdf", &facts);
        assert!(findings.iter().any(|f| f.what.contains("No text layer")));
    }

    #[test]
    fn a_text_pdf_is_not_reported_as_a_scan() {
        let facts = PdfFacts { pages: 3, text: "Contract terms and conditions ...".into(), ..Default::default() };
        assert!(!findings("clean.pdf", &facts).iter().any(|f| f.what.contains("No text layer")));
    }

    #[test]
    fn a_clean_flattened_pdf_produces_nothing() {
        let facts = PdfFacts { pages: 2, text: "plain contract text, several clauses".into(), ..Default::default() };
        assert!(findings("clean.pdf", &facts).is_empty());
    }
}
