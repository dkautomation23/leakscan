//! Office files: the parts nobody looks at before hitting send.
//!
//! `.docx`, `.xlsx` and `.pptx` are ZIP archives of XML. Four things hide in
//! there and travel with the file:
//!
//! * **tracked changes** - text the author deleted is still in `w:delText`,
//!   readable by anyone who turns markup back on;
//! * **comments** - internal review notes, with names attached;
//! * **hidden worksheets** - `state="hidden"`, and `veryHidden`, which Excel
//!   will not even list in the unhide dialog;
//! * **metadata** - author, last editor, company, revision count, editing time.
//!
//! Every one of these has cost somebody a deal or a headline.

use std::io::Read;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::finding::{Finding, Severity};

#[derive(Debug, Default)]
pub struct OfficeFacts {
    pub creator: String,
    pub last_modified_by: String,
    pub company: String,
    pub revision: String,
    pub editing_minutes: String,
    pub insertions: usize,
    pub deletions: usize,
    pub deleted_text: Vec<String>,
    pub comments: Vec<(String, String)>,
    pub hidden_sheets: Vec<(String, String)>,
    pub external_links: Vec<String>,
    /// Everything readable, for the personal-data pass.
    pub text: String,
}

fn attribute(element: &quick_xml::events::BytesStart, name: &str) -> Option<String> {
    element.attributes().flatten().find_map(|attribute| {
        let key = String::from_utf8_lossy(attribute.key.as_ref()).to_string();
        // Sheet attributes are unprefixed, relationship ones are not.
        if key == name || key.ends_with(&format!(":{name}")) {
            Some(String::from_utf8_lossy(&attribute.value).to_string())
        } else {
            None
        }
    })
}

/// Walk an XML document once, handing every start tag and text run to a closure.
fn walk<F: FnMut(&str, Option<&quick_xml::events::BytesStart>, Option<&str>)>(xml: &str, mut visit: F) {
    let mut reader = Reader::from_reader(xml.as_bytes());
    let mut buffer = Vec::new();
    let mut current = String::new();

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) => {
                current = String::from_utf8_lossy(element.name().as_ref()).to_string();
                visit(&current, Some(&element), None);
            }
            Ok(Event::Empty(element)) => {
                let name = String::from_utf8_lossy(element.name().as_ref()).to_string();
                visit(&name, Some(&element), None);
            }
            Ok(Event::Text(text)) => {
                if let Ok(value) = text.unescape() {
                    if !value.trim().is_empty() {
                        visit(&current, None, Some(value.as_ref()));
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buffer.clear();
    }
}

fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// Cap on how much any single zip entry - and all entries combined - are
/// allowed to inflate to. `--max-mb` only bounds the *compressed* file on
/// disk, so without this a 300 KB `.docx` can legally decompress into
/// hundreds of megabytes (a "zip bomb"). 64 MB is far above any legitimate
/// part of a real document (even a huge spreadsheet's sharedStrings.xml runs
/// a few MB at most), while small enough that inflating one hostile entry -
/// or all of them together - cannot exhaust memory on an ordinary machine.
const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;

pub fn inspect(bytes: &[u8]) -> Result<OfficeFacts, String> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|error| error.to_string())?;
    let mut facts = OfficeFacts::default();

    let names: Vec<String> = (0..archive.len())
        .filter_map(|index| archive.by_index(index).ok().map(|file| file.name().to_string()))
        .collect();

    // Tracked across entries too: many entries just under the per-entry cap
    // would otherwise sum to an unbounded amount.
    let mut total_decompressed: u64 = 0;

    for name in &names {
        let mut buffer = Vec::new();
        {
            let Ok(file) = archive.by_name(name) else { continue };
            // Read one byte past the cap - enough to tell "landed exactly on
            // it" apart from "kept going past it" - without ever buffering a
            // hostile entry's full, possibly huge, decompressed size.
            let mut limited = file.take(MAX_DECOMPRESSED_BYTES + 1);
            if limited.read_to_end(&mut buffer).is_err() {
                continue;
            }
        }

        let entry_len = buffer.len() as u64;
        if entry_len > MAX_DECOMPRESSED_BYTES {
            return Err(format!(
                "{name}: inflates past {} MB by itself - refusing to read it (looks like a zip bomb)",
                MAX_DECOMPRESSED_BYTES / 1_048_576
            ));
        }
        total_decompressed += entry_len;
        if total_decompressed > MAX_DECOMPRESSED_BYTES {
            return Err(format!(
                "{name}: this archive inflates past {} MB in total across its parts - refusing to read further (looks like a zip bomb)",
                MAX_DECOMPRESSED_BYTES / 1_048_576
            ));
        }

        // Binary parts (images, fonts) are skipped rather than decoded.
        let Ok(contents) = String::from_utf8(buffer) else { continue };

        match name.as_str() {
            "docProps/core.xml" => read_core_properties(&contents, &mut facts),
            "docProps/app.xml" => read_app_properties(&contents, &mut facts),
            "xl/workbook.xml" => read_workbook(&contents, &mut facts),
            n if n.ends_with("comments.xml") => read_comments(&contents, &mut facts),
            n if n.starts_with("xl/externalLinks/") && n.ends_with(".rels") => {
                read_external_links(&contents, &mut facts)
            }
            n if n == "word/document.xml"
                || n.starts_with("xl/sharedStrings")
                || (n.starts_with("ppt/slides/") && n.ends_with(".xml")) =>
            {
                read_body(&contents, &mut facts)
            }
            _ => {}
        }
    }

    Ok(facts)
}

fn read_core_properties(xml: &str, facts: &mut OfficeFacts) {
    let mut last_tag = String::new();
    walk(xml, |tag, element, text| {
        if element.is_some() {
            last_tag = local(tag).to_string();
        }
        if let Some(value) = text {
            match last_tag.as_str() {
                "creator" => facts.creator = value.trim().to_string(),
                "lastModifiedBy" => facts.last_modified_by = value.trim().to_string(),
                "revision" => facts.revision = value.trim().to_string(),
                _ => {}
            }
        }
    });
}

fn read_app_properties(xml: &str, facts: &mut OfficeFacts) {
    let mut last_tag = String::new();
    walk(xml, |tag, element, text| {
        if element.is_some() {
            last_tag = local(tag).to_string();
        }
        if let Some(value) = text {
            match last_tag.as_str() {
                "Company" => facts.company = value.trim().to_string(),
                "TotalTime" => facts.editing_minutes = value.trim().to_string(),
                _ => {}
            }
        }
    });
}

fn read_workbook(xml: &str, facts: &mut OfficeFacts) {
    walk(xml, |tag, element, _| {
        if local(tag) != "sheet" {
            return;
        }
        let Some(element) = element else { return };
        let state = attribute(element, "state").unwrap_or_default();
        if state == "hidden" || state == "veryHidden" {
            let name = attribute(element, "name").unwrap_or_else(|| "(unnamed)".into());
            facts.hidden_sheets.push((name, state));
        }
    });
}

fn read_comments(xml: &str, facts: &mut OfficeFacts) {
    let mut author = String::new();
    let mut collecting = false;
    let mut text = String::new();

    walk(xml, |tag, element, value| {
        match (local(tag), element, value) {
            ("comment", Some(element), _) => {
                if !text.trim().is_empty() {
                    facts.comments.push((author.clone(), text.trim().to_string()));
                }
                author = attribute(element, "author").unwrap_or_else(|| "(unknown)".into());
                text.clear();
                collecting = true;
            }
            (_, _, Some(value)) if collecting => {
                text.push_str(value);
                text.push(' ');
            }
            _ => {}
        }
    });
    if !text.trim().is_empty() {
        facts.comments.push((author, text.trim().to_string()));
    }
}

fn read_external_links(xml: &str, facts: &mut OfficeFacts) {
    walk(xml, |tag, element, _| {
        if local(tag) != "Relationship" {
            return;
        }
        if let Some(element) = element {
            if let Some(target) = attribute(element, "Target") {
                if target.starts_with("file:") || target.contains("\\\\") || target.contains("://") {
                    facts.external_links.push(target);
                }
            }
        }
    });
}

fn read_body(xml: &str, facts: &mut OfficeFacts) {
    let mut in_deleted = false;

    walk(xml, |tag, element, value| {
        let name = local(tag);
        if element.is_some() {
            match name {
                "ins" => facts.insertions += 1,
                "del" => {
                    facts.deletions += 1;
                    in_deleted = true;
                }
                "delText" => in_deleted = true,
                "t" => in_deleted = false,
                _ => {}
            }
        }
        if let Some(value) = value {
            if name == "delText" || (in_deleted && name == "t") {
                facts.deleted_text.push(value.trim().to_string());
            } else {
                facts.text.push_str(value);
                facts.text.push(' ');
            }
        }
    });
}

/// Turn the facts into findings a person can act on.
pub fn findings(path: &str, facts: &OfficeFacts) -> Vec<Finding> {
    let mut findings = Vec::new();

    if facts.deletions > 0 || facts.insertions > 0 {
        let sample = facts
            .deleted_text
            .iter()
            .filter(|text| !text.is_empty())
            .take(2)
            .cloned()
            .collect::<Vec<_>>()
            .join(" / ");
        let detail = if sample.is_empty() {
            format!("{} insertion(s), {} deletion(s) still in the file", facts.insertions, facts.deletions)
        } else {
            format!(
                "{} insertion(s), {} deletion(s). Deleted text still readable, e.g.: \"{}\"",
                facts.insertions,
                facts.deletions,
                sample.chars().take(120).collect::<String>()
            )
        };
        findings.push(Finding::new(
            path,
            Severity::Critical,
            "Tracked changes are still in the document",
            detail,
            "Review > Accept All Changes, then save. Turning markup off only hides it on screen.",
        ));
    }

    if !facts.comments.is_empty() {
        let sample = facts
            .comments
            .iter()
            .take(2)
            .map(|(author, text)| format!("{author}: {}", text.chars().take(60).collect::<String>()))
            .collect::<Vec<_>>()
            .join(" | ");
        findings.push(Finding::new(
            path,
            Severity::Critical,
            format!("{} comment(s) left in the file", facts.comments.len()),
            sample,
            "Delete all comments before sending, or export to PDF from a cleaned copy.",
        ));
    }

    if !facts.hidden_sheets.is_empty() {
        let sheets = facts
            .hidden_sheets
            .iter()
            .map(|(name, state)| format!("{name} ({state})"))
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding::new(
            path,
            Severity::Critical,
            format!("{} hidden worksheet(s)", facts.hidden_sheets.len()),
            sheets,
            "Unhide and check the contents - 'veryHidden' sheets do not appear in Excel's unhide list.",
        ));
    }

    if !facts.external_links.is_empty() {
        findings.push(Finding::new(
            path,
            Severity::Warning,
            "Links to external workbooks or network paths",
            facts.external_links.join(", ").chars().take(150).collect::<String>(),
            "These expose internal server names and break for the recipient. Paste values instead.",
        ));
    }

    let identity: Vec<String> = [
        ("author", &facts.creator),
        ("last edited by", &facts.last_modified_by),
        ("company", &facts.company),
    ]
    .into_iter()
    .filter(|(_, value)| !value.is_empty())
    .map(|(label, value)| format!("{label}: {value}"))
    .collect();

    if !identity.is_empty() {
        findings.push(Finding::new(
            path,
            Severity::Warning,
            "Document metadata identifies people and the organisation",
            identity.join(", "),
            "File > Info > Check for Issues > Inspect Document, then remove document properties.",
        ));
    }

    if let Ok(minutes) = facts.editing_minutes.parse::<u32>() {
        if minutes > 0 {
            findings.push(Finding::new(
                path,
                Severity::Note,
                "Total editing time is recorded",
                format!("{minutes} minute(s) - visible to the recipient"),
                "Removed by the same document inspector as the other properties.",
            ));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_properties_are_read() {
        let xml = r#"<?xml version="1.0"?>
        <cp:coreProperties xmlns:cp="x" xmlns:dc="y">
            <dc:creator>Anna Weber</dc:creator>
            <cp:lastModifiedBy>legal.review</cp:lastModifiedBy>
            <cp:revision>7</cp:revision>
        </cp:coreProperties>"#;
        let mut facts = OfficeFacts::default();
        read_core_properties(xml, &mut facts);
        assert_eq!(facts.creator, "Anna Weber");
        assert_eq!(facts.last_modified_by, "legal.review");
        assert_eq!(facts.revision, "7");
    }

    #[test]
    fn deleted_text_is_recovered_from_tracked_changes() {
        let xml = r#"<w:document xmlns:w="x"><w:body>
            <w:p><w:r><w:t>Our price is </w:t></w:r>
            <w:del w:author="Anna"><w:r><w:delText>4,000 EUR</w:delText></w:r></w:del>
            <w:ins w:author="Anna"><w:r><w:t>7,500 EUR</w:t></w:r></w:ins></w:p>
        </w:body></w:document>"#;
        let mut facts = OfficeFacts::default();
        read_body(xml, &mut facts);

        assert_eq!(facts.deletions, 1);
        assert_eq!(facts.insertions, 1);
        assert!(facts.deleted_text.iter().any(|text| text.contains("4,000 EUR")));
        // The visible text is kept for the personal-data pass.
        assert!(facts.text.contains("7,500 EUR"));
        // The removed price must not leak into the "visible" text.
        assert!(!facts.text.contains("4,000 EUR"));
    }

    #[test]
    fn hidden_and_very_hidden_sheets_are_both_found() {
        let xml = r#"<workbook><sheets>
            <sheet name="Summary" sheetId="1"/>
            <sheet name="Margins" sheetId="2" state="hidden"/>
            <sheet name="Salaries" sheetId="3" state="veryHidden"/>
        </sheets></workbook>"#;
        let mut facts = OfficeFacts::default();
        read_workbook(xml, &mut facts);

        assert_eq!(facts.hidden_sheets.len(), 2);
        assert!(facts.hidden_sheets.iter().any(|(name, state)| name == "Salaries" && state == "veryHidden"));
    }

    #[test]
    fn comments_keep_their_authors() {
        let xml = r#"<w:comments xmlns:w="x">
            <w:comment w:id="1" w:author="Tom" w:date="2026-08-01"><w:p><w:r><w:t>Can we go lower?</w:t></w:r></w:p></w:comment>
            <w:comment w:id="2" w:author="Dana"><w:p><w:r><w:t>Only if they sign in August</w:t></w:r></w:p></w:comment>
        </w:comments>"#;
        let mut facts = OfficeFacts::default();
        read_comments(xml, &mut facts);

        assert_eq!(facts.comments.len(), 2);
        assert_eq!(facts.comments[0].0, "Tom");
        assert!(facts.comments[1].1.contains("sign in August"));
    }

    #[test]
    fn network_paths_are_reported_and_ordinary_targets_are_not() {
        let xml = r#"<Relationships>
            <Relationship Id="rId1" Target="file:///\\\\fileserver\\finance\\budget.xlsx"/>
            <Relationship Id="rId2" Target="sharedStrings.xml"/>
        </Relationships>"#;
        let mut facts = OfficeFacts::default();
        read_external_links(xml, &mut facts);
        assert_eq!(facts.external_links.len(), 1);
    }

    #[test]
    fn tracked_changes_are_critical_and_quote_the_deleted_text() {
        let facts = OfficeFacts {
            deletions: 1,
            deleted_text: vec!["4,000 EUR".into()],
            ..Default::default()
        };
        let findings = findings("offer.docx", &facts);
        let tracked = findings.iter().find(|f| f.what.contains("Tracked changes")).unwrap();
        assert_eq!(tracked.severity, Severity::Critical);
        assert!(tracked.detail.contains("4,000 EUR"));
    }

    #[test]
    fn a_clean_document_produces_no_findings() {
        let facts = OfficeFacts::default();
        assert!(findings("clean.docx", &facts).is_empty());
    }

    #[test]
    fn a_zip_entry_that_inflates_past_the_cap_is_rejected_not_fully_read() {
        use std::io::Write;

        // A run of zero bytes compresses to almost nothing under deflate, so
        // this is a realistic docx-shaped zip bomb: tiny on disk, huge once
        // inflated. 65 MB is chosen to sit just past the 64 MB cap the fix
        // enforces, without the test itself allocating an unreasonable amount.
        let payload = vec![0u8; 65 * 1024 * 1024];

        let mut zip_bytes = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
            let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            writer.start_file("word/document.xml", options).expect("start zip entry");
            writer.write_all(&payload).expect("write oversized payload");
            writer.finish().expect("finish zip");
        }

        let result = inspect(&zip_bytes);
        assert!(result.is_err(), "an entry that inflates past the cap must be rejected, not read in full");
        let message = result.unwrap_err();
        assert!(message.contains("word/document.xml"), "error should name the offending entry: {message}");
    }
}
