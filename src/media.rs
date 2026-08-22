//! Photographs: the coordinates, the camera and the owner's name.
//!
//! A JPEG straight off a phone carries where it was taken to within a few
//! metres. That is the single most consequential thing in this whole tool -
//! product photos taken at home, "anonymous" listings, whistleblower documents.

use std::io::BufReader;

use exif::{In, Tag, Value};

use crate::finding::{Finding, Severity};

#[derive(Debug, Default)]
pub struct ImageFacts {
    pub gps: Option<(f64, f64)>,
    pub camera: String,
    pub serial: String,
    pub taken_at: String,
    pub artist: String,
    pub software: String,
}

/// EXIF stores coordinates as degrees/minutes/seconds rationals.
fn to_degrees(value: &Value) -> Option<f64> {
    if let Value::Rational(parts) = value {
        if parts.len() >= 3 {
            let degrees = parts[0].to_f64();
            let minutes = parts[1].to_f64();
            let seconds = parts[2].to_f64();
            return Some(degrees + minutes / 60.0 + seconds / 3600.0);
        }
    }
    None
}

fn text(field: Option<&exif::Field>) -> String {
    field
        .map(|field| field.display_value().to_string().trim_matches('"').to_string())
        .unwrap_or_default()
}

pub fn inspect(bytes: &[u8]) -> Result<ImageFacts, String> {
    let mut reader = BufReader::new(std::io::Cursor::new(bytes));
    let exif = exif::Reader::new()
        .read_from_container(&mut reader)
        .map_err(|error| error.to_string())?;

    let mut facts = ImageFacts {
        camera: [
            text(exif.get_field(Tag::Make, In::PRIMARY)),
            text(exif.get_field(Tag::Model, In::PRIMARY)),
        ]
        .join(" ")
        .trim()
        .to_string(),
        serial: text(exif.get_field(Tag::BodySerialNumber, In::PRIMARY)),
        taken_at: text(exif.get_field(Tag::DateTimeOriginal, In::PRIMARY)),
        artist: text(exif.get_field(Tag::Artist, In::PRIMARY)),
        software: text(exif.get_field(Tag::Software, In::PRIMARY)),
        gps: None,
    };

    let latitude = exif.get_field(Tag::GPSLatitude, In::PRIMARY).and_then(|f| to_degrees(&f.value));
    let longitude = exif.get_field(Tag::GPSLongitude, In::PRIMARY).and_then(|f| to_degrees(&f.value));
    if let (Some(mut lat), Some(mut lon)) = (latitude, longitude) {
        if text(exif.get_field(Tag::GPSLatitudeRef, In::PRIMARY)).starts_with('S') {
            lat = -lat;
        }
        if text(exif.get_field(Tag::GPSLongitudeRef, In::PRIMARY)).starts_with('W') {
            lon = -lon;
        }
        facts.gps = Some((lat, lon));
    }

    Ok(facts)
}

pub fn findings(path: &str, facts: &ImageFacts) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some((latitude, longitude)) = facts.gps {
        findings.push(Finding::new(
            path,
            Severity::Critical,
            "GPS coordinates in the photo",
            format!("{latitude:.5}, {longitude:.5} - paste that into any map"),
            "Strip EXIF before publishing. Most phones keep location on by default.",
        ));
    }

    let identifying: Vec<String> = [
        ("camera", &facts.camera),
        ("serial", &facts.serial),
        ("artist", &facts.artist),
        ("software", &facts.software),
    ]
    .into_iter()
    .filter(|(_, value)| !value.is_empty())
    .map(|(label, value)| format!("{label}: {value}"))
    .collect();

    if !identifying.is_empty() {
        // A camera serial number links every photo you have ever published to
        // the same device - and to any photo where you were named.
        let severity = if facts.serial.is_empty() { Severity::Note } else { Severity::Warning };
        findings.push(Finding::new(
            path,
            severity,
            "Camera and owner details in EXIF",
            identifying.join(", "),
            "Strip metadata on export, or run the folder through an EXIF remover.",
        ));
    }

    if !facts.taken_at.is_empty() {
        findings.push(Finding::new(
            path,
            Severity::Note,
            "Capture timestamp in EXIF",
            facts.taken_at.clone(),
            "Fine for most uses; matters when a photo is supposed to be recent or anonymous.",
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use exif::Rational;

    fn rational(numerator: u32, denominator: u32) -> Rational {
        Rational { num: numerator, denom: denominator }
    }

    #[test]
    fn dms_converts_to_decimal_degrees() {
        // 52 deg 31' 12" = 52.52
        let value = Value::Rational(vec![rational(52, 1), rational(31, 1), rational(12, 1)]);
        let degrees = to_degrees(&value).unwrap();
        assert!((degrees - 52.52).abs() < 0.0001, "got {degrees}");
    }

    #[test]
    fn fractional_seconds_survive() {
        let value = Value::Rational(vec![rational(13, 1), rational(24, 1), rational(1234, 100)]);
        let degrees = to_degrees(&value).unwrap();
        assert!((degrees - 13.403_428).abs() < 0.0001, "got {degrees}");
    }

    #[test]
    fn a_short_rational_is_not_a_coordinate() {
        assert!(to_degrees(&Value::Rational(vec![rational(52, 1)])).is_none());
        assert!(to_degrees(&Value::Ascii(vec![b"52".to_vec()])).is_none());
    }

    #[test]
    fn coordinates_are_critical_and_printed_usably() {
        let facts = ImageFacts { gps: Some((52.52437, 13.41053)), ..Default::default() };
        let findings = findings("photo.jpg", &facts);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].detail.contains("52.52437"));
    }

    #[test]
    fn a_serial_number_raises_the_severity_above_a_plain_camera_name() {
        let plain = ImageFacts { camera: "Apple iPhone 15".into(), ..Default::default() };
        let with_serial = ImageFacts {
            camera: "Canon EOS R6".into(),
            serial: "042051000537".into(),
            ..Default::default()
        };
        assert_eq!(findings("a.jpg", &plain)[0].severity, Severity::Note);
        assert_eq!(findings("b.jpg", &with_serial)[0].severity, Severity::Warning);
    }

    #[test]
    fn a_stripped_photo_reports_nothing() {
        assert!(findings("clean.jpg", &ImageFacts::default()).is_empty());
    }
}
