//! Finding personal data in text, without the false alarms.
//!
//! Regex alone is why most scanners get ignored: every 16-digit order number
//! becomes a "credit card" and every long hex string becomes a "secret". Here
//! each candidate is validated - card numbers by Luhn, IBANs by ISO 7064
//! mod-97, and everything is reported with the count, not the value.

use std::collections::BTreeMap;

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Email,
    Phone,
    Iban,
    CardNumber,
    ApiKey,
    PrivateKey,
    NationalId,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Email => "e-mail address",
            Kind::Phone => "phone number",
            Kind::Iban => "IBAN",
            Kind::CardNumber => "payment card number",
            Kind::ApiKey => "API key or token",
            Kind::PrivateKey => "private key",
            Kind::NationalId => "national ID number",
        }
    }

    /// Card numbers and keys are a different order of problem to an e-mail
    /// address on a letterhead.
    pub fn is_critical(self) -> bool {
        matches!(self, Kind::CardNumber | Kind::PrivateKey | Kind::ApiKey | Kind::Iban)
    }
}

/// Redact a value so a report can be read over someone's shoulder.
pub fn mask(value: &str) -> String {
    let visible: Vec<char> = value.chars().filter(|c| !c.is_whitespace()).collect();
    match visible.len() {
        0..=4 => "*".repeat(visible.len()),
        len => format!(
            "{}{}{}",
            visible[..2].iter().collect::<String>(),
            "*".repeat(len - 4),
            visible[len - 2..].iter().collect::<String>()
        ),
    }
}

/// ISO/IEC 7812 check digit. Rejects the order numbers that look like cards.
pub fn luhn_valid(digits: &str) -> bool {
    let digits: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, &digit)| {
            if index % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                digit
            }
        })
        .sum();
    sum % 10 == 0
}

/// ISO 7064 mod-97-10, the check every real IBAN passes and no invoice number does.
pub fn iban_valid(candidate: &str) -> bool {
    let cleaned: String = candidate.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if cleaned.len() < 15 || cleaned.len() > 34 {
        return false;
    }
    let (head, tail) = cleaned.split_at(4);
    let rearranged = format!("{tail}{head}");

    let mut remainder: u32 = 0;
    for character in rearranged.chars() {
        let value = if character.is_ascii_digit() {
            character.to_digit(10).unwrap()
        } else if character.is_ascii_alphabetic() {
            character.to_ascii_uppercase() as u32 - 'A' as u32 + 10
        } else {
            return false;
        };
        // Two-digit letters have to be fed in as two digits.
        remainder = if value > 9 {
            (remainder * 100 + value) % 97
        } else {
            (remainder * 10 + value) % 97
        };
    }
    remainder == 1
}

pub struct Detector {
    email: Regex,
    phone: Regex,
    iban: Regex,
    card: Regex,
    api_key: Regex,
    private_key: Regex,
    national_id: Regex,
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector {
    pub fn new() -> Self {
        Self {
            email: Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b").unwrap(),
            // International or long national numbers only: short digit runs are
            // dates, quantities and reference numbers.
            phone: Regex::new(r"(?:\+|00)\d[\d\s().\-]{8,16}\d").unwrap(),
            iban: Regex::new(r"\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b").unwrap(),
            card: Regex::new(r"\b(?:\d[ \-]?){12,18}\d\b").unwrap(),
            api_key: Regex::new(
                r"(?x)
                  AKIA[0-9A-Z]{16}
                | gh[pousr]_[A-Za-z0-9]{30,}
                | xox[baprs]-[0-9A-Za-z\-]{10,}
                | sk-[A-Za-z0-9]{20,}
                | AIza[0-9A-Za-z_\-]{35}
                | (?i:bearer)\s+[A-Za-z0-9._\-]{25,}
                ",
            )
            .unwrap(),
            private_key: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----").unwrap(),
            // German tax ID / similar 11-digit national numbers, only when labelled.
            national_id: Regex::new(
                r"(?i)\b(?:steuer[- ]?id|tax\s?id|ssn|national\s?insurance|nino|pesel|inn)\b\D{0,12}([A-Z0-9][A-Z0-9 \-]{6,14})",
            )
            .unwrap(),
        }
    }

    /// Count each kind of personal data, keeping one masked example per kind.
    pub fn scan(&self, text: &str) -> Vec<Hit> {
        let mut counts: BTreeMap<Kind, (usize, String)> = BTreeMap::new();

        let mut record = |kind: Kind, sample: &str| {
            let entry = counts.entry(kind).or_insert_with(|| (0, mask(sample)));
            entry.0 += 1;
        };

        for found in self.email.find_iter(text) {
            record(Kind::Email, found.as_str());
        }

        // Strong, validated matches go first, and are then blanked out of the
        // text: an IBAN contains a digit run that the phone pattern would
        // otherwise report a second time.
        let mut remaining: Vec<char> = text.chars().collect();
        let consume = |range: std::ops::Range<usize>, remaining: &mut Vec<char>| {
            let start = text[..range.start].chars().count();
            let length = text[range.clone()].chars().count();
            for slot in remaining.iter_mut().skip(start).take(length) {
                *slot = ' ';
            }
        };

        for found in self.iban.find_iter(text) {
            if iban_valid(found.as_str()) {
                record(Kind::Iban, found.as_str());
                consume(found.range(), &mut remaining);
            }
        }
        for found in self.card.find_iter(text) {
            let digits: String = found.as_str().chars().filter(char::is_ascii_digit).collect();
            if luhn_valid(&digits) {
                record(Kind::CardNumber, found.as_str());
                consume(found.range(), &mut remaining);
            }
        }

        let text_without_accounts: String = remaining.into_iter().collect();
        for found in self.phone.find_iter(&text_without_accounts) {
            record(Kind::Phone, found.as_str());
        }
        for found in self.api_key.find_iter(text) {
            record(Kind::ApiKey, found.as_str());
        }
        for found in self.private_key.find_iter(text) {
            record(Kind::PrivateKey, found.as_str());
        }
        for captures in self.national_id.captures_iter(&text_without_accounts) {
            if let Some(value) = captures.get(1) {
                record(Kind::NationalId, value.as_str());
            }
        }

        counts
            .into_iter()
            .map(|(kind, (count, sample))| Hit { kind, count, sample })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub kind: Kind,
    pub count: usize,
    pub sample: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_real_test_numbers() {
        // The card numbers every payment provider publishes for testing.
        for number in ["4242424242424242", "5555555555554444", "378282246310005"] {
            assert!(luhn_valid(number), "{number} should pass");
        }
    }

    #[test]
    fn luhn_rejects_order_numbers() {
        // Note the limit of this check: Luhn is a single check digit, so about
        // one random 16-digit number in ten passes it. It kills most false
        // positives, not all of them. (1111222233334444 happens to pass.)
        for number in ["4242424242424241", "1234567890123456", "9999888877776665"] {
            assert!(!luhn_valid(number), "{number} should fail");
        }
    }

    #[test]
    fn luhn_rejects_wrong_lengths() {
        assert!(!luhn_valid("42424242"));                    // too short
        assert!(!luhn_valid("42424242424242424242"));        // too long
    }

    #[test]
    fn iban_accepts_valid_examples() {
        for iban in ["GB82 WEST 1234 5698 7654 32", "DE89370400440532013000", "FR1420041010050500013M02606"] {
            assert!(iban_valid(iban), "{iban} should pass");
        }
    }

    #[test]
    fn iban_rejects_a_transposed_digit() {
        assert!(!iban_valid("DE89370400440532013001"));
        assert!(!iban_valid("GB82WEST12345698765433"));
    }

    #[test]
    fn masking_keeps_only_the_ends() {
        assert_eq!(mask("4242424242424242"), "42************42");
        assert_eq!(mask("ab"), "**");
        assert_eq!(mask("john.doe@example.com"), "jo****************om");
    }

    #[test]
    fn a_card_number_is_found_and_an_invoice_number_is_not() {
        let detector = Detector::new();
        let hits = detector.scan("Paid with 4242 4242 4242 4242 against invoice 1234567890123456");
        let cards: Vec<&Hit> = hits.iter().filter(|hit| hit.kind == Kind::CardNumber).collect();
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].count, 1);
    }

    #[test]
    fn an_iban_is_found_and_a_reference_is_not() {
        let detector = Detector::new();
        let hits = detector.scan("Transfer to DE89 3704 0044 0532 0130 00, ref XX00 1234 5678 9012 3456");
        assert!(hits.iter().any(|hit| hit.kind == Kind::Iban && hit.count == 1));
    }

    #[test]
    fn emails_and_phones_are_counted_not_listed() {
        let detector = Detector::new();
        let text = "a@b.com, c@d.org, call +49 170 555 2418 or +44 20 7946 0958";
        let hits = detector.scan(text);
        let emails = hits.iter().find(|hit| hit.kind == Kind::Email).unwrap();
        let phones = hits.iter().find(|hit| hit.kind == Kind::Phone).unwrap();
        assert_eq!(emails.count, 2);
        assert_eq!(phones.count, 2);
        assert!(!emails.sample.contains("a@b.com"));
    }

    #[test]
    fn an_iban_is_not_counted_again_as_a_phone_number() {
        let detector = Detector::new();
        let hits = detector.scan("Bank: DE89 3704 0044 0532 0130 00, phone +49 170 555 2418");
        let phones = hits.iter().find(|hit| hit.kind == Kind::Phone).unwrap();
        assert_eq!(phones.count, 1, "the IBAN digits must not count as a second number");
    }

    #[test]
    fn short_digit_runs_are_not_phone_numbers() {
        let detector = Detector::new();
        let hits = detector.scan("Order 2026-08-22 for 12 units at 45.00 each, total 540.00");
        assert!(hits.is_empty(), "got {hits:?}");
    }

    #[test]
    fn keys_and_tokens_are_caught() {
        let detector = Detector::new();
        // pragma: allowlist secret - test fixtures, no real credentials here
        let text = format!(
            "AKIA{}\n-----BEGIN RSA PRIVATE KEY-----\nAuthorization: Bearer {}", // pragma: allowlist secret
            "ABCDEFGHIJKLMNOP",
            "a".repeat(40)
        );
        let hits = detector.scan(&text);
        assert!(hits.iter().any(|hit| hit.kind == Kind::ApiKey));
        assert!(hits.iter().any(|hit| hit.kind == Kind::PrivateKey));
    }

    #[test]
    fn a_national_id_is_only_flagged_when_labelled() {
        let detector = Detector::new();
        let labelled = detector.scan("Steuer-ID: 12 345 678 901");
        let bare = detector.scan("Reference 12 345 678 901");
        assert!(labelled.iter().any(|hit| hit.kind == Kind::NationalId));
        assert!(!bare.iter().any(|hit| hit.kind == Kind::NationalId));
    }

    #[test]
    fn clean_text_produces_nothing() {
        let detector = Detector::new();
        assert!(detector.scan("The quarterly report shows growth of 12% across three regions.").is_empty());
    }
}
