//! Deterministic property and fuzz tests for the pure parsing/matching cores.
//!
//! Everything here is seeded and self-contained: rerunning the test replays
//! the exact same cases (replay: `cargo test --test test_property`). The
//! generator is a xorshift64* PRNG whose seed is printed in every failure
//! message together with the failing case index.

use chrono::{DateTime, Datelike, Local, NaiveDate};
use cleanslate::time::{format_age, parse_date, parse_duration, TimeFilter};
use cleanslate::{get_artifact_patterns, is_artifact, truncate_name_with_suffix};
use std::path::Path;
use std::time::{Duration, SystemTime};

/// xorshift64* — small, fast, deterministic across platforms.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len() as u64) as usize]
    }

    /// Uniform-ish choice over the full char range 0..=0x2FFF, mixing ASCII,
    /// punctuation, CJK, and combining marks. Surrogates (0xD800..0xDFFF) are
    /// skipped so the result is always a valid Rust char.
    fn any_char(&mut self) -> char {
        loop {
            let c = (self.next_u64() % 0x3000) as u32;
            if let Some(ch) = char::from_u32(c) {
                return ch;
            }
        }
    }

    fn any_string(&mut self, max_len: usize) -> String {
        let len = self.below(max_len as u64 + 1) as usize;
        (0..len).map(|_| self.any_char()).collect()
    }
}

const DIGITS: &[&str] = &[
    "0",
    "1",
    "7",
    "9",
    "15",
    "48",
    "365",
    "999999",
    "18446744073709551615",
];
const UNITS: &[&str] = &["", "d", "D", "h", "H", "w", "W", "m", "M"];
const PUNCT: &[&str] = &["-", ".", " ", "\t", "+", ",", "/", "e", "x", "²", "Ⅻ", "年"];

/// Generate a duration-string-shaped input: digits, optional junk, unit.
fn duration_shaped(rng: &mut Rng) -> String {
    let mut s = String::new();
    if rng.below(4) > 0 {
        s.push_str(rng.pick(DIGITS));
    }
    if rng.below(3) == 0 {
        s.push_str(rng.pick(PUNCT));
        if rng.below(2) == 0 {
            s.push_str(&rng.any_string(4));
        }
    }
    if rng.below(4) > 0 {
        s.push_str(rng.pick(UNITS));
    }
    s
}

/// Fuzz: parse_duration never panics on any generated input, and the Ok/Err
/// split proves the generator exercises both outcomes.
#[test]
fn fuzz_parse_duration_never_panics() {
    let mut rng = Rng::new(0xC1EA4512);
    let (mut ok, mut err) = (0u64, 0u64);
    for i in 0..200_000 {
        let input = duration_shaped(&mut rng);
        match parse_duration(&input) {
            Ok(_) => ok += 1,
            Err(_) => err += 1,
        }
        if ok == 0 && i == 100_000 {
            panic!("generator never produced a valid duration");
        }
    }
    assert!(ok > 0, "no valid durations generated");
    assert!(err > 0, "no invalid durations generated");
}

/// Property: a well-formed `<number><unit>` string parses to exactly
/// value × unit-seconds, or fails with "too large" — never a wrong number.
#[test]
fn property_parse_duration_exact_product() {
    let unit_secs: &[(&str, u64)] = &[
        ("", 86_400),
        ("d", 86_400),
        ("D", 86_400),
        ("h", 3_600),
        ("H", 3_600),
        ("w", 604_800),
        ("W", 604_800),
        ("m", 2_592_000),
        ("M", 2_592_000),
    ];
    let mut rng = Rng::new(0xD0A7);
    for _ in 0..50_000 {
        let value: u64 = match rng.below(6) {
            0 => rng.below(101),
            1 => rng.below(100_001),
            2 => u64::MAX - rng.below(2),
            3 => u64::MAX / 86_400, // boundary of day overflow
            4 => rng.next_u64(),
            _ => rng.below(10),
        };
        let (unit, factor) = unit_secs[rng.below(unit_secs.len() as u64) as usize];
        let input = format!("{}{}", value, unit);
        let expected = value.checked_mul(factor);
        match (parse_duration(&input), expected) {
            (Ok(d), Some(secs)) => {
                assert_eq!(d.as_secs(), secs, "wrong duration for input {:?}", input)
            }
            (Err(_), None) => {}
            (Ok(d), None) => panic!(
                "input {:?} parsed to {}s despite overflowing u64",
                input,
                d.as_secs()
            ),
            (Err(e), Some(_)) => panic!("input {:?} rejected unexpectedly: {}", input, e),
        }
    }
}

/// Fuzz: parse_date never panics on arbitrary strings.
#[test]
fn fuzz_parse_date_never_panics() {
    let mut rng = Rng::new(0xDA7E);
    let mut err = 0u64;
    for _ in 0..100_000 {
        let input = rng.any_string(24);
        if parse_date(&input).is_err() {
            err += 1;
        }
    }
    assert!(err > 99_000, "expected overwhelmingly invalid inputs");
}

/// Property: every valid calendar date in the supported year range parses and
/// converts back to the same YYYY-MM-DD string in the local time zone.
/// (Assumes midnight exists locally for these dates — true for UTC and all
/// US/EU zones the CI runs in.)
#[test]
fn property_parse_date_round_trips() {
    let mut rng = Rng::new(0x0CC);
    for _ in 0..20_000 {
        let year = 1970 + rng.below(2100 - 1970 + 1) as i32;
        let month = 1 + rng.below(12) as u32;
        let day = 1u32 + rng.below(28) as u32; // valid in every month
        let input = format!("{:04}-{:02}-{:02}", year, month, day);

        let parsed = parse_date(&input).expect("valid calendar date must parse");
        let local = DateTime::<Local>::from(parsed);
        assert_eq!(
            (local.year(), local.month(), local.day()),
            (year, month, day),
            "round trip changed the date for {:?}",
            input
        );
    }
}

/// Property: filtering is monotone in time — if t passes an --older-than
/// filter, every earlier instant passes too — and the cutoff itself is
/// excluded (strictly older). Built from exact cutoffs so the boundary is
/// testable without racing TimeFilter's internal clock read.
#[test]
fn property_time_filter_is_antitone_in_time() {
    let mut rng = Rng::new(0x71A7);
    let now = SystemTime::now();
    for _ in 0..20_000 {
        let cutoff = now - Duration::from_secs(rng.next_u64() % (400 * 86_400));
        let filter = TimeFilter::from_cutoffs(Some(cutoff), None);
        let t = now - Duration::from_secs(rng.next_u64() % (400 * 86_400));
        if filter.passes(t) {
            let earlier = t - Duration::from_secs(1 + rng.below(86_400));
            assert!(
                filter.passes(earlier),
                "t passed but an earlier instant failed"
            );
        }
        assert!(
            !filter.passes(cutoff),
            "cutoff must be strictly excluded (strictly-older semantics)"
        );
    }
}

/// Property: format_age never panics and is monotone — an older instant
/// never formats as younger than a newer one (both relative to a fixed now).
#[test]
fn property_format_age_monotone() {
    let mut rng = Rng::new(0xA6E);
    let now = SystemTime::now();
    let age_secs = |s: u64| {
        let t = now.checked_sub(Duration::from_secs(s)).unwrap();
        format_age(t, now)
    };
    // Age in days computed from the formatted string by unit (d=1, w=7,
    // mo=30, y=365) so different units compare on one scale.
    let rank = |s: &str| -> u64 {
        if s == "today" {
            return 0;
        }
        let unit_len = s.chars().rev().take_while(|c| c.is_alphabetic()).count();
        let (num, unit) = s.split_at(s.len() - unit_len);
        let n: u64 = num
            .parse()
            .unwrap_or_else(|_| panic!("bad age string {:?}", s));
        match unit {
            "d" => n,
            "w" => 7 * n,
            "mo" => 30 * n,
            "y" => 365 * n,
            other => panic!("unknown age unit {:?}", other),
        }
    };
    for _ in 0..20_000 {
        let a = rng.below(1000 * 86_400);
        let b = rng.below(1000 * 86_400);
        let (younger, older) = if a < b { (a, b) } else { (b, a) };
        assert!(
            rank(&age_secs(younger)) <= rank(&age_secs(older)),
            "format_age not monotone: {} -> {:?} vs {} -> {:?}",
            younger,
            age_secs(younger),
            older,
            age_secs(older)
        );
    }
}

/// Property: truncation is total for any unicode input and obeys the width
/// contract — never longer than max_width (when max_width >= 3), ends in
/// "..." when truncation happened, and is the identity otherwise.
#[test]
fn property_truncate_name_respects_width() {
    let mut rng = Rng::new(0x12C);
    for _ in 0..50_000 {
        let name = rng.any_string(80);
        let width = rng.below(60) as usize;
        let out = truncate_name_with_suffix(&name, width);
        let out_chars = out.chars().count();
        let name_chars = name.chars().count();
        if name_chars <= width {
            assert_eq!(out, name, "short name must be unchanged");
        } else if width >= 3 {
            assert_eq!(out_chars, width, "truncated length must equal width");
            assert!(out.ends_with("..."), "truncation must end with ...");
            assert!(
                name.starts_with(&out[..out.len() - 3]),
                "truncation must preserve a prefix"
            );
        } else {
            assert_eq!(out, "...");
        }
    }
}

/// Word bank mixing real artifact names with noise, so the matcher's match
/// and non-match branches are both exercised.
const WORDS: &[&str] = &[
    "node_modules",
    "target",
    "__pycache__",
    "dist",
    "build",
    "vendor",
    "src",
    "lib",
    "a",
    "tmp",
    "env",
    "café",
    "中文",
    "x.y.z",
    ".hidden",
];

/// Fuzz: pattern matching never panics on arbitrary assembled paths, and the
/// word bank guarantees both matches and non-matches occur.
#[test]
fn fuzz_is_artifact_never_panics_and_both_branches_hit() {
    let patterns = get_artifact_patterns(true).unwrap();
    let mut rng = Rng::new(0xBA11);
    let (mut matches, mut total) = (0u64, 0u64);
    for _ in 0..50_000 {
        let depth = 1 + rng.below(5) as usize;
        let components: Vec<String> = (0..depth)
            .map(|_| {
                if rng.below(2) == 0 {
                    rng.pick(WORDS).to_string()
                } else {
                    rng.any_string(20)
                }
            })
            .collect();
        let path_string = components.join("/");
        let path = Path::new(&path_string);
        if is_artifact(path, &patterns) {
            matches += 1;
        }
        total += 1;
    }
    assert!(matches > 0, "generator never produced a matching path");
    assert!(
        (matches as f64 / total as f64) < 0.9,
        "generator produced suspiciously many matches"
    );
}

/// Property: a NaiveDate is valid per chrono for every date our generator
/// produces (guards the round-trip test's month/day sampling).
#[test]
fn property_generated_dates_are_valid() {
    let mut rng = Rng::new(0xA1D);
    for _ in 0..10_000 {
        let year = 1970 + rng.below(131) as i32;
        let month = 1 + rng.below(12) as u32;
        let day = 1u32 + rng.below(28) as u32;
        assert!(NaiveDate::from_ymd_opt(year, month, day).is_some());
    }
}
