//! Confusables and homoglyph fuzz corpus for the target dimension.
//!
//! A deterministic seeded generator (an lcg entirely in 31-bit integer
//! arithmetic, so PHP and Rust walk the identical stream) mutates a small
//! base corpus ~5000 times with confusable-class mutations: fullwidth
//! mapping, ASCII case flips, whitespace padding, dot/plus/hyphen tag
//! insertion, accent injection and Cyrillic homoglyph substitution.
//!
//! Every mutation carries its own rule-model expectation, independent of
//! the implementation: the aliasing classes (nfkc folding, table provider
//! rules) must collapse onto one target pseudonym, while the look-alike
//! classes (accents, Cyrillic homoglyphs, embedded spaces, plus tags and
//! dots at providers outside the table) must stay distinct targets. Pin
//! both directions: under-normalizing splits one mailbox into many
//! targets, over-normalizing merges two mailboxes into one.

use kiwicaptcha_risk::identity::RiskIdentityFactory;
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::target::normalize_target;

const SEED: u64 = 0x6b6b_6b01;
const MUTATIONS: usize = 5000;

/// Base corpus with the provider class: g = gmail dots+plus, p = plus
/// tag, h = hyphen tag, n = none.
const BASES: &[(&str, &str)] = &[
    ("user.one@gmail.com", "g"),
    ("ali.ce.b+shop@gmail.com", "g"),
    ("bob.mailbox@googlemail.com", "g"),
    ("carol.last+news@outlook.com", "p"),
    ("dana.q+tag@live.com", "p"),
    ("evan.t+cart@hotmail.com", "p"),
    ("fiona+cloud@icloud.com", "p"),
    ("greg.h-ytag@yahoo.com", "h"),
    ("hilda@proton.me", "n"),
    ("ivan@fastmail.com", "n"),
    ("plainuser", "n"),
    ("mixed.Case@Example.COM", "n"),
];

/// Cyrillic look-alikes with no nfkc fold onto the Latin letter.
const CYRILLIC: &[(char, char)] = &[
    ('a', 'а'),
    ('e', 'е'),
    ('o', 'о'),
    ('p', 'р'),
    ('c', 'с'),
    ('y', 'у'),
    ('x', 'х'),
    ('i', 'і'),
    ('j', 'ј'),
    ('s', 'ѕ'),
];

/// 31-bit lcg: identical stream in PHP and Rust (the u31 product fits
/// both integer domains exactly).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = (self.0.wrapping_mul(1103515245).wrapping_add(12345)) & 0x7FFF_FFFF;
        self.0
    }

    fn pick(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Maps one ASCII char to its fullwidth form where one exists.
fn fullwidth(ch: char) -> char {
    match ch {
        '0'..='9' => char::from_u32(0xFF10 + ch as u32 - '0' as u32).unwrap(),
        'A'..='Z' => char::from_u32(0xFF21 + ch as u32 - 'A' as u32).unwrap(),
        'a'..='z' => char::from_u32(0xFF41 + ch as u32 - 'a' as u32).unwrap(),
        '@' => '\u{FF20}',
        '.' => '\u{FF0E}',
        '+' => '\u{FF0B}',
        '-' => '\u{FF0D}',
        other => other,
    }
}

/// The local part of an email base (the insertion range for provider tag
/// mutations); a plain identifier is its own range.
fn local_range(base: &str) -> usize {
    match base.rfind('@') {
        Some(at) => at,
        None => base.len(),
    }
}

/// The length of the base's provider-visible prefix: the part of the
/// identifier that survives the class's strip rules. Mutations whose
/// distinctness is asserted must land inside it, or the strip rule would
/// swallow them and fake a collapse.
fn visible_length(base: &str, class: &str) -> usize {
    let local = &base[..local_range(base)];
    let marker = match class {
        "g" | "p" => local.find('+'),
        "h" => local.find('-'),
        _ => None,
    };
    marker.unwrap_or(base.len())
}

/// The insertion index for a tag/dot mutation, chosen so the mutation
/// lands where the provider rules leave it visible unless the class
/// legitimately folds it: a stripping provider appends its own tag at the
/// end (the real-world aliasing form), while the non-folding insertions
/// stay ahead of any existing tag marker so a strip rule cannot swallow
/// them and fake a collapse.
fn insertion_index(rng: &mut Lcg, base: &str, class: &str, kind: u8) -> usize {
    let local = &base[..local_range(base)];
    let first_plus = local.find('+');
    let first_hyphen = local.find('-');
    let mut rand = || rng.pick(local.len() + 1);
    match kind {
        // Plus tags: appended at the stripping providers, ahead of a
        // hyphen rule elsewhere.
        4 => match class {
            "g" | "p" => local.len(),
            "h" => first_hyphen.unwrap_or_else(rand),
            _ => rand(),
        },
        // Hyphen tags: appended at the stripping provider, ahead of a
        // plus rule elsewhere.
        8 => match class {
            "h" => local.len(),
            "g" | "p" => first_plus.unwrap_or_else(rand),
            _ => rand(),
        },
        // Dots fold only at gmail; elsewhere they must stay visible.
        _ => match class {
            "g" => rand(),
            "p" => first_plus.unwrap_or_else(rand),
            "h" => first_hyphen.unwrap_or_else(rand),
            _ => rand(),
        },
    }
}

/// Applies one mutation of the given kind; `None` when the base offers no
/// position for that kind (a counted skip, never a silent one). The
/// provider class steers the tag insertions so the rule model's
/// expectation holds by construction.
fn mutate(rng: &mut Lcg, base: &str, class: &str, kind: u8) -> Option<String> {
    match kind {
        // Fullwidth window.
        0 => {
            let chars: Vec<char> = base.chars().collect();
            let start = rng.pick(chars.len());
            let span = 1 + rng.pick(4);
            let out: String = chars
                .iter()
                .enumerate()
                .map(|(j, c)| {
                    if j >= start && j < start + span {
                        fullwidth(*c)
                    } else {
                        *c
                    }
                })
                .collect();
            Some(out)
        }
        // ASCII case flips.
        1 => {
            let mut out = String::with_capacity(base.len());
            for ch in base.chars() {
                if ch.is_ascii_alphabetic() && rng.pick(2) == 0 {
                    out.push(if ch.is_ascii_lowercase() {
                        ch.to_ascii_uppercase()
                    } else {
                        ch.to_ascii_lowercase()
                    });
                } else {
                    out.push(ch);
                }
            }
            Some(out)
        }
        // Whitespace edges (space, tab, nbsp; nfkc folds nbsp).
        2 => {
            let pads = [" \t", "\u{a0}\u{a0}", "  "];
            let left = pads[rng.pick(pads.len())];
            let right = pads[rng.pick(pads.len())];
            Some(format!("{left}{base}{right}"))
        }
        // Dot / plus-tag / hyphen-tag insertion inside the local part.
        3 | 4 | 8 => {
            let at = insertion_index(rng, base, class, kind);
            let insert = match kind {
                3 => ".".to_string(),
                4 => format!("+t{}", rng.pick(10)),
                _ => format!("-y{}", rng.pick(10)),
            };
            Some(format!("{}{}{}", &base[..at], insert, &base[at..]))
        }
        // Accent injection: one ASCII alnum becomes e-acute.
        5 => {
            let visible = visible_length(base, class);
            for _ in 0..8 {
                let at = rng.pick(visible);
                if let Some(ch) = base[..].chars().nth(at) {
                    if ch.is_ascii_alphanumeric() {
                        let mut out = base[..at].to_string();
                        out.push('\u{e9}');
                        out.push_str(&base[at + ch.len_utf8()..]);
                        return Some(out);
                    }
                }
            }
            None
        }
        // Cyrillic homoglyph substitution.
        6 => {
            let visible = visible_length(base, class);
            let targets: Vec<usize> = base[..visible]
                .char_indices()
                .filter_map(|(at, ch)| CYRILLIC.iter().find(|(latin, _)| *latin == ch).map(|_| at))
                .collect();
            if targets.is_empty() {
                return None;
            }
            let at = targets[rng.pick(targets.len())];
            let homoglyph = CYRILLIC
                .iter()
                .find(|(latin, _)| base[..].chars().nth(at) == Some(*latin))
                .map(|(_, cyrillic)| *cyrillic)
                .expect("the target index maps to a look-alike");
            let mut out = base[..at].to_string();
            out.push(homoglyph);
            // The replaced Latin letter is one ASCII byte.
            out.push_str(&base[at + 1..]);
            Some(out)
        }
        // Embedded space at an interior position.
        7 => {
            let visible = visible_length(base, class);
            if visible < 2 {
                return None;
            }
            let at = 1 + rng.pick(visible - 1);
            Some(format!("{} {}", &base[..at], &base[at..]))
        }
        _ => unreachable!("nine mutation kinds"),
    }
}

#[test]
fn fuzz_corpus_collapses_and_splits_per_the_rule_model() {
    let factory = RiskIdentityFactory::new(RiskKeys::from_master(&[0x42; 32]));
    let id_of = |raw: &str| factory.target_id(&normalize_target(raw));
    let normalized = |raw: &str| normalize_target(raw);

    let mut rng = Lcg(SEED);
    let mut counts = [0usize; 9];
    for i in 0..MUTATIONS {
        let (base, class) = BASES[rng.pick(BASES.len())];
        let kind = rng.pick(9) as u8;
        counts[kind as usize] += 1;
        let Some(variant) = mutate(&mut rng, base, class, kind) else {
            continue;
        };

        // The rule model, stated per mutation class and provider class,
        // decides the expectation before the pipeline runs.
        let collapses = match kind {
            0..=2 => true,                     // fullwidth, case flip, whitespace edges
            3 => class == "g",                 // dot insertion only folds at gmail
            4 => class == "g" || class == "p", // plus tags fold at table providers
            5 => false,                        // accent injection never folds
            6 => false,                        // Cyrillic homoglyphs never fold
            7 => false,                        // embedded whitespace is part of the identifier
            _ => class == "h",                 // hyphen tags fold only at yahoo
        };

        let base_norm = normalized(base);
        if collapses {
            assert_eq!(
                normalized(&variant),
                base_norm,
                "mutation {i} of {:02x?} must normalize onto the base (kind {kind})",
                variant.as_bytes()
            );
            assert_eq!(
                id_of(&variant),
                id_of(base),
                "mutation {i} of {:02x?} must collapse onto one target (kind {kind})",
                variant.as_bytes()
            );
        } else {
            assert_ne!(
                normalized(&variant),
                base_norm,
                "mutation {i} of {:02x?} must stay a distinct identifier (kind {kind})",
                variant.as_bytes()
            );
            assert_ne!(
                id_of(&variant),
                id_of(base),
                "mutation {i} of {:02x?} must stay a distinct target (kind {kind})",
                variant.as_bytes()
            );
        }
    }

    // Every mutation family must have been exercised (a family that
    // silently stops generating would hollow out the corpus).
    for (kind, count) in counts.iter().enumerate() {
        assert!(
            *count > 150,
            "mutation kind {kind} must stay exercised ({count} samples)"
        );
    }
    assert!(counts.iter().sum::<usize>() >= MUTATIONS);
}
