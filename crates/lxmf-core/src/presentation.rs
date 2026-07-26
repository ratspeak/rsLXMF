//! Safe presentation helpers for untrusted announce metadata.

use unicode_normalization::UnicodeNormalization;

/// Maximum retained characters for an advertised LXMF display/node name.
pub const MAX_ADVERTISED_NAME_CHARS: usize = 128;

/// Normalize and bound an untrusted display name.
///
/// The result is NFKC-normalized, contains no control or presentation-control
/// codepoints, collapses all Unicode whitespace to one ASCII space, and is
/// truncated by Unicode scalar values rather than UTF-8 bytes.
pub fn sanitize_name(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let mut output = String::new();
    let mut pending_space = false;
    let mut retained = 0usize;

    for character in input.nfkc() {
        if is_filtered_name_character(character) {
            continue;
        }
        if character.is_whitespace() {
            pending_space = !output.is_empty();
            continue;
        }
        if pending_space {
            // A collapsed separator is useful only when the current visible
            // character also fits. Never consume the final slot with a
            // trailing space that disappears on the next sanitization pass.
            if max_chars.saturating_sub(retained) < 2 {
                break;
            }
            output.push(' ');
            retained += 1;
            pending_space = false;
        }
        if retained == max_chars {
            break;
        }
        output.push(character);
        retained += 1;
    }

    output
}

fn is_filtered_name_character(character: char) -> bool {
    let codepoint = character as u32;
    character.is_control()
        || is_bidi_control(codepoint)
        || is_private_use(codepoint)
        || is_zero_width(codepoint)
        || is_variation_selector(codepoint)
        || is_emoji(codepoint)
}

fn is_bidi_control(codepoint: u32) -> bool {
    matches!(
        codepoint,
        0x061C
            | 0x200E
            | 0x200F
            | 0x202A..=0x202E
            | 0x2066..=0x2069
            | 0x206A..=0x206F
    )
}

fn is_private_use(codepoint: u32) -> bool {
    matches!(
        codepoint,
        0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD
    )
}

fn is_zero_width(codepoint: u32) -> bool {
    matches!(
        codepoint,
        0x034F | 0x180E | 0x200B..=0x200D | 0x2060 | 0xFEFF
    )
}

fn is_variation_selector(codepoint: u32) -> bool {
    matches!(codepoint, 0xFE00..=0xFE0F | 0xE0100..=0xE01EF)
}

// Bounded presentation policy, intentionally broader than a font-dependent
// emoji lookup. It covers the Unicode emoji blocks and legacy symbol ranges
// that gain emoji presentation through variation selectors.
fn is_emoji(codepoint: u32) -> bool {
    matches!(
        codepoint,
        0x00A9
            | 0x00AE
            | 0x203C
            | 0x2049
            | 0x2122
            | 0x2139
            | 0x2190..=0x21FF
            | 0x2300..=0x23FF
            | 0x2460..=0x24FF
            | 0x25A0..=0x27BF
            | 0x2934..=0x2935
            | 0x2B00..=0x2BFF
            | 0x3030
            | 0x303D
            | 0x3297
            | 0x3299
            | 0x1F000..=0x1FAFF
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn normalizes_nfkc_and_collapses_unicode_whitespace() {
        assert_eq!(
            sanitize_name("  ＲＮＳ\u{00A0}\tCommunity  ", 128),
            "RNS Community"
        );
    }

    #[test]
    fn removes_controls_bidi_private_use_emoji_variants_and_zero_width() {
        let hostile = "safe\n\u{202E}txt\u{E000}\u{1F680}\u{FE0F}\u{200D} name";
        assert_eq!(sanitize_name(hostile, 128), "safetxt name");
    }

    #[test]
    fn truncates_multibyte_text_by_characters_without_panicking() {
        assert_eq!(sanitize_name("Ångström東京", 8), "Ångström");
        assert_eq!(sanitize_name("東京通信", 3), "東京通");
        assert_eq!(sanitize_name("anything", 0), "");
    }

    #[test]
    fn truncation_never_retains_a_separator_without_following_text() {
        assert_eq!(sanitize_name("¡ A", 2), "¡");
        assert_eq!(sanitize_name("A B", 3), "A B");
    }

    proptest! {
        #[test]
        fn arbitrary_utf8_is_bounded_and_idempotent(input in ".*", limit in 0usize..256) {
            let sanitized = sanitize_name(&input, limit);
            prop_assert!(sanitized.chars().count() <= limit);
            prop_assert_eq!(sanitize_name(&sanitized, limit), sanitized);
        }
    }
}
