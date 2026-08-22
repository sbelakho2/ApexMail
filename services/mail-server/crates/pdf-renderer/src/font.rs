//! Minimal TrueType font parsing for PDF embedding.
//!
//! The renderer embeds real Unicode fonts as PDF `/Type0` CID fonts with
//! `Identity-H` encoding. That requires exactly three things from the font
//! file — no outline parsing at all (the PDF viewer reads the raw `glyf`
//! data from the embedded `FontFile2` stream itself):
//!
//! * `cmap` — codepoint → glyph ID (formats 4 and 12),
//! * `hmtx`/`hhea` — advance widths for the `/W` array and layout,
//! * `head`/`maxp` — unitsPerEm, glyph count, and the FontBBox.
//!
//! The repo has a history of corrupt committed TTFs (scrambled table
//! directories), so the parser validates structure strictly and every
//! lookup is bounds-checked; a malformed table is an error, never a panic.

use std::collections::HashMap;

/// Parsed TrueType font, borrowing the raw asset bytes.
pub struct TtfFont {
    data: Vec<u8>,
    units_per_em: u16,
    num_glyphs: u16,
    number_of_h_metrics: u16,
    hmtx_offset: usize,
    hmtx_len: usize,
    /// Codepoint → glyph ID (0 entries are skipped: glyph 0 is .notdef).
    cmap: HashMap<u32, u16>,
    /// head xMin/yMin/xMax/yMax — used verbatim as the PDF FontBBox.
    bbox: [i16; 4],
    ascent: i16,
    descent: i16,
}

#[derive(Debug, thiserror::Error)]
pub enum FontError {
    #[error("font file truncated ({needed} bytes needed at offset {offset})")]
    Truncated { offset: usize, needed: usize },
    #[error("unsupported sfnt version 0x{0:08x} (need a TrueType glyf font, not CFF/OTTO)")]
    UnsupportedVersion(u32),
    #[error("required table '{0}' missing")]
    MissingTable(&'static str),
    #[error("cmap has no usable Unicode subtable")]
    NoUnicodeCmap,
}

fn be_u16(data: &[u8], offset: usize) -> Result<u16, FontError> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or(FontError::Truncated { offset, needed: 2 })?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn be_i16(data: &[u8], offset: usize) -> Result<i16, FontError> {
    Ok(be_u16(data, offset)? as i16)
}

fn be_u32(data: &[u8], offset: usize) -> Result<u32, FontError> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or(FontError::Truncated { offset, needed: 4 })?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

impl TtfFont {
    /// Parse a TrueType font from raw bytes. Accepts the 0x00010000 and
    /// `true` sfnt versions; rejects OTTO (CFF outlines cannot back a
    /// CIDFontType2 / FontFile2 embedding).
    pub fn parse(data: Vec<u8>) -> Result<Self, FontError> {
        // 12-byte sfnt header: version, numTables, searchRange,
        // entrySelector, rangeShift.
        if data.len() < 12 {
            return Err(FontError::Truncated {
                offset: 0,
                needed: 12,
            });
        }
        let version = be_u32(&data, 0)?;
        if version != 0x0001_0000 && version != u32::from_be_bytes(*b"true") {
            return Err(FontError::UnsupportedVersion(version));
        }
        let num_tables = be_u16(&data, 4)? as usize;

        // Table directory: 16-byte records (tag, checksum, offset, length).
        let mut tables: Vec<([u8; 4], usize, usize)> = Vec::with_capacity(num_tables);
        for i in 0..num_tables {
            let rec = 12 + i * 16;
            if data.len() < rec + 16 {
                return Err(FontError::Truncated {
                    offset: rec,
                    needed: 16,
                });
            }
            let tag = [data[rec], data[rec + 1], data[rec + 2], data[rec + 3]];
            let offset = be_u32(&data, rec + 8)? as usize;
            let length = be_u32(&data, rec + 12)? as usize;
            if offset
                .checked_add(length)
                .is_none_or(|end| end > data.len())
            {
                return Err(FontError::Truncated {
                    offset,
                    needed: length,
                });
            }
            tables.push((tag, offset, length));
        }
        let table = |tag: &[u8; 4]| -> Option<usize> {
            tables
                .iter()
                .find(|(t, _, _)| t == tag)
                .map(|(_, off, _)| *off)
        };

        // head: unitsPerEm @18, FontBBox @36..44, indexToLocFormat unused here.
        let head = table(b"head").ok_or(FontError::MissingTable("head"))?;
        let units_per_em = be_u16(&data, head + 18)?;
        if units_per_em == 0 {
            return Err(FontError::Truncated {
                offset: head + 18,
                needed: 2,
            });
        }
        let bbox = [
            be_i16(&data, head + 36)?,
            be_i16(&data, head + 38)?,
            be_i16(&data, head + 40)?,
            be_i16(&data, head + 42)?,
        ];

        // maxp: numGlyphs @4.
        let maxp = table(b"maxp").ok_or(FontError::MissingTable("maxp"))?;
        let num_glyphs = be_u16(&data, maxp + 4)?;

        // hhea: ascender @4, descender @6, numberOfHMetrics @34.
        let hhea = table(b"hhea").ok_or(FontError::MissingTable("hhea"))?;
        let ascent = be_i16(&data, hhea + 4)?;
        let descent = be_i16(&data, hhea + 6)?;
        let number_of_h_metrics = be_u16(&data, hhea + 34)?;
        if number_of_h_metrics == 0 {
            return Err(FontError::Truncated {
                offset: hhea + 34,
                needed: 2,
            });
        }

        let (hmtx_offset, hmtx_len) = tables
            .iter()
            .find(|(t, _, _)| t == b"hmtx")
            .map(|(_, off, len)| (*off, *len))
            .ok_or(FontError::MissingTable("hmtx"))?;

        // cmap: merge every Unicode-capable subtable (formats 4 and 12).
        let cmap_offset = table(b"cmap").ok_or(FontError::MissingTable("cmap"))?;
        let mut cmap = HashMap::new();
        let subtable_count = be_u16(&data, cmap_offset + 2)? as usize;
        for i in 0..subtable_count {
            let rec = cmap_offset + 4 + i * 8;
            if rec + 8 > data.len() {
                return Err(FontError::Truncated {
                    offset: rec,
                    needed: 8,
                });
            }
            let platform = be_u16(&data, rec)?;
            let encoding = be_u16(&data, rec + 2)?;
            let sub_off = cmap_offset + be_u32(&data, rec + 4)? as usize;
            let unicode = (platform == 3 && (encoding == 1 || encoding == 10))
                || (platform == 0 && encoding >= 3);
            if !unicode || sub_off >= data.len() {
                continue;
            }
            match be_u16(&data, sub_off)? {
                4 => parse_cmap4(&data, sub_off, &mut cmap)?,
                12 => parse_cmap12(&data, sub_off, &mut cmap)?,
                _ => {}
            }
        }
        if cmap.is_empty() {
            return Err(FontError::NoUnicodeCmap);
        }

        Ok(Self {
            data,
            units_per_em,
            num_glyphs,
            number_of_h_metrics,
            hmtx_offset,
            hmtx_len,
            cmap,
            bbox,
            ascent,
            descent,
        })
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn units_per_em(&self) -> u16 {
        self.units_per_em
    }

    pub fn num_glyphs(&self) -> u16 {
        self.num_glyphs
    }

    /// head FontBBox (xMin, yMin, xMax, yMax) in font units.
    pub fn bbox(&self) -> [i16; 4] {
        self.bbox
    }

    pub fn ascent(&self) -> i16 {
        self.ascent
    }

    pub fn descent(&self) -> i16 {
        self.descent
    }

    /// Glyph ID for a codepoint, or None when the font lacks the glyph.
    pub fn glyph(&self, ch: char) -> Option<u16> {
        self.cmap.get(&(ch as u32)).copied().filter(|gid| *gid != 0)
    }

    pub fn covers(&self, ch: char) -> bool {
        self.glyph(ch).is_some()
    }

    /// Advance width (font units) for a glyph. Glyphs past the hmtx
    /// long-metrics section share the last metric's advance, per spec.
    pub fn advance(&self, gid: u16) -> u16 {
        let idx = if (gid as usize) < self.number_of_h_metrics as usize {
            gid as usize
        } else {
            self.number_of_h_metrics as usize - 1
        };
        let offset = self.hmtx_offset + idx * 4;
        be_u16(&self.data, offset).unwrap_or(0)
    }

    /// Width in points for a glyph at the given font size.
    pub fn advance_pt(&self, gid: u16, font_size: f64) -> f64 {
        f64::from(self.advance(gid)) * font_size / f64::from(self.units_per_em)
    }

    /// Reverse map for tests: glyph ID → a representative codepoint.
    pub fn reverse_map(&self) -> HashMap<u16, char> {
        let mut rev = HashMap::with_capacity(self.cmap.len());
        for (&cp, &gid) in &self.cmap {
            if gid != 0 {
                rev.entry(gid).or_insert_with(|| {
                    char::from_u32(cp)
                        .filter(|c| *c != '\0')
                        .unwrap_or('\u{FFFD}')
                });
            }
        }
        rev
    }

    /// True when the hmtx table is internally consistent (used by tests).
    pub fn hmtx_is_sane(&self) -> bool {
        let needed = self.number_of_h_metrics as usize * 4
            + (self.num_glyphs as usize - self.number_of_h_metrics as usize) * 2;
        self.hmtx_len >= needed
    }
}

/// cmap subtable format 4 (segmented 16-bit mapping, BMP).
fn parse_cmap4(data: &[u8], offset: usize, map: &mut HashMap<u32, u16>) -> Result<(), FontError> {
    let seg_count_x2 = be_u16(data, offset + 6)? as usize;
    if !seg_count_x2.is_multiple_of(2) {
        return Err(FontError::Truncated {
            offset,
            needed: seg_count_x2,
        });
    }
    let seg_count = seg_count_x2 / 2;
    let end_codes = offset + 14;
    let start_codes = end_codes + seg_count_x2 + 2;
    let id_deltas = start_codes + seg_count_x2;
    let id_range_offsets = id_deltas + seg_count_x2;
    // Bounds-check the whole record block once.
    let _ = be_u16(data, id_range_offsets + seg_count_x2.saturating_sub(1))?;

    for seg in 0..seg_count {
        let end = be_u16(data, end_codes + seg * 2)? as u32;
        let start = be_u16(data, start_codes + seg * 2)? as u32;
        let delta = be_u16(data, id_deltas + seg * 2)? as i32 as u32;
        let range_offset = be_u16(data, id_range_offsets + seg * 2)? as usize;
        if start > end || start > 0xFFFF {
            continue;
        }
        if range_offset == 0 {
            for cp in start..=end.min(0xFFFF) {
                let gid = (cp.wrapping_add(delta)) & 0xFFFF;
                if gid != 0 {
                    map.entry(cp).or_insert(gid as u16);
                }
            }
        } else {
            let glyph_id_base = id_range_offsets + seg * 2;
            for (i, cp) in (start..=end.min(0xFFFF)).enumerate() {
                let addr = glyph_id_base + range_offset + i * 2;
                let gid = be_u16(data, addr)?;
                if gid != 0 {
                    let final_gid = (gid as u32).wrapping_add(delta) & 0xFFFF;
                    if final_gid != 0 {
                        map.entry(cp).or_insert(final_gid as u16);
                    }
                }
            }
        }
    }
    Ok(())
}

/// cmap subtable format 12 (segmented 32-bit mapping, full Unicode).
fn parse_cmap12(data: &[u8], offset: usize, map: &mut HashMap<u32, u16>) -> Result<(), FontError> {
    let n_groups = be_u32(data, offset + 12)? as usize;
    for g in 0..n_groups {
        let rec = offset + 16 + g * 12;
        let start = be_u32(data, rec)?;
        let end = be_u32(data, rec + 4)?;
        let start_gid = be_u32(data, rec + 8)?;
        if start > end {
            continue;
        }
        // Cap the expansion so a hostile table cannot OOM the process;
        // real Noto groups are contiguous, well below this span.
        let span = end - start;
        if span > 0x10_FFFF {
            continue;
        }
        for (i, cp) in (start..=end).enumerate() {
            let gid = start_gid + i as u32;
            if gid != 0 && gid <= 0xFFFF {
                map.entry(cp).or_insert(gid as u16);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noto_sans() -> TtfFont {
        TtfFont::parse(include_bytes!("../assets/fonts/NotoSans-Regular.ttf").to_vec())
            .expect("NotoSans-Regular.ttf parses")
    }

    fn noto_sans_sc() -> TtfFont {
        TtfFont::parse(include_bytes!("../assets/fonts/NotoSansSC-Regular.ttf").to_vec())
            .expect("NotoSansSC-Regular.ttf parses")
    }

    #[test]
    fn parses_head_hhea_maxp_of_both_fonts() {
        let sans = noto_sans();
        assert_eq!(sans.units_per_em(), 1000);
        assert!(sans.num_glyphs() > 1000);
        let bbox = sans.bbox();
        assert!(bbox[0] < 0 && bbox[1] < 0 && bbox[2] > 0 && bbox[3] > 0);
        assert!(sans.ascent() > 0);
        assert!(sans.descent() < 0);

        let sc = noto_sans_sc();
        assert_eq!(sc.units_per_em(), 1000);
        assert!(sc.num_glyphs() > 10_000);
    }

    #[test]
    fn cmap_covers_expected_scripts_per_font() {
        let sans = noto_sans();
        for ch in ['A', 'z', '0', 'Ж', 'я', 'α', 'Ω', '—', 'é'] {
            assert!(sans.covers(ch), "Noto Sans should cover {ch:?}");
        }
        for ch in ['你', '好', '世'] {
            assert!(!sans.covers(ch), "Noto Sans must not cover {ch:?}");
        }

        let sc = noto_sans_sc();
        for ch in ['你', '好', '世', '界', '，', 'A', 'Ж'] {
            assert!(sc.covers(ch), "Noto Sans SC should cover {ch:?}");
        }
    }

    #[test]
    fn hmtx_advances_are_sane_and_proportional() {
        let sans = noto_sans();
        let space = sans.glyph(' ').expect("space glyph");
        assert_eq!(sans.advance(space), 260, "Noto Sans space is 260/1000 em");
        let w = sans.advance(sans.glyph('W').unwrap());
        let i = sans.advance(sans.glyph('I').unwrap());
        assert!(w > i, "W ({w}) must be wider than I ({i})");
        // Glyphs beyond numberOfHMetrics share the last advance — must not
        // panic and must return something.
        let _ = sans.advance(sans.num_glyphs() - 1);

        let sc = noto_sans_sc();
        assert_eq!(sc.advance(sc.glyph('你').unwrap()), 1000);
        assert!(sc.hmtx_is_sane() && sans.hmtx_is_sane());
    }

    #[test]
    fn reverse_map_round_trips_selected_codepoints() {
        let sans = noto_sans();
        let rev = sans.reverse_map();
        for ch in ['A', 'Ж', 'α', '9'] {
            let gid = sans.glyph(ch).expect("covered");
            assert_eq!(rev.get(&gid), Some(&ch), "reverse map must return {ch:?}");
        }

        let sc = noto_sans_sc();
        let rev_sc = sc.reverse_map();
        for ch in ['你', '好'] {
            let gid = sc.glyph(ch).expect("covered");
            assert_eq!(rev_sc.get(&gid), Some(&ch));
        }
    }

    #[test]
    fn advance_pt_scales_with_font_size() {
        let sans = noto_sans();
        let gid = sans.glyph('W').unwrap();
        let at_10 = sans.advance_pt(gid, 10.0);
        let at_20 = sans.advance_pt(gid, 20.0);
        assert!((at_20 - 2.0 * at_10).abs() < 1e-9);
        assert!(
            at_10 > 5.0 && at_10 < 12.0,
            "W at 10pt is ~9.4pt, got {at_10}"
        );
    }

    #[test]
    fn rejects_truncated_and_non_truetype_inputs() {
        assert!(TtfFont::parse(Vec::new()).is_err());
        assert!(TtfFont::parse(vec![0u8; 11]).is_err());
        // Valid version but truncated table directory.
        let mut truncated = vec![0u8; 12];
        truncated[3] = 1; // 0x00010000
        truncated[4] = 0xFF;
        assert!(TtfFont::parse(truncated).is_err());
        // OTTO (CFF) is rejected: CIDFontType2 needs glyf outlines.
        let mut otto = vec![0u8; 12];
        otto[0..4].copy_from_slice(b"OTTO");
        assert!(matches!(
            TtfFont::parse(otto),
            Err(FontError::UnsupportedVersion(_))
        ));
        // A table pointing outside the file must be rejected.
        let mut bomb = vec![0u8; 12 + 16];
        bomb[3] = 1;
        bomb[4] = 1; // one table
        bomb[12..16].copy_from_slice(b"head");
        // offset = huge
        bomb[20..24].copy_from_slice(&0xFFFF_0000u32.to_be_bytes());
        assert!(TtfFont::parse(bomb).is_err());
    }
}
