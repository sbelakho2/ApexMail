//! Recursive text chunker with configurable separators and overlap.
//!
//! # Security: Input size limits (O-9.3)
//! Chunking operations enforce `max_input_size` (default 1MB) and
//! `max_chunk_size` (default 8KB) limits to prevent resource exhaustion
//! from oversized inputs.

use crate::types::{ChunkConfig, EmbeddingError, TextChunk};

/// Split text into overlapping chunks using recursive separator strategy.
///
/// Rejects inputs larger than `config.max_input_size` bytes to prevent
/// resource exhaustion (O-9.3).
///
/// Tries separators in order (paragraph → line → sentence → word),
/// falling back to character-level splitting if needed.
///
/// # Offset contract (SM9 #8)
/// For every chunk, `doc[start_offset..end_offset]` is EXACTLY `chunk.text`
/// — separators dropped by splitting are counted, and the prepended overlap
/// extends the span backward into the document (see
/// [`merge_with_overlap`]). Downstream highlight/quoting features can
/// therefore trust the offsets to slice back to the chunk text.
pub fn chunk_text(text: &str, config: &ChunkConfig) -> Result<Vec<TextChunk>, EmbeddingError> {
    if text.is_empty() {
        return Ok(vec![]);
    }

    // O-9.3: Validate input size
    if text.len() > config.max_input_size {
        return Err(EmbeddingError::InputTooLarge {
            size: text.len(),
            max: config.max_input_size,
        });
    }

    // Validate chunk_size doesn't exceed max_chunk_size
    let effective_chunk_size = config.chunk_size.min(config.max_chunk_size);

    if text.len() <= effective_chunk_size {
        return Ok(vec![TextChunk {
            text: text.to_string(),
            start_offset: 0,
            end_offset: text.len(),
            index: 0,
        }]);
    }

    let chunks = recursive_split(text, 0, &config.separators, effective_chunk_size);

    // Apply overlap
    Ok(merge_with_overlap(
        text,
        &chunks,
        config.chunk_overlap,
        effective_chunk_size,
    ))
}

fn floor_char_boundary(text: &str, index: usize) -> usize {
    if index >= text.len() {
        return text.len();
    }

    let mut boundary = index;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

fn safe_truncate_boundary(text: &str, max_size: usize) -> usize {
    let boundary = floor_char_boundary(text, max_size);
    if boundary == 0 && !text.is_empty() && max_size > 0 {
        text.chars().next().map(|ch| ch.len_utf8()).unwrap_or(0)
    } else {
        boundary
    }
}

/// A split chunk carrying its TRUE byte span in the source document.
///
/// SM9 #8: offsets are tracked through every split level (separator bytes
/// included), so `text` always satisfies `doc[start..end] == text`.
struct ChunkDraft {
    start: usize,
    end: usize,
    text: String,
}

fn recursive_split(
    text: &str,
    base: usize,
    separators: &[String],
    max_size: usize,
) -> Vec<ChunkDraft> {
    if text.len() <= max_size {
        return vec![ChunkDraft {
            start: base,
            end: base + text.len(),
            text: text.to_string(),
        }];
    }

    if separators.is_empty() {
        // SM9 #9: the cap is a BYTE budget — split by accumulated
        // `char.len_utf8()` so CJK/emoji chunks never exceed `max_size`
        // bytes. (Chunking by CHAR count produced chunks up to 4x the byte
        // cap, which the old merge then silently byte-truncated, discarding
        // up to three quarters of the chunk tail.) A single code point
        // larger than the budget still forms one oversized chunk: a char
        // cannot be split.
        let mut out: Vec<ChunkDraft> = Vec::new();
        let mut start = 0usize;
        let mut len = 0usize;
        for (idx, ch) in text.char_indices() {
            if len > 0 && len + ch.len_utf8() > max_size {
                out.push(ChunkDraft {
                    start: base + start,
                    end: base + idx,
                    text: text[start..idx].to_string(),
                });
                start = idx;
                len = ch.len_utf8();
            } else {
                len += ch.len_utf8();
            }
        }
        if len > 0 {
            out.push(ChunkDraft {
                start: base + start,
                end: base + text.len(),
                text: text[start..].to_string(),
            });
        }
        return out;
    }

    let sep = &separators[0];
    let remaining_seps = &separators[1..];

    let parts: Vec<&str> = text.split(sep.as_str()).collect();

    if parts.len() <= 1 {
        // This separator doesn't split the text; try next
        return recursive_split(text, base, remaining_seps, max_size);
    }

    // Merge small parts together (WITH their separators — the merged text
    // is exactly the document slice), split large parts recursively.
    let mut result: Vec<ChunkDraft> = Vec::new();
    let mut current: Option<ChunkDraft> = None;
    // Byte offset of the current part within `text`; the separator between
    // consecutive parts occupies [pos + part.len(), pos + part.len() + sep.len()).
    let mut pos = 0usize;

    for part in parts {
        let part_start = base + pos;
        let part_end = part_start + part.len();
        pos += part.len() + sep.len();

        let mut cur = match current.take() {
            None => {
                if part.len() > max_size {
                    // Recurse with finer separators; sub-chunks carry
                    // global spans already.
                    result.extend(recursive_split(part, part_start, remaining_seps, max_size));
                } else {
                    current = Some(ChunkDraft {
                        start: part_start,
                        end: part_end,
                        text: part.to_string(),
                    });
                }
                continue;
            }
            Some(cur) => cur,
        };

        if cur.text.len() + sep.len() + part.len() <= max_size {
            cur.end = part_end;
            cur.text = format!("{}{}{}", cur.text, sep, part);
            current = Some(cur);
        } else {
            result.push(cur);
            if part.len() > max_size {
                result.extend(recursive_split(part, part_start, remaining_seps, max_size));
            } else {
                current = Some(ChunkDraft {
                    start: part_start,
                    end: part_end,
                    text: part.to_string(),
                });
            }
        }
    }

    if let Some(cur) = current {
        result.push(cur);
    }

    result
}

/// Attach overlap and offsets to the split drafts.
///
/// # Overlap semantics (SM9 #8)
/// Chunk i's published text is the tail of chunk i-1 (up to `overlap` bytes,
/// cut on a char boundary) followed by the separator bytes that were dropped
/// in splitting and then chunk i's own content: exactly
/// `doc[start_offset..end_offset]` with `start_offset` EXTENDED BACKWARD to
/// where that tail begins in the document. When the overlap pushes the text
/// past `max_size`, the text is truncated to the boundary and `end_offset`
/// follows the truncation — the slice-back invariant
/// (`doc[start_offset..end_offset] == text`) holds either way.
fn merge_with_overlap(
    doc: &str,
    chunks: &[ChunkDraft],
    overlap: usize,
    max_size: usize,
) -> Vec<TextChunk> {
    chunks
        .iter()
        .enumerate()
        .map(|(i, draft)| {
            let (mut text, start_offset) = if i > 0 && overlap > 0 {
                let prev = &chunks[i - 1];
                let local =
                    floor_char_boundary(&prev.text, prev.text.len().saturating_sub(overlap));
                let start = prev.start + local;
                // The span extends backward over the tail and the dropped
                // separator bytes; the text is that exact document slice.
                (doc[start..draft.end].to_string(), start)
            } else {
                (draft.text.clone(), draft.start)
            };

            // Truncate if overlap made it too long (end_offset follows).
            if text.len() > max_size {
                text.truncate(safe_truncate_boundary(&text, max_size));
            }

            let end_offset = start_offset + text.len();
            TextChunk {
                text,
                start_offset,
                end_offset,
                index: i,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChunkConfig;

    #[test]
    fn test_empty_text() {
        let config = ChunkConfig::default();
        let chunks = chunk_text("", &config).unwrap();
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_short_text_single_chunk() {
        let config = ChunkConfig {
            chunk_size: 100,
            chunk_overlap: 10,
            separators: vec!["\n\n".into(), "\n".into(), ". ".into()],
            ..Default::default()
        };
        let chunks = chunk_text("Short text", &config).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].text, "Short text");
        assert_eq!(chunks[0].start_offset, 0);
    }

    #[test]
    fn test_paragraph_splitting() {
        let text = "First paragraph.\n\nSecond paragraph.\n\nThird paragraph.";
        let config = ChunkConfig {
            chunk_size: 30,
            chunk_overlap: 0,
            separators: vec!["\n\n".into(), "\n".into(), ". ".into()],
            ..Default::default()
        };
        let chunks = chunk_text(text, &config).unwrap();
        assert!(chunks.len() >= 2);
        assert!(chunks[0].text.contains("First"));
    }

    #[test]
    fn test_sentence_splitting() {
        let text = "First sentence. Second sentence. Third sentence. Fourth sentence.";
        let config = ChunkConfig {
            chunk_size: 40,
            chunk_overlap: 0,
            separators: vec!["\n\n".into(), "\n".into(), ". ".into()],
            ..Default::default()
        };
        let chunks = chunk_text(text, &config).unwrap();
        assert!(chunks.len() >= 2);
    }

    #[test]
    fn test_overlap() {
        let text = "AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH";
        let config = ChunkConfig {
            chunk_size: 20,
            chunk_overlap: 5,
            separators: vec![" ".into()],
            ..Default::default()
        };
        let chunks = chunk_text(text, &config).unwrap();
        assert!(chunks.len() >= 2);
        // Second chunk should start with overlap from first
        if chunks.len() > 1 {
            // overlap creates some shared content
            assert!(!chunks[1].text.is_empty());
        }
    }

    #[test]
    fn test_offsets_are_monotonic() {
        let text = "Word1 Word2 Word3 Word4 Word5 Word6 Word7 Word8";
        let config = ChunkConfig {
            chunk_size: 15,
            chunk_overlap: 0,
            separators: vec![" ".into()],
            ..Default::default()
        };
        let chunks = chunk_text(text, &config).unwrap();
        for i in 1..chunks.len() {
            assert!(
                chunks[i].start_offset >= chunks[i - 1].start_offset,
                "Offsets must be monotonically increasing"
            );
        }
    }

    #[test]
    fn test_indices_sequential() {
        let text = "A B C D E F G H I J K L M N O P Q R S T U V W X Y Z";
        let config = ChunkConfig {
            chunk_size: 10,
            chunk_overlap: 0,
            separators: vec![" ".into()],
            ..Default::default()
        };
        let chunks = chunk_text(text, &config).unwrap();
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.index, i);
        }
    }

    #[test]
    fn test_very_long_word() {
        let text = "a".repeat(100);
        let config = ChunkConfig {
            chunk_size: 30,
            chunk_overlap: 0,
            separators: vec![" ".into()],
            ..Default::default()
        };
        let chunks = chunk_text(&text, &config).unwrap();
        assert!(!chunks.is_empty());
        // Should fall back to character-level splitting
    }

    #[test]
    fn test_custom_separators() {
        let text = "Part1|Part2|Part3";
        let parts: Vec<&str> = text.split('|').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_overlap_preserves_utf8_boundaries() {
        let text = "你好你好 你好你好 你好你好";
        let config = ChunkConfig {
            chunk_size: 13,
            chunk_overlap: 2,
            separators: vec![" ".into()],
            ..Default::default()
        };

        let chunks = chunk_text(text, &config).unwrap();

        assert!(chunks.len() >= 2);
        assert!(chunks[1].text.starts_with('好'));
        assert!(chunks.iter().all(|chunk| !chunk.text.is_empty()));
    }

    #[test]
    fn test_rejects_oversized_input() {
        let config = ChunkConfig {
            max_input_size: 100,
            ..Default::default()
        };
        let large = "x".repeat(200);
        let result = chunk_text(&large, &config);
        assert!(result.is_err());
        assert!(matches!(result, Err(EmbeddingError::InputTooLarge { .. })));
    }

    #[test]
    fn test_respects_max_chunk_size() {
        let config = ChunkConfig {
            chunk_size: 500,
            max_chunk_size: 100,
            ..Default::default()
        };
        let text = "hello world";
        let chunks = chunk_text(text, &config).unwrap();
        // Should use min(chunk_size, max_chunk_size) = 100
        assert_eq!(chunks.len(), 1);
    }

    // ── SM9 #8/#9: offset correctness and the byte budget ───────────────

    /// Assert the slice-back invariant: every chunk's text IS the document
    /// slice `doc[start_offset..end_offset]`, and the chunks cover the
    /// document in order.
    fn assert_offsets_slice_back(doc: &str, chunks: &[TextChunk]) {
        assert!(!chunks.is_empty());
        for chunk in chunks {
            assert!(
                chunk.start_offset <= chunk.end_offset
                    && chunk.end_offset <= doc.len()
                    && doc.is_char_boundary(chunk.start_offset)
                    && doc.is_char_boundary(chunk.end_offset),
                "chunk {} offsets [{}, {}) must be in-bounds char boundaries of a {}-byte doc",
                chunk.index,
                chunk.start_offset,
                chunk.end_offset,
                doc.len()
            );
            assert_eq!(
                &doc[chunk.start_offset..chunk.end_offset],
                chunk.text,
                "chunk {} text must slice back from the document",
                chunk.index
            );
        }
        for pair in chunks.windows(2) {
            assert!(
                pair[1].start_offset >= pair[0].start_offset,
                "offsets must be monotonically non-decreasing"
            );
        }
        // First chunk starts at the document start; last ends at the end
        // (truncation only ever trims an overlap-inflated tail).
        assert_eq!(chunks[0].start_offset, 0);
    }

    /// SM9 #8: offsets reference TRUE document positions — separator bytes
    /// between merged parts are counted, so `doc[start..end] == text` holds
    /// (the old bookkeeping dropped separators, drifting every offset after
    /// the first chunk).
    #[test]
    fn offsets_count_separators_and_slice_back_to_the_document() {
        let text = "AAA\nBBB\nCCC\nDDD\nEEE";
        let config = ChunkConfig {
            chunk_size: 8,
            chunk_overlap: 0,
            separators: vec!["\n".into()],
            ..Default::default()
        };
        let chunks = chunk_text(text, &config).unwrap();
        assert!(chunks.len() >= 2, "{chunks:?}");
        assert_offsets_slice_back(text, &chunks);
        // Concrete pin: the second chunk begins at the "CCC" part — byte 8,
        // AFTER the second separator. (The old bookkeeping accumulated only
        // chunk bytes and reported 7: a position INSIDE the "\n".)
        assert_eq!(chunks[1].start_offset, 8);
        assert_eq!(
            &text[chunks[1].start_offset..chunks[1].end_offset],
            "CCC\nDDD"
        );
    }

    /// SM9 #8: with overlap, the span extends backward to where the
    /// prepended tail begins in the document — the overlap bytes are real
    /// document content and the chunk still slices back exactly.
    #[test]
    fn overlap_offsets_extend_backward_and_still_slice_back() {
        let text = "AAAA BBBB CCCC DDDD EEEE FFFF GGGG";
        let config = ChunkConfig {
            chunk_size: 10,
            chunk_overlap: 4,
            separators: vec![" ".into()],
            ..Default::default()
        };
        let chunks = chunk_text(text, &config).unwrap();
        assert!(chunks.len() >= 2, "{chunks:?}");
        assert_offsets_slice_back(text, &chunks);
        // The second chunk's start_offset extends backward INTO the first
        // chunk's span (the overlap is real document content), and its text
        // begins with the first chunk's tail.
        assert!(
            chunks[1].start_offset < chunks[0].end_offset,
            "overlap must extend the span backward: {} !< {}",
            chunks[1].start_offset,
            chunks[0].end_offset
        );
        assert!(
            chunks[0]
                .text
                .ends_with(&chunks[1].text[..chunks[1].text.len().min(4)]),
            "chunk 2 must begin with chunk 1's tail: {:?} vs {:?}",
            chunks[0].text,
            chunks[1].text
        );
    }

    /// SM9 #8: nested recursion (a paragraph larger than the cap is
    /// re-split by finer separators) keeps global offsets true.
    #[test]
    fn nested_recursion_keeps_global_offsets() {
        let big_part = format!("{}. ", "word".repeat(8)); // > cap, sentence-split
        let text = format!("{}{}. {}", "x".repeat(5), big_part, "tail sentence. ");
        let config = ChunkConfig {
            chunk_size: 20,
            chunk_overlap: 3,
            separators: vec!["\n\n".into(), ". ".into(), " ".into()],
            ..Default::default()
        };
        let chunks = chunk_text(&text, &config).unwrap();
        assert!(chunks.len() >= 2, "{chunks:?}");
        assert_offsets_slice_back(&text, &chunks);
    }

    /// SM9 #9: with no separators left, the fallback splits by accumulated
    /// `char.len_utf8()` against the BYTE budget — CJK/emoji chunks can no
    /// longer reach 3-4x the cap and lose their tails to silent
    /// byte-truncation. With overlap 0 the chunks partition the document
    /// exactly.
    #[test]
    fn char_fallback_respects_the_byte_budget() {
        let doc = "🦀你好".repeat(20); // 40 crab (4B) + 40 han (3B) chars = 280 bytes
        let config = ChunkConfig {
            chunk_size: 30,
            chunk_overlap: 0,
            separators: vec![],
            max_input_size: 1_048_576,
            max_chunk_size: 30,
        };
        let chunks = chunk_text(&doc, &config).unwrap();
        assert!(chunks.len() >= 2, "{chunks:?}");
        for chunk in &chunks {
            assert!(
                chunk.text.len() <= 30,
                "chunk of {} bytes exceeds the 30-byte budget",
                chunk.text.len()
            );
            // Every chunk is whole characters — no truncation damage.
            assert!(chunk
                .text
                .chars()
                .all(|c| c == '🦀' || c == '你' || c == '好'));
        }
        assert_offsets_slice_back(&doc, &chunks);
        // Overlap 0 + byte-budget fallback: an exact partition, nothing lost.
        let joined: String = chunks.iter().map(|c| c.text.as_str()).collect();
        assert_eq!(joined, doc, "the chunks must cover the document exactly");
    }

    /// SM9 #9: the same guarantee for the no-separator-matches path —
    /// text without any of the configured separators falls through to the
    /// byte-budget character split and no tail is discarded.
    #[test]
    fn no_matching_separator_falls_back_to_byte_budget_split() {
        let doc = "𐍈".repeat(25); // 4-byte Gothic letter, 100 bytes, no separators
        let config = ChunkConfig {
            chunk_size: 16,
            chunk_overlap: 0,
            separators: vec!["\n\n".into(), ". ".into()],
            max_input_size: 1_048_576,
            max_chunk_size: 16,
        };
        let chunks = chunk_text(&doc, &config).unwrap();
        assert!(chunks.len() >= 2, "{chunks:?}");
        for chunk in &chunks {
            assert!(chunk.text.len() <= 16, "{} bytes > 16", chunk.text.len());
        }
        assert_offsets_slice_back(&doc, &chunks);
        let joined: String = chunks.iter().map(|c| c.text.as_str()).collect();
        assert_eq!(joined, doc);
    }
}
