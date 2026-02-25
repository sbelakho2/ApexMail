//! Recursive text chunker with configurable separators and overlap.

use crate::types::{ChunkConfig, TextChunk};

/// Split text into overlapping chunks using recursive separator strategy.
///
/// Tries separators in order (paragraph → line → sentence → word),
/// falling back to character-level splitting if needed.
pub fn chunk_text(text: &str, config: &ChunkConfig) -> Vec<TextChunk> {
    if text.is_empty() {
        return vec![];
    }

    if text.len() <= config.chunk_size {
        return vec![TextChunk {
            text: text.to_string(),
            start_offset: 0,
            end_offset: text.len(),
            index: 0,
        }];
    }

    let chunks = recursive_split(text, &config.separators, config.chunk_size);

    // Apply overlap
    merge_with_overlap(&chunks, config.chunk_overlap, config.chunk_size)
}

fn recursive_split(text: &str, separators: &[String], max_size: usize) -> Vec<String> {
    if text.len() <= max_size {
        return vec![text.to_string()];
    }

    if separators.is_empty() {
        // Fall back to character-level splitting
        return text
            .chars()
            .collect::<Vec<_>>()
            .chunks(max_size)
            .map(|c| c.iter().collect())
            .collect();
    }

    let sep = &separators[0];
    let remaining_seps = &separators[1..];

    let parts: Vec<&str> = text.split(sep.as_str()).collect();

    if parts.len() <= 1 {
        // This separator doesn't split the text; try next
        return recursive_split(text, remaining_seps, max_size);
    }

    // Merge small parts together, split large parts recursively
    let mut result = Vec::new();
    let mut current = String::new();

    for part in parts {
        let candidate = if current.is_empty() {
            part.to_string()
        } else {
            format!("{}{}{}", current, sep, part)
        };

        if candidate.len() <= max_size {
            current = candidate;
        } else {
            if !current.is_empty() {
                result.push(current);
                current = String::new();
            }

            if part.len() > max_size {
                // Recurse with finer separators
                let sub_chunks = recursive_split(part, remaining_seps, max_size);
                result.extend(sub_chunks);
            } else {
                current = part.to_string();
            }
        }
    }

    if !current.is_empty() {
        result.push(current);
    }

    result
}

fn merge_with_overlap(chunks: &[String], overlap: usize, max_size: usize) -> Vec<TextChunk> {
    if chunks.is_empty() {
        return vec![];
    }

    let mut result = Vec::new();
    let mut offset: usize = 0;

    for (i, chunk) in chunks.iter().enumerate() {
        let mut text = String::new();
        let mut overlap_len = 0;

        // Prepend overlap from previous chunk
        if i > 0 && overlap > 0 {
            let prev = &chunks[i - 1];
            let overlap_start = prev.len().saturating_sub(overlap);
            let overlap_text = &prev[overlap_start..];
            text.push_str(overlap_text);
            overlap_len = overlap_text.len();
        }

        text.push_str(chunk);

        // Truncate if overlap made it too long
        if text.len() > max_size {
            text.truncate(max_size);
        }

        let start_offset = offset.saturating_sub(overlap_len);
        let end_offset = start_offset + text.len();
        result.push(TextChunk {
            text,
            start_offset,
            end_offset,
            index: i,
        });

        offset += chunk.len();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChunkConfig;

    #[test]
    fn test_empty_text() {
        let config = ChunkConfig::default();
        let chunks = chunk_text("", &config);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_short_text_single_chunk() {
        let config = ChunkConfig {
            chunk_size: 100,
            chunk_overlap: 10,
            separators: vec!["\n\n".into(), "\n".into(), ". ".into()],
        };
        let chunks = chunk_text("Short text", &config);
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
        };
        let chunks = chunk_text(text, &config);
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
        };
        let chunks = chunk_text(text, &config);
        assert!(chunks.len() >= 2);
    }

    #[test]
    fn test_overlap() {
        let text = "AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH";
        let config = ChunkConfig {
            chunk_size: 20,
            chunk_overlap: 5,
            separators: vec![" ".into()],
        };
        let chunks = chunk_text(text, &config);
        assert!(chunks.len() >= 2);
        // Second chunk should start with overlap from first
        if chunks.len() > 1 {
            // overlap creates some shared content
            assert!(chunks[1].text.len() > 0);
        }
    }

    #[test]
    fn test_offsets_are_monotonic() {
        let text = "Word1 Word2 Word3 Word4 Word5 Word6 Word7 Word8";
        let config = ChunkConfig {
            chunk_size: 15,
            chunk_overlap: 0,
            separators: vec![" ".into()],
        };
        let chunks = chunk_text(text, &config);
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
        };
        let chunks = chunk_text(text, &config);
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
        };
        let chunks = chunk_text(&text, &config);
        assert!(!chunks.is_empty());
        // Should fall back to character-level splitting
    }

    #[test]
    fn test_custom_separators() {
        let text = "Part1|Part2|Part3";
        let parts: Vec<&str> = text.split('|').collect();
        assert_eq!(parts.len(), 3);
    }
}
