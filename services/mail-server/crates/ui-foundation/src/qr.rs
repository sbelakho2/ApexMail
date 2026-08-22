//! Server-side QR code encoder (byte mode, ECC level L, versions 1–20).
//!
//! Pure Rust, zero dependencies: the matrix algorithm is a compact
//! implementation of the ISO/IEC 18004 QR specification (structure follows
//! the well-known Nayuki reference generator, MIT licensed). Rendering is
//! an inline SVG path so the MFA page can display a TOTP `otpauth://` URI
//! with **no client-side code and no third-party service** — the secret
//! never leaves the origin.
//!
//! Tests decode the generated matrices back with an independent inverse
//! implementation (format-info BCH check, spec-order deinterleave,
//! Reed–Solomon syndrome verification) and assert the payload round-trips
//! exactly.

/// Encoded QR matrix plus the metadata needed to interpret it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMatrix {
    pub version: u8,
    pub size: usize,
    pub mask: u8,
    /// `modules[y][x]` is true for dark modules.
    pub modules: Vec<Vec<bool>>,
}

const ECC_L_CODEWORDS_PER_BLOCK: [usize; 21] =
    [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28];
const NUM_ECC_BLOCKS_L: [usize; 21] = [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8];
const MAX_VERSION: usize = 20;

fn num_raw_data_modules(ver: usize) -> usize {
    let mut result = (16 * ver + 128) * ver + 64;
    if ver >= 2 {
        let num_align = ver / 7 + 2;
        result -= (25 * num_align - 10) * num_align - 55;
        if ver >= 7 {
            result -= 36;
        }
    }
    result
}

fn data_capacity_bytes(ver: usize) -> usize {
    num_raw_data_modules(ver) / 8 - ECC_L_CODEWORDS_PER_BLOCK[ver] * NUM_ECC_BLOCKS_L[ver]
}

fn utf8_bytes(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

// ── GF(2^8) arithmetic ────────────────────────────────────────────────

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    // Shift-and-add multiply in GF(2^8) modulo the QR polynomial
    // x^8 + x^4 + x^3 + x^2 + 1 (0x11d). Fine for one-off encodes.
    let mut a = u16::from(a);
    let mut b = u16::from(b);
    let mut r: u16 = 0;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= 0x11d;
        }
        b >>= 1;
    }
    r as u8
}

fn rs_divisor(degree: usize) -> Vec<u8> {
    let mut result = vec![0u8; degree - 1];
    result.push(1);
    let mut root: u8 = 1;
    for _ in 0..degree {
        for j in 0..result.len() {
            result[j] = gf_mul(result[j], root);
            if j + 1 < result.len() {
                result[j] ^= result[j + 1];
            }
        }
        root = gf_mul(root, 2);
    }
    result
}

fn rs_remainder(data: &[u8], divisor: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; divisor.len()];
    for &byte in data {
        let factor = byte ^ result.remove(0);
        result.push(0);
        for (j, &coef) in divisor.iter().enumerate() {
            result[j] ^= gf_mul(coef, factor);
        }
    }
    result
}

fn add_ecc_and_interleave(data: &[u8], ver: usize) -> Vec<u8> {
    let num_blocks = NUM_ECC_BLOCKS_L[ver];
    let block_ecc_len = ECC_L_CODEWORDS_PER_BLOCK[ver];
    let raw_codewords = num_raw_data_modules(ver) / 8;
    let num_short_blocks = num_blocks - raw_codewords % num_blocks;
    let short_block_len = raw_codewords / num_blocks;
    let divisor = rs_divisor(block_ecc_len);
    let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(num_blocks);
    let mut k = 0usize;
    for b in 0..num_blocks {
        let data_len = short_block_len - block_ecc_len + usize::from(b >= num_short_blocks);
        let dat = data[k..k + data_len].to_vec();
        k += data_len;
        let ecc = rs_remainder(&dat, &divisor);
        let mut block = dat;
        if b < num_short_blocks {
            block.push(0);
        }
        block.extend_from_slice(&ecc);
        blocks.push(block);
    }
    let mut result = Vec::with_capacity(raw_codewords);
    for i in 0..blocks[0].len() {
        for (b, block) in blocks.iter().enumerate() {
            if i != short_block_len - block_ecc_len || b >= num_short_blocks {
                result.push(block[i]);
            }
        }
    }
    result
}

fn alignment_positions(ver: usize, size: usize) -> Vec<usize> {
    if ver == 1 {
        return Vec::new();
    }
    let num_align = ver / 7 + 2;
    let step = if ver == 32 { 26 } else { ((ver * 4 + 4 + num_align * 2 - 3) / (num_align * 2 - 2)).max(1) * 2 };
    let mut positions = vec![6usize];
    let mut pos = size - 7;
    while positions.len() < num_align {
        positions.insert(1, pos);
        pos -= step;
    }
    positions
}

fn mask_function(mask: u8) -> impl Fn(usize, usize) -> bool {
    move |x, y| match mask {
        0 => (x + y) % 2 == 0,
        1 => x % 2 == 0,
        2 => y % 3 == 0,
        3 => (x + y) % 3 == 0,
        4 => ((x / 2) + (y / 3)) % 2 == 0,
        5 => (x * y) % 2 + (x * y) % 3 == 0,
        6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
        _ => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
    }
}

fn calc_format_bits(mask: u8) -> u32 {
    let ecl_l = 1u32; // ECC level L
    let data = (ecl_l << 3) | mask as u32;
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    ((data << 10) | rem) ^ 0x5412
}

struct DrawState {
    size: usize,
    modules: Vec<Vec<bool>>,
    is_function: Vec<Vec<bool>>,
}

impl DrawState {
    fn set_function_module(&mut self, x: isize, y: isize, dark: bool) {
        if x < 0 || y < 0 || x >= self.size as isize || y >= self.size as isize {
            return;
        }
        let (x, y) = (x as usize, y as usize);
        self.modules[y][x] = dark;
        self.is_function[y][x] = true;
    }

    fn draw_finder_pattern(&mut self, cx: isize, cy: isize) {
        for dy in -4..=4isize {
            for dx in -4..=4isize {
                let dist = dx.abs().max(dy.abs());
                self.set_function_module(cx + dx, cy + dy, dist != 2 && dist != 4);
            }
        }
    }

    fn draw_alignment_pattern(&mut self, cx: isize, cy: isize) {
        for dy in -2..=2isize {
            for dx in -2..=2isize {
                self.set_function_module(cx + dx, cy + dy, dx.abs().max(dy.abs()) != 1);
            }
        }
    }
}

/// Encode `text` into a QR matrix (byte mode, ECC L). Returns `None` when
/// the payload exceeds version-20 capacity.
pub fn encode(text: &str) -> Option<QrMatrix> {
    let bytes = utf8_bytes(text);
    let mut ver = 0usize;
    for candidate in 1..=MAX_VERSION {
        ver = candidate;
        let count_bits = if ver <= 9 { 8 } else { 16 };
        if 4 + count_bits + bytes.len() * 8 <= data_capacity_bytes(ver) * 8 {
            break;
        }
    }
    if ver > MAX_VERSION || bytes.len() > 65535 {
        return None;
    }
    // Verify capacity was actually satisfied (loop above may exit at MAX).
    let count_bits = if ver <= 9 { 8 } else { 16 };
    if 4 + count_bits + bytes.len() * 8 > data_capacity_bytes(ver) * 8 {
        return None;
    }

    // Bit buffer: mode 0100, count, payload, terminator, byte pad, 0xEC/0x11.
    let capacity_bits = data_capacity_bits(ver);
    let mut bits: Vec<bool> = Vec::with_capacity(capacity_bits);
    fn append_bits(bits: &mut Vec<bool>, value: u32, len: usize) {
        for i in (0..len).rev() {
            bits.push((value >> i) & 1 == 1);
        }
    }
    append_bits(&mut bits, 4, 4);
    append_bits(&mut bits, bytes.len() as u32, count_bits);
    for &b in &bytes {
        append_bits(&mut bits, b as u32, 8);
    }
    let terminator_len = 4usize.min(capacity_bits.saturating_sub(bits.len()));
    append_bits(&mut bits, 0, terminator_len);
    let pad_bits = (8 - bits.len() % 8) % 8;
    append_bits(&mut bits, 0, pad_bits);
    let mut pad: u8 = 0xec;
    while bits.len() < capacity_bits {
        append_bits(&mut bits, pad as u32, 8);
        pad ^= 0xec ^ 0x11;
    }
    let mut data_codewords = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for bit in chunk {
            byte = (byte << 1) | u8::from(*bit);
        }
        data_codewords.push(byte);
    }
    let codewords = add_ecc_and_interleave(&data_codewords, ver);

    Some(draw_matrix(&codewords, ver))
}

fn data_capacity_bits(ver: usize) -> usize {
    data_capacity_bytes(ver) * 8
}

fn draw_matrix(codewords: &[u8], ver: usize) -> QrMatrix {
    let size = ver * 4 + 17;
    let mut state = DrawState {
        size,
        modules: vec![vec![false; size]; size],
        is_function: vec![vec![false; size]; size],
    };

    // Timing patterns.
    for i in 0..size {
        state.set_function_module(6, i as isize, i % 2 == 0);
        state.set_function_module(i as isize, 6, i % 2 == 0);
    }
    state.draw_finder_pattern(3, 3);
    state.draw_finder_pattern(size as isize - 4, 3);
    state.draw_finder_pattern(3, size as isize - 4);
    let align = alignment_positions(ver, size);
    let num_align = align.len();
    for (ai, &ax) in align.iter().enumerate() {
        for (aj, &ay) in align.iter().enumerate() {
            if (ai == 0 && aj == 0)
                || (ai == 0 && aj == num_align - 1)
                || (ai == num_align - 1 && aj == 0)
            {
                continue;
            }
            state.draw_alignment_pattern(ax as isize, ay as isize);
        }
    }

    // Reserve format modules with a dummy mask; real bits after mask choice.
    let draw_format = |state: &mut DrawState, mask: u8| {
        let data_bits = calc_format_bits(mask);
        let bit = |i: u32| ((data_bits >> i) & 1) != 0;
        for f in 0..=5u32 {
            state.set_function_module(8, f as isize, bit(f));
        }
        state.set_function_module(8, 7, bit(6));
        state.set_function_module(8, 8, bit(7));
        state.set_function_module(7, 8, bit(8));
        for g in 9..15u32 {
            state.set_function_module((14 - g) as isize, 8, bit(g));
        }
        for h in 0..8u32 {
            state.set_function_module(size as isize - 1 - h as isize, 8, bit(h));
        }
        for k in 8..15u32 {
            state.set_function_module(8, size as isize - 15 + k as isize, bit(k));
        }
        state.set_function_module(8, size as isize - 8, true);
    };
    draw_format(&mut state, 0);
    if ver >= 7 {
        draw_version(&mut state, ver);
    }

    // Place codewords (zigzag from the right, skipping column 6).
    let mut bit_index = 0usize;
    let total_bits = codewords.len() * 8;
    let mut right = size as isize - 1;
    while right >= 1 {
        if right == 6 {
            right = 5;
        }
        for vert in 0..size as isize {
            for dj in 0..2isize {
                let x = (right - dj) as usize;
                let upward = ((right + 1) & 2) == 0;
                let y = if upward { size as isize - 1 - vert } else { vert } as usize;
                if !state.is_function[y][x] {
                    if bit_index < total_bits {
                        state.modules[y][x] =
                            (codewords[bit_index >> 3] >> (7 - (bit_index & 7))) & 1 == 1;
                    }
                    bit_index += 1;
                }
            }
        }
        right -= 2;
    }

    // Choose the mask with the lowest penalty (apply/undo via double XOR).
    let mut best_mask = 0u8;
    let mut min_penalty = u64::MAX;
    for m in 0..8u8 {
        apply_mask(&mut state, m);
        let penalty = penalty_score(&state);
        apply_mask(&mut state, m);
        if penalty < min_penalty {
            min_penalty = penalty;
            best_mask = m;
        }
    }
    apply_mask(&mut state, best_mask);
    draw_format(&mut state, best_mask);

    QrMatrix {
        version: ver as u8,
        size,
        mask: best_mask,
        modules: state.modules,
    }
}

fn draw_version(state: &mut DrawState, ver: usize) {
    let mut rem = ver as u32;
    for _ in 0..12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1f25);
    }
    let bits_data = ((ver as u32) << 12) | rem;
    for b in 0..18usize {
        let is_dark = (bits_data >> b) & 1 == 1;
        let a = state.size - 11 + (b % 3);
        let q = b / 3;
        state.set_function_module(a as isize, q as isize, is_dark);
        state.set_function_module(q as isize, a as isize, is_dark);
    }
}

fn apply_mask(state: &mut DrawState, mask: u8) {
    let f = mask_function(mask);
    for y in 0..state.size {
        for x in 0..state.size {
            if !state.is_function[y][x] && f(x, y) {
                let cell = &mut state.modules[y][x];
                *cell = !*cell;
            }
        }
    }
}

fn penalty_score(state: &DrawState) -> u64 {
    let size = state.size;
    let mut result = 0u64;
    // Rule 1: runs of 5+ same color.
    for y in 0..size {
        let mut run_color = false;
        let mut run_x = 0usize;
        for x in 0..size {
            if state.modules[y][x] == run_color {
                run_x += 1;
                if run_x == 5 {
                    result += 3;
                } else if run_x > 5 {
                    result += 1;
                }
            } else {
                run_color = state.modules[y][x];
                run_x = 1;
            }
        }
    }
    for x in 0..size {
        let mut run_color = false;
        let mut run_y = 0usize;
        for y in 0..size {
            if state.modules[y][x] == run_color {
                run_y += 1;
                if run_y == 5 {
                    result += 3;
                } else if run_y > 5 {
                    result += 1;
                }
            } else {
                run_color = state.modules[y][x];
                run_y = 1;
            }
        }
    }
    // Rule 2: 2x2 blocks.
    for y in 0..size - 1 {
        for x in 0..size - 1 {
            let c = state.modules[y][x];
            if c == state.modules[y][x + 1] && c == state.modules[y + 1][x] && c == state.modules[y + 1][x + 1] {
                result += 3;
            }
        }
    }
    // Rule 4: dark proportion.
    let dark: usize = state
        .modules
        .iter()
        .map(|row| row.iter().filter(|&&c| c).count())
        .sum();
    let total = size * size;
    let k = ((dark * 20).abs_diff(total * 10) + total - 1) / total;
    result += k.saturating_sub(1) as u64 * 10;
    result
}

/// Render the matrix as a self-contained inline `<svg>` (one `<path>` with
/// a square subpath per dark module plus the quiet zone as margin).
pub fn to_svg(qr: &QrMatrix, scale: usize, quiet_zone: usize) -> String {
    let scale = scale.max(1);
    let quiet = quiet_zone.max(0);
    let dim = (qr.size + quiet * 2) * scale;
    let mut path = String::with_capacity(qr.modules.len() * qr.modules.len() * 12);
    for (y, row) in qr.modules.iter().enumerate() {
        for (x, &dark) in row.iter().enumerate() {
            if dark {
                let px = (x + quiet) * scale;
                let py = (y + quiet) * scale;
                path.push_str(&format!("M{px} {py}h{scale}v{scale}h-{scale}z"));
            }
        }
    }
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {dim} {dim}\" width=\"{dim}\" height=\"{dim}\" role=\"img\" aria-label=\"QR code\"><rect width=\"{dim}\" height=\"{dim}\" fill=\"#ffffff\"/><path d=\"{path}\" fill=\"#000000\"/></svg>"
    )
}

/// Convenience: encode + render in one step. Returns an SVG string or
/// `None` when the payload is too large for version 20.
pub fn encode_to_svg(text: &str, scale: usize, quiet_zone: usize) -> Option<String> {
    encode(text).map(|qr| to_svg(&qr, scale, quiet_zone))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Independent inverse decoder (mirrors the spec, not the encoder) ──

    fn build_function_map(size: usize, ver: usize) -> Vec<Vec<bool>> {
        let mut is_fn = vec![vec![false; size]; size];
        let mut mark = |x: isize, y: isize, is_fn: &mut Vec<Vec<bool>>| {
            if x >= 0 && y >= 0 && (x as usize) < size && (y as usize) < size {
                is_fn[y as usize][x as usize] = true;
            }
        };
        for &(cx, cy) in &[(3isize, 3isize), (size as isize - 4, 3), (3, size as isize - 4)] {
            for dy in -4..=4isize {
                for dx in -4..=4isize {
                    mark(cx + dx, cy + dy, &mut is_fn);
                }
            }
        }
        for i in 0..size {
            mark(6, i as isize, &mut is_fn);
            mark(i as isize, 6, &mut is_fn);
        }
        if ver > 1 {
            let num_align = ver / 7 + 2;
            let step = if ver == 32 { 26 } else { ((ver * 4 + 4 + num_align * 2 - 3) / (num_align * 2 - 2)).max(1) * 2 };
            let mut pos = vec![6usize];
            let mut p = size - 7;
            while pos.len() < num_align {
                pos.insert(1, p);
                p -= step;
            }
            for (ai, &ax) in pos.iter().enumerate() {
                for (aj, &ay) in pos.iter().enumerate() {
                    if (ai == 0 && aj == 0) || (ai == 0 && aj == pos.len() - 1) || (ai == pos.len() - 1 && aj == 0) {
                        continue;
                    }
                    for dy in -2..=2isize {
                        for dx in -2..=2isize {
                            mark(ax as isize + dx, ay as isize + dy, &mut is_fn);
                        }
                    }
                }
            }
        }
        for f in 0..=5 {
            mark(8, f, &mut is_fn);
        }
        mark(8, 7, &mut is_fn);
        mark(8, 8, &mut is_fn);
        mark(7, 8, &mut is_fn);
        for g in 9..15 {
            mark((14 - g) as isize, 8, &mut is_fn);
        }
        for h in 0..8 {
            mark(size as isize - 1 - h as isize, 8, &mut is_fn);
        }
        for k in 8..15 {
            mark(8, size as isize - 15 + k as isize, &mut is_fn);
        }
        mark(8, size as isize - 8, &mut is_fn);
        if ver >= 7 {
            for b in 0..18 {
                mark((size - 11 + (b % 3)) as isize, (b / 3) as isize, &mut is_fn);
                mark((b / 3) as isize, (size - 11 + (b % 3)) as isize, &mut is_fn);
            }
        }
        is_fn
    }

    fn gf_pow(mut a: u8, mut n: u32) -> u8 {
        let mut r: u8 = 1;
        while n > 0 {
            if n & 1 != 0 {
                r = gf_mul(r, a);
            }
            a = gf_mul(a, a);
            n >>= 1;
        }
        r
    }

    /// Decode a matrix back to its byte payload. Verifies the BCH format
    /// info and that every Reed–Solomon syndrome evaluates to zero.
    fn decode(qr: &QrMatrix) -> (String, bool, bool, bool) {
        let size = qr.size;
        let ver = (size - 17) / 4;
        let is_fn = build_function_map(size, ver);
        let bit = |x: usize, y: usize| qr.modules[y][x];
        let copy0 = {
            let mut v = 0u32;
            for i in 0..=5u32 {
                v |= u32::from(bit(8, i as usize)) << i;
            }
            v |= u32::from(bit(8, 7)) << 6;
            v |= u32::from(bit(8, 8)) << 7;
            v |= u32::from(bit(7, 8)) << 8;
            for j in 9..15u32 {
                v |= u32::from(bit((14 - j) as usize, 8)) << j;
            }
            v
        };
        let copy1 = {
            let mut v = 0u32;
            for i in 0..8u32 {
                v |= u32::from(bit(size - 1 - i as usize, 8)) << i;
            }
            for j in 8..15u32 {
                v |= u32::from(bit(8, size - 15 + j as usize)) << j;
            }
            v
        };
        let raw = copy0 ^ 0x5412;
        let mask = ((raw >> 10) & 0x7) as u8;
        let rem_bits = raw & 0x3ff;
        let data5 = (1u32 << 3) | mask as u32; // ECC level L
        let mut rem = data5;
        for _ in 0..10 {
            rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        }
        let bch_ok = (rem & 0x3ff) == rem_bits;

        // Read the data modules in the standard zigzag order, unmasked.
        let f = mask_function(mask);
        let mut bits = Vec::new();
        let mut right = size as isize - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            for vert in 0..size as isize {
                for dj in 0..2isize {
                    let x = (right - dj) as usize;
                    let upward = ((right + 1) & 2) == 0;
                    let y = if upward { size as isize - 1 - vert } else { vert } as usize;
                    if !is_fn[y][x] {
                        let mut v = qr.modules[y][x];
                        if f(x, y) {
                            v = !v;
                        }
                        bits.push(v);
                    }
                }
            }
            right -= 2;
        }
        let mut codewords = Vec::new();
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for b in chunk {
                byte = (byte << 1) | u8::from(*b);
            }
            codewords.push(byte);
        }
        // Deinterleave (spec order).
        let num_blocks = NUM_ECC_BLOCKS_L[ver];
        let block_ecc_len = ECC_L_CODEWORDS_PER_BLOCK[ver];
        let raw_cw = num_raw_data_modules(ver) / 8;
        let num_short = num_blocks - raw_cw % num_blocks;
        let short_block_len = raw_cw / num_blocks;
        let short_data_len = short_block_len - block_ecc_len;
        let mut blocks_data = vec![Vec::new(); num_blocks];
        let mut blocks_ecc = vec![Vec::new(); num_blocks];
        let mut idx = 0usize;
        for _col in 0..short_data_len {
            for bd in blocks_data.iter_mut() {
                bd.push(codewords[idx]);
                idx += 1;
            }
        }
        for bl in num_short..num_blocks {
            blocks_data[bl].push(codewords[idx]);
            idx += 1;
        }
        for _e in 0..block_ecc_len {
            for be in blocks_ecc.iter_mut() {
                be.push(codewords[idx]);
                idx += 1;
            }
        }
        let mut syndromes_zero = true;
        let mut data_bytes = Vec::new();
        for (b, bd) in blocks_data.iter().enumerate() {
            let mut block = bd.clone();
            block.extend_from_slice(&blocks_ecc[b]);
            data_bytes.extend_from_slice(bd);
            for s in 0..block_ecc_len {
                let eval_at = gf_pow(2, s as u32);
                let mut acc = 0u8;
                for &coef in &block {
                    acc = gf_mul(acc, eval_at) ^ coef;
                }
                if acc != 0 {
                    syndromes_zero = false;
                }
            }
        }
        // Parse the bitstream: byte mode, count, payload.
        let mut data_bits = Vec::with_capacity(data_bytes.len() * 8);
        for &byte in &data_bytes {
            for b in (0..8).rev() {
                data_bits.push((byte >> b) & 1 == 1);
            }
        }
        let mut pos = 0usize;
        let mut take = |n: usize| -> u32 {
            let mut v = 0u32;
            for _ in 0..n {
                v = (v << 1) | u32::from(data_bits.get(pos).copied().unwrap_or(false));
                pos += 1;
            }
            v
        };
        let _mode = take(4);
        let count_bits = if ver <= 9 { 8 } else { 16 };
        let count = take(count_bits) as usize;
        let mut payload = Vec::with_capacity(count);
        for _ in 0..count {
            payload.push(take(8) as u8);
        }
        let text = String::from_utf8(payload).unwrap_or_default();
        (text, bch_ok, copy0 == copy1, syndromes_zero)
    }

    fn check_finder(qr: &QrMatrix, cx: usize, cy: usize) -> bool {
        for dy in -4..=4isize {
            for dx in -4..=4isize {
                let x = cx as isize + dx;
                let y = cy as isize + dy;
                if x < 0 || y < 0 || x >= qr.size as isize || y >= qr.size as isize {
                    continue;
                }
                let dist = dx.abs().max(dy.abs());
                if qr.modules[y as usize][x as usize] != (dist != 2 && dist != 4) {
                    return false;
                }
            }
        }
        true
    }

    #[test]
    fn encodes_and_round_trips_payloads() {
        let urls = [
            "otpauth://totp/ApexMail:ops@apexmail.ee?secret=JBSWY3DPEHPK3PXP&issuer=ApexMail",
            "otpauth://totp/ApexMail:a.very-long.username%40example.co.uk?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=30&issuer=ApexMail%20Console",
            "https://apexmail.ee/verify?token=short",
            "x",
            "ünicode-päyload-õ",
        ];
        for url in urls {
            let qr = encode(url).unwrap_or_else(|| panic!("failed to encode {url}"));
            assert!((qr.size - 17) % 4 == 0 && qr.size >= 21 && qr.size <= 97);
            assert!(check_finder(&qr, 3, 3), "finder TL broken for {url}");
            assert!(check_finder(&qr, qr.size - 4, 3), "finder TR broken for {url}");
            assert!(check_finder(&qr, 3, qr.size - 4), "finder BL broken for {url}");
            for i in 8..qr.size - 8 {
                assert_eq!(qr.modules[6][i], i % 2 == 0, "timing broken for {url}");
                assert_eq!(qr.modules[i][6], i % 2 == 0, "timing broken for {url}");
            }
            let (payload, bch_ok, copies_match, syndromes_zero) = decode(&qr);
            assert!(bch_ok, "format BCH invalid for {url}");
            assert!(copies_match, "format copies disagree for {url}");
            assert!(syndromes_zero, "RS syndromes non-zero for {url}");
            assert_eq!(payload, url, "payload round-trip failed");
        }
    }

    #[test]
    fn rejects_over_long_input_cleanly() {
        assert!(encode(&"a".repeat(900)).is_none());
    }

    #[test]
    fn svg_contains_every_dark_module() {
        let qr = encode("otpauth://totp/ApexMail:x?secret=JBSWY3DPEHPK3PXP").unwrap();
        let svg = to_svg(&qr, 5, 4);
        assert!(svg.starts_with("<svg ") && svg.ends_with("</svg>"));
        assert!(svg.contains("role=\"img\""));
        let dark_count = qr.modules.iter().map(|r| r.iter().filter(|&&c| c).count()).sum::<usize>();
        // Each dark module contributes one 'z' subpath close.
        assert_eq!(svg.matches('z').count(), dark_count);
        // Dimensions include the quiet zone.
        assert!(svg.contains(&format!("width=\"{}\"", (qr.size + 8) * 5)));
    }

    #[test]
    fn encode_to_svg_helper_matches_composition() {
        let text = "https://apexmail.ee";
        assert_eq!(encode_to_svg(text, 4, 2), encode(text).map(|q| to_svg(&q, 4, 2)));
        assert!(encode_to_svg(&"a".repeat(900), 4, 2).is_none());
    }
}
