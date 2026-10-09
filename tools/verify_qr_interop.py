#!/usr/bin/env python3
"""Independent ISO/IEC 18004 QR decoder for the ApexMail MFA code generator.

Review §3 P1-13: the encoder's own test decoder shares the implementation it
is supposed to validate (same mask function, same GF arithmetic), so a
transposed mask formula round-trips undetected. This decoder is written from
the SPECIFICATION, not from `crates/ui-foundation/src/qr.rs`:

  * mask conditions 0-7 are Table 10 (ISO/IEC 18004:2015) written directly
    with row `i` and column `j`,
  * alignment-pattern coordinates are Annex E (hardcoded table),
  * the L-level block structure is the standard table (EC codewords per
    block / block count),
  * format info is BCH(15,5) with the 0x537 generator and the 0x5412 mask,
  * Reed-Solomon syndromes are computed over GF(2^8) with the 0x11D
    primitive polynomial built from exp/log tables.

It reads a case stream on stdin and decodes every case from the module
matrix alone (the payload is only used for the final comparison):

    CASES <n>
    CASE <version> <mask> <size> <expected_len>
    <expected payload as lowercase hex>
    <size lines of 0/1, '1' = dark module>
    ...

Exit 0 and print OK lines when every case decodes to its expected payload
with valid format info, matching format copies, the requested mask and zero
RS syndromes. Any failure exits 1 with a `FAIL ...` reason on stderr.
"""

from __future__ import annotations

import sys

# ── GF(2^8) with primitive polynomial x^8+x^4+x^3+x^2+1 (0x11D) ──────────
GF_EXP = [0] * 512
GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    GF_EXP[_i] = _x
    GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    GF_EXP[_i] = GF_EXP[_i - 255]


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return GF_EXP[GF_LOG[a] + GF_LOG[b]]


# ── Annex E: alignment-pattern centre coordinates (versions 1-20) ────────
ALIGNMENT = {
    1: [],
    2: [6, 18],
    3: [6, 22],
    4: [6, 26],
    5: [6, 30],
    6: [6, 34],
    7: [6, 22, 38],
    8: [6, 24, 42],
    9: [6, 26, 46],
    10: [6, 28, 50],
    11: [6, 30, 54],
    12: [6, 32, 58],
    13: [6, 34, 62],
    14: [6, 26, 46, 66],
    15: [6, 26, 48, 70],
    16: [6, 26, 50, 74],
    17: [6, 30, 54, 78],
    18: [6, 30, 56, 82],
    19: [6, 30, 58, 86],
    20: [6, 34, 62, 90],
}

# ── ECC level L: (EC codewords per block, block count) ──────────────────
ECC_L = {
    1: (7, 1), 2: (10, 1), 3: (15, 1), 4: (20, 1), 5: (26, 1),
    6: (18, 2), 7: (20, 2), 8: (24, 2), 9: (30, 2), 10: (18, 4),
    11: (20, 4), 12: (24, 4), 13: (26, 4), 14: (30, 4), 15: (22, 6),
    16: (24, 6), 17: (28, 6), 18: (30, 6), 19: (28, 7), 20: (28, 8),
}
# Total data codewords for level L (spec tables; used to check the count).
DATA_CODEWORDS_L = {
    1: 19, 2: 34, 3: 55, 4: 80, 5: 108, 6: 136, 7: 156, 8: 194,
    9: 232, 10: 274, 11: 324, 12: 370, 13: 428, 14: 461, 15: 523,
    16: 589, 17: 647, 18: 721, 19: 795, 20: 861,
}


def mask_condition(mask: int, i: int, j: int) -> bool:
    """Table 10 conditions. `i` = row, `j` = column."""
    if mask == 0:
        return (i + j) % 2 == 0
    if mask == 1:
        return i % 2 == 0
    if mask == 2:
        return j % 3 == 0
    if mask == 3:
        return (i + j) % 3 == 0
    if mask == 4:
        return (i // 2 + j // 3) % 2 == 0
    if mask == 5:
        return (i * j) % 2 + (i * j) % 3 == 0
    if mask == 6:
        return ((i * j) % 2 + (i * j) % 3) % 2 == 0
    if mask == 7:
        return ((i + j) % 2 + (i * j) % 3) % 2 == 0
    raise ValueError(f"mask out of range: {mask}")


def function_map(size: int, version: int) -> list[list[bool]]:
    """True for modules that are NOT data (function patterns + format)."""
    fn = [[False] * size for _ in range(size)]

    def mark(x: int, y: int) -> None:
        if 0 <= x < size and 0 <= y < size:
            fn[y][x] = True

    def box(cx: int, cy: int, r: int) -> None:
        for dy in range(-r, r + 1):
            for dx in range(-r, r + 1):
                mark(cx + dx, cy + dy)

    # Finder patterns + separators (±4 includes the separator).
    box(3, 3, 4)
    box(size - 4, 3, 4)
    box(3, size - 4, 4)
    # Timing patterns.
    for k in range(size):
        mark(6, k)
        mark(k, 6)
    # Alignment patterns (skip the three finder corners).
    pos = ALIGNMENT[version]
    last = len(pos) - 1
    for ai, ax in enumerate(pos):
        for aj, ay in enumerate(pos):
            if (ai == 0 and aj in (0, last)) or (ai == last and aj == 0):
                continue
            box(ax, ay, 2)
    # Format information (both copies) + the dark module.
    for k in range(9):
        mark(8, k)
        mark(k, 8)
    for k in range(8):
        mark(size - 1 - k, 8)
        mark(8, size - 1 - k)
    # Version information for version >= 7.
    if version >= 7:
        for a in range(6):
            for b in range(3):
                mark(size - 11 + b, a)
                mark(a, size - 11 + b)
    return fn


def read_format_bits(matrix: list[list[int]], size: int, copy: int) -> int:
    """The 15-bit format word as laid out by the spec (bit 0 = first module)."""
    if copy == 1:
        # Around the top-left finder: (8,0..5), (8,7), (8,8), (7,8), (5..0,8).
        coords = [(8, k) for k in range(6)] + [(8, 7), (8, 8), (7, 8)]
        coords += [(k, 8) for k in range(5, -1, -1)]
    else:
        # Split second copy: (size-1..size-8, 8) then (8, size-7..size-1).
        coords = [(size - 1 - k, 8) for k in range(8)]
        coords += [(8, size - 15 + k) for k in range(8, 15)]
    word = 0
    for k, (x, y) in enumerate(coords):
        word |= matrix[y][x] << k
    return word


def read_format(matrix: list[list[int]], size: int) -> tuple[int, bool]:
    """Return (mask, bch_valid) for format-info copy 1."""
    raw = read_format_bits(matrix, size, 1) ^ 0x5412
    mask = (raw >> 10) & 0x7
    rem = raw & 0x3FF
    value = (0b01 << 3) | mask  # ECC level L == 01
    for _ in range(10):
        value = (value << 1) ^ ((value >> 9) * 0x537)
    return mask, (value & 0x3FF) == rem


def read_codewords(matrix: list[list[int]], fn: list[list[bool]], size: int, mask: int) -> list[int]:
    """Read (and unmask) the data modules in the spec's placement order."""
    bits: list[int] = []
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        for step in range(size):
            y = (size - 1 - step) if upward else step
            for j in (col, col - 1):
                if not fn[y][j]:
                    bit = matrix[y][j]
                    if mask_condition(mask, y, j):
                        bit ^= 1
                    bits.append(bit)
        upward = not upward
        col -= 2
    codewords = []
    for k in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[k : k + 8]:
            byte = (byte << 1) | b
        codewords.append(byte)
    return codewords


def deinterleave(codewords: list[int], version: int) -> list[list[int]]:
    """Split the codeword stream into (data+ecc) blocks per the spec."""
    ec_per_block, blocks = ECC_L[version]
    total = DATA_CODEWORDS_L[version] + ec_per_block * blocks
    if len(codewords) < total:
        raise ValueError(f"codeword stream short: {len(codewords)} < {total}")
    codewords = codewords[:total]
    short_len = total // blocks
    num_short = blocks - total % blocks
    short_data = short_len - ec_per_block
    data_blocks: list[list[int]] = [[] for _ in range(blocks)]
    ec_blocks: list[list[int]] = [[] for _ in range(blocks)]
    idx = 0
    for _ in range(short_data):
        for b in range(blocks):
            data_blocks[b].append(codewords[idx])
            idx += 1
    for b in range(num_short, blocks):
        data_blocks[b].append(codewords[idx])
        idx += 1
    for _ in range(ec_per_block):
        for b in range(blocks):
            ec_blocks[b].append(codewords[idx])
            idx += 1
    return [data_blocks[b] + ec_blocks[b] for b in range(blocks)]


def syndromes_zero(block: list[int], ec_len: int) -> bool:
    """Evaluate the block polynomial at alpha^0..alpha^(ec_len-1)."""
    for s in range(ec_len):
        acc = 0
        for coef in block:
            acc = gf_mul(acc, GF_EXP[s]) ^ coef
        if acc != 0:
            return False
    return True


def decode_case(version: int, mask: int, size: int, rows: list[str]) -> bytes:
    if size != 4 * version + 17:
        raise ValueError(f"size {size} does not match version {version}")
    matrix = [[1 if ch == "1" else 0 for ch in row.strip()] for row in rows]
    if any(len(r) != size for r in matrix):
        raise ValueError("row length mismatch")
    fn = function_map(size, version)
    got_mask, bch_ok = read_format(matrix, size)
    if not bch_ok:
        raise ValueError("format-info BCH check failed")
    if got_mask != mask:
        raise ValueError(f"format encodes mask {got_mask}, expected {mask}")
    if read_format_bits(matrix, size, 1) != read_format_bits(matrix, size, 2):
        raise ValueError("format-info copies disagree")
    codewords = read_codewords(matrix, fn, size, got_mask)
    blocks = deinterleave(codewords, version)
    ec_per_block = ECC_L[version][0]
    for b, block in enumerate(blocks):
        if not syndromes_zero(block, ec_per_block):
            raise ValueError(f"RS syndromes non-zero in block {b}")
    data = [cw for block in blocks for cw in block[:-ec_per_block]]
    if len(data) != DATA_CODEWORDS_L[version]:
        raise ValueError(f"data codeword count {len(data)} != {DATA_CODEWORDS_L[version]}")
    bits = [(byte >> (7 - k)) & 1 for byte in data for k in range(8)]
    mode = 0
    for b in bits[:4]:
        mode = (mode << 1) | b
    if mode != 0b0100:
        raise ValueError(f"mode {mode:04b} is not byte mode")
    pos = 4
    count_bits = 8 if version <= 9 else 16
    count = 0
    for b in bits[pos : pos + count_bits]:
        count = (count << 1) | b
    pos += count_bits
    payload = bytearray()
    for _ in range(count):
        byte = 0
        for b in bits[pos : pos + 8]:
            byte = (byte << 1) | b
        payload.append(byte)
        pos += 8
    return bytes(payload)


def main() -> int:
    lines = [line.rstrip("\n") for line in sys.stdin]
    if not lines:
        print("FAIL empty input", file=sys.stderr)
        return 1
    head = lines[0].split()
    if len(head) != 2 or head[0] != "CASES":
        print(f"FAIL header must be 'CASES <n>', got {lines[0]!r}", file=sys.stderr)
        return 1
    expected_cases = int(head[1])
    idx = 1
    failures = 0
    case_no = 0
    while case_no < expected_cases:
        if idx >= len(lines):
            print(f"FAIL truncated stream at case {case_no + 1}", file=sys.stderr)
            return 1
        header = lines[idx].split()
        idx += 1
        if header[0] != "CASE" or len(header) != 5:
            print(f"FAIL bad case header: {lines[idx - 1]!r}", file=sys.stderr)
            return 1
        version, mask, size, exp_len = (int(v) for v in header[1:])
        payload_hex = lines[idx].strip()
        idx += 1
        rows = lines[idx : idx + size]
        idx += size
        case_no += 1
        expected = bytes.fromhex(payload_hex)
        if len(expected) != exp_len:
            print(f"FAIL case {case_no}: expected length mismatch", file=sys.stderr)
            return 1
        try:
            got = decode_case(version, mask, size, rows)
        except ValueError as exc:
            print(f"FAIL case {case_no} (v{version} mask {mask}): {exc}", file=sys.stderr)
            failures += 1
            continue
        if got != expected:
            print(
                f"FAIL case {case_no} (v{version} mask {mask}): payload mismatch "
                f"{got!r} != {expected!r}",
                file=sys.stderr,
            )
            failures += 1
            continue
        print(f"OK case {case_no} v{version} mask{mask} bytes={len(got)}")
    if idx != len(lines):
        print(f"FAIL trailing data after {expected_cases} cases", file=sys.stderr)
        return 1
    if failures:
        print(f"FAIL {failures}/{expected_cases} QR cases failed", file=sys.stderr)
        return 1
    print(f"OK all {expected_cases} QR cases decode independently")
    return 0


if __name__ == "__main__":
    sys.exit(main())
