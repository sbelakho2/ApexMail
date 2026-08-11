//! KiwiCaptcha WASM solver — hybrid solving engine for the browser widget.
//!
//! Exposes two chunked proof-of-work solvers:
//! - `solve_sha256_chunk`  — classic CPU-bound SHA-256 PoW.
//! - `solve_argon2_chunk`  — memory-hard Argon2id PoW (ASIC/GPU resistant).
//!
//! Both take the challenge prefix and salt as raw pointer/length pairs (the
//! widget allocates the buffers with `__wbindgen_malloc`, copies the bytes,
//! and frees them with `__wbindgen_free`) and search a half-open counter
//! range `[start_counter, start_counter + chunk_size)`, returning the first
//! counter whose hash meets `target_bits` leading-zero bits, or -1 if the
//! chunk is exhausted. Chunking lets the widget yield to the UI between calls.
//!
//! The counter is encoded as its decimal representation (identical to the
//! server verifier in `kiwicaptcha::verify::derive_hash` and to the pure-JS
//! fallback), so all three solvers agree byte-for-byte on the preimage:
//! `SHA-256(prefix || decimal(counter) || salt)` / Argon2id with the same
//! password layout.

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use std::alloc::Layout;
use wasm_bindgen::prelude::*;

/// Install the panic hook that forwards Rust panics to console.error.
/// Safe to call multiple times; only the first call installs the hook.
#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Allocate `len` bytes in WASM linear memory and return the pointer.
///
/// This is the widget's buffer allocator for the raw-pointer solver ABI.
/// It is an explicit wasm-bindgen public symbol (rather than relying on
/// wasm-bindgen's generated `__wbindgen_malloc`) so that wasm-opt/binaryen
/// cannot dead-code-eliminate it, and so the name is stable across toolchain
/// versions.
///
/// # Allocation contract
///
/// The allocation is made directly through [`std::alloc`] with the layout
/// `Layout::from_size_align(len, 8)`. The returned pointer must be released
/// with [`dealloc`], passing the **exact same** `len` — the deallocator
/// rebuilds the identical layout, which is what makes
/// [`std::alloc::dealloc`] sound. (A `Vec::with_capacity`-based allocator
/// would be unsound here: `with_capacity` only guarantees `capacity >= len`,
/// while `Vec::from_raw_parts` requires the exact original capacity.)
///
/// Returns **null on allocation failure** (when `std::alloc::alloc` returns
/// null, i.e. the linear memory is exhausted, or when the layout cannot be
/// represented, e.g. `len` beyond `isize::MAX`); callers must check for null
/// and fall back to the pure-JS solver path. `len == 0` returns a
/// dangling-but-aligned pointer (non-null, 8-byte aligned) that must never be
/// dereferenced or passed to [`dealloc`] — no backing memory is allocated.
///
/// The JS glue passes back the exact original byte length, so the contract
/// holds across the boundary.
#[wasm_bindgen]
pub fn alloc(len: usize) -> *mut u8 {
    let layout = match Layout::from_size_align(len, 8) {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };
    if len == 0 {
        // Dangling but 8-byte aligned and non-null; never dereferenceable and
        // never passed to `dealloc` (the JS glue only frees real buffers).
        return layout.align() as *mut u8;
    }
    let ptr = unsafe { std::alloc::alloc(layout) };
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    ptr
}

/// Free a buffer previously returned by [`alloc`].
///
/// `len` must match the allocation size **exactly** (it is the length passed
/// to [`alloc`]); the same `Layout::from_size_align(len, 8)` is rebuilt so
/// the deallocation is sound. Null pointers and zero-length requests are
/// no-ops (nothing was allocated for them).
///
/// Safety: the caller must pass a pointer/len produced by [`alloc`] and must
/// not use the pointer afterwards.
#[wasm_bindgen]
pub unsafe fn dealloc(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let layout = Layout::from_size_align(len, 8).expect("allocation size overflows isize::MAX");
    unsafe { std::alloc::dealloc(ptr, layout) };
}

/// Search `[start_counter, start_counter + chunk_size)` for a counter whose
/// `SHA-256(prefix || decimal(counter) || salt)` output has at least
/// `target_bits` leading zero bits. Returns the counter or -1.
#[wasm_bindgen]
pub fn solve_sha256_chunk(
    prefix_ptr: *const u8,
    prefix_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    target_bits: u32,
    start_counter: u32,
    chunk_size: u32,
) -> i32 {
    if prefix_ptr.is_null() || salt_ptr.is_null() {
        return -1;
    }
    let prefix = unsafe { std::slice::from_raw_parts(prefix_ptr, prefix_len) };
    let salt = unsafe { std::slice::from_raw_parts(salt_ptr, salt_len) };

    let end_counter = bounded_end(start_counter, chunk_size);

    let mut hasher_base = Sha256::new();
    hasher_base.update(prefix);

    let mut buf = [0u8; 12];

    for counter in start_counter..end_counter {
        let mut hasher = hasher_base.clone();

        let len = write_decimal(counter, &mut buf);
        hasher.update(&buf[..len]);

        hasher.update(salt);
        let result = hasher.finalize();

        if leading_zero_bits(&result) >= target_bits {
            return counter as i32;
        }
    }
    -1
}

/// Search `[start_counter, start_counter + chunk_size)` for a counter whose
/// `Argon2id(prefix || decimal(counter), salt)` output has at least
/// `target_bits` leading zero bits. Returns the counter or -1.
///
/// `m_kib`/`t`/`p` are the Argon2id parameters; they must match the server's
/// issued challenge parameters exactly. Invalid parameters return -1 so the
/// widget can fall back cleanly.
#[wasm_bindgen]
pub fn solve_argon2_chunk(
    prefix_ptr: *const u8,
    prefix_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    target_bits: u32,
    m_kib: u32,
    t: u32,
    p: u32,
    start_counter: u32,
    chunk_size: u32,
) -> i32 {
    if prefix_ptr.is_null() || salt_ptr.is_null() {
        return -1;
    }
    let prefix = unsafe { std::slice::from_raw_parts(prefix_ptr, prefix_len) };
    let salt = unsafe { std::slice::from_raw_parts(salt_ptr, salt_len) };

    let params = match Params::new(m_kib, t, p, Some(32)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let end_counter = bounded_end(start_counter, chunk_size);

    // Reuse the password buffer across iterations (only the counter digits change).
    let mut password = Vec::with_capacity(prefix.len() + 12);
    password.extend_from_slice(prefix);
    let digit_start = password.len();

    let mut buf = [0u8; 12];
    let mut output = [0u8; 32];

    for counter in start_counter..end_counter {
        password.truncate(digit_start);
        let len = write_decimal(counter, &mut buf);
        password.extend_from_slice(&buf[..len]);

        if hasher
            .hash_password_into(&password, salt, &mut output)
            .is_err()
        {
            return -1;
        }
        if leading_zero_bits(&output) >= target_bits {
            return counter as i32;
        }
    }
    -1
}

/// Clamp the search window so `end_counter` never overflows u32 or i32.
fn bounded_end(start_counter: u32, chunk_size: u32) -> u32 {
    start_counter
        .saturating_add(chunk_size)
        .min(i32::MAX as u32)
}

/// Write `n` as decimal ASCII digits into `buf`, returning the digit count.
fn write_decimal(mut n: u32, buf: &mut [u8; 12]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut temp = [0u8; 10];
    let mut j = 0;
    while n > 0 {
        temp[j] = b'0' + (n % 10) as u8;
        n /= 10;
        j += 1;
    }
    for i in 0..j {
        buf[i] = temp[j - 1 - i];
    }
    j
}

/// Count leading zero BITS of a 32-byte hash (big-endian bit order).
fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0;
    for &byte in hash {
        let lz = byte.leading_zeros();
        count += lz;
        if lz < 8 {
            break;
        }
    }
    count
}
