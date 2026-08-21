/* tslint:disable */
/* eslint-disable */

/**
 * Allocate `len` bytes in WASM linear memory and return the pointer.
 *
 * This is the widget's buffer allocator for the raw-pointer solver ABI.
 * It is an explicit wasm-bindgen public symbol (rather than relying on
 * wasm-bindgen's generated `__wbindgen_malloc`) so that wasm-opt/binaryen
 * cannot dead-code-eliminate it, and so the name is stable across toolchain
 * versions.
 *
 * # Allocation contract
 *
 * The allocation is made directly through [`std::alloc`] with the layout
 * `Layout::from_size_align(len, 8)`. The returned pointer must be released
 * with [`dealloc`], passing the **exact same** `len` — the deallocator
 * rebuilds the identical layout, which is what makes
 * [`std::alloc::dealloc`] sound. (A `Vec::with_capacity`-based allocator
 * would be unsound here: `with_capacity` only guarantees `capacity >= len`,
 * while `Vec::from_raw_parts` requires the exact original capacity.)
 *
 * Returns **null on allocation failure** (when `std::alloc::alloc` returns
 * null, i.e. the linear memory is exhausted, or when the layout cannot be
 * represented, e.g. `len` beyond `isize::MAX`); callers must check for null
 * and fall back to the pure-JS solver path. `len == 0` returns a
 * dangling-but-aligned pointer (non-null, 8-byte aligned) that must never be
 * dereferenced or passed to [`dealloc`] — no backing memory is allocated.
 *
 * The JS glue passes back the exact original byte length, so the contract
 * holds across the boundary.
 */
export function alloc(len: number): number;

/**
 * Free a buffer returned by [`alloc`].
 *
 * `len` must match the allocation size **exactly** (it is the length passed
 * to [`alloc`]); the same `Layout::from_size_align(len, 8)` is rebuilt so
 * the deallocation is sound. Null pointers and zero-length requests are
 * no-ops (nothing was allocated for them).
 *
 * Safety: the caller must pass a pointer/len produced by [`alloc`] and must
 * not use the pointer afterwards.
 */
export function dealloc(ptr: number, len: number): void;

/**
 * Install the panic hook that forwards Rust panics to console.error.
 * Safe to call multiple times; only the first call installs the hook.
 */
export function init_panic_hook(): void;

/**
 * Search `[start_counter, start_counter + chunk_size)` for a counter whose
 * `Argon2id(prefix || decimal(counter), salt)` output has at least
 * `target_bits` leading zero bits. Returns the counter or -1.
 *
 * `m_kib`/`t`/`p` are the Argon2id parameters; they must match the server's
 * issued challenge parameters exactly. Invalid parameters return -1 so the
 * widget can fall back cleanly.
 */
export function solve_argon2_chunk(prefix_ptr: number, prefix_len: number, salt_ptr: number, salt_len: number, target_bits: number, m_kib: number, t: number, p: number, start_counter: number, chunk_size: number): number;

/**
 * Search `[start_counter, start_counter + chunk_size)` for a counter whose
 * `SHA-256(prefix || decimal(counter) || salt)` output has at least
 * `target_bits` leading zero bits. Returns the counter or -1.
 */
export function solve_sha256_chunk(prefix_ptr: number, prefix_len: number, salt_ptr: number, salt_len: number, target_bits: number, start_counter: number, chunk_size: number): number;

/**
 * The solver PROTOCOL/ABI VERSION (an integer is the
 * clean primitive at the raw wasm-bindgen ABI boundary, where a String
 * return surfaces as a [ptr, len] tuple). The runtime handshake uses it
 * ONLY to prove that the driver, the worker and the WASM glue speak the
 * same protocol generation; it is NOT an exact-artifact identity. Exact
 * byte identity is guaranteed by the release system: tag + SHA256SUMS +
 * SRI.txt + SLSA attestation.
 *
 * This value MUST equal `KIWI_SOLVER_PROTOCOL_VERSION` in
 * `assets/kiwi-worker.js` — the worker verifies the loaded wasm's
 * exported value against its constant BEFORE sending `ready`, so a
 * mismatch fails closed instead of solving with a mismatched pair.
 */
export function solver_protocol_version(): number;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly alloc: (a: number) => number;
    readonly dealloc: (a: number, b: number) => void;
    readonly init_panic_hook: () => void;
    readonly solve_argon2_chunk: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => number;
    readonly solve_sha256_chunk: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
    readonly solver_protocol_version: () => number;
    readonly __wbindgen_export: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export2: (a: number, b: number) => number;
    readonly __wbindgen_export3: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
