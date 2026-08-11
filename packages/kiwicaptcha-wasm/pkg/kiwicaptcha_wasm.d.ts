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
 * The returned pointer must be released with [`dealloc`].
 */
export function alloc(len: number): number;

/**
 * Free a buffer previously returned by [`alloc`].
 *
 * `len` must match the allocation size exactly (it is the Vec capacity).
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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly alloc: (a: number) => number;
    readonly dealloc: (a: number, b: number) => void;
    readonly init_panic_hook: () => void;
    readonly solve_argon2_chunk: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => number;
    readonly solve_sha256_chunk: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
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
