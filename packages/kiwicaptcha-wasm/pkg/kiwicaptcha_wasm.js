/* @ts-self-types="./kiwicaptcha_wasm.d.ts" */

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
 * @param {number} len
 * @returns {number}
 */
export function alloc(len) {
    const ret = wasm.alloc(len);
    return ret >>> 0;
}

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
 * @param {number} ptr
 * @param {number} len
 */
export function dealloc(ptr, len) {
    wasm.dealloc(ptr, len);
}

/**
 * Install the panic hook that forwards Rust panics to console.error.
 * Safe to call multiple times; only the first call installs the hook.
 */
export function init_panic_hook() {
    wasm.init_panic_hook();
}

/**
 * Search `[start_counter, start_counter + chunk_size)` for a counter whose
 * Argon2id hash of the prefix, the decimal counter and the salt has at
 * least `target_bits` leading zero bits. Returns the counter or -1.
 *
 * `m_kib`/`t`/`p` are the Argon2id parameters; they must match the server's
 * issued challenge parameters exactly. Invalid parameters return -1 so the
 * widget can fall back cleanly.
 * @param {number} prefix_ptr
 * @param {number} prefix_len
 * @param {number} salt_ptr
 * @param {number} salt_len
 * @param {number} target_bits
 * @param {number} m_kib
 * @param {number} t
 * @param {number} p
 * @param {number} start_counter
 * @param {number} chunk_size
 * @returns {number}
 */
export function solve_argon2_chunk(prefix_ptr, prefix_len, salt_ptr, salt_len, target_bits, m_kib, t, p, start_counter, chunk_size) {
    const ret = wasm.solve_argon2_chunk(prefix_ptr, prefix_len, salt_ptr, salt_len, target_bits, m_kib, t, p, start_counter, chunk_size);
    return ret;
}

/**
 * Search `[start_counter, start_counter + chunk_size)` for a counter whose
 * SHA-256 hash of the prefix, the decimal counter and the salt has at
 * least `target_bits` leading zero bits.
 *
 * The chunk is TIME-budgeted (≈ [`SHA_CHUNK_TIME_BUDGET_MS`] of wall
 * time), so the caller yields back to the event loop at roughly constant
 * latency regardless of the device. Return contract:
 * - `counter >= 0`    — a solution at that counter;
 * - `-1`              — no solution in the whole `chunk_size` window
 *                       (the caller advances by `chunk_size`);
 * - `-(scanned + 1)` (i.e. `<= -2`) — the time budget elapsed after
 *   `scanned` hashes with no solution; the caller resumes at
 *   `start_counter + scanned`, neither skipping nor redoing work.
 * @param {number} prefix_ptr
 * @param {number} prefix_len
 * @param {number} salt_ptr
 * @param {number} salt_len
 * @param {number} target_bits
 * @param {number} start_counter
 * @param {number} chunk_size
 * @returns {number}
 */
export function solve_sha256_chunk(prefix_ptr, prefix_len, salt_ptr, salt_len, target_bits, start_counter, chunk_size) {
    const ret = wasm.solve_sha256_chunk(prefix_ptr, prefix_len, salt_ptr, salt_len, target_bits, start_counter, chunk_size);
    return ret;
}

/**
 * The solver protocol/ABI version (an integer is the
 * clean primitive at the raw wasm-bindgen ABI boundary, where a String
 * return surfaces as a [ptr, len] tuple). The runtime handshake uses it
 * only to prove that the driver, the worker and the WASM glue speak the
 * same protocol generation; it is not an exact-artifact identity. Exact
 * byte identity is guaranteed by the release system: tag + SHA256SUMS +
 * SRI.txt + SLSA attestation.
 *
 * This value MUST equal `KIWI_SOLVER_PROTOCOL_VERSION` in
 * `assets/kiwi-worker.js` — the worker verifies the loaded wasm's
 * exported value against its constant before sending `ready`, so a
 * mismatch fails closed instead of solving with a mismatched pair.
 * @returns {number}
 */
export function solver_protocol_version() {
    const ret = wasm.solver_protocol_version();
    return ret >>> 0;
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_throw_bb96b2010945f0bc: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_error_757e9472f8410341: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_export(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_now_8b265300afd5f2b9: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_export2, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./kiwicaptcha_wasm_bg.js": import0,
    };
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (!module.ok) {
            throw new Error(`failed to fetch Wasm: ${module.status} ${module.statusText} fetching '${module.url}'`);
        }

        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('kiwicaptcha_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
