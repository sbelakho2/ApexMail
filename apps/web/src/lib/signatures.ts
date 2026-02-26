const encoder = new TextEncoder();

function toBase64Url(bytes: Uint8Array): string {
    if (typeof Buffer !== 'undefined') {
        return Buffer.from(bytes).toString('base64url');
    }

    let binary = '';
    bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
    });

    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(value: string): Uint8Array {
    if (typeof Buffer !== 'undefined') {
        return new Uint8Array(Buffer.from(value, 'base64url'));
    }

    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

export function encodeStringToBase64Url(value: string): string {
    return toBase64Url(encoder.encode(value));
}

export function decodeBase64UrlToString(value: string): string {
    return new TextDecoder().decode(fromBase64Url(value));
}

export async function hmacSha256Base64Url(secret: string, value: string): Promise<string> {
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(value));
    return toBase64Url(new Uint8Array(signature));
}

export function constantTimeEqual(left: string, right: string): boolean {
    if (left.length !== right.length) return false;

    let diff = 0;
    for (let i = 0; i < left.length; i += 1) {
        diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
    }

    return diff === 0;
}

export async function createSignedToken(payload: unknown, secret: string): Promise<string> {
    const payloadB64 = encodeStringToBase64Url(JSON.stringify(payload));
    const signature = await hmacSha256Base64Url(secret, payloadB64);
    return `${payloadB64}.${signature}`;
}

export async function verifySignedToken<T>(token: string, secret: string): Promise<{ valid: boolean; payload?: T }> {
    const [payloadB64, signature] = token.split('.');

    if (!payloadB64 || !signature) {
        return { valid: false };
    }

    const expectedSignature = await hmacSha256Base64Url(secret, payloadB64);
    if (!constantTimeEqual(signature, expectedSignature)) {
        return { valid: false };
    }

    try {
        const payload = JSON.parse(decodeBase64UrlToString(payloadB64)) as T;
        return { valid: true, payload };
    } catch {
        return { valid: false };
    }
}

export function generateRandomBase64Url(byteLength = 32): string {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return toBase64Url(bytes);
}
