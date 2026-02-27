export function parseIpv4(value: string): number | null {
    const parts = value.split('.');
    if (parts.length !== 4) return null;
    const numbers = parts.map(part => Number(part));
    if (numbers.some(number => Number.isNaN(number) || number < 0 || number > 255)) return null;
    return ((numbers[0] << 24) >>> 0) + (numbers[1] << 16) + (numbers[2] << 8) + numbers[3];
}

export function parseCidr(input: string): { network: number; maskBits: number } | null {
    const [ip, mask] = input.split('/');
    if (!ip || !mask) return null;
    const ipValue = parseIpv4(ip);
    const maskBits = Number(mask);
    if (ipValue === null || Number.isNaN(maskBits) || maskBits < 0 || maskBits > 32) return null;
    const maskValue = maskBits === 0 ? 0 : ((0xffffffff << (32 - maskBits)) >>> 0);
    return { network: ipValue & maskValue, maskBits };
}

export function isValidIpOrCidr(input: string): boolean {
    const trimmed = input.trim();
    if (!trimmed) return false;
    if (trimmed.includes('/')) return parseCidr(trimmed) !== null;
    return parseIpv4(trimmed) !== null;
}

export function hasCidrOverlap(candidate: string, existing: string[]): string | null {
    const normalizedCandidate = candidate.trim();
    const candidateCidr = normalizedCandidate.includes('/') ? parseCidr(normalizedCandidate) : null;
    const candidateIp = !normalizedCandidate.includes('/') ? parseIpv4(normalizedCandidate) : null;

    for (const current of existing) {
        if (current === normalizedCandidate) {
            return `Duplicate entry: ${current}`;
        }

        const currentCidr = current.includes('/') ? parseCidr(current) : null;
        const currentIp = !current.includes('/') ? parseIpv4(current) : null;

        if (candidateIp !== null && currentCidr) {
            const maskValue = currentCidr.maskBits === 0 ? 0 : ((0xffffffff << (32 - currentCidr.maskBits)) >>> 0);
            if ((candidateIp & maskValue) === currentCidr.network) {
                return `IP overlaps existing range: ${current}`;
            }
        }

        if (candidateCidr && currentIp !== null) {
            const maskValue = candidateCidr.maskBits === 0 ? 0 : ((0xffffffff << (32 - candidateCidr.maskBits)) >>> 0);
            if ((currentIp & maskValue) === candidateCidr.network) {
                return `Range overlaps existing IP: ${current}`;
            }
        }

        if (candidateCidr && currentCidr) {
            const smallestMaskBits = Math.min(candidateCidr.maskBits, currentCidr.maskBits);
            const smallestMask = smallestMaskBits === 0 ? 0 : ((0xffffffff << (32 - smallestMaskBits)) >>> 0);
            if ((candidateCidr.network & smallestMask) === (currentCidr.network & smallestMask)) {
                return `CIDR overlaps existing range: ${current}`;
            }
        }
    }

    return null;
}
