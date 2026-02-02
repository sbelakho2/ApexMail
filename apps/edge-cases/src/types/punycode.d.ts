declare module 'punycode/' {
  export function toASCII(domain: string): string;
  export function toUnicode(domain: string): string;
  export function encode(string: string): string;
  export function decode(string: string): string;
  export const ucs2: {
    decode(string: string): number[];
    encode(array: number[]): string;
  };
  export const version: string;
}
