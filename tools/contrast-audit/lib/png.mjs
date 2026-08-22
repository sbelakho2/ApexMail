// Minimal PNG decoder for RGBA/RGB 8-bit non-interlaced images (Playwright screenshots).
// Purpose: pixel-level confirmation of WCAG contrast findings without native deps.
import zlib from 'node:zlib';

/**
 * @returns {{width:number, height:number, channels:number, data:Uint8Array}}
 */
export function decodePng(buf) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (buf.length < 8 || !buf.subarray(0, 8).equals(sig)) throw new Error('not a PNG');
  let pos = 8;
  let width = 0, height = 0, bitDepth = 0, colorType = 0, interlace = 0;
  const idat = [];
  let palette = null, trns = null;
  while (pos < buf.length) {
    const len = buf.readUInt32BE(pos);
    const type = buf.toString('ascii', pos + 4, pos + 8);
    const data = buf.subarray(pos + 8, pos + 8 + len);
    if (type === 'IHDR') {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data[8];
      colorType = data[9];
      interlace = data[12];
    } else if (type === 'IDAT') {
      idat.push(data);
    } else if (type === 'PLTE') {
      palette = data;
    } else if (type === 'tRNS') {
      trns = data;
    } else if (type === 'IEND') {
      break;
    }
    pos += 12 + len;
  }
  if (bitDepth !== 8) throw new Error(`unsupported bit depth ${bitDepth}`);
  if (interlace !== 0) throw new Error('interlaced PNG unsupported');
  const channelsByType = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };
  const ch = channelsByType[colorType];
  if (!ch) throw new Error(`unsupported color type ${colorType}`);
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const stride = width * ch;
  const out = new Uint8Array(width * height * 4);
  let prev = new Uint8Array(stride);
  let cur = new Uint8Array(stride);
  let p = 0;
  for (let y = 0; y < height; y++) {
    const filter = raw[p++];
    for (let i = 0; i < stride; i++) cur[i] = raw[p + i];
    p += stride;
    switch (filter) {
      case 0: break;
      case 1:
        for (let i = ch; i < stride; i++) cur[i] = (cur[i] + cur[i - ch]) & 0xff;
        break;
      case 2:
        for (let i = 0; i < stride; i++) cur[i] = (cur[i] + prev[i]) & 0xff;
        break;
      case 3:
        for (let i = 0; i < stride; i++) {
          const left = i >= ch ? cur[i - ch] : 0;
          cur[i] = (cur[i] + ((left + prev[i]) >> 1)) & 0xff;
        }
        break;
      case 4:
        for (let i = 0; i < stride; i++) {
          const a = i >= ch ? cur[i - ch] : 0;
          const b = prev[i];
          const c = i >= ch ? prev[i - ch] : 0;
          const pp = a + b - c;
          const pa = Math.abs(pp - a), pb = Math.abs(pp - b), pc = Math.abs(pp - c);
          const pred = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
          cur[i] = (cur[i] + pred) & 0xff;
        }
        break;
      default:
        throw new Error(`bad filter ${filter}`);
    }
    const rowStart = y * width * 4;
    for (let x = 0; x < width; x++) {
      const s = x * ch;
      const d = rowStart + x * 4;
      if (colorType === 6) {
        out[d] = cur[s]; out[d + 1] = cur[s + 1]; out[d + 2] = cur[s + 2]; out[d + 3] = cur[s + 3];
      } else if (colorType === 2) {
        out[d] = cur[s]; out[d + 1] = cur[s + 1]; out[d + 2] = cur[s + 2]; out[d + 3] = 255;
      } else if (colorType === 4) {
        out[d] = out[d + 1] = out[d + 2] = cur[s]; out[d + 3] = cur[s + 1];
      } else if (colorType === 0) {
        out[d] = out[d + 1] = out[d + 2] = cur[s]; out[d + 3] = 255;
      } else if (colorType === 3) {
        const idx = cur[s] * 3;
        out[d] = palette[idx]; out[d + 1] = palette[idx + 1]; out[d + 2] = palette[idx + 2];
        out[d + 3] = trns && cur[s] < trns.length ? trns[cur[s]] : 255;
      }
    }
    const t = prev; prev = cur; cur = t;
  }
  return { width, height, channels: 4, data: out };
}

export function pngPixel(img, x, y) {
  x = Math.max(0, Math.min(img.width - 1, Math.round(x)));
  y = Math.max(0, Math.min(img.height - 1, Math.round(y)));
  const i = (y * img.width + x) * 4;
  return [img.data[i], img.data[i + 1], img.data[i + 2], img.data[i + 3]];
}
