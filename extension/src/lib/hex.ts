// Pure hex helpers with no external dependencies. Isolated so the
// offscreen and service-worker bundles don't pull in @noble/hashes (which
// keccak.ts DOES pull). This keeps the offscreen bundle small (~8 kB).
//
// hexToBytes left-pads when the length is odd. Designed for Ethereum
// hex strings where "0x1" means 0x01.

export function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (let i = 0; i < b.length; i++) {
    out += b[i].toString(16).padStart(2, "0");
  }
  return out;
}

export function hexToBytes(h: string): Uint8Array {
  let s = h.startsWith("0x") || h.startsWith("0X") ? h.slice(2) : h;
  if (s.length % 2 !== 0) s = "0" + s;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}
