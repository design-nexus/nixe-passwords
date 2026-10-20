// The extension's pairing derivation, through WebCrypto exactly as background.js does
// it, on fixed keys. crates/nixe-passwords-core's crypto tests assert the same output
// from the daemon's side (RustCrypto), so the two can't drift apart.
//
//   node apps/passwords/browser/test/pairing-vector.mjs

const { subtle } = globalThis.crypto;
const hex = (b) => Buffer.from(b).toString("hex");
const enc = new TextEncoder();

// PKCS#8 for a raw X25519 private key.
const pkcs8 = (raw) => Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(raw)]);
const ext = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const daemon = Uint8Array.from({ length: 32 }, (_, i) => i + 33);

async function pair(privRaw) {
  const key = await subtle.importKey("pkcs8", pkcs8(privRaw), { name: "X25519" }, true, ["deriveBits"]);
  const jwk = await subtle.exportKey("jwk", key);
  return { key, pub: Buffer.from(jwk.x, "base64url") };
}

const mine = await pair(ext);
const theirs = await pair(daemon);
const peer = await subtle.importKey("raw", theirs.pub, { name: "X25519" }, false, []);
const shared = await subtle.deriveBits({ name: "X25519", public: peer }, mine.key, 256);
const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
const salt = Buffer.concat([mine.pub, theirs.pub]);
const derive = (info, bits) => subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) }, ikm, bits);
const key = await derive("nixe-passwords pair v1", 256);
const code = String(new DataView(await derive("nixe-passwords code v1", 32)).getUint32(0) % 1000000).padStart(6, "0");
console.log(JSON.stringify({ ext_public: hex(mine.pub), daemon_public: hex(theirs.pub), key: hex(key), code }));
