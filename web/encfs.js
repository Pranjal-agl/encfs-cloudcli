// encfs.js — a WebCrypto implementation of the encfs-cloudcli on-disk formats.
//
// Byte-for-byte compatible with the C++ implementation (src/crypto.cpp,
// src/file_codec.cpp, src/index.cpp, src/key_setup.cpp); CI cross-checks the
// two. Works in browsers and in Node >= 20 (globalThis.crypto).
//
// Everything runs locally: nothing here touches the network.

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const MAGIC = enc.encode("ENCFS");
export const FORMAT_VERSION = 2;
export const HEADER_SIZE = 5 + 1 + 4 + 32;
export const TAG_SIZE = 16;
export const DEFAULT_CHUNK_SIZE = 1024 * 1024;
const ROLLBACK_PROBE = 4;

// ── Byte helpers ────────────────────────────────────────────────────────────

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
export const u32le = (v) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v, true); return b; };
export const u64le = (v) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v), true); return b; };
const getU32 = (b, o) => new DataView(b.buffer, b.byteOffset).getUint32(o, true);
const getU64 = (b, o) => new DataView(b.buffer, b.byteOffset).getBigUint64(o, true);
const getI64 = (b, o) => new DataView(b.buffer, b.byteOffset).getBigInt64(o, true);

export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export function fromHex(s) {
  if (s.length % 2 || /[^0-9a-fA-F]/.test(s)) throw new Error("invalid hex");
  return Uint8Array.from(s.match(/../g) || [], (h) => parseInt(h, 16));
}
const equalBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

export class AuthError extends Error {}

// ── Primitives ──────────────────────────────────────────────────────────────

export async function hmac(key, data) {
  const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, data));
}

export const deriveSubkey = (key, label) => hmac(key, enc.encode(label));

async function aesKey(raw, usage) {
  return subtle.importKey("raw", raw, "AES-GCM", false, [usage]);
}

// AES-256-GCM. WebCrypto wants/returns ciphertext||tag, which is exactly how
// both our formats lay chunks out.
async function gcmEncrypt(key, nonce, aad, plaintext) {
  return new Uint8Array(await subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, plaintext));
}
async function gcmDecrypt(key, nonce, aad, ctAndTag) {
  try {
    return new Uint8Array(await subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, ctAndTag));
  } catch {
    throw new AuthError("authentication failed");
  }
}

export const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

// ── Keys ────────────────────────────────────────────────────────────────────

// Same rules as KeyManager::LoadKeyFromFile: 32 raw bytes, or 64 hex chars
// with optional surrounding whitespace.
export function parseKeyFile(bytes) {
  if (bytes.length === 32) return bytes;
  const text = dec.decode(bytes).trim();
  if (text.length === 64 && /^[0-9a-fA-F]+$/.test(text)) return fromHex(text);
  throw new Error("A key file must contain 64 hex characters or exactly 32 raw bytes");
}

// How v1 read key files: the first 32 bytes verbatim.
export function legacyKey(bytes) {
  if (bytes.length < 32) throw new Error("key file too short");
  return bytes.slice(0, 32);
}

// <backing>/encfs.kdf (see src/key_setup.cpp):
//   v1 "ENCFSKDF" | iterations:u32le | salt[16]               master = PBKDF2(pass)
//   v2 "ENCFSKD2" | iterations:u32le | salt[16] | wrapped[60]  master = AES-GCM-unwrap(
//      PBKDF2(pass), wrapped, aad = first 28 bytes)
export async function keyFromPassphrase(passphrase, kdfBytes) {
  const magic = dec.decode(kdfBytes.slice(0, 8));
  const v1 = magic === "ENCFSKDF" && kdfBytes.length === 28;
  const v2 = magic === "ENCFSKD2" && kdfBytes.length === 88;
  if (!v1 && !v2) throw new Error("not a valid encfs.kdf file");
  const iterations = getU32(kdfBytes, 8);
  if (iterations < 10000 || iterations > 50_000_000) throw new Error("unreasonable iteration count in encfs.kdf");
  const salt = kdfBytes.slice(12, 28);
  const base = await subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveBits"]);
  const derived = new Uint8Array(await subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, 256));
  if (v1) return derived;
  const kek = await aesKey(derived, "decrypt");
  const wrapped = kdfBytes.slice(28);
  try {
    return await gcmDecrypt(kek, wrapped.slice(0, 12), kdfBytes.slice(0, 28), wrapped.slice(12));
  } catch {
    throw new AuthError("wrong passphrase");
  }
}

// All keys derived from the master key (see README "Keys").
export async function deriveKeys(master) {
  return {
    master,
    index: await deriveSubkey(master, "encfs_index_key_derivation"),
    filename: await deriveSubkey(master, "encfs_filename_hmac"),
    content: await deriveSubkey(master, "encfs_content_key_v2"),
  };
}

export async function remoteIdFor(keys, path) {
  return toHex(await hmac(keys.filename, enc.encode(path)));
}

// ── Index ───────────────────────────────────────────────────────────────────

export async function decryptIndex(keys, bytes) {
  if (bytes.length < 28) throw new Error("index too short");
  const key = await aesKey(keys.index, "decrypt");
  const plain = await gcmDecrypt(key, bytes.slice(0, 12), new Uint8Array(), bytes.slice(12));
  return parseIndex(plain);
}

// Index v2: "EIX2" | generation:u64 | inodes | paths (see src/index.h).
// Index v1: count | (name | id | version | size | mtime)* ; empty id = directory.
// Returns one entry per path: { name, remoteId, type, isDirectory, isSymlink,
// version, size, mtime, mode, target, nlink }.
export function parseIndex(plain) {
  let pos = 0;
  const need = (n) => { if (plain.length - pos < n) throw new Error("malformed index"); };
  const u8 = () => { need(1); return plain[pos++]; };
  const u32 = () => { need(4); const v = getU32(plain, pos); pos += 4; return v; };
  const u64 = () => { need(8); const v = getU64(plain, pos); pos += 8; return v; };
  const str = () => { const n = u32(); need(n); const v = dec.decode(plain.slice(pos, pos + n)); pos += n; return v; };
  const TYPES = { 1: "file", 2: "directory", 3: "symlink" };
  const entry = (name, inode, nlink) => ({
    name, ...inode, nlink,
    isDirectory: inode.type === "directory", isSymlink: inode.type === "symlink",
  });

  if (plain.length >= 4 && dec.decode(plain.slice(0, 4)) === "EIX2") {
    pos = 4;
    const generation = u64();
    const inodes = new Map();
    for (let i = 0, n = u32(); i < n; i++) {
      const remoteId = str();
      const type = TYPES[u8()];
      if (!type) throw new Error("malformed index (bad type)");
      const version = u64(), size = Number(u64()), mtime = Number(BigInt.asIntN(64, u64()));
      const mode = u32() & 0o7777, target = str();
      inodes.set(remoteId, { remoteId, type, version, size, mtime, mode, target });
    }
    const paths = [];
    for (let i = 0, n = u32(); i < n; i++) {
      const name = str(), id = str();
      if (!inodes.has(id)) throw new Error("malformed index (dangling path)");
      paths.push([name, id]);
    }
    if (pos !== plain.length) throw new Error("malformed index (trailing data)");
    const links = new Map();
    for (const [, id] of paths) links.set(id, (links.get(id) || 0) + 1);
    const entries = paths.map(([name, id]) => entry(name, inodes.get(id), links.get(id)));
    entries.generation = generation;
    return entries;
  }

  const entries = [];
  for (let i = 0, n = u32(); i < n; i++) {
    const name = str(), remoteId = str();
    const version = u64(), size = Number(u64()), mtime = Number(BigInt.asIntN(64, u64()));
    const type = remoteId === "" ? "directory" : "file";
    entries.push(entry(name, { remoteId, type, version, size, mtime,
                               mode: type === "directory" ? 0o755 : 0o644, target: "" }, 1));
  }
  if (pos !== plain.length) throw new Error("malformed index (trailing data)");
  return entries;
}

// Write index v2 from path entries (entries sharing a remoteId are hard links).
export function serializeIndex(entries, generation = 1) {
  const TYPE = { file: 1, directory: 2, symlink: 3 };
  const str = (v) => { const b = enc.encode(v); return [u32le(b.length), b]; };
  const inodes = new Map();
  for (const e of entries) {
    const remoteId = e.remoteId || toHex(randomBytes(32));
    e.remoteId = remoteId;
    if (!inodes.has(remoteId)) inodes.set(remoteId, e);
  }
  const parts = [enc.encode("EIX2"), u64le(generation), u32le(inodes.size)];
  for (const [id, e] of inodes) {
    parts.push(...str(id), new Uint8Array([TYPE[e.type || "file"]]), u64le(e.version ?? 1),
               u64le(e.size ?? 0), u64le(BigInt.asUintN(64, BigInt(e.mtime ?? 0))),
               u32le(e.mode ?? 0o644), ...str(e.target ?? ""));
  }
  parts.push(u32le(entries.length));
  for (const e of entries) parts.push(...str(e.name), ...str(e.remoteId));
  return concat(...parts);
}

export async function encryptIndex(keys, entries, generation = 1) {
  const nonce = randomBytes(12);
  const key = await aesKey(keys.index, "encrypt");
  return concat(nonce, await gcmEncrypt(key, nonce, new Uint8Array(), serializeIndex(entries, generation)));
}

// ── Blob format v2 ──────────────────────────────────────────────────────────

export function fileAad(remoteId, version) {
  return concat(enc.encode("encfs-file-v2\0"), enc.encode(remoteId), new Uint8Array([0]), u64le(version));
}

function chunkNonce(index, last) {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setUint32(7, index, false);
  n[11] = last ? 1 : 0;
  return n;
}

async function fileKey(contentKey, salt) {
  return aesKey(await hmac(contentKey, concat(enc.encode("encfs-v2-chunk-key"), salt)), "encrypt");
}
async function fileKeyDec(contentKey, salt) {
  return aesKey(await hmac(contentKey, concat(enc.encode("encfs-v2-chunk-key"), salt)), "decrypt");
}

export async function encryptBlob(plaintext, key, aad = new Uint8Array(), chunkSize = DEFAULT_CHUNK_SIZE) {
  const salt = randomBytes(32);
  const header = concat(MAGIC, new Uint8Array([FORMAT_VERSION]), u32le(chunkSize), salt);
  const fullAad = concat(header, aad);
  const k = await fileKey(key, salt);
  const n = Math.max(1, Math.ceil(plaintext.length / chunkSize));
  const parts = [header];
  for (let i = 0; i < n; i++) {
    const chunk = plaintext.subarray(i * chunkSize, Math.min(plaintext.length, (i + 1) * chunkSize));
    parts.push(u32le(chunk.length), await gcmEncrypt(k, chunkNonce(i, i === n - 1), fullAad, chunk));
  }
  return concat(...parts);
}

// Describe a blob's layout without decrypting it (used by the explainer).
export function parseBlob(blob) {
  if (blob.length < 6 || !equalBytes(blob.slice(0, 5), MAGIC)) throw new Error("not an encfs blob");
  const version = blob[5];
  if (version === 1) return { version, legacy: true };
  if (version !== 2) throw new Error(`unsupported format version ${version}`);
  if (blob.length < HEADER_SIZE) throw new Error("truncated header");
  const chunkSize = getU32(blob, 6);
  if (chunkSize === 0 || chunkSize > 64 * 1024 * 1024) throw new Error("invalid chunk size");
  const chunks = [];
  let off = HEADER_SIZE;
  while (off < blob.length) {
    if (blob.length - off < 4) throw new Error("truncated chunk header");
    const len = getU32(blob, off);
    if (len > chunkSize) throw new Error("chunk larger than chunk size");
    if (blob.length - off - 4 < len + TAG_SIZE) throw new Error("truncated chunk");
    const end = off + 4 + len + TAG_SIZE;
    const last = end === blob.length;
    if (!last && len !== chunkSize) throw new Error("short non-final chunk");
    chunks.push({ offset: off, length: len, last });
    off = end;
  }
  if (!chunks.length) throw new Error("no chunks");
  return { version, chunkSize, salt: blob.slice(10, HEADER_SIZE), header: blob.slice(0, HEADER_SIZE), chunks };
}

// Decrypt a v2 blob. Throws AuthError naming the first chunk that fails.
export async function decryptBlob(blob, key, aad = new Uint8Array()) {
  const info = parseBlob(blob);
  if (info.legacy) throw new Error("legacy v1 blob");
  const k = await fileKeyDec(key, info.salt);
  const fullAad = concat(info.header, aad);
  const out = [];
  for (const [i, c] of info.chunks.entries()) {
    try {
      out.push(await gcmDecrypt(k, chunkNonce(i, c.last), fullAad,
                                blob.subarray(c.offset + 4, c.offset + 4 + c.length + TAG_SIZE)));
    } catch {
      const err = new AuthError(`chunk ${i} failed authentication`);
      err.chunk = i;
      throw err;
    }
  }
  return concat(...out);
}

// v1: "ENCFS" | 0x01 | file_nonce(12) | n:u32 ; chunk: len | nonce(12) | ct | tag
export async function decryptLegacyV1(blob, masterKey) {
  const k = await aesKey(masterKey, "decrypt");
  const n = getU32(blob, 18);
  const out = [];
  let off = 22;
  for (let i = 0; i < n; i++) {
    if (blob.length - off < 16) throw new Error("truncated v1 blob");
    const len = getU32(blob, off);
    const nonce = blob.slice(off + 4, off + 16);
    off += 16;
    if (blob.length - off < len + TAG_SIZE) throw new Error("truncated v1 chunk");
    out.push(await gcmDecrypt(k, nonce, new Uint8Array(), blob.subarray(off, off + len + TAG_SIZE)));
    off += len + TAG_SIZE;
  }
  return concat(...out);
}

// ── Files (FileCodec equivalent) ────────────────────────────────────────────

export async function encryptFile(keys, plaintext, remoteId, version, chunkSize) {
  return encryptBlob(plaintext, keys.content, fileAad(remoteId, version), chunkSize);
}

// Same rules as FileCodec::Decrypt: the expected version, or one ahead
// (crash before the index was saved); an older version is a rollback.
// Returns { status: "ok" | "rollback" | "corrupt", plaintext?, version?, legacy? }
export async function decryptFile(keys, blob, remoteId, expectedVersion) {
  let info;
  try { info = parseBlob(blob); } catch (e) { return { status: "corrupt", error: e.message }; }
  if (info.legacy) {
    try { return { status: "ok", plaintext: await decryptLegacyV1(blob, keys.master), legacy: true }; }
    catch (e) { return { status: "corrupt", error: e.message }; }
  }
  const v = BigInt(expectedVersion);
  for (const candidate of [v, v + 1n]) {
    try {
      return { status: "ok", plaintext: await decryptBlob(blob, keys.content, fileAad(remoteId, candidate)), version: candidate };
    } catch { /* try next */ }
  }
  for (let back = 1n; back <= BigInt(ROLLBACK_PROBE) && back < v; back++) {
    try {
      await decryptBlob(blob, keys.content, fileAad(remoteId, v - back));
      return { status: "rollback", error: `This copy is version ${v - back}, but the index expects version ${v}` };
    } catch { /* keep probing */ }
  }
  return { status: "corrupt", error: "authentication failed (wrong key, wrong file, or tampered)" };
}

// Open a backing directory's index with a key file, trying the legacy
// interpretation too (like ResolveMasterKey).
export async function openIndex(keyFileBytes, indexBytes) {
  const candidates = [];
  try { candidates.push({ key: parseKeyFile(keyFileBytes), legacy: false }); } catch { /* no strict key */ }
  try {
    const l = legacyKey(keyFileBytes);
    if (!candidates.length || !equalBytes(l, candidates[0].key)) candidates.push({ key: l, legacy: true });
  } catch { /* too short */ }
  for (const c of candidates) {
    const keys = await deriveKeys(c.key);
    try { return { keys, entries: await decryptIndex(keys, indexBytes), legacyKey: c.legacy }; }
    catch { /* next candidate */ }
  }
  throw new Error("This key can't decrypt the index (wrong key, or the index is corrupt)");
}
