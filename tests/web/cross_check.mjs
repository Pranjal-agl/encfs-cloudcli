// Cross-checks web/encfs.js against the C++ implementation.
//   node tests/web/cross_check.mjs <fixtures dir>
// 1. Reads the backing directory web_fixtures generated (C++ → JS).
// 2. Writes blobs and an index of its own into <dir>/js (JS → C++),
//    which `web_fixtures verify` then checks.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import * as encfs from "../../web/encfs.js";

const dir = process.argv[2];
let failures = 0;
const check = (ok, what) => { console.log(`  ${ok ? "✓" : "✗"} ${what}`); if (!ok) failures++; };
const read = (p) => new Uint8Array(readFileSync(p));

// ── C++ → JS ──
const { keys, entries, legacyKey } = await encfs.openIndex(read(`${dir}/key`), read(`${dir}/backing/index.enc`));
check(!legacyKey, "JS opens the C++ index with a hex key file");
check(entries.generation >= 1, "JS reads index v2 (generation " + entries.generation + ")");
const byName = new Map(entries.map((e) => [e.name, e]));

for (const line of readFileSync(`${dir}/expected.tsv`, "utf8").split("\n").filter(Boolean)) {
  const [name, status, hex] = line.split("\t");
  const entry = byName.get(name);
  if (!entry) { check(false, `index has '${name}'`); continue; }
  if (status === "dir") { check(entry.isDirectory, `'${name}' is a directory`); continue; }
  if (status === "symlink") {
    check(entry.isSymlink && encfs.toHex(new TextEncoder().encode(entry.target)) === hex, `'${name}' is a symlink to the right target`);
    continue;
  }
  const blob = read(`${dir}/backing/${entry.remoteId}.enc`);
  const res = await encfs.decryptFile(keys, blob, entry.remoteId, entry.version);
  const same = res.status === status && (status !== "ok" || encfs.toHex(res.plaintext) === hex);
  check(same, `JS decrypts '${name}' → ${res.status}${res.legacy ? " (v1)" : ""}`);
}

const pkey = await encfs.keyFromPassphrase("correct horse battery staple", read(`${dir}/encfs.kdf`));
check(encfs.toHex(pkey) === readFileSync(`${dir}/kdf_expected.hex`, "utf8").trim(), "PBKDF2 passphrase key matches");
const wkey = await encfs.keyFromPassphrase("correct horse battery staple", read(`${dir}/kdf_v2/encfs.kdf`));
check(encfs.toHex(wkey) === readFileSync(`${dir}/kdf_v2_expected.hex`, "utf8").trim(), "JS unwraps a v2 (wrapped) encfs.kdf");
let wrongRejected = false;
try { await encfs.keyFromPassphrase("wrong", read(`${dir}/kdf_v2/encfs.kdf`)); } catch (e) { wrongRejected = e instanceof encfs.AuthError; }
check(wrongRejected, "JS rejects a wrong passphrase for a v2 encfs.kdf");

// Tampering is detected by the JS decoder too.
const hello = byName.get("hello.txt");
const tampered = read(`${dir}/backing/${hello.remoteId}.enc`);
tampered[tampered.length - 3] ^= 1;
check((await encfs.decryptFile(keys, tampered, hello.remoteId, hello.version)).status === "corrupt",
      "JS rejects a tampered blob");

// ── JS → C++ ──
mkdirSync(`${dir}/js`, { recursive: true });
const manifest = [];
const jsEntries = [];
const pattern = (n, s) => Uint8Array.from({ length: n }, (_, i) => (i * 13 + s) & 0xff);
const cases = [
  ["js/empty", new Uint8Array(), 64],
  ["js/one", pattern(1, 1), 64],
  ["js/exact", pattern(128, 2), 64],
  ["js/odd", pattern(1000, 3), 64],
  ["js/default-chunk", pattern(70000, 4), encfs.DEFAULT_CHUNK_SIZE],
  ["js/naïve.txt", new TextEncoder().encode("written in the browser"), 64],
];
for (const [i, [name, pt, cs]] of cases.entries()) {
  const remoteId = await encfs.remoteIdFor(keys, name);
  const version = 3 + i;
  writeFileSync(`${dir}/js/blob${i}`, await encfs.encryptFile(keys, pt, remoteId, version, cs));
  manifest.push([name, `blob${i}`, version, encfs.toHex(pt)].join("\t"));
  jsEntries.push({ name, remoteId, version, size: pt.length, mtime: 1700000000 + i });
}
writeFileSync(`${dir}/js/manifest.tsv`, manifest.join("\n") + "\n");
jsEntries.push({ name: "js/dir", type: "directory", mode: 0o750, mtime: 1700000100 });
jsEntries.push({ name: "js/link", type: "symlink", target: "../elsewhere", mode: 0o777 });
jsEntries.push({ ...jsEntries[1], name: "js/one-hardlink" });  // same inode as js/one
writeFileSync(`${dir}/js/index.enc`, await encfs.encryptIndex(keys, jsEntries));
console.log(`  · wrote ${cases.length} JS blobs + index for C++ to verify`);

process.exit(failures ? 1 : 0);
