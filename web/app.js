import * as encfs from "./encfs.js";

const $ = (sel) => document.querySelector(sel);
const textEnc = new TextEncoder();
const textDec = new TextDecoder("utf-8", { fatal: false });

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
}

// ═══ Live blob ═════════════════════════════════════════════════════════════

const demo = {
  keys: null,
  name: "notes.txt",
  version: 1n,
  original: null,   // blob as encrypted
  blob: null,       // blob as currently tampered with
  flipped: new Set(),
  openAs: "notes.txt",
  expected: 1n,
  note: "",
  failedChunk: -1,
};

function regionsFor(blob) {
  let info;
  try { info = encfs.parseBlob(blob); } catch { info = encfs.parseBlob(demo.original); }
  const rows = [
    { label: "Header", start: 0, end: 10, kind: "header" },
    { label: "Salt", start: 10, end: encfs.HEADER_SIZE, kind: "salt" },
  ];
  info.chunks.forEach((c, i) => rows.push({
    label: c.last ? `Chunk ${i} (last)` : `Chunk ${i}`,
    start: c.offset, end: c.offset + 4 + c.length + encfs.TAG_SIZE,
    kind: "chunk", index: i, length: c.length,
  }));
  return { rows, chunkSize: info.chunkSize };
}

function describeByte(i, row, chunkSize) {
  if (i < 5) return ["r-magic", "file signature “ENCFS”"];
  if (i === 5) return ["r-ver", "format version 2"];
  if (i < 10) return ["r-cs", `chunk size, ${chunkSize} bytes (little-endian)`];
  if (i < encfs.HEADER_SIZE) return ["r-salt", "random salt. With your key it derives this file’s own AES key"];
  const off = i - row.start;
  if (off < 4) return ["r-len", `length of chunk ${row.index}: ${row.length} bytes`];
  if (off < 4 + row.length) return ["r-ct", `ciphertext of chunk ${row.index}`];
  return ["r-tag", `authentication tag of chunk ${row.index}. It covers the chunk, its position, ` +
                   `whether it is last, the header, and which file this is`];
}

function renderBytes() {
  const { rows, chunkSize } = regionsFor(demo.blob);
  const container = $("#bytes");
  container.replaceChildren();
  let first = true;
  for (const row of rows) {
    const label = el("div", { class: "row-label", text: row.label });
    if (row.kind === "chunk" && row.index === demo.failedChunk) label.classList.add("fail");
    const bytes = el("div", { class: "row-bytes" });
    for (let i = row.start; i < Math.min(row.end, demo.blob.length); i++) {
      const [cls, desc] = describeByte(i, row, chunkSize);
      const b = el("button", {
        type: "button",
        class: `byte ${cls}${demo.flipped.has(i) ? " flipped" : ""}`,
        "data-i": String(i),
        "data-desc": `Byte ${i}: ${desc}.`,
        "aria-label": `Byte ${i}, ${desc}`,
        tabindex: first ? "0" : "-1",
        text: demo.blob[i].toString(16).padStart(2, "0"),
      });
      first = false;
      bytes.append(b);
    }
    container.append(el("div", { class: "row" }, label, bytes));
  }
  $("#demo-id").textContent = demo.remoteId;
  const n = encfs.parseBlob(demo.original).chunks.length;
  $('[data-attack="truncate"]').disabled = n < 2;
  $('[data-attack="swap"]').disabled = n < 3;
}

function setVerdict(ok, headline, detail) {
  const v = $("#verdict");
  v.className = `verdict ${ok ? "ok" : "bad"}`;
  v.replaceChildren(el("strong", { text: headline }), " ", detail.main,
                    detail.why ? el("span", { class: "why", text: detail.why }) : null);
}

async function verify() {
  demo.failedChunk = -1;
  const remoteId = await encfs.remoteIdFor(demo.keys, demo.openAs);
  let parsed = true;
  try { encfs.parseBlob(demo.blob); } catch (e) {
    parsed = false;
    setVerdict(false, "Rejected.", { main: `The blob no longer parses: ${e.message}.`, why: demo.note });
  }
  if (parsed) {
    const res = await encfs.decryptFile(demo.keys, demo.blob, remoteId, demo.expected);
    if (res.status === "ok") {
      setVerdict(true, "Verified.", {
        main: `Decrypts to: “${textDec.decode(res.plaintext)}”`,
        why: demo.note || `${demo.blob.length} bytes on disk for ${res.plaintext.length} bytes of text.`,
      });
    } else if (res.status === "rollback") {
      setVerdict(false, "Rejected as a rollback.", { main: `${res.error}.`, why: demo.note });
    } else {
      // Find which chunk broke, for the byte map.
      try {
        await encfs.decryptBlob(demo.blob, demo.keys.content, encfs.fileAad(remoteId, demo.expected));
      } catch (e) {
        if (e.chunk !== undefined) demo.failedChunk = e.chunk;
      }
      const where = demo.failedChunk >= 0 ? `Chunk ${demo.failedChunk} failed authentication.` : "Authentication failed.";
      setVerdict(false, "Rejected.", { main: where, why: demo.note });
    }
  }
  renderBytes();
}

async function encryptDemo() {
  const plaintext = textEnc.encode($("#plaintext").value);
  const chunkSize = Number($("#chunk-size").value);
  $("#chunk-size-out").textContent = String(chunkSize);
  demo.remoteId = await encfs.remoteIdFor(demo.keys, demo.name);
  demo.original = await encfs.encryptFile(demo.keys, plaintext, demo.remoteId, demo.version, chunkSize);
  resetTampering();
  await verify();
}

function resetTampering() {
  demo.blob = demo.original.slice();
  demo.flipped = new Set();
  demo.openAs = demo.name;
  demo.expected = demo.version;
  demo.note = "";
}

function flipByte(i) {
  demo.blob[i] ^= 0x01;
  if (demo.flipped.has(i)) demo.flipped.delete(i); else demo.flipped.add(i);
  const { rows, chunkSize } = regionsFor(demo.original);
  const row = rows.find((r) => i >= r.start && i < r.end) || rows[0];
  const [cls] = describeByte(i, row, chunkSize);
  demo.note = demo.flipped.size === 0 ? "Every flipped bit has been flipped back." : {
    "r-magic": "The header is part of every chunk’s authenticated data, so changing it breaks them all.",
    "r-ver": "The header is part of every chunk’s authenticated data, so changing it breaks them all.",
    "r-cs": "The chunk size is authenticated too, and the layout stops making sense without it.",
    "r-salt": "A different salt derives a different file key, so no chunk decrypts.",
    "r-len": "The length says where the chunk ends. Altering it breaks the layout or the tag check.",
    "r-ct": "AES-GCM’s tag detects any change to the ciphertext, down to a single bit.",
    "r-tag": "The tag no longer matches the chunk it protects.",
  }[cls];
}

const attacks = {
  flip() {
    const info = encfs.parseBlob(demo.original);
    const c = info.chunks[Math.floor(Math.random() * info.chunks.length)];
    const span = 4 + c.length + encfs.TAG_SIZE;
    flipByte(c.offset + 4 + Math.floor(Math.random() * (span - 4)));
  },
  truncate() {
    resetTampering();
    const { chunks } = encfs.parseBlob(demo.original);
    demo.blob = demo.original.slice(0, chunks[chunks.length - 1].offset);
    demo.note = `Chunk ${chunks.length - 2} is now at the end, but it was sealed with its “last chunk” ` +
                "flag off. Dropping data from the end is detected.";
  },
  swap() {
    resetTampering();
    const { chunks } = encfs.parseBlob(demo.original);
    const [a, b] = chunks;
    const span = b.offset - a.offset;
    demo.blob.set(demo.original.subarray(b.offset, b.offset + span), a.offset);
    demo.blob.set(demo.original.subarray(a.offset, a.offset + span), b.offset);
    demo.note = "Each chunk’s position is built into its nonce, so a chunk moved to another slot fails.";
  },
  rename() {
    resetTampering();
    demo.openAs = "passwords.txt";
    demo.note = "The blob is untouched, but this time it’s read as “passwords.txt”. The file’s ID is " +
                "authenticated with every chunk, so blobs can’t be swapped between files.";
  },
  rollback() {
    resetTampering();
    demo.expected = demo.version + 1n;
    demo.note = "The blob is authentic, but the index has since moved to version 2. A stale or " +
                "replayed copy from the cloud is refused.";
  },
  reset() { resetTampering(); },
};

async function initDemo() {
  demo.keys = await encfs.deriveKeys(encfs.randomBytes(32));
  let timer;
  const rerun = () => { clearTimeout(timer); timer = setTimeout(encryptDemo, 120); };
  $("#plaintext").addEventListener("input", rerun);
  $("#chunk-size").addEventListener("input", rerun);

  const bytes = $("#bytes");
  bytes.addEventListener("click", async (e) => {
    const b = e.target.closest(".byte");
    if (!b) return;
    flipByte(Number(b.dataset.i));
    await verify();
    $(`.byte[data-i="${b.dataset.i}"]`)?.focus();
  });
  const showInfo = (e) => {
    const b = e.target.closest(".byte");
    if (b) $("#byte-info").textContent = b.dataset.desc;
  };
  bytes.addEventListener("mouseover", showInfo);
  bytes.addEventListener("focusin", showInfo);
  bytes.addEventListener("keydown", (e) => {
    const b = e.target.closest(".byte");
    if (!b) return;
    const all = [...bytes.querySelectorAll(".byte")];
    const i = all.indexOf(b);
    const step = { ArrowRight: 1, ArrowLeft: -1, ArrowDown: 16, ArrowUp: -16 }[e.key];
    if (!step) return;
    e.preventDefault();
    const next = all[Math.max(0, Math.min(all.length - 1, i + step))];
    b.tabIndex = -1;
    next.tabIndex = 0;
    next.focus();
  });

  document.querySelectorAll("[data-attack]").forEach((btn) =>
    btn.addEventListener("click", async () => {
      attacks[btn.dataset.attack]();
      await verify();
    }));

  await encryptDemo();
}

// ═══ Recovery ══════════════════════════════════════════════════════════════

const vault = { files: new Map(), keys: null, entries: [] };  // name → File

const readFile = async (f) => new Uint8Array(await f.arrayBuffer());

function formatSize(n) {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n, u = -1;
  do { v /= 1024; u++; } while (v >= 1024 && u < units.length - 1);
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[u]}`;
}

function addBackingFiles(list) {
  for (const f of list) vault.files.set(f.name, f);
  // Whole-file blobs are `<id>.enc`; segments of large files `<id>.<seg>.<ver>.enc`.
  const blobs = [...vault.files.keys()].filter((n) => /^[0-9a-f]{64}(\.\d+\.\d+)?\.enc$/.test(n)).length;
  const has = (n) => vault.files.has(n);
  const parts = [`${blobs} encrypted blob${blobs === 1 ? "" : "s"}`];
  parts.push(has("index.enc") ? "the index" : "no index.enc yet");
  if (has("encfs.kdf")) parts.push("passphrase settings");
  $("#backing-summary").textContent = `Found ${parts.join(", ")}.`;
}

function selectedMode() {
  return document.querySelector('input[name="key-mode"]:checked').value;
}

async function unlock() {
  const status = $("#unlock-status");
  status.textContent = "";
  const index = vault.files.get("index.enc");
  if (!index) {
    status.textContent = "Choose a backing folder that contains index.enc first.";
    return;
  }
  const indexBytes = await readFile(index);
  try {
    const mode = selectedMode();
    if (mode === "passphrase") {
      const kdf = vault.files.get("encfs.kdf");
      if (!kdf) throw new Error("This folder has no encfs.kdf, so it wasn’t set up with a passphrase.");
      status.textContent = "Deriving the key from your passphrase…";
      let master;
      try { master = await encfs.keyFromPassphrase($("#passphrase").value, await readFile(kdf)); }
      catch (e) { throw new Error(e instanceof encfs.AuthError ? "That passphrase is wrong." : e.message); }
      status.textContent = "";
      vault.keys = await encfs.deriveKeys(master);
      try { vault.entries = await encfs.decryptIndex(vault.keys, indexBytes); }
      catch { throw new Error("That passphrase can’t decrypt this index."); }
    } else {
      let keyBytes;
      if (mode === "file") {
        const f = $("#key-file").files[0];
        if (!f) throw new Error("Choose your key file.");
        keyBytes = await readFile(f);
      } else {
        keyBytes = textEnc.encode($("#key-hex").value);
      }
      const opened = await encfs.openIndex(keyBytes, indexBytes);
      vault.keys = opened.keys;
      vault.entries = opened.entries;
      if (opened.legacyKey) {
        status.textContent = "Unlocked with the legacy (v1) key interpretation. ";
      }
    }
  } catch (e) {
    status.textContent = e.message;
    return;
  }
  $("#key-hex").value = "";
  $("#passphrase").value = "";
  const files = vault.entries.filter((e) => !e.isDirectory && !e.isSymlink).length;
  status.textContent += `Unlocked: ${files} file${files === 1 ? "" : "s"} in the index.`;
  renderFileList();
}

function blobFor(entry) {
  return vault.files.get(`${entry.remoteId}.enc`);
}

// Every stored object this entry needs is in the chosen folder.
function hasAllObjects(entry) {
  return encfs.objectIds(entry).every((id) => vault.files.has(`${id}.enc`));
}

function renderFileList() {
  const entries = [...vault.entries].sort((a, b) => a.name.localeCompare(b.name));
  const tbody = el("tbody");
  for (const entry of entries) {
    const depth = entry.name.split("/").length - 1;
    const base = entry.name.split("/").pop();
    const nameCell = el("td", { class: "path" });
    nameCell.style.paddingLeft = `${0.5 + depth * 1.25}rem`;
    if (entry.isDirectory) {
      nameCell.append(el("span", { class: "dir", text: `${base}/` }));
      tbody.append(el("tr", {}, nameCell, el("td"), el("td", { class: "when" }), el("td"), el("td")));
      continue;
    }
    if (entry.isSymlink) {
      nameCell.append(base, el("span", { class: "hint", text: ` → ${entry.target}` }));
      tbody.append(el("tr", {}, nameCell, el("td"), el("td", { class: "when" }),
                      el("td", {}, el("span", { class: "state missing", text: "Symbolic link" })), el("td")));
      continue;
    }
    nameCell.append(base);
    const present = hasAllObjects(entry) || (entry.size === 0 && !entry.segmentSize);
    const state = el("span", {
      class: `state ${present ? "" : "missing"}`,
      text: present ? "Ready" : "Blob not in this folder",
    });
    const save = el("button", { type: "button", text: "Save" });
    save.disabled = !present;
    save.addEventListener("click", () => saveFile(entry, state));
    entry.stateNode = state;
    tbody.append(el("tr", {},
      nameCell,
      el("td", { class: "num", text: formatSize(entry.size) }),
      el("td", { class: "when", text: entry.mtime > 0 ? new Date(entry.mtime * 1000).toLocaleDateString() : "–" }),
      el("td", {}, state),
      el("td", {}, save)));
  }
  const table = el("table", {},
    el("thead", {}, el("tr", {},
      el("th", { text: "Name" }), el("th", { class: "num", text: "Size" }),
      el("th", { class: "when", text: "Modified" }), el("th", { text: "Status" }), el("th"))),
    tbody);
  $("#file-list").replaceChildren(entries.length ? table : el("p", { class: "hint", text: "The index is empty." }));
  $("#file-list-actions").hidden = false;
}

async function decryptEntry(entry) {
  if (entry.segmentSize) {
    return encfs.decryptSegmented(vault.keys, entry, async (id) => {
      const f = vault.files.get(`${id}.enc`);
      return f ? readFile(f) : null;
    });
  }
  const blob = blobFor(entry);
  if (!blob) {
    if (entry.size === 0) return { status: "ok", plaintext: new Uint8Array() };
    return { status: "missing" };
  }
  return encfs.decryptFile(vault.keys, await readFile(blob), entry.remoteId, entry.version);
}

function showResult(state, res) {
  const text = {
    ok: "Verified",
    rollback: "Older than the index expects",
    corrupt: "Failed: tampered or for another file",
    missing: "Blob not in this folder",
  }[res.status];
  state.textContent = text;
  state.className = `state ${res.status === "ok" ? "ok" : res.status === "missing" ? "missing" : "bad"}`;
}

async function saveFile(entry, state) {
  const res = await decryptEntry(entry);
  showResult(state, res);
  if (res.status !== "ok") return;
  const url = URL.createObjectURL(new Blob([res.plaintext]));
  const a = el("a", { href: url, download: entry.name.split("/").pop() });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

async function verifyAll() {
  const btn = $("#verify-all");
  btn.disabled = true;
  let ok = 0, bad = 0, missing = 0;
  for (const entry of vault.entries) {
    if (entry.isDirectory || entry.isSymlink) continue;
    const res = await decryptEntry(entry);
    showResult(entry.stateNode, res);
    if (res.status === "ok") ok++; else if (res.status === "missing") missing++; else bad++;
  }
  btn.disabled = false;
  $("#unlock-status").textContent =
    `${ok} verified, ${bad} failed, ${missing} not in this folder.`;
}

function lock() {
  vault.keys = null;
  vault.entries = [];
  vault.files.clear();
  $("#backing-folder").value = "";
  $("#backing-files").value = "";
  $("#key-file").value = "";
  $("#key-file-name").textContent = "";
  $("#backing-summary").textContent = "";
  $("#unlock-status").textContent = "Locked. The key and file list have been cleared from this page.";
  $("#file-list").replaceChildren(el("p", { class: "hint", text: "Your files will appear here after unlocking." }));
  $("#file-list-actions").hidden = true;
}

function initRecovery() {
  $("#backing-folder").addEventListener("change", (e) => addBackingFiles(e.target.files));
  $("#backing-files").addEventListener("change", (e) => addBackingFiles(e.target.files));
  $("#key-file").addEventListener("change", (e) => {
    $("#key-file-name").textContent = e.target.files[0]?.name ?? "";
  });
  document.querySelectorAll('input[name="key-mode"]').forEach((r) =>
    r.addEventListener("change", () => {
      document.querySelectorAll(".key-input").forEach((d) => { d.hidden = d.dataset.mode !== selectedMode(); });
    }));
  $("#unlock").addEventListener("click", unlock);
  $("#passphrase").addEventListener("keydown", (e) => { if (e.key === "Enter") unlock(); });
  $("#key-hex").addEventListener("keydown", (e) => { if (e.key === "Enter") unlock(); });
  $("#verify-all").addEventListener("click", verifyAll);
  $("#lock").addEventListener("click", lock);
}

initRecovery();
initDemo().catch((e) => {
  $("#verdict").textContent = `This browser can’t run the demo: ${e.message}`;
});
