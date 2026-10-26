/**
 * Outlook's .msg format: an OLE compound file (a small file system inside one file) whose
 * streams hold the message's MAPI properties. This reads just enough of it to rebuild an
 * ordinary email (headers, text, HTML and attachments) that the rest of the engine analyses.
 *
 * The file comes from strangers, so every read is bounds-checked and every chain is capped:
 * a crafted file makes the reader give up, never loop forever or allocate without limit.
 */

const SIGNATURE = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const END_OF_CHAIN = 0xfffffffe;
const NO_STREAM = 0xffffffff;
/** Forwards of forwards inside forwards: deeper than any real message nests. */
const MAX_DEPTH = 3;

export function isOutlookMsg(bytes: Uint8Array): boolean {
  return SIGNATURE.every((b, i) => bytes[i] === b);
}

interface Entry {
  name: string;
  type: number;
  left: number;
  right: number;
  child: number;
  start: number;
  size: number;
}

class CompoundFile {
  private readonly bytes: Uint8Array;
  private readonly view: DataView;
  private readonly sectorSize: number;
  private readonly sectors: number;
  private readonly fat: number[] = [];
  private readonly miniFat: number[] = [];
  private readonly miniCutoff: number;
  private miniStream: Uint8Array = new Uint8Array(0);
  readonly entries: Entry[] = [];

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const shift = this.u16(0x1e);
    if (shift !== 9 && shift !== 12) throw new Error("Unsupported sector size");
    this.sectorSize = 1 << shift;
    this.sectors = Math.floor(bytes.length / this.sectorSize);
    this.miniCutoff = this.u32(0x38);

    // The FAT's own sectors are listed in the header, then in a chain of DIFAT sectors. No table
    // can have more sectors than the file does, which caps every loop below even when a crafted
    // chain points back at itself.
    const fatSectors: number[] = [];
    for (let i = 0; i < 109; i++) fatSectors.push(this.u32(0x4c + i * 4));
    let difat = this.u32(0x44);
    for (let n = 0; n < Math.min(this.u32(0x48), this.sectors) && difat < this.sectors; n++) {
      const at = this.offset(difat);
      for (let i = 0; i < this.sectorSize / 4 - 1; i++) fatSectors.push(this.u32(at + i * 4));
      difat = this.u32(at + this.sectorSize - 4);
    }
    for (const sector of fatSectors.slice(0, Math.min(this.u32(0x2c), this.sectors))) {
      if (sector >= this.sectors) continue;
      const at = this.offset(sector);
      for (let i = 0; i < this.sectorSize / 4 && this.fat.length < this.sectors; i++) this.fat.push(this.u32(at + i * 4));
    }

    const directory = this.read(this.u32(0x30), Infinity, false);
    for (let at = 0; at + 128 <= directory.length; at += 128) this.entries.push(this.entry(directory, at));
    const root = this.entries[0];
    if (!root || root.type !== 5) throw new Error("No root entry");

    this.miniStream = this.read(root.start, root.size, false);
    const miniFatBytes = this.read(this.u32(0x3c), Infinity, false);
    const miniFatView = new DataView(miniFatBytes.buffer, miniFatBytes.byteOffset, miniFatBytes.byteLength);
    const miniSectors = Math.ceil(this.miniStream.length / 64);
    for (let at = 0; at + 4 <= miniFatBytes.length && this.miniFat.length < miniSectors; at += 4) this.miniFat.push(miniFatView.getUint32(at, true));
  }

  /** A stream's bytes, from the mini stream when it's small. */
  stream(entry: Entry): Uint8Array {
    return this.read(entry.start, entry.size, entry.size < this.miniCutoff);
  }

  /** The entries directly inside a storage. Siblings form a tree; a visited set stops crafted cycles. */
  children(index: number): Entry[] {
    const out: Entry[] = [];
    const seen = new Set<number>();
    const stack = [this.entries[index]?.child ?? NO_STREAM];
    while (stack.length) {
      const i = stack.pop()!;
      if (i === NO_STREAM || i >= this.entries.length || seen.has(i)) continue;
      seen.add(i);
      const entry = this.entries[i]!;
      out.push(entry);
      stack.push(entry.left, entry.right);
    }
    return out;
  }

  indexOf(entry: Entry): number {
    return this.entries.indexOf(entry);
  }

  private read(start: number, size: number, mini: boolean): Uint8Array {
    const unit = mini ? 64 : this.sectorSize;
    const table = mini ? this.miniFat : this.fat;
    const source = mini ? this.miniStream : this.bytes;
    const base = mini ? 0 : this.sectorSize;
    const limit = Math.min(size, source.length);
    const chunks: Uint8Array[] = [];
    let length = 0;
    // A valid chain never visits a sector twice; a crafted one that loops is rejected.
    const visited = new Set<number>();
    for (let sector = start; sector !== END_OF_CHAIN && length < limit; ) {
      if (sector >= table.length || visited.has(sector)) throw new Error("Broken sector chain");
      visited.add(sector);
      const at = base + sector * unit;
      if (at + unit > source.length) throw new Error("Sector outside the file");
      chunks.push(source.subarray(at, at + unit));
      length += unit;
      sector = table[sector]!;
    }
    const out = new Uint8Array(Math.min(length, limit));
    let offset = 0;
    for (const chunk of chunks) {
      if (offset >= out.length) break;
      out.set(chunk.subarray(0, out.length - offset), offset);
      offset += chunk.length;
    }
    return out;
  }

  private entry(directory: Uint8Array, at: number): Entry {
    const view = new DataView(directory.buffer, directory.byteOffset + at, 128);
    const nameLength = Math.min(view.getUint16(0x40, true), 64);
    return {
      name: new TextDecoder("utf-16le").decode(directory.subarray(at, at + Math.max(0, nameLength - 2))),
      type: view.getUint8(0x42),
      left: view.getUint32(0x44, true),
      right: view.getUint32(0x48, true),
      child: view.getUint32(0x4c, true),
      start: view.getUint32(0x74, true),
      size: view.getUint32(0x78, true),
    };
  }

  private offset(sector: number): number {
    return (sector + 1) * this.sectorSize;
  }

  private u16(at: number): number {
    return this.view.getUint16(at, true);
  }

  private u32(at: number): number {
    return this.view.getUint32(at, true);
  }
}

/** Windows code pages that .msg files name, as TextDecoder labels. */
const CODE_PAGES: Record<number, string> = {
  65001: "utf-8", 1252: "windows-1252", 1250: "windows-1250", 1251: "windows-1251", 1253: "windows-1253",
  1254: "windows-1254", 1255: "windows-1255", 1256: "windows-1256", 1257: "windows-1257", 1258: "windows-1258",
  28591: "iso-8859-1", 28592: "iso-8859-2", 28605: "iso-8859-15", 20127: "us-ascii", 932: "shift_jis",
  936: "gbk", 949: "euc-kr", 950: "big5", 51932: "euc-jp", 20866: "koi8-r", 874: "windows-874",
};

function decode(bytes: Uint8Array, label: string): string {
  try {
    return new TextDecoder(label).decode(bytes);
  } catch {
    // An encoding this runtime doesn't know: Latin-1 keeps every byte and the ASCII intact.
    return Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  }
}

/** The MAPI properties of one message: its own storage's streams plus a few fixed-size values. */
class MessageProperties {
  private readonly file: CompoundFile;
  private readonly streams = new Map<string, Entry>();
  private readonly fixed = new Map<number, DataView>();

  /** `headerSize`: the fixed-property stream's header, 32 bytes for the top message, 24 for an attached one and 8 for an attachment. */
  constructor(file: CompoundFile, storage: number, headerSize: number) {
    this.file = file;
    for (const entry of file.children(storage)) this.streams.set(entry.name.toUpperCase(), entry);
    const props = this.streams.get("__PROPERTIES_VERSION1.0");
    if (props) {
      const bytes = file.stream(props);
      for (let at = headerSize; at + 16 <= bytes.length; at += 16) {
        const view = new DataView(bytes.buffer, bytes.byteOffset + at, 16);
        this.fixed.set(view.getUint32(0, true), new DataView(bytes.buffer, bytes.byteOffset + at + 8, 8));
      }
    }
  }

  get codePage(): string {
    const cpid = this.fixed.get(0x3fde0003) ?? this.fixed.get(0x3ffd0003);
    return CODE_PAGES[cpid?.getUint32(0, true) ?? 65001] ?? "utf-8";
  }

  string(id: number): string | null {
    const tag = id.toString(16).toUpperCase().padStart(4, "0");
    const unicode = this.streams.get(`__SUBSTG1.0_${tag}001F`);
    if (unicode) return decode(this.file.stream(unicode), "utf-16le").replace(/\0+$/, "");
    const ansi = this.streams.get(`__SUBSTG1.0_${tag}001E`);
    return ansi ? decode(this.file.stream(ansi), this.codePage).replace(/\0+$/, "") : null;
  }

  binary(id: number): Uint8Array | null {
    const entry = this.streams.get(`__SUBSTG1.0_${id.toString(16).toUpperCase().padStart(4, "0")}0102`);
    return entry ? this.file.stream(entry) : null;
  }

  /** A timestamp property (Windows FILETIME), as a date. */
  time(id: number): Date | null {
    const value = this.fixed.get(((id << 16) | 0x0040) >>> 0);
    if (!value) return null;
    const ticks = value.getUint32(0, true) + value.getUint32(4, true) * 2 ** 32;
    const date = new Date(ticks / 10_000 - 11_644_473_600_000);
    return Number.isNaN(date.getTime()) || ticks === 0 ? null : date;
  }

  storages(prefix: string): Entry[] {
    return [...this.streams.values()].filter((e) => e.type === 1 && e.name.toUpperCase().startsWith(prefix));
  }

  child(name: string): Entry | undefined {
    return this.streams.get(name.toUpperCase());
  }
}

const PR = {
  subject: 0x0037,
  senderName: 0x0c1a,
  senderEmail: 0x0c1f,
  senderSmtp: 0x5d01,
  representingName: 0x0042,
  representingEmail: 0x0065,
  displayTo: 0x0e04,
  messageId: 0x1035,
  transportHeaders: 0x007d,
  body: 0x1000,
  html: 0x1013,
  submitTime: 0x0039,
  deliveryTime: 0x0e06,
  attachData: 0x3701,
  attachFilename: 0x3704,
  attachLongFilename: 0x3707,
  attachMimeTag: 0x370e,
};

/** Base64 in 76-character lines, as MIME wants it. */
function base64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary).replace(/.{76}(?=.)/g, "$&\r\n");
}

const utf8 = (text: string) => new TextEncoder().encode(text);

/** Headers that describe the original MIME structure, which the rebuilt message replaces. */
const CONTENT_HEADER = /^(content-type|content-transfer-encoding|mime-version)\s*:/i;
/** A header line: a printable field name, then a colon. */
const HEADER_LINE = /^[!-9;-~]+:/;

/**
 * The stored headers, minus the old MIME structure and any line that isn't a header, so text
 * in this property can't smuggle in a MIME boundary and reshape the rebuilt message.
 */
function cleanHeaders(raw: string): string {
  const out: string[] = [];
  let skipping = false;
  for (const line of raw.replace(/\r?\n/g, "\n").split("\n")) {
    if (/^[ \t]/.test(line)) {
      if (!skipping && out.length) out.push(line);
      continue;
    }
    if (!line.trim()) break;
    skipping = CONTENT_HEADER.test(line) || !HEADER_LINE.test(line);
    if (!skipping) out.push(line);
  }
  return out.join("\r\n");
}

/** A header-safe value: no line breaks a sender could use to inject extra headers. */
const headerValue = (value: string) => value.replace(/[\r\n]+/g, " ").trim();

function attachmentPart(file: CompoundFile, storage: Entry, depth: number): string | null {
  const props = new MessageProperties(file, file.indexOf(storage), 8);
  const name = props.string(PR.attachLongFilename) ?? props.string(PR.attachFilename) ?? "attachment";
  const safeName = encodeURIComponent(headerValue(name));
  // An attached message (Outlook's "forward as attachment") is a whole email of its own.
  const embedded = props.child("__substg1.0_3701000D");
  if (embedded && embedded.type === 1) {
    if (depth >= MAX_DEPTH) return null;
    const inner = messageToEml(file, new MessageProperties(file, file.indexOf(embedded), 24), depth + 1);
    return `Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename*=UTF-8''${safeName}.eml\r\n\r\n${inner}`;
  }
  const data = props.binary(PR.attachData);
  if (!data) return null;
  const type = headerValue(props.string(PR.attachMimeTag) ?? "application/octet-stream").replace(/[^\w.+/-]/g, "") || "application/octet-stream";
  return [
    `Content-Type: ${type}; name*=UTF-8''${safeName}`,
    `Content-Disposition: attachment; filename*=UTF-8''${safeName}`,
    "Content-Transfer-Encoding: base64",
    "",
    base64(data),
  ].join("\r\n");
}

function messageToEml(file: CompoundFile, props: MessageProperties, depth: number): string {
  const transport = props.string(PR.transportHeaders);
  let headers = transport ? cleanHeaders(transport) : "";
  if (!headers) {
    // Drafts and sent items have no transport headers: rebuild the basics from properties.
    const name = props.string(PR.senderName) ?? props.string(PR.representingName) ?? "";
    const address = [props.string(PR.senderSmtp), props.string(PR.representingEmail), props.string(PR.senderEmail)].find((a) => a?.includes("@")) ?? "";
    const date = props.time(PR.deliveryTime) ?? props.time(PR.submitTime);
    const to = props.string(PR.displayTo);
    const messageId = props.string(PR.messageId);
    headers = [
      `From: ${headerValue(name ? `"${name.replace(/"/g, "'")}" <${address}>` : address)}`,
      ...(to?.includes("@") ? [`To: ${headerValue(to)}`] : []),
      `Subject: ${headerValue(props.string(PR.subject) ?? "")}`,
      ...(date ? [`Date: ${date.toUTCString()}`] : []),
      ...(messageId ? [`Message-ID: ${headerValue(messageId)}`] : []),
    ].join("\r\n");
  }

  const mixed = `phish-check-mixed-${depth}`;
  const alternative = `phish-check-alt-${depth}`;
  const text = props.string(PR.body);
  const htmlBytes = props.binary(PR.html);
  const html = htmlBytes ? decode(htmlBytes, props.codePage) : props.string(PR.html);
  const bodies = [
    ...(text ? [`Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${base64(utf8(text))}`] : []),
    ...(html ? [`Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${base64(utf8(html))}`] : []),
  ];
  const parts = [
    `Content-Type: multipart/alternative; boundary="${alternative}"\r\n\r\n${bodies.map((b) => `--${alternative}\r\n${b}\r\n`).join("")}--${alternative}--`,
    ...props.storages("__ATTACH_VERSION1.0_#").flatMap((storage) => attachmentPart(file, storage, depth) ?? []),
  ];
  return [
    headers,
    "MIME-Version: 1.0",
    `Content-Type: multipart/mixed; boundary="${mixed}"`,
    "",
    ...parts.map((part) => `--${mixed}\r\n${part}`),
    `--${mixed}--`,
    "",
  ].join("\r\n");
}

/**
 * Rebuilds an Outlook .msg file as a standard email, or returns null when the file can't be
 * read. Rich-text-only bodies (no plain text or HTML stored) come through without a body.
 */
export function msgToEml(bytes: Uint8Array): string | null {
  if (!isOutlookMsg(bytes)) return null;
  try {
    const file = new CompoundFile(bytes);
    return messageToEml(file, new MessageProperties(file, 0, 32), 0);
  } catch {
    return null;
  }
}
