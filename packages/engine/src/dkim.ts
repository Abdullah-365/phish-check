/**
 * DKIM, checked here rather than taken on trust (RFC 6376, RFC 8463).
 *
 * A provider's Authentication-Results header is only as honest as the server that wrote it, and
 * when the reader's provider adds none, a sender can forge one. A signature can't be forged: it
 * verifies against the key its domain publishes in DNS, or it doesn't.
 *
 * Signatures cover exact bytes, so everything here works on the message as bytes: one changed
 * character, or a re-encoded body, and the signature no longer verifies.
 */

export interface DkimSignatureInfo {
  domain: string;
  selector: string;
}

/** A selector's DNS record, as the Worker found it; null when the domain publishes none. */
export interface DkimKey extends DkimSignatureInfo {
  record: string | null;
}

/**
 * pass: the signature verifies and covers the whole body. body-changed: the signature is genuine,
 * but the body was changed after signing (a mailing list footer, a company gateway rewriting
 * links) or has content added past the part it covers. fail: the signature doesn't verify against
 * the domain's key, so the signed headers were changed or the signature was made up. no-key: the
 * domain publishes no key for it. unchecked: no key was looked up. unsupported: an algorithm or
 * key this can't check.
 */
export type DkimOutcome = "pass" | "body-changed" | "fail" | "no-key" | "unchecked" | "unsupported";

export interface DkimResult extends DkimSignatureInfo {
  result: DkimOutcome;
}

interface Field {
  /** Lowercase field name. */
  name: string;
  /** The field as written, folding included, without the final CRLF. */
  raw: string;
}

interface Signature extends DkimSignatureInfo {
  index: number;
  algorithm: string;
  bodyHash: string;
  value: string;
  signed: string[];
  headerCanon: "simple" | "relaxed";
  bodyCanon: "simple" | "relaxed";
  length: number | null;
}

/** Signatures past this many aren't checked: a real message carries one to three. */
const MAX_SIGNATURES = 5;
const ALGORITHMS = new Set(["rsa-sha256", "rsa-sha1", "ed25519-sha256"]);

/** Bytes as a string of the same length, one character per byte, so nothing is lost either way. */
function binary(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 0x8000) out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return out;
}

function toBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

/** Where the header block ends: just past the first blank line. */
function headerEnd(bytes: Uint8Array): number {
  for (let i = 0; i + 1 < bytes.length; i++) {
    if (bytes[i] !== 0x0a) continue;
    if (bytes[i + 1] === 0x0a) return i + 2;
    if (bytes[i + 1] === 0x0d && bytes[i + 2] === 0x0a) return i + 3;
  }
  return bytes.length;
}

/** The header fields as written, with CRLF line endings throughout. */
function headerFields(bytes: Uint8Array): Field[] {
  const head = binary(bytes.subarray(0, headerEnd(bytes))).replace(/\r?\n/g, "\r\n");
  const fields: Field[] = [];
  for (const line of head.split("\r\n")) {
    const last = fields.at(-1);
    if (/^[ \t]/.test(line) && last) last.raw += `\r\n${line}`;
    else if (line.includes(":")) fields.push({ name: line.slice(0, line.indexOf(":")).trim().toLowerCase(), raw: line });
  }
  return fields;
}

function tags(value: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of value.split(";")) {
    const at = part.indexOf("=");
    if (at < 0) continue;
    out.set(part.slice(0, at).replace(/\s+/g, "").toLowerCase(), part.slice(at + 1).trim());
  }
  return out;
}

function parseSignature(field: Field, index: number): Signature | null {
  const t = tags(field.raw.slice(field.raw.indexOf(":") + 1));
  const domain = t.get("d")?.toLowerCase();
  const selector = t.get("s")?.toLowerCase();
  const algorithm = t.get("a")?.toLowerCase();
  const bodyHash = t.get("bh")?.replace(/\s+/g, "");
  const value = t.get("b")?.replace(/\s+/g, "");
  const signed = t.get("h")?.split(":").map((h) => h.trim().toLowerCase()).filter(Boolean);
  if (t.get("v") !== "1" || !domain || !selector || !algorithm || !bodyHash || !value || !signed?.length) return null;
  const [headerCanon = "simple", bodyCanon = "simple"] = (t.get("c") ?? "simple/simple").toLowerCase().split("/");
  const length = t.has("l") ? Number(t.get("l")) : null;
  if ((headerCanon !== "simple" && headerCanon !== "relaxed") || (bodyCanon !== "simple" && bodyCanon !== "relaxed")) return null;
  return { index, domain, selector, algorithm, bodyHash, value, signed, headerCanon, bodyCanon, length: Number.isFinite(length) ? length : null };
}

function signatures(fields: Field[]): Signature[] {
  return fields
    .flatMap((field, index) => (field.name === "dkim-signature" ? (parseSignature(field, index) ?? []) : []))
    .slice(0, MAX_SIGNATURES);
}

/** The DKIM signatures a message carries, for looking up their keys. Only the headers are read. */
export function dkimSignatures(bytes: Uint8Array): DkimSignatureInfo[] {
  return signatures(headerFields(bytes)).map(({ domain, selector }) => ({ domain, selector }));
}

/**
 * The body in canonical form (RFC 6376 §3.4.3–3.4.4), worked out on the bytes in one pass, since
 * a body can run to megabytes. Line endings become CRLF and empty lines at the end are dropped;
 * relaxed also drops each line's trailing whitespace and shrinks the rest to single spaces.
 */
function canonBody(body: Uint8Array, mode: "simple" | "relaxed"): Uint8Array {
  if (mode === "simple" && crlfOnly(body)) return simpleAsIs(body);
  const relaxed = mode === "relaxed";
  const length = body.length;
  const out = new Uint8Array(length * 2 + 2);
  let n = 0;
  // How much of the output to keep: up to the end of the last line that isn't empty.
  let keep = 0;
  let content = false;
  let space = false;
  let i = 0;
  // Reads stay in bounds: one past the end would slow the whole loop down.
  while (i < length) {
    const c = body[i++]!;
    if (c === 0x0a || (c === 0x0d && i < length && body[i] === 0x0a)) {
      if (c === 0x0d) i++;
      out[n++] = 0x0d;
      out[n++] = 0x0a;
      if (content) keep = n;
      content = false;
      space = false;
    } else if (relaxed && (c === 0x20 || c === 0x09)) {
      space = true;
    } else {
      if (space) {
        out[n++] = 0x20;
        space = false;
      }
      out[n++] = c;
      content = true;
    }
  }
  if (content) {
    out[n++] = 0x0d;
    out[n++] = 0x0a;
    keep = n;
  }
  // An empty body is a single CRLF in simple, and nothing at all in relaxed.
  if (!keep && !relaxed) return CRLF;
  return out.subarray(0, keep);
}

const CRLF = new Uint8Array([0x0d, 0x0a]);

/** Whether every line already ends in CRLF, as mail does on the wire. */
function crlfOnly(body: Uint8Array): boolean {
  for (let i = body.indexOf(0x0a); i >= 0; i = body.indexOf(0x0a, i + 1)) if (i === 0 || body[i - 1] !== 0x0d) return false;
  return true;
}

/** Simple canonical form of a CRLF body: only the empty lines at the end change, so nothing is copied. */
function simpleAsIs(body: Uint8Array): Uint8Array {
  let end = body.length;
  while (end >= 2 && body[end - 2] === 0x0d && body[end - 1] === 0x0a) end -= 2;
  if (!end) return CRLF;
  if (end < body.length) return body.subarray(0, end + 2);
  const out = new Uint8Array(end + 2);
  out.set(body);
  out.set(CRLF, end);
  return out;
}

function canonHeader(raw: string, mode: "simple" | "relaxed"): string {
  if (mode === "simple") return raw;
  const at = raw.indexOf(":");
  const name = raw.slice(0, at).trim().toLowerCase();
  const value = raw.slice(at + 1).replace(/\r\n(?=[ \t])/g, "").replace(/[ \t]+/g, " ").trim();
  return `${name}:${value}`;
}

const base64Bytes = (value: string) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));

async function digest(algorithm: "SHA-256" | "SHA-1", data: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest(algorithm, data as Uint8Array<ArrayBuffer>);
  return btoa(binary(new Uint8Array(hash)));
}

/** DER length prefix. */
const derLength = (n: number) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);

/** Wraps a bare PKCS#1 RSA key, which some domains publish, in the SubjectPublicKeyInfo WebCrypto expects. */
function spkiFromPkcs1(pkcs1: Uint8Array): Uint8Array {
  const algorithm = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  const bitString = [0x03, ...derLength(pkcs1.length + 1), 0x00, ...pkcs1];
  const body = [...algorithm, ...bitString];
  return new Uint8Array([0x30, ...derLength(body.length), ...body]);
}

/** The signature's key, null when the record holds none (an empty p= means it was revoked), or "unsupported". */
async function importKey(record: string, algorithm: string): Promise<CryptoKey | null | "unsupported"> {
  const t = tags(record);
  const key = t.get("p")?.replace(/\s+/g, "");
  if (!key) return null;
  const type = (t.get("k") ?? "rsa").toLowerCase();
  const der = base64Bytes(key);
  if (algorithm.startsWith("rsa-") && type === "rsa") {
    const hash = algorithm === "rsa-sha1" ? "SHA-1" : "SHA-256";
    const params = { name: "RSASSA-PKCS1-v1_5", hash };
    try {
      return await crypto.subtle.importKey("spki", der as Uint8Array<ArrayBuffer>, params, false, ["verify"]);
    } catch {
      return crypto.subtle.importKey("spki", spkiFromPkcs1(der) as Uint8Array<ArrayBuffer>, params, false, ["verify"]);
    }
  }
  if (algorithm === "ed25519-sha256" && type === "ed25519") {
    return crypto.subtle.importKey("raw", der as Uint8Array<ArrayBuffer>, { name: "Ed25519" }, false, ["verify"]);
  }
  return "unsupported";
}

/** The data a signature covers: the signed fields, then the signature field itself with its b= emptied. */
function signedData(fields: Field[], signature: Signature): string {
  const used = new Set<number>([signature.index]);
  const parts: string[] = [];
  for (const name of signature.signed) {
    // Repeated fields are taken from the bottom up, each one once.
    for (let i = fields.length - 1; i >= 0; i--) {
      if (used.has(i) || fields[i]!.name !== name) continue;
      used.add(i);
      parts.push(`${canonHeader(fields[i]!.raw, signature.headerCanon)}\r\n`);
      break;
    }
  }
  const own = fields[signature.index]!.raw;
  const at = own.indexOf(":") + 1;
  const emptied = own.slice(0, at) + own.slice(at).replace(/(^|;)(\s*b\s*=)[^;]*/i, "$1$2");
  parts.push(canonHeader(emptied, signature.headerCanon));
  return parts.join("");
}

/**
 * Tags a company's mail system adds to a subject after checking the signature, such as
 * "[EXTERNAL]" or "***SPAM***". They break an honest signature, so a failing one is tried again
 * without them. That can't make a fake signature pass: it still has to verify.
 */
const SUBJECT_TAG =
  /^(:\s*)(?:[[(][^\])\r\n]{0,30}\b(?:external|ext|caution|warning|spam|suspected|suspicious|phish(?:ing)?|unverified)\b[^\])\r\n]{0,30}[\])]:?|\*{1,5}\s*(?:external|ext|caution|warning|spam|suspicious)\s*\*{1,5}:?|(?:external|ext|caution|warning|spam|suspicious)\s*:)\s*/i;

function untagSubject(fields: Field[]): Field[] | null {
  let changed = false;
  const out = fields.map((field) => {
    if (field.name !== "subject") return field;
    const at = field.raw.indexOf(":");
    let rest = field.raw.slice(at);
    for (let i = 0; i < 3 && SUBJECT_TAG.test(rest); i++) rest = rest.replace(SUBJECT_TAG, "$1");
    if (rest === field.raw.slice(at)) return field;
    changed = true;
    return { ...field, raw: field.raw.slice(0, at) + rest };
  });
  return changed ? out : null;
}

/** Whether the signature holds over the headers, which takes only the headers and the key. */
async function headersVerify(fields: Field[], signature: Signature, key: CryptoKey): Promise<boolean> {
  const value = base64Bytes(signature.value);
  const check = async (signedFields: Field[]) => {
    const data = toBytes(signedData(signedFields, signature));
    if (signature.algorithm === "ed25519-sha256") {
      const digestBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", data as Uint8Array<ArrayBuffer>));
      return crypto.subtle.verify({ name: "Ed25519" }, key, value as Uint8Array<ArrayBuffer>, digestBytes);
    }
    return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, value as Uint8Array<ArrayBuffer>, data as Uint8Array<ArrayBuffer>);
  };
  if (await check(fields)) return true;
  const untagged = signature.signed.includes("subject") ? untagSubject(fields) : null;
  return !!untagged && (await check(untagged));
}

type CanonicalBody = (mode: "simple" | "relaxed") => Uint8Array;

/**
 * The headers are checked before the body: a signature that holds over the headers is genuine
 * even when the body was changed since, and one that doesn't is worthless whatever the body says.
 */
async function verifyOne(fields: Field[], body: CanonicalBody, signature: Signature, key: DkimKey | undefined): Promise<DkimOutcome> {
  // The standard requires From to be signed: a signature without it vouches for nothing.
  if (!ALGORITHMS.has(signature.algorithm) || !signature.signed.includes("from")) return "unsupported";
  if (!key) return "unchecked";
  if (!key.record) return "no-key";
  const imported = await importKey(key.record, signature.algorithm);
  if (imported === "unsupported") return "unsupported";
  if (!imported) return "no-key";
  if (!(await headersVerify(fields, signature, imported))) return "fail";

  const canonical = body(signature.bodyCanon);
  // Content past an l= limit isn't covered by the signature, so the body as a whole isn't verified.
  if (signature.length !== null && signature.length !== canonical.length) return "body-changed";
  const hash = signature.algorithm === "rsa-sha1" ? "SHA-1" : "SHA-256";
  return (await digest(hash, canonical)) === signature.bodyHash ? "pass" : "body-changed";
}

/** Verifies every signature on a message (as bytes) against the keys looked up for it. */
export async function verifySignatures(bytes: Uint8Array, keys: DkimKey[]): Promise<DkimResult[]> {
  const fields = headerFields(bytes);
  // The body is put in canonical form only once a signature holds over the headers, and once per form.
  const canonical = new Map<"simple" | "relaxed", Uint8Array>();
  const body: CanonicalBody = (mode) => {
    let done = canonical.get(mode);
    if (!done) canonical.set(mode, (done = canonBody(bytes.subarray(headerEnd(bytes)), mode)));
    return done;
  };
  const results: DkimResult[] = [];
  for (const signature of signatures(fields)) {
    const key = keys.find((k) => k.domain === signature.domain && k.selector === signature.selector);
    let result: DkimOutcome;
    try {
      result = await verifyOne(fields, body, signature, key);
    } catch {
      result = "unsupported";
    }
    results.push({ domain: signature.domain, selector: signature.selector, result });
  }
  return results;
}
