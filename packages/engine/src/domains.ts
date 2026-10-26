import { parse } from "tldts";
import type { Brand } from "./brands.ts";

export function addressDomain(address: string): string {
  const at = address.lastIndexOf("@");
  return at >= 0 ? address.slice(at + 1).replace(/[>\s]/g, "").toLowerCase() : "";
}

/** The part of a hostname an organisation registers, e.g. mail.shop.example → shop.example. */
export function registrable(host: string): string {
  const info = parse(host);
  return (info.isIp ? info.hostname : info.domain) ?? host.toLowerCase();
}

export function urlHost(href: string): string | null {
  try {
    const url = new URL(href.startsWith("www.") ? `http://${href}` : href);
    return /^https?:$/.test(url.protocol) ? url.hostname.toLowerCase() : null;
  } catch {
    return null;
  }
}

/** The domain a link's visible text claims to go to, when the text looks like an address. */
export function claimedHost(text: string): string | null {
  const match = text.trim().match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:[/?#]\S*)?$/i);
  return match ? match[1]!.toLowerCase() : null;
}

export function isIpHost(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[");
}

// --- Punycode (RFC 3492), so xn-- labels can be shown and compared as letters.

const BASE = 36;

function digitOf(code: number): number {
  if (code >= 48 && code <= 57) return code - 22;
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 97;
  return BASE;
}

function adapt(delta: number, points: number, first: boolean): number {
  let k = 0;
  delta = first ? Math.floor(delta / 700) : delta >> 1;
  delta += Math.floor(delta / points);
  for (; delta > 455; k += BASE) delta = Math.floor(delta / 35);
  return Math.floor(k + (36 * delta) / (delta + 38));
}

function decodeLabel(input: string): string {
  const output: number[] = [];
  const basic = Math.max(input.lastIndexOf("-"), 0);
  for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
  let n = 128;
  let bias = 72;
  let i = 0;
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length; ) {
    const oldI = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) throw new RangeError("Invalid punycode");
      const digit = digitOf(input.charCodeAt(index++));
      if (digit >= BASE) throw new RangeError("Invalid punycode");
      i += digit * w;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    bias = adapt(i - oldI, output.length + 1, oldI === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** Turns xn-- labels back into the letters a reader would see. */
export function unicodeHost(host: string): string {
  return host
    .split(".")
    .map((label) => {
      if (!label.startsWith("xn--")) return label;
      try {
        return decodeLabel(label.slice(4));
      } catch {
        return label;
      }
    })
    .join(".");
}

// --- Look-alike characters

/** Letters from other alphabets that render like Latin ones. Letters only: digits stay digits in text. */
const LETTER_LOOKALIKES: Record<string, string> = {
  // Cyrillic
  "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y",
  "І": "I", "Ј": "J", "Ѕ": "S", "Ԛ": "Q", "Ԝ": "W", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
  "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w",
  // Greek
  "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
  "Υ": "Y", "Χ": "X", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "υ": "u", "ε": "e",
  // Cherokee
  "Ꭺ": "A", "Ᏼ": "B", "Ꮯ": "C", "Ꭰ": "D", "Ꭼ": "E", "Ꮐ": "G", "Ꮋ": "H", "Ꭻ": "J", "Ꮶ": "K", "Ꮮ": "L", "Ꮇ": "M", "Ꮲ": "P",
  "Ꮪ": "S", "Ꭲ": "T", "Ꮩ": "V", "Ꮃ": "W", "Ꮓ": "Z",
  // Armenian and other singles
  "ո": "n", "ս": "u", "օ": "o", "հ": "h", "ց": "g", "ɡ": "g", "ı": "i",
};

/** Swaps look-alike letters for Latin ones, one character for one, so offsets stay valid. */
export function latinizeSameLength(text: string): string {
  return text.replace(/[^\x00-\x7F]/g, (ch) => LETTER_LOOKALIKES[ch] ?? ch);
}

/** Single letters with a space between each, like "C o i n b a s e". */
const SPACED_LETTERS = /(?<![\p{L}\p{N}])(?:\p{L} ){2,}\p{L}(?![\p{L}\p{N}])/gu;

/**
 * Plain Latin text for brand and keyword matching: styled letters, look-alikes, invisible
 * characters and s p a c e d - o u t words undone.
 */
export function latinize(text: string): string {
  const plain = text.normalize("NFKC").replace(/[​‌⁠﻿­]/g, "").replace(SPACED_LETTERS, (run) => run.replace(/ /g, ""));
  return latinizeSameLength(plain);
}

const SWAPS: Record<string, string> = {
  "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s", "|": "l", "!": "i",
  // Cyrillic and Greek letters that look Latin
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
  "ԁ": "d", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ο": "o", "α": "a", "ν": "v", "ρ": "p",
  "τ": "t", "ι": "i", "κ": "k", "υ": "u", "ε": "e",
};
const PAIRS: Record<string, string> = { rn: "m", vv: "w" };

interface Piece {
  out: string;
  start: number;
  end: number;
  swapped: boolean;
}

function pieces(raw: string): Piece[] {
  const out: Piece[] = [];
  for (let i = 0; i < raw.length; ) {
    const pair = PAIRS[raw.slice(i, i + 2)];
    if (pair) {
      out.push({ out: pair, start: i, end: i + 2, swapped: true });
      i += 2;
      continue;
    }
    const ch = raw[i]!;
    const swap = SWAPS[ch];
    out.push({ out: swap ?? ch, start: i, end: i + 1, swapped: swap !== undefined });
    i++;
  }
  return out;
}

/** Explains one swap in plain words, e.g. 'the number "1" for the letter "l"'. */
export function describeSwap(raw: string, intended: string): string {
  if (/^\d$/.test(raw)) return `the number "${raw}" for the letter "${intended}"`;
  if (raw.length === 2) return `"${raw}" for "${intended}"`;
  if (/[^\x00-\x7f]/.test(raw)) return `a look-alike "${intended}" from another alphabet`;
  return `"${raw}" for "${intended}"`;
}

export interface BrandMatch {
  brand: Brand;
  kind: "swap" | "typo" | "contains";
  /** Character ranges in `display` that differ from the real brand name. */
  marks: [number, number][];
  /** Human description of the first swapped character, when kind is "swap". */
  swap: string | null;
  /** The host as a reader sees it (punycode decoded). */
  display: string;
}

export function belongsTo(host: string, brand: Brand): boolean {
  const lower = host.toLowerCase();
  if (brand.suffixes?.some((s) => lower.endsWith(s) || lower === s.slice(1))) return true;
  const info = parse(lower);
  const domain = info.domain ?? lower;
  if (brand.domains.includes(domain)) return true;
  // Brands own their name under most country codes: paypal.ca, amazon.co.uk.
  return info.domainWithoutSuffix === brand.slugs[0] && /^([a-z]{2}|(co|com|net|org)\.[a-z]{2})$/.test(info.publicSuffix ?? "");
}

/** Finds a brand that `host` imitates without belonging to it. */
export function imitatedBrand(host: string, brands: Brand[]): BrandMatch | null {
  const display = unicodeHost(host);
  const suffix = parse(host).publicSuffix ?? "";
  const label = suffix ? display.slice(0, Math.max(0, display.length - suffix.length - 1)) : display;
  const tokens = [...label.matchAll(/[^.\-_]+/g)].map((m) => ({ text: m[0], at: m.index! }));

  for (const brand of brands) {
    if (belongsTo(host, brand)) continue;
    for (const slug of brand.slugs) {
      for (const token of tokens) {
        const hit = matchToken(token.text, slug);
        if (!hit) continue;
        return {
          brand,
          kind: hit.kind,
          marks: hit.marks.map(([s, e]) => [s + token.at, e + token.at]),
          swap: hit.swap,
          display,
        };
      }
    }
  }
  return null;
}

function matchToken(
  token: string,
  slug: string,
): { kind: BrandMatch["kind"]; marks: [number, number][]; swap: string | null } | null {
  if (slug.length < 4) return token === slug ? { kind: "contains", marks: [[0, token.length]], swap: null } : null;

  const exact = token.indexOf(slug);
  if (exact >= 0) return { kind: "contains", marks: [[exact, exact + slug.length]], swap: null };

  const parts = pieces(token);
  const skeleton = parts.map((p) => p.out).join("");
  const at = skeleton.indexOf(slug);
  if (at >= 0) {
    let offset = 0;
    const swapped: Piece[] = [];
    for (const part of parts) {
      const inside = offset >= at && offset < at + slug.length;
      if (inside && part.swapped) swapped.push(part);
      offset += part.out.length;
    }
    const first = swapped[0];
    return {
      kind: "swap",
      marks: swapped.map((p) => [p.start, p.end]),
      swap: first ? describeSwap(token.slice(first.start, first.end), first.out) : null,
    };
  }

  if (slug.length >= 5 && Math.abs(skeleton.length - slug.length) <= 1 && oneEditApart(skeleton, slug)) {
    let start = 0;
    while (start < token.length && token[start] === slug[start]) start++;
    let end = 0;
    while (end < token.length - start && token[token.length - 1 - end] === slug[slug.length - 1 - end]) end++;
    return { kind: "typo", marks: [[start, Math.max(start + 1, token.length - end)]], swap: null };
  }
  return null;
}

/** True when a and b differ by one insertion, deletion, substitution or swap of neighbours. */
function oneEditApart(a: string, b: string): boolean {
  if (a === b) return false;
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  const restA = a.slice(i);
  const restB = b.slice(i);
  if (restA.slice(1) === restB.slice(1)) return true;
  if (restA.slice(1) === restB || restA === restB.slice(1)) return true;
  return restA.length >= 2 && restA[0] === restB[1] && restA[1] === restB[0] && restA.slice(2) === restB.slice(2);
}
