/**
 * SPF (RFC 7208), re-run here to test what an email's Authentication-Results header claims.
 *
 * A header that says "spf=pass" names the server address it checked. Asking the domain's own SPF
 * record whether it allows that address shows whether the claim could be true. It can't show which
 * server really delivered the email: only the receiving server saw that.
 */
import type { SpfResult } from "@phish-check/engine";
import { dns, txtData, type DnsAnswer, type DnsType } from "./dns.ts";

/** DNS queries one check may make: the 10 lookups RFC 7208 allows, the record itself and some slack. */
export const SPF_QUERIES = 12;
const MAX_LOOKUPS = 10;
const MAX_VOIDS = 2;
const MAX_MX = 10;

type Lookup = (name: string, type: DnsType) => Promise<DnsAnswer>;

interface Context {
  ip: Uint8Array;
  /** The domain being checked, which macros call the sender's domain. */
  sender: string;
  lookup: Lookup;
  queries: number;
  lookups: number;
  voids: number;
  /** Set when a term needed what isn't known here: the sender's mailbox, the server's own name, a reverse lookup. */
  guessed: boolean;
}

/** Ends the check early with an error result. */
class Stop extends Error {
  result: "permerror" | "temperror";
  constructor(result: "permerror" | "temperror") {
    super(result);
    this.result = result;
  }
}

/** An IP address as bytes: 4 for IPv4, 16 for IPv6. An IPv4 address written as IPv6 counts as IPv4. */
export function parseIp(text: string): Uint8Array | null {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (v4) {
    const bytes = v4.slice(1).map(Number);
    return bytes.every((b) => b <= 255) ? Uint8Array.from(bytes) : null;
  }
  if (!text.includes(":") || !/^[0-9a-f:.]+$/i.test(text)) return null;
  let body = text;
  let tail: Uint8Array | null = null;
  if (body.includes(".")) {
    const at = body.lastIndexOf(":");
    tail = parseIp(body.slice(at + 1));
    if (!tail || tail.length !== 4) return null;
    body = `${body.slice(0, at + 1)}0:0`;
  }
  const halves = body.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...rest];
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return null;
  const out = new Uint8Array(16);
  groups.forEach((g, i) => {
    const n = parseInt(g, 16);
    out[i * 2] = n >> 8;
    out[i * 2 + 1] = n & 0xff;
  });
  if (tail) out.set(tail, 12);
  const mapped = out.subarray(0, 10).every((b) => b === 0) && out[10] === 0xff && out[11] === 0xff;
  return mapped ? out.slice(12) : out;
}

function inNetwork(ip: Uint8Array, network: Uint8Array, bits: number): boolean {
  if (ip.length !== network.length) return false;
  for (let i = 0; i < ip.length && bits > 0; i++, bits -= 8) {
    const mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
    if ((ip[i]! & mask) !== (network[i]! & mask)) return false;
  }
  return true;
}

const QUALIFIERS: Record<string, SpfResult> = { "": "pass", "+": "pass", "-": "fail", "~": "softfail", "?": "neutral" };
const MACRO = /%(?:\{([a-z])(\d*)(r?)([.\-+,/_=]*)\}|[%_-])/gi;
const VALID_SPEC = /^(?:[^%\s]|%%|%_|%-|%\{[slodiphcrtv]\d*r?[.\-+,/_=]*\})+$/i;

interface Term {
  qualifier: SpfResult;
  name: "all" | "include" | "a" | "mx" | "ptr" | "ip4" | "ip6" | "exists";
  /** The domain after ":", macros not yet expanded. */
  spec: string | null;
  cidr4: number;
  cidr6: number;
  network: Uint8Array | null;
}

/** The record's mechanisms and redirect, or null for a syntax error, which makes the whole record a permerror. */
function parseRecord(record: string): { terms: Term[]; redirect: string | null } | null {
  const terms: Term[] = [];
  let redirect: string | null = null;
  for (const word of record.slice(6).trim().split(/\s+/).filter(Boolean)) {
    const modifier = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(word);
    if (modifier) {
      if (modifier[1]!.toLowerCase() === "redirect") {
        if (redirect !== null || !VALID_SPEC.test(modifier[2]!)) return null;
        redirect = modifier[2]!;
      }
      continue;
    }
    const m = /^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)(.*)$/i.exec(word);
    if (!m) return null;
    const name = m[2]!.toLowerCase() as Term["name"];
    const rest = m[3]!;
    const term: Term = { qualifier: QUALIFIERS[m[1]!]!, name, spec: null, cidr4: 32, cidr6: 128, network: null };
    if (name === "all") {
      if (rest) return null;
    } else if (name === "ip4" || name === "ip6") {
      const net = /^:([^/]+)(?:\/(\d{1,3}))?$/.exec(rest);
      const address = net ? parseIp(net[1]!) : null;
      if (!net || !address || (name === "ip4") !== (address.length === 4)) return null;
      const bits = net[2] === undefined ? address.length * 8 : Number(net[2]);
      if (bits > address.length * 8) return null;
      term.network = address;
      if (name === "ip4") term.cidr4 = bits;
      else term.cidr6 = bits;
    } else {
      const parts = /^(?::(.+?))?(?:\/(\d{1,2}))?(?:\/\/(\d{1,3}))?$/.exec(rest);
      if (!parts) return null;
      const [, spec, cidr4, cidr6] = parts;
      const needsSpec = name === "include" || name === "exists";
      const takesCidr = name === "a" || name === "mx";
      if ((needsSpec && !spec) || (!takesCidr && (cidr4 || cidr6)) || (spec && !VALID_SPEC.test(spec))) return null;
      if (Number(cidr4 ?? 32) > 32 || Number(cidr6 ?? 128) > 128) return null;
      term.spec = spec ?? null;
      term.cidr4 = Number(cidr4 ?? 32);
      term.cidr6 = Number(cidr6 ?? 128);
    }
    terms.push(term);
  }
  return { terms, redirect };
}

/** A domain-spec with its macros expanded (RFC 7208 section 7). */
function expand(spec: string, ctx: Context, domain: string): string {
  const expanded = spec.replace(MACRO, (whole: string, letter?: string, digits = "", reverse = "", delimiters = "") => {
    if (!letter) return whole === "%%" ? "%" : whole === "%_" ? " " : "%20";
    let value: string;
    switch (letter.toLowerCase()) {
      case "d":
        value = domain;
        break;
      case "o":
        value = ctx.sender;
        break;
      case "i":
        value = ctx.ip.length === 4 ? ctx.ip.join(".") : [...ctx.ip].flatMap((b) => [b >> 4, b & 15]).map((n) => n.toString(16)).join(".");
        break;
      case "v":
        value = ctx.ip.length === 4 ? "in-addr" : "ip6";
        break;
      default:
        // The sender's mailbox and the server's own name aren't sent here, so these are stand-ins.
        ctx.guessed = true;
        value = letter.toLowerCase() === "l" ? "postmaster" : letter.toLowerCase() === "s" ? `postmaster@${ctx.sender}` : letter.toLowerCase() === "h" ? ctx.sender : "unknown";
    }
    let parts = value.split(delimiters ? new RegExp(`[${delimiters.replace(/-/g, "\\-")}]`) : /\./);
    if (reverse) parts.reverse();
    if (digits) {
      if (!Number(digits)) throw new Stop("permerror");
      parts = parts.slice(-Number(digits));
    }
    const out = parts.join(".");
    return letter === letter.toUpperCase() ? encodeURIComponent(out) : out;
  });
  // A name over 253 characters loses labels from the left until it fits.
  let name = expanded.toLowerCase();
  while (name.length > 253 && name.includes(".")) name = name.slice(name.indexOf(".") + 1);
  return name;
}

const validDomain = (name: string) => name.length <= 253 && name.includes(".") && name.split(".").every((label) => label.length > 0 && label.length <= 63);

async function query(ctx: Context, name: string, type: DnsType): Promise<DnsAnswer> {
  if (++ctx.queries > SPF_QUERIES) throw new Stop("temperror");
  const answer = await ctx.lookup(name, type);
  if (answer.status !== 0 && answer.status !== 3) throw new Stop("temperror");
  return answer;
}

function countLookup(ctx: Context): void {
  if (++ctx.lookups > MAX_LOOKUPS) throw new Stop("permerror");
}

function countVoid(ctx: Context): void {
  if (++ctx.voids > MAX_VOIDS) throw new Stop("permerror");
}

async function addresses(ctx: Context, name: string): Promise<Uint8Array[]> {
  const v6 = ctx.ip.length === 16;
  const answer = await query(ctx, name, v6 ? "AAAA" : "A");
  return answer.records.filter((r) => r.type === (v6 ? 28 : 1)).flatMap((r) => parseIp(r.data) ?? []);
}

async function matches(ctx: Context, term: Term, domain: string): Promise<boolean> {
  const bits = ctx.ip.length === 4 ? term.cidr4 : term.cidr6;
  const target = () => (term.spec === null ? domain : expand(term.spec, ctx, domain));
  switch (term.name) {
    case "all":
      return true;
    case "ip4":
    case "ip6":
      return inNetwork(ctx.ip, term.network!, term.name === "ip4" ? term.cidr4 : term.cidr6);
    case "a": {
      countLookup(ctx);
      const list = await addresses(ctx, target());
      if (!list.length) countVoid(ctx);
      return list.some((address) => inNetwork(ctx.ip, address, bits));
    }
    case "mx": {
      countLookup(ctx);
      const answer = await query(ctx, target(), "MX");
      const hosts = answer.records.filter((r) => r.type === 15).flatMap((r) => r.data.trim().split(/\s+/)[1]?.replace(/\.$/, "") || []);
      if (!hosts.length) countVoid(ctx);
      if (hosts.length > MAX_MX) throw new Stop("permerror");
      for (const host of hosts) if ((await addresses(ctx, host)).some((address) => inNetwork(ctx.ip, address, bits))) return true;
      return false;
    }
    case "ptr":
      // Deprecated, and it needs a reverse lookup of the server; treated as not matching.
      countLookup(ctx);
      ctx.guessed = true;
      return false;
    case "exists": {
      countLookup(ctx);
      const found = (await query(ctx, target(), "A")).records.some((r) => r.type === 1);
      if (!found) countVoid(ctx);
      return found;
    }
    case "include": {
      countLookup(ctx);
      const result = await checkHost(ctx, target());
      if (result === "pass") return true;
      if (result === "temperror") throw new Stop("temperror");
      if (result === "permerror" || result === "none") throw new Stop("permerror");
      return false;
    }
  }
}

async function checkHost(ctx: Context, domain: string): Promise<SpfResult> {
  if (!validDomain(domain)) return "none";
  const answer = await query(ctx, domain, "TXT");
  const records = answer.records
    .filter((r) => r.type === 16)
    .map((r) => txtData(r.data))
    .filter((text) => /^v=spf1(?: |$)/i.test(text));
  if (!records.length) return "none";
  if (records.length > 1) return "permerror";
  const record = parseRecord(records[0]!);
  if (!record) return "permerror";
  for (const term of record.terms) if (await matches(ctx, term, domain)) return term.qualifier;
  if (record.redirect === null) return "neutral";
  countLookup(ctx);
  const result = await checkHost(ctx, expand(record.redirect, ctx, domain));
  return result === "none" ? "permerror" : result;
}

/**
 * Whether `domain`'s SPF record allows the server at `ip`. Anything this can't evaluate as the
 * receiving server would have (a reverse lookup, the sender's mailbox in a macro) can only have
 * changed a pass, so then anything but a pass comes back as temperror: unknown, not a failure.
 */
export async function evaluateSpf(domain: string, ip: string, lookup: Lookup = dns): Promise<SpfResult> {
  const address = parseIp(ip);
  if (!address) return "permerror";
  const ctx: Context = { ip: address, sender: domain.toLowerCase(), lookup, queries: 0, lookups: 0, voids: 0, guessed: false };
  let result: SpfResult;
  try {
    result = await checkHost(ctx, ctx.sender);
  } catch (err) {
    result = err instanceof Stop ? err.result : "temperror";
  }
  return ctx.guessed && result !== "pass" ? "temperror" : result;
}
