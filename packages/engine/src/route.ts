import type { Hop } from "./types.ts";

/**
 * Signs a hop was encrypted: a protocol with the "S" for TLS (RFC 3848, e.g. ESMTPS, UTF8SMTPS),
 * or the TLS notes servers add. Only these spots count, so a host named "smtps1.example" doesn't.
 */
const ENCRYPTED = /\bwith\s+(?:E?SMTPSA?|UTF8SMTPSA?|LMTPSA?|HTTPS)\b|\(using TLS|\bversion=TLS/i;

/** Parses Received headers (newest first, as stored) into hops, oldest first. */
export function parseRoute(received: string[]): Hop[] {
  return received.map(parseHop).reverse();
}

function parseHop(value: string): Hop {
  const semicolon = value.lastIndexOf(";");
  const main = semicolon >= 0 ? value.slice(0, semicolon) : value;
  const date = semicolon >= 0 ? value.slice(semicolon + 1).trim() || null : null;
  const fromClause = main.split(/\sby\s/i)[0] ?? "";
  const protocol = main.match(/\bwith\s+([a-z0-9]+)/i)?.[1]?.toUpperCase() ?? null;
  return {
    from: main.match(/^\s*from\s+([^\s;()[\]]+)/i)?.[1] ?? null,
    ip: fromClause.match(/\[(?:ipv6:)?([0-9a-f:.]+)\]/i)?.[1] ?? null,
    by: main.match(/\bby\s+([^\s;()[\]]+)/i)?.[1] ?? null,
    protocol,
    tls: ENCRYPTED.test(main) ? true : protocol ? false : null,
    date,
  };
}

export function isPublicIp(ip: string): boolean {
  if (ip.includes(":")) return !/^(::1|fe80:|fc|fd)/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  if (a === undefined || b === undefined) return false;
  return !(a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254));
}

/** The oldest hop that came from a public address: where the email entered the internet. */
export function originHop(route: Hop[]): Hop | null {
  return route.find((hop) => hop.from && hop.ip && isPublicIp(hop.ip)) ?? null;
}
