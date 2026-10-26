/** DNS lookups over HTTPS through Cloudflare's resolver. */

export const TIMEOUT_MS = 4000;
export const timeout = () => AbortSignal.timeout(TIMEOUT_MS);

export type DnsType = "A" | "AAAA" | "MX" | "TXT";

export interface DnsAnswer {
  /** The DNS response code: 0 is an answer, 3 means the name doesn't exist. */
  status: number;
  /** Answer records by type number (1 A, 5 CNAME, 15 MX, 16 TXT, 28 AAAA), CNAMEs followed included. */
  records: { type: number; data: string }[];
}

export async function dns(name: string, type: DnsType): Promise<DnsAnswer> {
  const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { accept: "application/dns-json" },
    signal: timeout(),
  });
  if (!res.ok) throw new Error(`DNS answered ${res.status}`);
  const data = (await res.json()) as { Status: number; Answer?: { type: number; data?: string }[] };
  return { status: data.Status, records: (data.Answer ?? []).map((a) => ({ type: a.type, data: String(a.data ?? "") })) };
}

/** A TXT record's text. DNS stores long records as several quoted strings, which are joined back up. */
export function txtData(data: string): string {
  const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]!.replace(/\\(\d{3}|.)/g, (_, c: string) => (c.length === 3 ? String.fromCharCode(Number(c)) : c)));
  return parts.length ? parts.join("") : data;
}
