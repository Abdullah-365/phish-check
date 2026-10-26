import {
  INTEL_LIMITS,
  inspectUrl,
  sharedHost,
  stripQuery,
  type DkimKey,
  type DkimSignatureInfo,
  type DomainIntel,
  type IntelRequest,
  type IntelResponse,
  type Listing,
  type SpfClaim,
} from "@phish-check/engine";
import { dns, timeout, txtData } from "./dns.ts";
import { evaluateSpf, parseIp, SPF_QUERIES } from "./spf.ts";

/** Optional keys, set with `wrangler secret put`. Each one switches on another lookup. */
export interface IntelEnv {
  /** abuse.ch Auth-Key: enables URLhaus (links) and MalwareBazaar (attachments). */
  ABUSECH_KEY?: string;
  /** Google Safe Browsing API key. */
  GSB_KEY?: string;
  /** VirusTotal API key. */
  VT_KEY?: string;
}

/** Subrequests one check may make: under the free plan's 50, with room for the cache. */
const SUBREQUESTS = 40;
/** VirusTotal's free API allows 4 lookups a minute. */
const VT_PER_REQUEST = 4;
/** Antivirus engines that must agree before a file is called malware. */
const VT_MIN_ENGINES = 3;
const DOMAIN = /^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;
const HASH = /^[0-9a-f]{64}$/;
/** A DKIM selector: one or more DNS labels. Some domains use underscores in them. */
const SELECTOR = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/;

const strings = (value: unknown): string[] => (Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : []);

const keyName = (s: DkimSignatureInfo) => `${s.selector}._domainkey.${s.domain}`;

function signatures(value: unknown): DkimSignatureInfo[] {
  const out = new Map<string, DkimSignatureInfo>();
  for (const item of Array.isArray(value) ? value : []) {
    if (!item || typeof item !== "object") continue;
    const { domain, selector } = item as Record<string, unknown>;
    if (typeof domain !== "string" || typeof selector !== "string") continue;
    const s = { domain: domain.trim().toLowerCase(), selector: selector.trim().toLowerCase() };
    if (DOMAIN.test(s.domain) && SELECTOR.test(s.selector) && keyName(s).length <= 253) out.set(keyName(s), s);
  }
  return [...out.values()].slice(0, INTEL_LIMITS.dkim);
}

function spfQuery(value: unknown): SpfClaim | null {
  if (!value || typeof value !== "object") return null;
  const { domain, ip } = value as Record<string, unknown>;
  if (typeof domain !== "string" || typeof ip !== "string") return null;
  const query = { domain: domain.trim().toLowerCase(), ip: ip.trim().toLowerCase() };
  return DOMAIN.test(query.domain) && query.ip.length <= 45 && parseIp(query.ip) ? query : null;
}

/** Accepts only well-formed indicators, within limits. Anything else is dropped, not echoed. */
export function parseRequest(body: unknown): IntelRequest | null {
  if (!body || typeof body !== "object") return null;
  const raw = body as Record<string, unknown>;
  const domains = strings(raw.domains)
    .map((d) => d.trim().toLowerCase())
    .filter((d) => DOMAIN.test(d))
    .slice(0, INTEL_LIMITS.domains);
  const urls = strings(raw.urls)
    .filter((u) => /^https?:\/\//i.test(u) && u.length <= 2048)
    .map(stripQuery)
    .slice(0, INTEL_LIMITS.urls);
  const hashes = strings(raw.hashes)
    .map((h) => h.trim().toLowerCase())
    .filter((h) => HASH.test(h))
    .slice(0, INTEL_LIMITS.hashes);
  const spf = spfQuery(raw.spf);
  return {
    domains: [...new Set(domains)],
    urls: [...new Set(urls)],
    hashes: [...new Set(hashes)],
    dkim: signatures(raw.dkim),
    ...(spf ? { spf } : {}),
  };
}

/**
 * Caches an answer in the Workers cache, so repeated checks don't hammer the services. `keep`
 * leaves out answers that may just be a passing hiccup.
 */
async function cached<T>(key: string, seconds: number, work: () => Promise<T>, keep: (value: T) => boolean = () => true): Promise<T> {
  const cache = typeof caches === "undefined" ? null : (caches as unknown as { default: Cache }).default;
  const url = `https://intel.cache.phish-check/${encodeURIComponent(key)}`;
  const hit = cache ? await cache.match(url) : undefined;
  if (hit) return (await hit.json()) as T;
  const value = await work();
  if (keep(value)) await cache?.put(url, new Response(JSON.stringify(value), { headers: { "content-type": "application/json", "cache-control": `max-age=${seconds}` } }));
  return value;
}

interface Rdap {
  found: boolean;
  registered: string | null;
  registrar: string | null;
}

/** Identifies the tool to the services it queries, as their usage policies ask. */
const USER_AGENT = "phish-check/0.2 (+https://github.com/Abdullah-365/phish-check)";

let bootstrapMemo: { at: number; servers: Map<string, string> } | null = null;
const BOOTSTRAP_TTL = 24 * 60 * 60 * 1000;
const bootstrapFresh = () => !!bootstrapMemo && Date.now() - bootstrapMemo.at <= BOOTSTRAP_TTL;

/** IANA's official list of which registry answers RDAP queries for each domain ending. */
async function rdapServer(tld: string): Promise<string | null> {
  if (!bootstrapMemo || !bootstrapFresh()) {
    const data = await cached("rdap-bootstrap", 86_400, async () => {
      const res = await fetch("https://data.iana.org/rdap/dns.json", { headers: { "user-agent": USER_AGENT }, signal: timeout() });
      if (!res.ok) throw new Error(`IANA bootstrap answered ${res.status}`);
      return (await res.json()) as { services: [string[], string[]][] };
    });
    const servers = new Map<string, string>();
    for (const [tlds, urls] of data.services) {
      const base = urls.find((u) => u.startsWith("https://")) ?? urls[0];
      if (base) for (const t of tlds) servers.set(t.toLowerCase(), base.endsWith("/") ? base : `${base}/`);
    }
    bootstrapMemo = { at: Date.now(), servers };
  }
  return bootstrapMemo.servers.get(tld) ?? null;
}

/** Registration date and registrar, straight from the domain's registry. */
async function rdap(domain: string): Promise<Rdap> {
  const tld = domain.split(".").at(-1)!;
  const server = await rdapServer(tld);
  // Some country registries (like .de) don't offer RDAP at all.
  if (!server) throw new Error(`No RDAP server for .${tld}`);
  const res = await fetch(`${server}domain/${domain}`, {
    headers: { accept: "application/rdap+json, application/json", "user-agent": USER_AGENT },
    signal: timeout(),
  });
  if (res.status === 404) return { found: false, registered: null, registrar: null };
  if (!res.ok) throw new Error(`RDAP answered ${res.status}`);
  const data = (await res.json()) as {
    events?: { eventAction?: string; eventDate?: string }[];
    entities?: { roles?: string[]; vcardArray?: [string, unknown[][]] }[];
  };
  const registered = data.events?.find((e) => e.eventAction === "registration")?.eventDate ?? null;
  const card = data.entities?.find((e) => e.roles?.includes("registrar"))?.vcardArray?.[1];
  const name = card?.find((field) => field[0] === "fn")?.[3];
  return { found: true, registered, registrar: typeof name === "string" ? name : null };
}

/**
 * The public key a DKIM signature names, at <selector>._domainkey.<domain>. A name that doesn't
 * exist, or holds no key, is an answer too (record null); a resolver failure is not.
 */
async function dkimKey(signature: DkimSignatureInfo): Promise<{ record: string | null }> {
  const answer = await dns(keyName(signature), "TXT");
  if (answer.status === 3) return { record: null };
  if (answer.status !== 0) throw new Error(`DNS status ${answer.status}`);
  // Type 16 is TXT; the answer can also hold the CNAMEs followed to reach it.
  const records = answer.records.filter((r) => r.type === 16).map((r) => txtData(r.data));
  return { record: records.find((r) => /(?:^|;)\s*p\s*=/i.test(r)) ?? null };
}

async function mailbox(domain: string): Promise<{ exists: boolean; mailbox: boolean }> {
  const mx = await dns(domain, "MX");
  if (mx.status === 3) return { exists: false, mailbox: false };
  if (mx.records.some((r) => r.type === 15)) return { exists: true, mailbox: true };
  // No MX record: mail falls back to the A record, if there is one.
  const a = await dns(domain, "A");
  return { exists: a.status !== 3, mailbox: a.records.some((r) => r.type === 1) };
}

interface Feed {
  urls: Set<string>;
  hosts: Set<string>;
}

let feedMemo: { at: number; feed: Feed } | null = null;

const normalise = (url: string) => {
  try {
    const u = new URL(url);
    return `${u.host.toLowerCase()}${u.pathname.replace(/\/+$/, "")}`;
  } catch {
    return url.toLowerCase();
  }
};

/**
 * OpenPhish's free community feed of live phishing pages, refreshed hourly. It's published on
 * GitHub now; the old openphish.com/feed.txt address only redirects there, costing a request.
 */
const OPENPHISH_FEED = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";

async function openPhish(): Promise<Feed> {
  if (feedMemo && Date.now() - feedMemo.at < 60 * 60 * 1000) return feedMemo.feed;
  const text = await cached("openphish-feed", 3600, async () => {
    const res = await fetch(OPENPHISH_FEED, { headers: { "user-agent": USER_AGENT }, signal: timeout() });
    if (!res.ok) throw new Error(`OpenPhish answered ${res.status}`);
    return res.text();
  });
  const urls = new Set<string>();
  const hosts = new Set<string>();
  for (const line of text.split("\n")) {
    const url = line.trim();
    if (!url) continue;
    urls.add(normalise(url));
    const info = inspectUrl(url);
    // Shared platforms hold countless honest pages too; only dedicated hosts are listed whole.
    if (info && !sharedHost(info)) hosts.add(info.host);
  }
  feedMemo = { at: Date.now(), feed: { urls, hosts } };
  return feedMemo.feed;
}

const GSB_THREATS: Record<string, string> = {
  SOCIAL_ENGINEERING: "phishing",
  MALWARE: "malware",
  UNWANTED_SOFTWARE: "unwanted software",
  POTENTIALLY_HARMFUL_APPLICATION: "a harmful app",
};

async function safeBrowsing(urls: string[], key: string): Promise<Map<string, string>> {
  const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    signal: timeout(),
    body: JSON.stringify({
      client: { clientId: "phish-check", clientVersion: "0.2.0" },
      threatInfo: {
        threatTypes: Object.keys(GSB_THREATS),
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: urls.map((url) => ({ url })),
      },
    }),
  });
  if (!res.ok) throw new Error(`Safe Browsing answered ${res.status}`);
  const data = (await res.json()) as { matches?: { threatType: string; threat: { url: string } }[] };
  return new Map((data.matches ?? []).map((m) => [m.threat.url, GSB_THREATS[m.threatType] ?? "a threat"]));
}

async function urlhaus(url: string, key: string): Promise<string | null> {
  const res = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
    method: "POST",
    headers: { "Auth-Key": key, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ url }),
    signal: timeout(),
  });
  if (!res.ok) throw new Error(`URLhaus answered ${res.status}`);
  const data = (await res.json()) as { query_status?: string; threat?: string };
  return data.query_status === "ok" ? (data.threat ?? "malware").replace(/_/g, " ") : null;
}

async function malwareBazaar(hash: string, key: string): Promise<string | null> {
  const res = await fetch("https://mb-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Auth-Key": key, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ query: "get_info", hash }),
    signal: timeout(),
  });
  if (!res.ok) throw new Error(`MalwareBazaar answered ${res.status}`);
  const data = (await res.json()) as { query_status?: string; data?: { signature?: string | null }[] };
  return data.query_status === "ok" ? `malware${data.data?.[0]?.signature ? ` (${data.data[0].signature})` : ""}` : null;
}

async function virusTotal(hash: string, key: string): Promise<string | null> {
  const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, { headers: { "x-apikey": key }, signal: timeout() });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`VirusTotal answered ${res.status}`);
  const data = (await res.json()) as { data?: { attributes?: { last_analysis_stats?: { malicious?: number } } } };
  const engines = data.data?.attributes?.last_analysis_stats?.malicious ?? 0;
  // One or two engines flag plenty of harmless files; it takes several agreeing to call it malware.
  return engines >= VT_MIN_ENGINES ? `flagged by ${engines} antivirus engines` : null;
}

/**
 * Runs every lookup that's available. A failing service is reported, never fatal.
 *
 * Workers on the free plan may make 50 subrequests per request, so lookups draw on a budget.
 * Each claims its worst case when it starts, and they start strongest evidence first:
 * blocklists, then files, then DKIM keys and SPF, then domains, then the per-link services.
 */
export async function lookup(request: IntelRequest, env: IntelEnv): Promise<IntelResponse> {
  const sources = new Set<string>();
  const unavailable = new Set<string>();
  let budget = SUBREQUESTS;
  const attempt = async <T>(source: string, cost: number, work: () => Promise<T>): Promise<T | null> => {
    if (budget < cost) {
      unavailable.add(source);
      return null;
    }
    budget -= cost;
    try {
      const value = await work();
      sources.add(source);
      return value;
    } catch {
      unavailable.add(source);
      return null;
    }
  };

  const hasUrls = request.urls.length > 0;
  const feedTask = hasUrls ? attempt("OpenPhish", 1, openPhish) : null;
  const gsbTask = hasUrls && env.GSB_KEY ? attempt("Google Safe Browsing", 1, () => safeBrowsing(request.urls, env.GSB_KEY!)) : null;

  const hashesTask = Promise.all(
    request.hashes.map(async (sha256, index) => {
      const [bazaar, total] = await Promise.all([
        env.ABUSECH_KEY ? attempt("MalwareBazaar", 1, () => cached(`mb:${sha256}`, 86_400, () => malwareBazaar(sha256, env.ABUSECH_KEY!))) : null,
        env.VT_KEY && index < VT_PER_REQUEST ? attempt("VirusTotal", 1, () => cached(`vt:${sha256}`, 86_400, () => virusTotal(sha256, env.VT_KEY!))) : null,
      ]);
      const found: Listing[] = [];
      if (bazaar) found.push({ source: "MalwareBazaar", threat: bazaar });
      if (total) found.push({ source: "VirusTotal", threat: total });
      return { sha256, listings: found };
    }),
  );

  const keysTask = Promise.all(
    (request.dkim ?? []).map(async (signature): Promise<DkimKey | null> => {
      const key = await attempt("DNS", 1, () => cached(`dkim:${keyName(signature)}`, 3_600, () => dkimKey(signature)));
      return key && { ...signature, record: key.record };
    }),
  );

  const { spf } = request;
  // An inconclusive answer may be a passing DNS hiccup, so it isn't kept.
  const spfTask = spf
    ? attempt("DNS", SPF_QUERIES, () => cached(`spf:${spf.domain}:${spf.ip}`, 3_600, () => evaluateSpf(spf.domain, spf.ip), (r) => r !== "temperror"))
    : null;

  const domainsTask = Promise.all(
    request.domains.map(async (domain): Promise<DomainIntel> => {
      const [registry, mail] = await Promise.all([
        // The registry list is fetched once per isolate; after that a lookup is one request.
        attempt("RDAP", bootstrapFresh() ? 1 : 2, () => cached(`rdap:${domain}`, 86_400, () => rdap(domain))),
        attempt("DNS", 2, () => cached(`dns:${domain}`, 3_600, () => mailbox(domain))),
      ]);
      return {
        domain,
        registered: registry?.registered ?? null,
        registrar: registry?.registrar ?? null,
        exists: mail?.exists ?? (registry?.found === false ? false : null),
        mailbox: mail?.mailbox ?? null,
      };
    }),
  );

  const listings = new Map<string, Listing[]>(request.urls.map((url) => [url, []]));
  const urlsTask = (async () => {
    const [feed, matches] = await Promise.all([feedTask, gsbTask]);
    for (const url of request.urls) {
      const host = inspectUrl(url)?.host;
      if (feed && (feed.urls.has(normalise(url)) || (host && feed.hosts.has(host)))) listings.get(url)!.push({ source: "OpenPhish", threat: "phishing" });
    }
    for (const [url, threat] of matches ?? []) listings.get(stripQuery(url))?.push({ source: "Google Safe Browsing", threat });
    if (env.ABUSECH_KEY) {
      await Promise.all(
        request.urls.map(async (url) => {
          const threat = await attempt("URLhaus", 1, () => cached(`urlhaus:${url}`, 3_600, () => urlhaus(url, env.ABUSECH_KEY!)));
          if (threat) listings.get(url)!.push({ source: "URLhaus", threat });
        }),
      );
    }
  })();

  const [domains, , hashes, keys, spfResult] = await Promise.all([domainsTask, urlsTask, hashesTask, keysTask, spfTask]);
  return {
    domains,
    urls: [...listings].map(([url, found]) => ({ url, listings: found })),
    hashes,
    // A key that couldn't be looked up is left out, so it isn't mistaken for one that doesn't exist.
    dkim: keys.filter((k) => k !== null),
    ...(spf && spfResult ? { spf: { ...spf, result: spfResult } } : {}),
    // Sorted, so the report lists services the same way whichever answered first.
    sources: [...sources].sort(),
    unavailable: [...unavailable].filter((s) => !sources.has(s)).sort(),
  };
}
