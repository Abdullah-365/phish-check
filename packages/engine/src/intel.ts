/**
 * Online verification. The engine decides what to look up and how to read the answers;
 * the Worker does the lookups. Only domains, link addresses without their query strings,
 * file fingerprints and DKIM key names are ever sent: never the email itself.
 */
import { authChecks, failedChecks, forgedAuthFinding } from "./auth.ts";
import { BRANDS, FREE_MAIL } from "./brands.ts";
import { links } from "./content.ts";
import type { DkimKey, DkimResult, DkimSignatureInfo } from "./dkim.ts";
import { addressDomain, belongsTo, registrable } from "./domains.ts";
import { indicators } from "./evidence.ts";
import type { Analysis, AuthResult, AuthSummary, Finding, Severity } from "./types.ts";
import { inspectUrl, type UrlInfo } from "./urls.ts";
import { headline, nextSteps, score } from "./verdict.ts";

export interface IntelRequest {
  /** Registrable domains: the sender's, the Reply-To's and every link destination's. */
  domains: string[];
  /** Link destinations with query strings and fragments removed. */
  urls: string[];
  /** SHA-256 fingerprints of attachments. */
  hashes: string[];
  /** DKIM signatures whose public keys to fetch from DNS. Older clients don't send it. */
  dkim?: DkimSignatureInfo[];
}

export interface DomainIntel {
  domain: string;
  /** ISO date the domain was registered, from RDAP. */
  registered: string | null;
  registrar: string | null;
  /** False when DNS says the domain doesn't exist (NXDOMAIN). */
  exists: boolean | null;
  /** Whether the domain can receive mail (has MX or A records). */
  mailbox: boolean | null;
}

export interface Listing {
  /** Who listed it, e.g. "OpenPhish" or "URLhaus". */
  source: string;
  threat: string;
}

export interface IntelResponse {
  domains: DomainIntel[];
  urls: { url: string; listings: Listing[] }[];
  hashes: { sha256: string; listings: Listing[] }[];
  /** Services that answered. */
  sources: string[];
  /** Services that were configured but failed or timed out. */
  unavailable: string[];
  /** The DNS records of those DKIM keys. Older Workers don't send it. */
  dkim?: DkimKey[];
}

export const INTEL_LIMITS = { domains: 10, urls: 20, hashes: 10, dkim: 3 };

/** Big brands and mailbox providers aren't worth a lookup: their age and reputation are known. */
function worthLooking(domain: string): boolean {
  return !FREE_MAIL.has(domain) && !BRANDS.some((b) => belongsTo(domain, b));
}

/** File-sharing, code and social platforms, where every user's pages live under the same host. */
const SHARING = new Set([
  "sharepoint.com", "1drv.ms", "live.com", "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "box.com",
  "mega.nz", "mediafire.com", "we.tl", "sendspace.com", "4shared.com", "canva.com", "figma.com", "padlet.com",
  "notion.so", "airtable.com", "linkedin.com", "facebook.com", "instagram.com", "t.me", "medium.com", "zoom.us",
]);

/**
 * Whether a link's host is shared by countless unrelated people: big brands, mailbox providers,
 * file-sharing sites, free hosting and shorteners. One bad page there says nothing about the
 * rest of the host, and the host's age says nothing about the page.
 */
export function sharedHost(info: UrlInfo): boolean {
  return (
    info.tags.has("disposable") ||
    info.tags.has("shortener") ||
    SHARING.has(info.owner) ||
    FREE_MAIL.has(info.owner) ||
    BRANDS.some((b) => belongsTo(info.host, b))
  );
}

export function stripQuery(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return url.split(/[?#]/)[0] ?? url;
  }
}

/**
 * The address a link is looked up by. Phishing links often carry the reader's own email address
 * in the path, plainly or in base64; then only the site is sent, never the address.
 */
function lookupUrl(info: UrlInfo, recipient: string | null): string {
  const url = stripQuery(info.url.href);
  if (!recipient) return url;
  const address = recipient.toLowerCase();
  const forms = [address, encodeURIComponent(address)];
  try {
    const base64 = btoa(address).replace(/=+$/, "");
    forms.push(base64, base64.replace(/\+/g, "-").replace(/\//g, "_"));
  } catch {
    // Addresses with non-Latin letters have no btoa form; the plain forms still apply.
  }
  const lower = url.toLowerCase();
  return forms.some((form) => lower.includes(form.toLowerCase())) ? `${info.url.protocol}//${info.url.host}/` : url;
}

const senderDomain = (analysis: Analysis) => (analysis.sender?.address ? registrable(addressDomain(analysis.sender.address)) : null);

/**
 * The signatures whose keys are worth fetching: those from the sender's own domain, which can
 * prove who sent it, and those the Authentication-Results header vouches for, which can show the
 * header is lying. For a plain forward they're the forward's own, so they say nothing.
 */
function signaturesToCheck(analysis: Analysis): DkimSignatureInfo[] {
  if (!analysis.dkim || analysis.partial) return [];
  const sender = senderDomain(analysis);
  const claimed = new Set(analysis.dkim.claimed.map(registrable));
  const rank = (s: DkimSignatureInfo) => (registrable(s.domain) === sender ? 0 : claimed.has(registrable(s.domain)) ? 1 : 2);
  const seen = new Set<string>();
  return analysis.dkim.signatures
    .filter((s) => rank(s) < 2 && !seen.has(`${s.selector}._domainkey.${s.domain}`) && seen.add(`${s.selector}._domainkey.${s.domain}`))
    .sort((a, b) => rank(a) - rank(b))
    .slice(0, INTEL_LIMITS.dkim);
}

/** What to ask the Worker about, for one analysis. */
export function intelRequest(analysis: Analysis): IntelRequest {
  const domains = new Set<string>();
  const urls = new Set<string>();
  const sender = senderDomain(analysis);
  if (sender && sender.includes(".")) domains.add(sender);
  // Links inside attachments count too: a PDF with one link is a favourite way past link scanners.
  const hrefs = [...links(analysis.content).map((l) => l.href), ...analysis.attachments.flatMap((a) => a.links)];
  for (const href of hrefs) {
    const info = inspectUrl(href);
    if (!info) continue;
    // A shared platform is as old as the platform, not the page on it: only its URL is worth checking.
    if (!sharedHost(info)) domains.add(info.owner);
    urls.add(lookupUrl(info, analysis.recipient));
  }
  return {
    domains: [...domains].filter(worthLooking).slice(0, INTEL_LIMITS.domains),
    urls: [...urls].slice(0, INTEL_LIMITS.urls),
    hashes: analysis.attachments.map((a) => a.sha256).slice(0, INTEL_LIMITS.hashes),
    dkim: signaturesToCheck(analysis),
  };
}

const DAY = 24 * 60 * 60 * 1000;
/** Domains change their keys from time to time, so a signature only says something about a recent email. */
const KEYS_HOLD_DAYS = 30;

interface SignatureEvidence {
  auth: AuthSummary;
  /** Authentication findings the evidence overrides. */
  drop: Set<string>;
  finding: Finding | null;
}

/**
 * What the email's DKIM signatures, verified here, say about its Authentication-Results header.
 * A verified signature from the sender's own domain proves who sent it, whatever any header says.
 * A pass the header vouches for whose signature doesn't verify, or whose key doesn't exist, means
 * the email was changed after it arrived or the header was written by the sender.
 */
function signatureEvidence(analysis: Analysis, results: DkimResult[], now: Date): SignatureEvidence {
  const unchanged: SignatureEvidence = { auth: analysis.auth, drop: new Set(), finding: null };
  if (!analysis.dkim || analysis.partial || !results.length) return unchanged;
  const sender = senderDomain(analysis);
  if (sender && results.some((r) => r.result === "pass" && registrable(r.domain) === sender)) {
    return { auth: { ...analysis.auth, dkim: "pass", verified: true }, drop: new Set(["auth-none"]), finding: null };
  }

  const received = analysis.receivedAt ? Date.parse(analysis.receivedAt) : NaN;
  const recent = now.getTime() - received <= KEYS_HOLD_DAYS * DAY;
  // A claim with no signature behind it at all was already caught offline, which is proof enough.
  if (!recent || analysis.findings.some((f) => f.rule === "auth-forged")) return unchanged;
  for (const claim of new Set(analysis.dkim.claimed.map(registrable))) {
    const own = results.filter((r) => registrable(r.domain) === claim);
    // Any genuine signature from the domain backs the claim, even one whose body changed since.
    if (!own.length || !own.every((r) => r.result === "fail" || r.result === "no-key")) continue;
    const first = own[0]!;
    const demote = (result: AuthResult): AuthResult => (result === "pass" ? "unknown" : result);
    return {
      // The header's passes can't be believed now; any failures it records still stand.
      auth: { ...analysis.auth, spf: demote(analysis.auth.spf), dkim: "fail", dmarc: demote(analysis.auth.dmarc), verified: false },
      drop: new Set(),
      finding: forgedAuthFinding(
        `claims dkim=pass for ${first.domain} · ${first.result === "no-key" ? `it publishes no key "${first.selector}"` : "the signature doesn't verify"}`,
        false,
      ),
    };
  }
  return unchanged;
}

function age(registered: string | null, reference: Date): number | null {
  if (!registered) return null;
  const when = new Date(registered).getTime();
  if (Number.isNaN(when)) return null;
  const days = (reference.getTime() - when) / DAY;
  // Registered after the email was sent: the domain changed hands since, so its age says nothing.
  return days < 0 ? null : days;
}

function describeAge(days: number): string {
  if (days < 1) return "less than a day";
  if (days < 2) return "1 day";
  if (days < 60) return `${Math.floor(days)} days`;
  return `${Math.floor(days / 30)} months`;
}

const ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };
const AUTH_CHECKS = new Set(["dmarc", "spf", "dkim"]);

/**
 * Folds lookup results into an analysis and re-scores it. `dkim` is what verifyDkim found
 * using the keys in `intel.dkim`.
 */
export function applyIntel(analysis: Analysis, intel: IntelResponse, now = new Date(), dkim: DkimResult[] = []): Analysis {
  const evidence = signatureEvidence(analysis, dkim, now);
  // Ages are measured to when the reader's provider received the email. The Date header won't do:
  // a sender could backdate it to make a days-old domain look registered "after" the email.
  const reference = analysis.receivedAt ? new Date(analysis.receivedAt) : now;
  const sender = senderDomain(analysis);
  const fromTarget = { kind: "header", field: "from" } as const;
  const findings: Finding[] = [];

  for (const d of intel.domains) {
    const days = age(d.registered, reference);
    const isSender = d.domain === sender;
    if (days !== null && days < 90) {
      const fresh = days < 30;
      const where = isSender ? null : locate(analysis, d.domain);
      findings.push({
        id: `intel-new-domain-${d.domain}`,
        rule: isSender ? "intel-new-sender-domain" : "intel-new-link-domain",
        category: "intel",
        severity: fresh ? "high" : "medium",
        title: isSender ? "The sender's domain is brand new" : `A link${where?.file ? ` inside ${where.file}` : ""} goes to a brand-new website`,
        real: { text: `${d.domain} · registered ${describeAge(days)} before this email` },
        explanation: `${d.domain} was registered only ${describeAge(days)} before this email was sent${d.registrar ? `, through ${d.registrar}` : ""}. Real organisations use domains for years; scammers register fresh ones and drop them within days.`,
        lensLabel: isSender ? "Real sender" : "Real destination",
        target: where ? where.target : fromTarget,
        ...(where?.file ? { url: where.href } : {}),
      });
    }
    if (isSender && d.exists === false) {
      findings.push({
        id: "intel-dead-sender-domain",
        rule: "intel-dead-sender-domain",
        category: "intel",
        severity: "medium",
        title: "The sender's domain doesn't exist",
        real: { text: `${d.domain} · not found in DNS` },
        explanation: `Nobody runs ${d.domain} right now, so either the address was made up or the domain was shut down for abuse.`,
        lensLabel: "Real sender",
        target: fromTarget,
      });
    } else if (isSender && d.exists && d.mailbox === false) {
      findings.push({
        id: "intel-no-mailbox",
        rule: "intel-no-mailbox",
        category: "intel",
        severity: "low",
        title: "The sender's domain can't receive replies",
        real: { text: `${d.domain} · no mail server` },
        explanation: `${d.domain} has no mail server, so nobody can write back to it. Senders who want replies never set up a domain like this.`,
        lensLabel: "Real sender",
        target: fromTarget,
      });
    }
  }

  for (const u of intel.urls) {
    const listing = u.listings[0];
    if (!listing) continue;
    const where = locate(analysis, u.url);
    // OpenPhish and Safe Browsing's social-engineering list hold fake pages; URLhaus and Safe
    // Browsing's other lists hold links that hand out malware.
    const phishing = /phish/i.test(listing.threat);
    findings.push({
      id: `intel-blocklisted-${u.url}`,
      rule: "intel-blocklisted",
      category: "intel",
      severity: "high",
      title: `A link${where.file ? ` inside ${where.file}` : ""} is on a ${phishing ? "phishing" : "malware"} blocklist`,
      real: { text: `${u.url} · ${listing.source}: ${listing.threat}` },
      explanation: phishing
        ? `${listing.source} has already reported this address as a phishing page. Security teams found it on other victims first.`
        : `${listing.source} has already reported this address for spreading malware: opening it can download a harmful file. Security teams found it on other victims first.`,
      lensLabel: "Blocklisted",
      target: where.target,
      ...(where.file ? { url: where.href } : {}),
    });
  }

  for (const h of intel.hashes) {
    const listing = h.listings[0];
    if (!listing) continue;
    const file = analysis.attachments.find((a) => a.sha256 === h.sha256);
    findings.push({
      id: `intel-known-malware-${h.sha256}`,
      rule: "intel-known-malware",
      category: "intel",
      severity: "high",
      title: "The attachment is known malware",
      ...(file ? { seen: { text: file.filename } } : {}),
      real: { text: `${listing.source}: ${listing.threat}` },
      explanation: `This exact file is already in ${listing.source}'s malware records. Don't open it.`,
      lensLabel: "Attachment",
      target: file ? { kind: "node", id: file.id } : { kind: "header", field: "subject" },
    });
  }

  const all = [
    ...analysis.findings.filter((f) => f.category !== "intel" && !evidence.drop.has(f.rule)),
    ...findings,
    ...(evidence.finding ? [evidence.finding] : []),
  ].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  const result = score(all);
  const words = headline(result.verdict, all);
  return {
    ...analysis,
    findings: all,
    verdict: result.verdict,
    score: result.score,
    headline: words.headline,
    summary: words.summary,
    auth: evidence.auth,
    checks: [...authChecks(evidence.auth, analysis.partial), ...analysis.checks.filter((c) => !AUTH_CHECKS.has(c.id))],
    // Rebuilt so blocklisted links make the list, and so does an email the lookups turned bad.
    indicators: result.verdict === "no-red-flags" ? [] : indicators({ ...analysis, findings: all }),
    stats: { ...analysis.stats, tricks: all.filter((f) => f.severity !== "info").length, failedChecks: failedChecks(evidence.auth) },
    nextSteps: nextSteps(result.verdict, all, analysis.mailProvider),
    intel: { sources: intel.sources, unavailable: intel.unavailable },
  };
}

/**
 * Where a looked-up domain or URL appears, for placing its finding: the first link in the reading
 * view that points there, or else the attachment that contains it.
 */
function locate(analysis: Analysis, needle: string): { target: Finding["target"]; href?: string; file?: string } {
  const matches = (href: string) => {
    const info = inspectUrl(href);
    return !!info && (info.owner === needle || lookupUrl(info, analysis.recipient) === needle);
  };
  const link = links(analysis.content).find((l) => matches(l.href));
  if (link) return { target: { kind: "node", id: link.id } };
  for (const file of analysis.attachments) {
    const href = file.links.find(matches);
    if (href) return { target: { kind: "node", id: file.id }, href, file: file.filename };
  }
  return { target: { kind: "header", field: "subject" } };
}
