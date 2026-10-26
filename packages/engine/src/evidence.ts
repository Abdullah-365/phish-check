import { links } from "./content.ts";
import { addressDomain, unicodeHost, urlHost } from "./domains.ts";
import { originHop } from "./route.ts";
import type { Analysis, Finding, Hop, Indicator, KeyHeader, ParsedEmail } from "./types.ts";

const defangHost = (host: string) => host.replace(/\./g, "[.]");

/** A URL that can't be clicked by accident, with the query removed: it often carries the recipient's address. */
function defangUrl(href: string): string {
  try {
    const url = new URL(href);
    return `${url.protocol.replace(/^http/, "hxxp")}//${defangHost(url.hostname)}${url.pathname === "/" ? "" : url.pathname}`;
  } catch {
    return href.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
  }
}

const defangAddress = (address: string) => {
  const at = address.lastIndexOf("@");
  return `${address.slice(0, at + 1)}${defangHost(address.slice(at + 1))}`;
};

/**
 * What an analyst would block or search for. Built from the analysis alone, so applyIntel can
 * rebuild it once online checks add findings.
 */
export function indicators(analysis: Pick<Analysis, "findings" | "content" | "sender" | "route" | "attachments">): Indicator[] {
  const out: Indicator[] = [];
  const add = (indicator: Indicator) => {
    if (!out.some((i) => i.value === indicator.value)) out.push(indicator);
  };
  const sender = analysis.sender?.address;

  // Only called for emails we judged bad, so the sender itself is worth recording.
  if (sender) {
    const brand = analysis.findings.find((f) => f.category === "sender" && f.brand)?.brand;
    add({ type: "domain", value: defangHost(unicodeHost(addressDomain(sender))), note: brand ? `Pretends to be ${brand}` : "Sending domain" });
    add({ type: "email", value: defangAddress(sender), note: "From address" });
  }
  // The Reply-To finding shows the address replies really go to.
  const replyTo = analysis.findings.find((f) => f.rule === "reply-elsewhere")?.real?.text;
  if (replyTo) add({ type: "email", value: defangAddress(replyTo), note: "Reply-To" });

  const byId = new Map(links(analysis.content).map((l) => [l.id, l]));
  for (const finding of analysis.findings) {
    // A link in the body is found through its node; one inside an attachment travels with the finding.
    const inBody = (finding.category === "link" || finding.category === "intel") && finding.target.kind === "node" ? byId.get(finding.target.id)?.href : undefined;
    const href = finding.url ?? inBody;
    if (!href) continue;
    const host = urlHost(href);
    const domainNote = finding.brand ? `Fake ${finding.brand} site` : finding.rule === "intel-new-link-domain" ? "Brand-new link domain" : "Link destination";
    if (host) add({ type: "domain", value: defangHost(unicodeHost(host)), note: domainNote });
    const what = finding.rule === "intel-blocklisted" ? "Blocklisted link" : finding.url ? "Link" : "Link target";
    add({ type: "url", value: defangUrl(href), note: `${what}${finding.url ? " in an attachment" : ""}, query removed` });
  }

  const tracker = analysis.findings.find((f) => f.rule === "tracker");
  if (tracker?.target.kind === "node") {
    const id = tracker.target.id;
    const image = analysis.content.blocks.flatMap((b) => b.inlines).find((i) => i.type === "image" && i.id === id);
    if (image?.type === "image") add({ type: "url", value: defangUrl(image.src.startsWith("//") ? `https:${image.src}` : image.src), note: "Open tracker" });
  }

  const origin = originHop(analysis.route);
  // The note is copied along with the value, so its hostname is defanged too.
  if (origin?.ip) add({ type: "ip", value: origin.ip.replace(/\.(\d+)$/, "[.]$1"), note: `Sending server${origin.from ? `, ${defangHost(origin.from)}` : ""}` });

  // Malware databases can know a file that looked harmless here.
  const knownMalware = new Set(analysis.findings.flatMap((f) => (f.rule === "intel-known-malware" && f.target.kind === "node" ? [f.target.id] : [])));
  for (const file of analysis.attachments) {
    if (file.risky || knownMalware.has(file.id)) add({ type: "sha256", value: file.sha256, note: file.filename });
  }
  return out;
}

const header = (email: ParsedEmail, name: string) => email.headers.find((h) => h.name === name)?.value ?? null;

/** The handful of headers an analyst would look at first, with the suspicious parts flagged. */
export function keyHeaders(email: ParsedEmail, findings: Finding[], route: Hop[]): KeyHeader[] {
  const out: KeyHeader[] = [];
  const rules = new Set(findings.map((f) => f.rule));
  const auth = email.authenticationResults[0];
  if (auth) {
    out.push({
      name: "Authentication-Results",
      // One result per line, the way analysts read them.
      value: auth.split(/;\s*/).filter(Boolean).join(";\n    "),
      flags: [...auth.matchAll(/\b(?:spf|dkim|dmarc)=(?:fail|softfail|none|permerror|temperror|neutral)\b/gi)].map((m) => m[0]),
    });
  }
  const origin = originHop(route);
  const received = origin?.from ? email.received.find((r) => r.includes(origin.from!)) : email.received.at(-1);
  if (received) out.push({ name: "Received", value: received, flags: findings.length && origin?.from ? [origin.from] : [] });

  const from = header(email, "from");
  const fromDomain = email.from ? addressDomain(email.from.address) : "";
  if (from) {
    out.push({ name: "From", value: from, flags: rules.has("sender-disguise") || rules.has("sender-lookalike") ? [fromDomain] : [] });
  }
  const replyTo = header(email, "reply-to");
  if (replyTo) {
    out.push({ name: "Reply-To", value: replyTo, flags: rules.has("reply-elsewhere") && email.replyTo[0] ? [addressDomain(email.replyTo[0].address)] : [] });
  }
  const returnPath = header(email, "return-path");
  if (returnPath) {
    const returnDomain = addressDomain(returnPath);
    out.push({ name: "Return-Path", value: returnPath, flags: returnDomain && fromDomain && returnDomain !== fromDomain && findings.length ? [returnDomain] : [] });
  }
  // Unfolded headers keep their original indentation; collapse it so lines read cleanly.
  return out.map((h) => ({
    ...h,
    value: h.value
      .split("\n")
      .map((line, i) => (i === 0 ? line : `    ${line.trim()}`).replace(/(\S)[ \t]{2,}/g, "$1 "))
      .join("\n"),
    flags: h.flags.filter(Boolean),
  }));
}
