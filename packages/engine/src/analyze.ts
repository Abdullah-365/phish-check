import { attachmentChecks, readerAttachments } from "./attachments.ts";
import { buildChecks, claimedDkimDomains, claimedSpf, DISTRUSTED_AUTH, failedChecks, forgedAuthFinding, readAuth, unbackedClaims } from "./auth.ts";
import { BRANDS, brandsMentionedIn } from "./brands.ts";
import {
  brandClaimFinding,
  formFindings,
  linkFindings,
  readableDestination,
  replyCheck,
  senderFindings,
  trackerFindings,
  type CheckContext,
} from "./checks.ts";
import { extractContent, images, links, plainText } from "./content.ts";
import { dkimSignatures, verifySignatures, type DkimKey, type DkimResult } from "./dkim.ts";
import { latinize } from "./domains.ts";
import { evasionFindings } from "./evasion.ts";
import { indicators, keyHeaders } from "./evidence.ts";
import { quotedOriginal, trustedForward } from "./forward.ts";
import { parseEmail, type RawEmail } from "./parse.ts";
import { providerFindings } from "./provider.ts";
import { parseRoute } from "./route.ts";
import type { Analysis, AuthSummary, Finding, ParsedEmail, Severity } from "./types.ts";
import { inspectUrl } from "./urls.ts";
import { authFindings, detectProvider, headline, nextSteps, score } from "./verdict.ts";
import { markWording, subjectGroups, wordingFindings } from "./wording.ts";

const UNKNOWN_AUTH: AuthSummary = { spf: "unknown", dkim: "unknown", dmarc: "unknown", recordedBy: null, verified: false };
const ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };
const LIST_HEADERS = new Set(["list-id", "list-post", "mailing-list", "x-mailing-list"]);
/** Wording findings that make a brand named in the subject look like impersonation rather than news. */
const LURES = new Set(["credentials", "pressure", "prize", "delivery", "fines", "storage", "invoice", "document", "crypto", "money", "callback", "sextortion", "advance-fee", "job"]);

/** The timestamp on the newest Received header, written by the reader's own provider. */
function deliveredAt(received: string[]): string | null {
  const date = parseRoute(received.slice(0, 1))[0]?.date;
  const when = date ? new Date(date) : null;
  return when && !Number.isNaN(when.getTime()) ? when.toISOString() : null;
}

export async function analyzeEmail(raw: RawEmail): Promise<Analysis> {
  return analyzeParsed(await parseEmail(raw));
}

/**
 * Checks the DKIM signatures of the message analyzeParsed judged, against keys the Worker looked
 * up for intelRequest's `dkim`. A .msg rebuilt from Outlook's properties can't match any signature.
 */
export async function verifyDkim(outer: ParsedEmail, keys: DkimKey[]): Promise<DkimResult[]> {
  const email = outer.embeddedMessages[0] ?? outer;
  return email.rebuilt ? [] : verifySignatures(email.raw, keys);
}

export async function analyzeParsed(outer: ParsedEmail): Promise<Analysis> {
  // "Forward as attachment" keeps the original intact: judge that, not the forward.
  const embedded = outer.embeddedMessages[0];
  const email = embedded ?? outer;
  const content = extractContent(email.html, email.text);
  for (const link of links(content)) {
    const destination = readableDestination(link.href);
    if (destination) link.destination = destination;
  }
  const bodyText = plainText(content);

  // The signatures behind the authentication results being read, so online checks can verify
  // them. A rebuilt .msg can't match any signature. A claimed DKIM pass from a domain that signed
  // nothing here means the header itself was written by the sender, so none of it counts.
  const dkim = email.rebuilt ? null : { signatures: dkimSignatures(email.raw), claimed: claimedDkimDomains(email.authenticationResults[0]) };
  const unbacked = dkim ? unbackedClaims(dkim.claimed, dkim.signatures) : [];
  const outerAuth = unbacked.length ? DISTRUSTED_AUTH : readAuth(email);
  // Its SPF claim needs no message bytes to test, so even a rebuilt .msg keeps it.
  const spfClaim = unbacked.length ? null : claimedSpf(email.authenticationResults[0]);

  // A plain "Forward" loses the original headers; only the quoted From line survives.
  // The raw text keeps the quoted header lines intact, so prefer it over the reading view.
  const quoted = embedded || !trustedForward(email.subject, outerAuth) ? null : quotedOriginal(email.text || bodyText);
  const partial = quoted !== null;
  const forwarded = embedded
    ? { mode: "attachment" as const, by: outer.from?.address ?? "" }
    : quoted
      ? { mode: "inline" as const, by: email.from?.address ?? "" }
      : null;

  const sender = quoted?.sender ?? email.from;
  const subject = quoted?.subject ?? email.subject;
  const auth = partial ? UNKNOWN_AUTH : outerAuth;
  const route = partial ? [] : parseRoute(email.received);
  const recipient = email.to[0]?.address ?? email.headers.find((h) => h.name === "delivered-to")?.value.trim() ?? null;
  const linkTexts = links(content).map((l) => l.text);
  // Look-alike letters are swapped back first, so "Ꮮеdgеr" is still recognised as Ledger.
  const brands = brandsMentionedIn(latinize([sender?.name ?? "", subject, bodyText, ...linkTexts].join("\n")));
  const displayName = latinize(sender?.name.trim() ?? "");
  const claimed = (displayName && BRANDS.find((b) => b.mentions.some((re) => re.test(displayName)))) || null;

  const ctx: CheckContext = {
    sender,
    replyTo: partial ? null : (email.replyTo[0] ?? null),
    recipient,
    content,
    brands,
    claimed,
    mailingList: email.headers.some((h) => LIST_HEADERS.has(h.name)),
  };

  // The first lines and the first images' alt text are where an email shows whose logo it wears.
  const heading = [
    ...content.blocks.slice(0, 2).map((b) => b.inlines.map((i) => ("text" in i ? i.text : "")).join(" ")),
    ...images(content).slice(0, 3).map((i) => i.alt),
  ].join("\n");
  const linkHosts = links(content).flatMap((l) => inspectUrl(l.href)?.host ?? []);

  const reply = replyCheck(ctx);
  const tracker = trackerFindings(content);
  const files = readerAttachments(email.attachments);
  const attachments = await attachmentChecks(files, bodyText);
  const wording = wordingFindings(markWording(content), subjectGroups(subject));
  const lured = wording.some((f) => LURES.has(f.rule));
  const brandClaim = brandClaimFinding(ctx, subject, heading, linkHosts, lured);
  const arcPassed = /\barc=pass\b/i.test(email.authenticationResults[0] ?? "");
  const headerText = email.headers
    .filter((h) => h.name === "from" || h.name === "to" || h.name === "subject")
    .map((h) => h.value)
    .join("\n");

  const findings: Finding[] = [
    // The provider judged the email as it arrived, forward or not, so its verdict always counts.
    ...providerFindings(email),
    ...senderFindings(ctx),
    ...(brandClaim ? [brandClaim] : []),
    ...(partial ? [] : authFindings(auth, arcPassed)),
    ...(unbacked.length ? [forgedAuthFinding(`claims dkim=pass for ${unbacked.join(", ")} · no signature from it`, true)] : []),
    ...(reply.finding ? [reply.finding] : []),
    ...linkFindings(ctx),
    ...formFindings(content),
    ...attachments.findings,
    ...wording,
    ...evasionFindings({
      content,
      subject,
      senderName: sender?.name ?? "",
      recipient,
      headerText,
      recipients: partial ? [] : [...email.to, ...email.headers.filter((h) => h.name === "cc").flatMap((h) => h.value.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g) ?? [])]
        .map((r) => (typeof r === "string" ? r : r.address))
        .filter(Boolean),
      mailingList: ctx.mailingList,
    }),
    ...(tracker.finding ? [tracker.finding] : []),
  ].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);

  const result = score(findings);
  const words = headline(result.verdict, findings);
  const mailProvider = detectProvider(email);
  const from = sender ? { name: sender.name, address: sender.address } : null;

  return {
    verdict: result.verdict,
    score: result.score,
    headline: words.headline,
    summary: words.summary,
    findings,
    checks: buildChecks(auth, reply, partial),
    auth,
    stats: {
      tricks: findings.filter((f) => f.severity !== "info").length,
      failedChecks: failedChecks(auth),
      trackers: tracker.count,
    },
    sender: from,
    subject,
    date: email.date,
    receivedAt: deliveredAt(email.received),
    recipient,
    content,
    attachments: attachments.summaries,
    route,
    indicators: result.verdict === "no-red-flags" ? [] : indicators({ findings, content, sender: from, route, attachments: attachments.summaries }),
    keyHeaders: partial ? [] : keyHeaders(email, findings, route),
    nextSteps: nextSteps(result.verdict, findings, mailProvider),
    forwarded,
    partial,
    mailProvider,
    intel: null,
    dkim,
    spfClaim,
  };
}
