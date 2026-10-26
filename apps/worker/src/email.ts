/**
 * Forward-to-check: someone forwards a suspicious email to check@abdullah1.dev and gets the
 * verdict back by email. Cloudflare Email Routing delivers the message here.
 *
 * Nothing is stored: the message is read, analysed and answered in memory. Cloudflare only lets
 * a Worker reply to a sender whose message passed DMARC, so the address can't be used to send
 * mail to someone whose address a spammer forged.
 */
import { analyzeParsed, applyIntel, intelRequest, parseEmail, verifyDkim, type Analysis, type ParsedEmail } from "@phish-check/engine";
import { readCapped } from "./body.ts";
import { lookup, type IntelEnv } from "./intel.ts";
import { noticeReply, verdictReply, type ReplyContent } from "./reply.ts";

/** Forwards bigger than this aren't read: real emails are far smaller. */
export const MAX_FORWARD = 5 * 1024 * 1024;
/** Replies one sender can get an hour, and that one isolate sends a minute: plenty for people, too few for abuse. */
const PER_SENDER_HOUR = 10;
const PER_MINUTE = 30;
const MAX_SENDERS = 10_000;

const senders = new Map<string, { count: number; resetAt: number }>();
let minute = { count: 0, resetAt: 0 };

/**
 * Why a message gets no reply at all, or null when it should get one. Answering bounces,
 * auto-replies or mailing lists would start mail loops or spam a list.
 */
export function skipReason(message: ForwardableEmailMessage): string | null {
  const from = message.from.toLowerCase();
  if (!from.includes("@")) return "no sender address";
  if (from === message.to.toLowerCase()) return "our own address";
  const auto = message.headers.get("auto-submitted");
  if (auto && auto.trim().toLowerCase() !== "no") return "automatic message";
  if (/^\s*(bulk|list|junk)\s*$/i.test(message.headers.get("precedence") ?? "")) return "bulk mail";
  if (message.headers.has("list-id")) return "mailing list";
  if (/^(mailer-daemon|postmaster|no-?reply|bounces?)([+@.-]|$)/.test(from)) return "bounce or no-reply sender";
  return null;
}

/** Counts a reply against the sender's hourly budget and this isolate's per-minute one. */
function allowed(sender: string, now = Date.now()): boolean {
  if (minute.resetAt < now) minute = { count: 0, resetAt: now + 60_000 };
  if (++minute.count > PER_MINUTE) return false;
  const entry = senders.get(sender);
  if (!entry || entry.resetAt < now) {
    senders.delete(sender);
    senders.set(sender, { count: 1, resetAt: now + 3_600_000 });
    if (senders.size > MAX_SENDERS) {
      for (const [key, value] of senders) if (value.resetAt < now || senders.size > MAX_SENDERS * 0.9) senders.delete(key);
    }
    return true;
  }
  return ++entry.count <= PER_SENDER_HOUR;
}

/** An email saved as a file and attached, rather than forwarded as an attachment. */
const EMAIL_FILE = /\.(eml|msg)$/i;

/**
 * What to check in the forward: the original inside a "forward as attachment", an attached
 * .eml or .msg file, or the quoted original of a plain forward. Null when there's no original.
 */
async function original(raw: Uint8Array): Promise<{ analysis: Analysis; email: ParsedEmail } | { seen: string }> {
  const parsed = await parseEmail(raw);
  const file = parsed.embeddedMessages.length ? undefined : parsed.attachments.find((a) => EMAIL_FILE.test(a.filename ?? ""));
  const email = file ? await parseEmail(file.content) : parsed;
  const analysis = await analyzeParsed(email);
  return file || analysis.forwarded ? { analysis, email } : { seen: contents(parsed) };
}

/** What a message carried, in a sentence, for when none of it is a forwarded email. */
function contents(parsed: ParsedEmail): string {
  const files = parsed.attachments.map((a) => `${a.filename || "an unnamed file"} (${a.declaredType}, ${Math.max(1, Math.round(a.size / 1024))} KB)`);
  if (!files.length) return "Your message had no attachments.";
  return `Your message had ${files.length === 1 ? "one attachment" : `${files.length} attachments`}, ${files.join(", ")}, but ${files.length === 1 ? "it isn't" : "none of them is"} an email.`;
}

export async function handleEmail(message: ForwardableEmailMessage, env: IntelEnv): Promise<void> {
  if (skipReason(message) || !allowed(message.from.toLowerCase())) return;
  const subject = message.headers.get("subject") ?? "";

  const reply = async (content: ReplyContent) => {
    const base = { from: message.to, subject: content.subject, text: content.text, html: content.html };
    try {
      // Marked as an automatic reply (RFC 3834), so other auto-responders don't answer it back.
      await message.reply({ ...base, headers: { "Auto-Submitted": "auto-replied" } });
    } catch {
      try {
        await message.reply(base);
      } catch {
        // Cloudflare refuses replies to senders that failed DMARC; there's no one to tell.
      }
    }
  };

  if (message.rawSize > MAX_FORWARD) return reply(noticeReply("too-large", subject));
  const raw = await readCapped(message.raw, MAX_FORWARD);
  if (!raw) return reply(noticeReply("too-large", subject));

  let found: Awaited<ReturnType<typeof original>>;
  try {
    found = await original(raw);
  } catch {
    return reply(noticeReply("unreadable", subject));
  }
  if ("seen" in found) {
    // TEMPORARY: the MIME skeleton of what arrived, for diagnosing the first live forwarding test. Remove once it passes.
    const lines = new TextDecoder().decode(raw).split(/\r?\n/);
    const skeleton = lines.filter((line, i) => /^--|^content-|^mime-/i.test(line) || (/^[ \t]/.test(line) && /^content-/i.test(lines[i - 1] ?? "")));
    return reply(noticeReply("not-a-forward", subject, `${found.seen}\n\n[debug] ${raw.length} bytes, ${lines.length} lines. Skeleton:\n${skeleton.join("\n").slice(0, 3000)}`));
  }

  let { analysis } = found;
  try {
    const request = intelRequest(analysis);
    if (request.domains.length || request.urls.length || request.hashes.length || request.dkim?.length || request.spf) {
      const response = await lookup(request, env);
      analysis = applyIntel(analysis, response, undefined, await verifyDkim(found.email, response.dkim ?? []));
    }
  } catch {
    // The verdict stands without online checks.
  }
  return reply(verdictReply(analysis, subject));
}
