/**
 * Forward-to-check: someone forwards a suspicious email to check@abdullah1.dev and gets the
 * verdict back by email. Cloudflare Email Routing delivers the message here.
 *
 * Nothing is stored: the message is read, analysed and answered in memory. Cloudflare only lets
 * a Worker reply to a sender whose message passed DMARC, so the address can't be used to send
 * mail to someone whose address a spammer forged.
 */
import { analyzeEmail, analyzeParsed, applyIntel, intelRequest, parseEmail, type Analysis } from "@phish-check/engine";
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
async function original(raw: Uint8Array): Promise<Analysis | null> {
  const parsed = await parseEmail(raw);
  const file = parsed.embeddedMessages.length ? undefined : parsed.attachments.find((a) => EMAIL_FILE.test(a.filename ?? ""));
  if (file) return analyzeEmail(file.content);
  const analysis = await analyzeParsed(parsed);
  return analysis.forwarded ? analysis : null;
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

  let analysis: Analysis | null;
  try {
    analysis = await original(raw);
  } catch {
    return reply(noticeReply("unreadable", subject));
  }
  if (!analysis) return reply(noticeReply("not-a-forward", subject));

  try {
    const request = intelRequest(analysis);
    if (request.domains.length || request.urls.length || request.hashes.length) analysis = applyIntel(analysis, await lookup(request, env));
  } catch {
    // The verdict stands without online checks.
  }
  return reply(verdictReply(analysis, subject));
}
