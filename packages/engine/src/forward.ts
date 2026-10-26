import { addressParser } from "postal-mime";
import type { AuthSummary, Mailbox } from "./types.ts";

/** "Fwd:" and its translations, as mail apps prefix a forwarded subject. */
const FORWARD_SUBJECT = /^\s*(?:fwd?|wg|tr|rv|enc|i|vs|vb|doorst|vl|pd)\s*:/i;

/**
 * Whether the outer email can be someone's own forward: a forward subject, signed by the sender's
 * own domain with a signature the header says passed. Without this, a phish could paste a fake
 * "Forwarded message" block to have its real sender, authentication and spam verdicts ignored.
 * An SPF pass alone isn't enough: a forged header can claim one, while a forged signature from
 * the sender's domain is caught. Every major mail service signs what its users send.
 */
export function trustedForward(subject: string, auth: AuthSummary, signedBySender: boolean): boolean {
  return FORWARD_SUBJECT.test(subject) && signedBySender && auth.dkim === "pass" && auth.dmarc !== "fail";
}

const MARKERS = [
  /^-{2,}\s*Forwarded message\s*-{2,}\s*$/im, // Gmail
  /^-{2,}\s*Original Message\s*-{2,}\s*$/im, // Outlook, Thunderbird
  /^Begin forwarded message:\s*$/im, // Apple Mail
];

/** Outlook's quoted header block: From / Sent / To / Subject lines with no marker above. */
const OUTLOOK_BLOCK = /^From:[^\n]+\n(?:Sent|Date):[^\n]+\n(?:To:[^\n]+\n)?(?:Cc:[^\n]+\n)?Subject:/im;

export interface QuotedOriginal {
  sender: Mailbox;
  subject: string | null;
}

/**
 * Finds the original sender inside a plain "Forward", where the original headers
 * are gone and only the quoted From line survives.
 */
export function quotedOriginal(text: string): QuotedOriginal | null {
  const marker = MARKERS.map((re) => text.search(re)).filter((i) => i >= 0).sort((a, b) => a - b)[0];
  const block = marker ?? text.search(OUTLOOK_BLOCK);
  if (block < 0) return null;
  const quoted = text.slice(block, block + 1500);
  const fromLine = quoted.match(/^\s*From:\s*(.+)$/im)?.[1];
  if (!fromLine) return null;
  const parsed = addressParser(fromLine.replace(/\s+/g, " ").trim())[0];
  const address = parsed && !parsed.group ? parsed.address : (fromLine.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/)?.[0] ?? "");
  if (!address) return null;
  return {
    sender: { name: parsed?.name ?? "", address },
    subject: quoted.match(/^\s*Subject:\s*(.+)$/im)?.[1]?.trim() ?? null,
  };
}
