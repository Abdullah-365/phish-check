import PostalMime from "postal-mime";
import type { Address, Email } from "postal-mime";
import type { AttachmentInfo, HeaderField, Mailbox, ParsedEmail } from "./types.ts";

export type RawEmail = string | ArrayBuffer | Uint8Array;

/** Bigger than any normal email; protects the browser tab and the Worker's memory. */
export const MAX_EMAIL_BYTES = 10 * 1024 * 1024;

/** Forwards of forwards are rare; anything deeper is not worth unwrapping. */
const MAX_EMBEDDED_DEPTH = 3;

export class EmailParseError extends Error {
  override name = "EmailParseError";
}

export async function parseEmail(raw: RawEmail): Promise<ParsedEmail> {
  if (byteLength(raw) > MAX_EMAIL_BYTES) {
    throw new EmailParseError(`Email is larger than ${MAX_EMAIL_BYTES / 1024 / 1024} MB`);
  }
  return parseAtDepth(raw, 0);
}

async function parseAtDepth(raw: RawEmail, depth: number): Promise<ParsedEmail> {
  let email: Email;
  try {
    email = await PostalMime.parse(raw, {
      // Keep forwarded originals as separate parts instead of merging them into the body.
      forceRfc822Attachments: true,
      attachmentEncoding: "arraybuffer",
      maxPartCount: 1000,
      maxHeadersSize: 512 * 1024,
    });
  } catch (err) {
    throw new EmailParseError("This doesn't look like a valid email", { cause: err });
  }

  if (email.headers.length === 0) {
    throw new EmailParseError("No email headers found. Paste the full original source, not just the body");
  }

  const headers: HeaderField[] = email.headers.map((h) => ({ name: h.key, value: h.value }));
  const attachments: AttachmentInfo[] = [];
  const embeddedMessages: ParsedEmail[] = [];

  for (const part of email.attachments) {
    const content = toBytes(part.content);
    if (part.mimeType === "message/rfc822" && depth < MAX_EMBEDDED_DEPTH) {
      try {
        embeddedMessages.push(await parseAtDepth(content, depth + 1));
        continue;
      } catch {
        // Unparseable inner message: keep it as an ordinary attachment.
      }
    }
    attachments.push({
      filename: part.filename,
      declaredType: part.mimeType,
      disposition: part.disposition,
      size: content.byteLength,
      content,
    });
  }

  return {
    headers,
    subject: email.subject ?? "",
    messageId: email.messageId ?? null,
    date: email.date ?? null,
    from: firstMailbox(email.from),
    sender: firstMailbox(email.sender),
    replyTo: mailboxes(email.replyTo),
    to: mailboxes(email.to),
    returnPath: email.returnPath ?? null,
    received: headerValues(headers, "received"),
    authenticationResults: headerValues(headers, "authentication-results"),
    text: email.text ?? "",
    html: email.html ?? "",
    attachments,
    embeddedMessages,
  };
}

function headerValues(headers: HeaderField[], name: string): string[] {
  return headers.filter((h) => h.name === name).map((h) => h.value);
}

function mailboxes(list: Address[] | undefined): Mailbox[] {
  return (list ?? []).flatMap((a) => (a.group ? a.group : [a])).map(({ name, address }) => ({ name, address }));
}

function firstMailbox(addr: Address | undefined): Mailbox | null {
  return addr ? (mailboxes([addr])[0] ?? null) : null;
}

function toBytes(content: ArrayBuffer | Uint8Array | string): Uint8Array {
  if (typeof content === "string") return new TextEncoder().encode(content);
  return content instanceof Uint8Array ? content : new Uint8Array(content);
}

function byteLength(raw: RawEmail): number {
  return typeof raw === "string" ? new TextEncoder().encode(raw).byteLength : raw.byteLength;
}
