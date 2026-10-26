/**
 * The email that answers a forwarded check. Everything taken from the checked email is defanged,
 * because mail apps turn anything that looks like an address into a clickable link: the only real
 * link in a reply is the one to phish-check itself.
 */
import type { Analysis } from "@phish-check/engine";

export interface ReplyContent {
  subject: string;
  text: string;
  html: string;
}

const SITE = "https://phish.abdullah1.dev";
const MAX_FINDINGS = 8;

const VERDICT: Record<Analysis["verdict"], { name: string; color: string }> = {
  phishing: { name: "Likely phishing", color: "#c5221f" },
  suspicious: { name: "Suspicious", color: "#a15c00" },
  "no-red-flags": { name: "No red flags found", color: "#137333" },
};

/**
 * Makes addresses unclickable: "https://evil.example/x" becomes "hxxps://evil[.]example/x", and
 * "evil.example", "someone@evil.example", "invoice.zip" or "203.0.113.50" get "[.]" too.
 * Numbers like 1.99 stay as they are.
 */
export function defang(text: string): string {
  return text
    .replace(/\bhttp(s?):\/\//gi, "hxxp$1://")
    .replace(/\b[\w-]+(?:\.[\w-]+)*\.[a-z][a-z0-9-]*\b/gi, (token) => token.replace(/\./g, "[.]"))
    .replace(/\b(\d{1,3}(?:\.\d{1,3}){2})\.(\d{1,3})\b/g, "$1[.]$2");
}

const escapeHtml = (text: string) =>
  text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/** Text that can quote the checked email, made safe for the reply's plain-text part. */
const plain = (text: string) => defang(text).replace(/`([^`]+)`/g, '"$1"');

/** ...and for its HTML part, with `labels` in bold. */
const rich = (text: string) => escapeHtml(defang(text)).replace(/`([^`]+)`/g, "<b>$1</b>");

/**
 * The advice comes from phish-check alone and only names real sites (like "type paypal.com into
 * your browser"), so it stays readable instead of defanged.
 */
const advice = (text: string) => text.replace(/`([^`]+)`/g, '"$1"');
const richAdvice = (text: string) => escapeHtml(text).replace(/`([^`]+)`/g, "<b>$1</b>");

/*
 * Replies don't repeat the forward's subject. It's usually the phish's own lure ("Action required:
 * your account has been limited"), and in a live test Gmail hid a reply carrying one. Mail apps that
 * thread by In-Reply-To, which Cloudflare sets, still show the reply with the forward.
 */

const FOOTER_TEXT = `For the full X-ray report, save the email as a file and drop it on ${SITE}.\nphish-check read the email you forwarded to write this reply and kept none of it.`;
const FOOTER_HTML = `<p style="margin:24px 0 0;font-size:13px;line-height:1.5;color:#5f6368">For the full X-ray report, save the email as a file and drop it on <a href="${SITE}" style="color:#1a73e8">phish.abdullah1.dev</a>.<br>phish-check read the email you forwarded to write this reply and kept none of it.</p>`;

function wrap(body: string): string {
  return `<div style="font-family:system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif;max-width:600px;color:#202124;font-size:15px;line-height:1.5">${body}${FOOTER_HTML}</div>`;
}

export function verdictReply(analysis: Analysis): ReplyContent {
  const verdict = VERDICT[analysis.verdict];
  const findings = analysis.findings.filter((f) => f.severity !== "info").slice(0, MAX_FINDINGS);
  const more = analysis.findings.filter((f) => f.severity !== "info").length - findings.length;
  const partial = analysis.partial
    ? "This was forwarded as plain text, so the original's headers were lost and the sender couldn't be fully checked. For a full check, forward it as an attachment."
    : null;
  const online = analysis.intel?.sources.length ? `Checked online: ${analysis.intel.sources.join(", ")}.` : null;

  const text = [
    `phish-check verdict: ${verdict.name}`,
    "",
    plain(analysis.headline),
    plain(analysis.summary),
    ...(partial ? ["", partial] : []),
    "",
    ...(findings.length
      ? ["What we found", ...findings.flatMap((f, i) => [`${i + 1}. ${plain(f.title)}`, `   ${plain(f.explanation)}`]), ...(more > 0 ? [`...and ${more} more.`] : [])]
      : ["We looked for disguised senders, links that lie about where they go, risky attachments, and pressure or money requests in the wording. None turned up."]),
    "",
    "What to do now",
    ...analysis.nextSteps.map((s) => `- ${advice(s.title)} ${advice(s.detail)}`),
    ...(online ? ["", online] : []),
    "",
    FOOTER_TEXT,
  ].join("\n");

  const html = wrap(
    [
      `<p style="margin:0;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#5f6368">phish-check verdict</p>`,
      `<p style="margin:2px 0 12px;font-size:30px;font-weight:700;color:${verdict.color}">${verdict.name}</p>`,
      `<p style="margin:0 0 4px;font-size:17px;font-weight:600">${rich(analysis.headline)}</p>`,
      `<p style="margin:0">${rich(analysis.summary)}</p>`,
      partial ? `<p style="margin:12px 0 0;padding:10px 12px;background:#fef7e0;border-radius:6px">${escapeHtml(partial)}</p>` : "",
      `<p style="margin:20px 0 6px;font-weight:600">What we found</p>`,
      findings.length
        ? `<ol style="margin:0;padding-left:20px">${findings.map((f) => `<li style="margin:0 0 8px"><b>${rich(f.title)}</b><br>${rich(f.explanation)}</li>`).join("")}</ol>${more > 0 ? `<p style="margin:0">...and ${more} more.</p>` : ""}`
        : `<p style="margin:0">We looked for disguised senders, links that lie about where they go, risky attachments, and pressure or money requests in the wording. None turned up.</p>`,
      `<p style="margin:20px 0 6px;font-weight:600">What to do now</p>`,
      `<ul style="margin:0;padding-left:20px">${analysis.nextSteps.map((s) => `<li style="margin:0 0 6px"><b>${richAdvice(s.title)}</b> ${richAdvice(s.detail)}</li>`).join("")}</ul>`,
      online ? `<p style="margin:16px 0 0;font-size:13px;color:#5f6368">${escapeHtml(online)}</p>` : "",
    ].join(""),
  );
  return { subject: `phish-check verdict: ${verdict.name}`, text, html };
}

const NOTICES = {
  "not-a-forward": {
    subject: "phish-check: no forwarded email found",
    title: "We couldn't find a forwarded email in your message.",
    body: "Forward the suspicious email as an attachment: in Gmail, open it and choose More, then Forward as attachment; in Outlook, choose More actions, then Forward as attachment. Attaching it as an .eml or .msg file works too.",
  },
  unreadable: {
    subject: "phish-check: couldn't read your forward",
    title: "We couldn't read the email you forwarded.",
    body: "Try forwarding it as an attachment instead, or save it as a file and drop it on phish.abdullah1.dev.",
  },
  "too-large": {
    subject: "phish-check: that email is too large",
    title: "That email is too large to check by email.",
    body: "Forwards over 5 MB aren't read. Save the email as a file and drop it on phish.abdullah1.dev instead.",
  },
} as const;

export type Notice = keyof typeof NOTICES;

/** `seen` says what the message did carry, so the sender can tell why it wasn't recognised. */
export function noticeReply(notice: Notice, seen?: string): ReplyContent {
  const { subject, title, body } = NOTICES[notice];
  const detail = seen ? defang(seen) : null;
  return {
    subject,
    text: `${title}\n\n${detail ? `${detail}\n\n` : ""}${body}\n\n${FOOTER_TEXT}`,
    html: wrap(
      `<p style="margin:0 0 8px;font-size:17px;font-weight:600">${escapeHtml(title)}</p>${detail ? `<p style="margin:0 0 8px">${escapeHtml(detail)}</p>` : ""}<p style="margin:0">${escapeHtml(body)}</p>`,
    ),
  };
}
