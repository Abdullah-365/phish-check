/** A single address with its display name ("" when the sender set none). */
export interface Mailbox {
  name: string;
  address: string;
}

export interface HeaderField {
  /** Lowercase header name. */
  name: string;
  /** Unfolded header value, otherwise as sent. */
  value: string;
}

export interface AttachmentInfo {
  filename: string | null;
  /** Lowercase MIME type as the sender declared it; not to be trusted on its own. */
  declaredType: string;
  disposition: string | null;
  size: number;
  content: Uint8Array;
}

/**
 * A parsed email, normalised so the checks never deal with parser quirks.
 * Header lists keep document order, which means the top entry is the most
 * recent hop: the one added by the recipient's own mail provider.
 */
export interface ParsedEmail {
  headers: HeaderField[];
  subject: string;
  messageId: string | null;
  date: string | null;
  from: Mailbox | null;
  sender: Mailbox | null;
  replyTo: Mailbox[];
  to: Mailbox[];
  returnPath: string | null;
  /** Received headers, top (newest) first. */
  received: string[];
  /** Authentication-Results headers, top (most trustworthy) first. */
  authenticationResults: string[];
  text: string;
  html: string;
  attachments: AttachmentInfo[];
  /**
   * Emails carried inside this one as message/rfc822 parts, which is what
   * "Forward as attachment" produces. The original sender's evidence lives here.
   */
  embeddedMessages: ParsedEmail[];
}

export type Verdict = "phishing" | "suspicious" | "no-red-flags";

// ---------------------------------------------------------------------------
// Reading view: a safe, style-free rendering model of the email body.
// Nothing in it ever loads remote content.

export type Inline =
  | { type: "text"; text: string }
  | { type: "break" }
  | {
      type: "link";
      id: string;
      href: string;
      text: string;
      button: boolean;
      /** Where it really leads, for display: redirects unwrapped, shortened without cutting off the owner. */
      destination?: string;
    }
  | { type: "image"; id: string; src: string; alt: string; tracker: boolean }
  /** A span of text a wording rule matched; the reading view highlights it underneath. */
  | { type: "phrase"; id: string; text: string; label: string };

export interface Block {
  id: string;
  kind: "p" | "heading" | "item" | "quote";
  inlines: Inline[];
}

export interface Content {
  blocks: Block[];
  /** True when the body was cut short to keep the reading view responsive. */
  truncated: boolean;
  /** Input fields asking for passwords, card numbers or similar, found in the email's HTML. */
  formFields: number;
  /** Characters of text styled so the reader can't see it. */
  hiddenText: number;
  /** Invisible characters found inside words; they're removed from the reading view. */
  zeroWidth: number;
  /** Letters from the maths block (𝐛𝐨𝐥𝐝, 𝑖𝑡𝑎𝑙𝑖𝑐), normalised to plain letters for the checks. */
  styledLetters: number;
  /** The first few words written in those letters, as they appeared. */
  styledWords: string[];
  /** Words mixing Latin letters with look-alikes from other alphabets, e.g. "Аmazon". */
  mixedScript: string[];
  /** Visible images, not counting tracking pixels. */
  images: number;
  /** Length of the visible text. */
  textLength: number;
}

// ---------------------------------------------------------------------------
// Analysis result

export type Severity = "high" | "medium" | "low" | "info";

/** Which detector produced a finding. Scoring caps each one, so one kind of evidence can't decide alone. */
export type Category = "provider" | "sender" | "link" | "attachment" | "wording" | "evasion" | "tracker" | "form" | "intel";

/** Text plus character ranges to highlight, for "you see / really" pairs. */
export interface Snippet {
  text: string;
  marks?: [start: number, end: number][];
}

/** Where a finding lives in the reading view. */
export type Target = { kind: "header"; field: "from" | "subject" } | { kind: "node"; id: string };

export interface Finding {
  /** Unique within one analysis. */
  id: string;
  /** Stable rule name, e.g. "link-mismatch". */
  rule: string;
  category: Category;
  severity: Severity;
  title: string;
  explanation: string;
  seen?: Snippet;
  real?: Snippet;
  /** Short caption for the X-ray lens, e.g. "Real destination". */
  lensLabel: string;
  target: Target;
  /** The organisation being imitated, when there is one. */
  brand?: string;
  /** The link this finding is about when it isn't in the email body, e.g. one inside an attachment. */
  url?: string;
}

export type AuthResult = "pass" | "fail" | "softfail" | "neutral" | "none" | "error" | "unknown";

export interface AuthSummary {
  spf: AuthResult;
  dkim: AuthResult;
  dmarc: AuthResult;
  /** The server that recorded the results, e.g. "mx.google.com". */
  recordedBy: string | null;
}

export interface Check {
  id: "dmarc" | "spf" | "dkim" | "reply-to";
  label: string;
  status: "pass" | "warn" | "fail" | "unknown";
  value: string;
  explanation: string;
}

export interface Hop {
  from: string | null;
  ip: string | null;
  by: string | null;
  protocol: string | null;
  tls: boolean | null;
  date: string | null;
}

export interface Indicator {
  type: "domain" | "url" | "ip" | "email" | "sha256";
  /** Defanged so it can't be clicked by accident. */
  value: string;
  note: string;
}

export interface KeyHeader {
  name: string;
  value: string;
  /** Substrings of `value` worth highlighting. */
  flags: string[];
}

export interface AttachmentSummary {
  id: string;
  filename: string;
  size: number;
  /** Plain description of what the file really is, e.g. "Macro-enabled Word document". */
  kind: string;
  risky: boolean;
  /** Fingerprint for reputation lookups; the file itself never leaves the device. */
  sha256: string;
  /** Web addresses found inside the file, such as the links in a PDF. */
  links: string[];
}

export interface NextStep {
  title: string;
  /** Plain text; `backticks` mark UI labels the reader should look for. */
  detail: string;
}

export interface Analysis {
  verdict: Verdict;
  score: number;
  headline: string;
  summary: string;
  findings: Finding[];
  checks: Check[];
  auth: AuthSummary;
  stats: { tricks: number; failedChecks: number; trackers: number };
  sender: { name: string; address: string } | null;
  subject: string;
  date: string | null;
  /**
   * When the reader's provider took delivery, from the newest Received header. Unlike `date`,
   * which is whatever the sender wrote, the sender can't set it.
   */
  receivedAt: string | null;
  recipient: string | null;
  content: Content;
  attachments: AttachmentSummary[];
  route: Hop[];
  indicators: Indicator[];
  keyHeaders: KeyHeader[];
  nextSteps: NextStep[];
  /** How the email reached us, when someone forwarded it. */
  forwarded: { mode: "attachment" | "inline"; by: string } | null;
  /** True when the original headers were lost, so sender checks were limited. */
  partial: boolean;
  /** The reader's mail provider, guessed from the delivery route; used for "how to report it". */
  mailProvider: "gmail" | "outlook" | "yahoo" | "apple" | null;
  /** Online lookups merged in by applyIntel, if any ran. */
  intel: { sources: string[]; unavailable: string[] } | null;
}
