import { registrable } from "./domains.ts";
import type { AuthResult, AuthSummary, Check, Finding, ParsedEmail, SpfClaim } from "./types.ts";

const RESULTS: Record<string, AuthResult> = {
  pass: "pass",
  fail: "fail",
  hardfail: "fail",
  policy: "fail",
  softfail: "softfail",
  neutral: "neutral",
  none: "none",
  // Microsoft's "no DMARC record, but it would have passed": not a real pass.
  bestguesspass: "none",
  temperror: "error",
  permerror: "error",
};

const toResult = (word: string | undefined): AuthResult => RESULTS[word?.toLowerCase() ?? ""] ?? "unknown";

/**
 * Reads the top Authentication-Results header, the one written by the
 * recipient's own provider. Lower ones may have been forged by the sender.
 */
export function readAuth(email: ParsedEmail): AuthSummary {
  const top = email.authenticationResults[0];
  const receivedSpf = email.headers.find((h) => h.name === "received-spf")?.value;
  if (!top) {
    return { spf: receivedSpf ? toResult(receivedSpf.trim().split(/[\s(;]/)[0]) : "unknown", dkim: "unknown", dmarc: "unknown", recordedBy: null, verified: false };
  }
  const results = (method: string) =>
    [...top.matchAll(new RegExp(`(?:^|[;\\s])${method}\\s*=\\s*([a-z]+)`, "gi"))].map((m) => toResult(m[1]));
  const spf = results("spf");
  const dkim = results("dkim");
  const dmarc = results("dmarc");
  return {
    spf: spf[0] ?? (receivedSpf ? toResult(receivedSpf.trim().split(/[\s(;]/)[0]) : "none"),
    // Several signatures can be present; one valid signature is enough.
    dkim: dkim.includes("pass") ? "pass" : (dkim[0] ?? "none"),
    dmarc: dmarc[0] ?? "none",
    recordedBy: top.split(";")[0]?.trim().split(/\s+/)[0] || null,
    verified: false,
  };
}

/** What's left once an email's own Authentication-Results header turns out to be fake. */
export const DISTRUSTED_AUTH: AuthSummary = { spf: "unknown", dkim: "unknown", dmarc: "unknown", recordedBy: null, verified: false };

/**
 * Claimed DKIM passes for domains that signed nothing in the email. A provider only records a
 * pass for a signature it found, so a claim with no signature behind it was written by the sender.
 */
export function unbackedClaims(claimed: string[], signatures: { domain: string }[]): string[] {
  const signed = new Set(signatures.map((s) => registrable(s.domain)));
  return claimed.filter((domain) => !signed.has(registrable(domain)));
}

/**
 * `proven`: the header claims a signature the email doesn't carry, which needs no key to see.
 * Otherwise the signature exists but doesn't verify against the domain's key, which is strong but
 * not proof: a mail system may have changed the email after it arrived.
 */
export function forgedAuthFinding(detail: string, proven: boolean): Finding {
  return {
    id: proven ? "auth-forged" : "auth-signature-fail",
    rule: proven ? "auth-forged" : "auth-signature-fail",
    category: proven ? "sender" : "intel",
    severity: proven ? "high" : "medium",
    title: proven ? "Its authentication results are faked" : "Its signature doesn't check out",
    real: { text: detail },
    explanation: proven
      ? "A header in the email claims it passed the checks that prove who sent it, but the email carries no signature to back that up. Only a sender trying to look legitimate fakes this."
      : "A header in the email says its signature passed, but phish-check checked the signature against the key the signing domain publishes, and it doesn't hold up. Either the email was changed after it arrived, or the sender wrote that header to look legitimate.",
    lensLabel: "Authentication",
    target: { kind: "header", field: "from" },
  };
}

/**
 * The signing domains an Authentication-Results header says passed DKIM, from its header.d
 * (or header.i) values. A forged header has to name them, and they can then be checked.
 */
export function claimedDkimDomains(results: string | undefined): string[] {
  const out = new Set<string>();
  for (const segment of (results ?? "").split(";")) {
    if (!/(?:^|\s)dkim\s*=\s*pass\b/i.test(segment)) continue;
    const domain = segment.match(/\bheader\.d\s*=\s*([^\s;()]+)/i)?.[1] ?? segment.match(/\bheader\.i\s*=\s*[^\s;@()]*@([^\s;()]+)/i)?.[1];
    if (domain) out.add(domain.toLowerCase());
  }
  return [...out];
}

/**
 * The SPF pass an Authentication-Results header claims: the domain it checked and the address of
 * the server it names. Gmail writes "designates <ip> as permitted sender", Microsoft "sender IP
 * is <ip>", others client-ip= or smtp.remote-ip=.
 */
export function claimedSpf(results: string | undefined): SpfClaim | null {
  const header = results ?? "";
  for (const segment of header.split(";")) {
    if (!/(?:^|\s)spf\s*=\s*pass\b/i.test(segment)) continue;
    const from = segment.match(/\bsmtp\.mailfrom\s*=\s*"?([^\s;()"]+)/i)?.[1] ?? segment.match(/\bsmtp\.helo\s*=\s*([^\s;()]+)/i)?.[1];
    const ip =
      segment.match(/\bdesignates\s+([0-9a-f.:]+)\s+as\s+permitted\s+sender/i)?.[1] ??
      segment.match(/\bsender\s+ip\s+is\s+([0-9a-f.:]+)/i)?.[1] ??
      header.match(/\b(?:smtp\.remote-ip|client-ip)\s*=\s*([0-9a-f.:]+)/i)?.[1];
    const domain = from?.split("@").pop()?.replace(/\.$/, "").toLowerCase();
    if (domain?.includes(".") && ip && IP_ADDRESS.test(ip)) return { domain, ip: ip.toLowerCase() };
  }
  return null;
}

/** Four IPv4 octets, or anything with colons (IPv6); the Worker checks it properly. */
const IP_ADDRESS = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:.]*)$/i;

/** A claimed SPF pass that the domain's own record doesn't support, for the server the claim names. */
export function spfMismatchFinding(detail: string): Finding {
  return {
    id: "auth-spf-mismatch",
    rule: "auth-spf-mismatch",
    category: "intel",
    severity: "medium",
    title: "Its SPF result doesn't check out",
    real: { text: detail },
    explanation:
      "A header in the email says it passed SPF, the check of which servers may send for a domain. phish-check asked that domain about the server the header itself names, and the domain doesn't allow it. Either the domain changed its list since, or the sender wrote that header to look legitimate.",
    lensLabel: "Authentication",
    target: { kind: "header", field: "from" },
  };
}

export function failedChecks(auth: AuthSummary): number {
  return [auth.spf, auth.dkim, auth.dmarc].filter((r) => r === "fail" || r === "softfail" || r === "none" || r === "error").length;
}

const VALUE: Record<AuthResult, string> = {
  pass: "Pass",
  fail: "Fail",
  softfail: "Softfail",
  neutral: "Neutral",
  none: "Missing",
  error: "Error",
  unknown: "Unknown",
};

const STATUS: Record<AuthResult, Check["status"]> = {
  pass: "pass",
  fail: "fail",
  softfail: "warn",
  neutral: "warn",
  none: "fail",
  error: "warn",
  unknown: "unknown",
};

const EXPLAIN = {
  dmarc: {
    pass: "The domain in the From address vouches for this email.",
    fail: "The domain in the From address doesn't vouch for this email.",
    none: "The sender's domain publishes no policy to check against.",
  },
  spf: {
    pass: "It came from a server the domain lists as its own.",
    fail: "It came from a server the domain says isn't allowed to send for it.",
    softfail: "It came from a server the domain doesn't list as its own.",
    neutral: "The domain doesn't say whether this server may send for it.",
    none: "The domain doesn't list which servers may send for it.",
  },
  dkim: {
    pass: "A signature proves it wasn't changed along the way.",
    fail: "Its signature doesn't match, so it may have been changed along the way.",
    none: "Nothing proves the message wasn't changed along the way.",
  },
} as const;

/** When phish-check verified the sender's signature itself, the cards say so. */
const VERIFIED: Partial<Record<Check["id"], string>> = {
  dmarc: "The sender's domain signed this email, and phish-check verified the signature itself.",
  dkim: "A valid signature from the sender's own domain proves it wasn't changed. phish-check checked it itself.",
};

const unknownText = (partial: boolean) =>
  partial ? "Not available: the original headers were lost when this was forwarded." : "Your email provider didn't record this check.";

/** The three authentication cards: DMARC, SPF and DKIM. */
export function authChecks(auth: AuthSummary, partial: boolean): Check[] {
  const check = (id: "dmarc" | "spf" | "dkim", label: string): Check => {
    const result = auth[id];
    const explain = EXPLAIN[id] as Partial<Record<AuthResult, string>>;
    const verified = auth.verified && result === "pass" ? VERIFIED[id] : undefined;
    return {
      id,
      label,
      status: STATUS[result],
      value: VALUE[result],
      explanation: verified ?? (result === "unknown" ? unknownText(partial) : (explain[result] ?? "The check couldn't be completed.")),
    };
  };
  return [check("dmarc", "Domain policy · DMARC"), check("spf", "Sending server · SPF"), check("dkim", "Signature · DKIM")];
}

export function buildChecks(
  auth: AuthSummary,
  reply: { elsewhere: boolean; domain: string | null },
  partial: boolean,
): Check[] {
  const unknown = unknownText(partial);
  return [
    ...authChecks(auth, partial),
    partial
      ? { id: "reply-to", label: "Replies go to", status: "unknown", value: "Unknown", explanation: unknown }
      : reply.elsewhere
      ? { id: "reply-to", label: "Replies go to", status: "fail", value: "Elsewhere", explanation: `${reply.domain}, a different domain from the sender's.` }
      : { id: "reply-to", label: "Replies go to", status: "pass", value: "The sender", explanation: "Hitting reply goes back to the address it came from." },
  ];
}
