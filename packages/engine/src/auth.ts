import type { AuthResult, AuthSummary, Check, ParsedEmail } from "./types.ts";

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
    return { spf: receivedSpf ? toResult(receivedSpf.trim().split(/[\s(;]/)[0]) : "unknown", dkim: "unknown", dmarc: "unknown", recordedBy: null };
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

export function buildChecks(
  auth: AuthSummary,
  reply: { elsewhere: boolean; domain: string | null },
  partial: boolean,
): Check[] {
  const unknown = partial
    ? "Not available: the original headers were lost when this was forwarded."
    : "Your email provider didn't record this check.";
  const check = (id: "dmarc" | "spf" | "dkim", label: string): Check => {
    const result = auth[id];
    const explain = EXPLAIN[id] as Partial<Record<AuthResult, string>>;
    return {
      id,
      label,
      status: STATUS[result],
      value: VALUE[result],
      explanation: result === "unknown" ? unknown : (explain[result] ?? "The check couldn't be completed."),
    };
  };
  return [
    check("dmarc", "Domain policy · DMARC"),
    check("spf", "Sending server · SPF"),
    check("dkim", "Signature · DKIM"),
    partial
      ? { id: "reply-to", label: "Replies go to", status: "unknown", value: "Unknown", explanation: unknown }
      : reply.elsewhere
      ? { id: "reply-to", label: "Replies go to", status: "fail", value: "Elsewhere", explanation: `${reply.domain}, a different domain from the sender's.` }
      : { id: "reply-to", label: "Replies go to", status: "pass", value: "The sender", explanation: "Hitting reply goes back to the address it came from." },
  ];
}
