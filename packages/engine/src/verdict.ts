import { BRANDS } from "./brands.ts";
import type { AuthSummary, Category, Finding, NextStep, ParsedEmail, Severity, Verdict } from "./types.ts";

const WEIGHT: Record<Severity, number> = { high: 45, medium: 20, low: 8, info: 0 };

/** The most any one detector can contribute, so a pile of weak hits of one kind can't decide alone. */
const CAP: Record<Category, number> = {
  provider: 60,
  sender: 90,
  link: 70,
  attachment: 90,
  wording: 60,
  evasion: 45,
  tracker: 0,
  form: 45,
  intel: 90,
};

/**
 * Turns findings into a verdict. Two independent high-severity findings, or enough
 * combined weight from different detectors, make it phishing.
 */
export function score(findings: Finding[]): { score: number; verdict: Verdict } {
  const byCategory = new Map<Category, number>();
  for (const f of findings) byCategory.set(f.category, (byCategory.get(f.category) ?? 0) + WEIGHT[f.severity]);
  let total = 0;
  for (const [category, weight] of byCategory) total += Math.min(CAP[category], weight);

  const highs = findings.filter((f) => f.severity === "high").length;
  // 28 is one medium plus one low: two independent, if modest, warning signs.
  const verdict: Verdict = highs >= 2 || total >= 70 ? "phishing" : highs >= 1 || total >= 28 ? "suspicious" : "no-red-flags";
  return { score: total, verdict };
}

/** Authentication results turned into findings, so they're explained and weighed like everything else. */
export function authFindings(auth: AuthSummary, arcPassed: boolean): Finding[] {
  const from = { kind: "header", field: "from" } as const;
  if (auth.dmarc === "fail") {
    return [
      {
        id: "auth-dmarc-fail",
        rule: "auth-dmarc-fail",
        category: "sender",
        severity: arcPassed ? "low" : "medium",
        title: "The sender's own domain disowns it",
        real: { text: "dmarc=fail" },
        explanation: arcPassed
          ? "The domain in the From address doesn't vouch for it. A mailing list or forwarding service in between can cause this, so it counts for less here."
          : "The domain in the From address publishes rules for which mail is really from it, and this email breaks them.",
        lensLabel: "Authentication",
        target: from,
      },
    ];
  }
  const passed = [auth.spf, auth.dkim, auth.dmarc].includes("pass");
  const known = [auth.spf, auth.dkim, auth.dmarc].some((r) => r !== "unknown");
  if (known && !passed) {
    return [
      {
        id: "auth-none",
        rule: "auth-none",
        category: "sender",
        severity: "medium",
        title: "Nothing vouches for the sender",
        real: { text: `spf=${auth.spf} · dkim=${auth.dkim} · dmarc=${auth.dmarc}` },
        explanation: "It passed none of SPF, DKIM or DMARC, the checks that prove an email really comes from the domain it shows. Anyone could have sent it.",
        lensLabel: "Authentication",
        target: from,
      },
    ];
  }
  return [];
}

const has = (findings: Finding[], ...rules: string[]) => findings.some((f) => rules.includes(f.rule));

/** What kind of scam it is, for the headline: [rule, as a verdict, as a warning]. */
const KINDS: [string, string, string][] = [
  ["sextortion", "It's a blackmail scam. Don't pay.", "It looks like a blackmail scam. Don't pay."],
  ["advance-fee", "It's an advance-fee scam.", "It looks like an advance-fee scam."],
  ["money", "It's a money scam.", "It asks for money the way scammers do."],
  ["callback", "It's a fake receipt meant to make you call scammers.", "It looks like a fake receipt meant to make you call scammers."],
  ["crypto", "It's a crypto scam.", "It looks like a crypto scam."],
  ["delivery", "It's a fake delivery notice.", "It looks like a fake delivery notice."],
  ["fines", "It's a fake fine or tax notice.", "It looks like a fake fine or tax notice."],
  ["storage", "It's a fake storage warning.", "It looks like a fake storage warning."],
  ["prize", "It's a prize scam.", "It looks like a prize scam."],
  ["job", "It's a job scam.", "It looks like a job scam."],
  ["credentials", "It's trying to steal your login.", "It may be trying to steal your login."],
  ["invoice", "It's a fake bill.", "It looks like a fake bill."],
  ["document", "It's a fake shared file.", "It looks like a fake shared file."],
  ["gambling", "It's casino spam.", "It looks like casino spam."],
  ["dating", "It's a dating scam.", "It looks like a dating scam."],
  ["health", "It's miracle-cure spam.", "It looks like miracle-cure spam."],
];

export function headline(verdict: Verdict, findings: Finding[]): { headline: string; summary: string } {
  if (verdict === "no-red-flags") {
    // Minor findings are still listed, so the headline mustn't claim nothing was found.
    const minor = findings.filter((f) => f.severity !== "info").length;
    return {
      headline: !minor
        ? "Nothing we checked looks wrong."
        : minor === 1
          ? "One small thing stood out, but nothing that marks it as phishing."
          : "A few small things stood out, but nothing that marks it as phishing.",
      summary: "We didn't find clear signs of phishing. That's not a guarantee, so stay careful with links and money requests.",
    };
  }
  const kind = KINDS.find(([rule]) => has(findings, rule));
  if (verdict === "suspicious") {
    return {
      headline: kind?.[2] ?? (has(findings, "provider-flagged") ? "Your email provider already flagged it as spam." : "Some things here don't add up."),
      summary: "Don't act on it until you've checked with the sender another way. Here's what we found.",
    };
  }
  const brand = findings.find((f) => f.brand && (f.category === "sender" || f.category === "link"))?.brand;
  const text = brand
    ? `It says ${brand}. It isn't ${brand}.`
    : kind
      ? kind[1]
      : findings.some((f) => f.category === "attachment" && f.severity === "high")
        ? "Its attachment is built to cause harm."
        : has(findings, "link-mismatch", "link-lookalike", "link-brand")
          ? "Its links don't go where they say."
          : has(findings, "sender-invalid", "sender-missing")
            ? "It comes from an address that can't exist."
            : "Several things here don't add up.";
  return { headline: text, summary: "Don't click anything in it, and don't reply. Everything we found is below." };
}

export type Provider = "gmail" | "outlook" | "yahoo" | "apple";

/** Guesses the reader's mail provider from the servers that delivered the email. */
export function detectProvider(email: ParsedEmail): Provider | null {
  const trail = [email.authenticationResults[0], email.received[0], email.received[1]].join(" ").toLowerCase();
  if (/google\.com|gmail/.test(trail)) return "gmail";
  if (/outlook\.com|protection\.outlook|hotmail|microsoft\.com/.test(trail)) return "outlook";
  if (/yahoo/.test(trail)) return "yahoo";
  if (/icloud\.com|\bme\.com|apple\.com/.test(trail)) return "apple";
  return null;
}

const REPORT: Record<Provider | "any", string> = {
  gmail: "In Gmail: `⋮` then `Report phishing`. It helps block the sender for everyone.",
  outlook: "In Outlook: `Report` then `Report phishing`. It helps block the sender for everyone.",
  yahoo: "In Yahoo Mail: `⋯` then `Report spam`.",
  apple: "In Apple Mail: move it to `Junk`. That teaches the filter to catch the next one.",
  any: "Use your email app's `Report phishing` or `Report junk` option. It helps block the sender.",
};

export function nextSteps(verdict: Verdict, findings: Finding[], provider: Provider | null): NextStep[] {
  const report: NextStep = { title: "Report it to your email provider.", detail: REPORT[provider ?? "any"] };
  if (verdict === "no-red-flags") {
    return [
      { title: "Still unsure? Check another way.", detail: "If it asks for money, a password or a quick decision, contact the sender with a number or website you already know." },
      { title: "Keep an eye on what it asks for.", detail: "Our checks can't read intentions. An unexpected request is the best warning sign there is." },
    ];
  }
  const brandName = findings.find((f) => f.brand)?.brand;
  const brand = BRANDS.find((b) => b.name === brandName);
  const already: NextStep = has(findings, "sextortion")
    ? { title: "Worried it could be real?", detail: "It isn't. If it quotes a real password of yours, that came from an old data breach: change that password everywhere you use it." }
    : has(findings, "callback")
      ? { title: "Already called the number?", detail: "If you let them connect to your computer, disconnect it from the internet and get it checked. Call your bank using the number on your card." }
    : has(findings, "money")
      ? { title: "Already sent money or gift cards?", detail: "Call your bank and the gift card company right away. They can sometimes stop the payment." }
      : findings.some((f) => f.category === "attachment" && f.severity === "high")
        ? { title: "Already opened the attachment?", detail: "Disconnect from the internet and run a full virus scan, or ask your IT team for help." }
        : has(findings, "prize", "delivery", "fines", "invoice", "crypto")
          ? { title: "Already entered card details?", detail: "Call your bank or card issuer now and ask them to block the card. Watch your statement for small test charges." }
          : brand
            ? { title: "Already typed your password?", detail: `Type ${brand.home} into your browser yourself, change your password, and turn on two-step login.` }
            : { title: "Already clicked a link?", detail: "Change the password of any account you signed in to, and turn on two-step login." };

  if (verdict === "suspicious") {
    return [
      { title: "Don't act on it yet.", detail: "Check with the sender using a phone number or website you already know, not anything in this email." },
      has(findings, "money")
        ? { title: "Never pay because an email says so.", detail: "Gift cards and wire transfers are almost impossible to get back." }
        : report,
      already,
    ];
  }
  return [{ title: "Don't click, download, or reply.", detail: "Even a reply tells them your address works." }, report, already];
}
