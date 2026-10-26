import type { Finding, ParsedEmail, Severity } from "./types.ts";

/**
 * Verdicts the recipient's own mail provider already stamped on the email.
 *
 * These only ever count against an email. A sender could forge them, but forging
 * a spam verdict only hurts the sender, and "looks clean" is never taken from them.
 */
interface Stamp {
  severity: Severity;
  label: string;
  detail: string;
}

const values = (email: ParsedEmail, name: string) => email.headers.filter((h) => h.name === name).map((h) => h.value.trim());

const MICROSOFT_CATEGORIES: Record<string, string> = {
  PHSH: "phishing",
  HPHSH: "high-confidence phishing",
  HPHISH: "high-confidence phishing",
  MALW: "malware",
  SPOOF: "spoofing",
  UIMP: "impersonation of a person",
  DIMP: "impersonation of a domain",
  GIMP: "impersonation",
  AMP: "malware",
  HSPM: "high-confidence spam",
  SPM: "spam",
  BULK: "bulk mail",
};

function microsoft(email: ParsedEmail): Stamp | null {
  const report = values(email, "x-forefront-antispam-report").join(";");
  const category = report.match(/\bCAT:([A-Z]+)/i)?.[1]?.toUpperCase();
  const filter = report.match(/\bSFV:([A-Z]+)/i)?.[1]?.toUpperCase();
  const sclHeader = parseInt(values(email, "x-ms-exchange-organization-scl")[0] ?? "", 10);
  const scl = Number.isFinite(sclHeader) ? sclHeader : parseInt(report.match(/\bSCL:(-?\d)/i)?.[1] ?? "", 10);

  const named = category ? MICROSOFT_CATEGORIES[category] : undefined;
  if (named && !/spam|bulk/.test(named)) {
    return { severity: "high", label: `Microsoft: ${named}`, detail: `Microsoft's filters classified it as ${named} before it reached you.` };
  }
  if (scl >= 7 || filter === "BLK" || category === "HSPM") {
    return { severity: "high", label: `Microsoft: high-confidence spam${scl >= 0 ? ` (SCL ${scl})` : ""}`, detail: `Microsoft's filters rated it ${scl >= 0 ? `${scl} out of 9` : "high-confidence spam"} before it reached you.` };
  }
  if (scl >= 5 || filter === "SPM" || category === "SPM") {
    return { severity: "medium", label: `Microsoft: spam${scl >= 0 ? ` (SCL ${scl})` : ""}`, detail: `Microsoft's filters rated it as spam${scl >= 0 ? ` (${scl} out of 9)` : ""} before it reached you.` };
  }
  return null;
}

function spamFilters(email: ParsedEmail): Stamp | null {
  const flag = values(email, "x-spam-flag")[0];
  const status = values(email, "x-spam-status")[0];
  const level = values(email, "x-spam-level")[0];
  const rspamd = values(email, "x-rspamd-action")[0];
  const barracuda = values(email, "x-barracuda-spam-status")[0];
  const proofpoint = values(email, "x-proofpoint-spam-details").join(" ");

  if (/rule=(phish|malware|virus)/i.test(proofpoint)) {
    return { severity: "high", label: "Proofpoint: phishing", detail: "Proofpoint's filters classified it as phishing before it reached you." };
  }
  if (/^yes/i.test(flag ?? "") || /^yes/i.test(status ?? "") || /^yes/i.test(barracuda ?? "") || (level?.match(/\*/g)?.length ?? 0) >= 5 || /^(reject|add header|rewrite subject)/i.test(rspamd ?? "")) {
    const score = status?.match(/score=(-?[\d.]+)/i)?.[1];
    return { severity: "medium", label: `Spam filter: spam${score ? ` (score ${score})` : ""}`, detail: "Your provider's spam filter marked it as spam before it reached you." };
  }
  if (/rule=spam/i.test(proofpoint)) {
    return { severity: "medium", label: "Proofpoint: spam", detail: "Proofpoint's filters marked it as spam before it reached you." };
  }
  return null;
}

export function providerFindings(email: ParsedEmail): Finding[] {
  const out: Finding[] = [];
  const stamp = microsoft(email) ?? spamFilters(email);
  if (stamp) {
    out.push({
      id: "provider-flagged",
      rule: "provider-flagged",
      category: "provider",
      severity: stamp.severity,
      title: "Your email provider already flagged it",
      real: { text: stamp.label },
      explanation: stamp.detail,
      lensLabel: "Provider verdict",
      target: { kind: "header", field: "subject" },
    });
  }

  // Microsoft's composite authentication: its own judgement of whether the sender may use this address.
  const compauth = (email.authenticationResults[0] ?? "").match(/compauth=(\w+)(?:\s+reason=(\d+))?/i);
  if (compauth && /fail/i.test(compauth[1]!)) {
    out.push({
      id: "spoof-check",
      rule: "spoof-check",
      category: "provider",
      severity: "medium",
      title: "It failed Microsoft's spoofing check",
      real: { text: `compauth=fail${compauth[2] ? ` reason=${compauth[2]}` : ""}` },
      explanation: "Microsoft checks whether a sender is allowed to use the address it shows. This one isn't.",
      lensLabel: "Spoof check",
      target: { kind: "header", field: "from" },
    });
  }
  return out;
}
