import type { Analysis, Target } from "@phish-check/engine";

/** The reading-view element a finding points at: "from", "subject" or a node id. */
export function targetKey(target: Target): string {
  return target.kind === "header" ? target.field : target.id;
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export const VERDICT_NAME: Record<Analysis["verdict"], string> = {
  phishing: "Likely phishing",
  suspicious: "Suspicious",
  "no-red-flags": "No red flags found",
};

/** A plain-text summary someone can paste into a message to their IT team. */
export function summaryText(analysis: Analysis): string {
  const from = analysis.sender ? `${analysis.sender.name ? `${analysis.sender.name} ` : ""}<${analysis.sender.address}>` : "unknown";
  const lines = [
    `phish-check verdict: ${VERDICT_NAME[analysis.verdict]}`,
    analysis.headline,
    "",
    `From: ${from}`,
    `Subject: ${analysis.subject || "(none)"}`,
    "",
  ];
  if (analysis.findings.length) {
    lines.push("What we found:");
    analysis.findings.forEach((f, i) => lines.push(`${i + 1}. ${f.title}. ${f.explanation}`));
    lines.push("");
  }
  lines.push(`Checks: ${analysis.checks.map((c) => `${c.label.split(" · ")[1] ?? c.label} ${c.value}`).join(" · ")}`);
  if (analysis.partial) lines.push("Note: this was an inline forward, so the original headers weren't available.");
  lines.push("", `Checked in the browser with phish-check (${location.origin}). The email itself was never uploaded.`);
  return lines.join("\n");
}

export function indicatorText(analysis: Analysis): string {
  return analysis.indicators.map((i) => `${i.type}\t${i.value}\t${i.note}`).join("\n");
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Saves the analysis as JSON. It never contains attachment bytes. */
export function downloadReport(analysis: Analysis): void {
  const report = { tool: "phish-check", generatedAt: new Date().toISOString(), analysis };
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `phish-check-report-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function formatWhen(iso: string | null): string {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat(undefined, { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }).format(date);
}
