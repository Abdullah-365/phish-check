import type { Analysis, IntelResponse } from "@phish-check/engine";
import { loadEngine } from "./engine.ts";

const KEY = "phish-check:online-checks";

/** Online checks are on unless the reader turned them off. */
export function onlineChecksEnabled(): boolean {
  try {
    return localStorage.getItem(KEY) !== "off";
  } catch {
    return true;
  }
}

export function setOnlineChecks(on: boolean): void {
  try {
    localStorage.setItem(KEY, on ? "on" : "off");
  } catch {
    // Storage can be blocked; the choice still holds for this visit.
  }
}

export type IntelState =
  | { status: "off" }
  | { status: "skipped" }
  | { status: "checking" }
  | { status: "done"; response: IntelResponse }
  | { status: "unavailable" };

/**
 * Asks the Worker about the email's domains, links and attachment fingerprints, then
 * folds the answers into the analysis. The email itself is never sent.
 */
export async function checkOnline(analysis: Analysis): Promise<{ analysis: Analysis; response: IntelResponse }> {
  const engine = await loadEngine();
  const request = engine.intelRequest(analysis);
  if (!request.domains.length && !request.urls.length && !request.hashes.length) {
    const response: IntelResponse = { domains: [], urls: [], hashes: [], sources: [], unavailable: [] };
    return { analysis, response };
  }
  const res = await fetch("/api/intel", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Online checks answered ${res.status}`);
  const response = (await res.json()) as IntelResponse;
  return { analysis: engine.applyIntel(analysis, response), response };
}
