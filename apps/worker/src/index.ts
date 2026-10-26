/**
 * One Worker serves the whole tool:
 * - static web app (Cloudflare serves apps/web/dist before this code runs)
 * - /api/intel  online checks: domain age, DNS, phishing blocklists (keys stay here)
 * - email       forward-to-check handler (phase 5)
 */
import { lookup, parseRequest, type IntelEnv } from "./intel.ts";

export interface Env extends IntelEnv {
  ASSETS: Fetcher;
}

const VERSION = "0.2.0";
const MAX_BODY = 32 * 1024;
const PER_MINUTE = 30;

/** A small per-visitor budget, so nobody can turn the Worker into a free lookup service. */
const budget = new Map<string, { count: number; resetAt: number }>();

const MAX_VISITORS = 10_000;

function allowed(ip: string): boolean {
  const now = Date.now();
  const entry = budget.get(ip);
  if (!entry || entry.resetAt < now) {
    budget.delete(ip);
    budget.set(ip, { count: 1, resetAt: now + 60_000 });
    if (budget.size > MAX_VISITORS) forgetOldest(now);
    return true;
  }
  entry.count++;
  return entry.count <= PER_MINUTE;
}

/** Frees room without wiping everyone's count: expired entries first, then the oldest (Maps keep insertion order). */
function forgetOldest(now: number): void {
  for (const [ip, entry] of budget) if (entry.resetAt < now) budget.delete(ip);
  for (const ip of budget.keys()) {
    if (budget.size <= MAX_VISITORS * 0.9) break;
    budget.delete(ip);
  }
}

/** Reads the body up to `limit` bytes. Returns null as soon as it's bigger, without buffering the rest. */
async function readBody(request: Request, limit: number): Promise<string | null> {
  if (Number(request.headers.get("content-length") ?? 0) > limit) return null;
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);
      return json({ ok: true, service: "phish-check", version: VERSION });
    }

    if (url.pathname === "/api/intel") {
      if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
      if (!allowed(request.headers.get("cf-connecting-ip") ?? "local")) return json({ error: "Too many checks. Try again in a minute." }, 429);
      const text = await readBody(request, MAX_BODY);
      if (text === null) return json({ error: "Request too large" }, 413);
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        return json({ error: "Expected JSON" }, 400);
      }
      const intelRequest = parseRequest(body);
      if (!intelRequest) return json({ error: "Expected domains, urls and hashes" }, 400);
      return json(await lookup(intelRequest, env));
    }

    return json({ error: "Not found" }, 404);
  },
} satisfies ExportedHandler<Env>;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}
