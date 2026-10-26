import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../src/index.ts";
import { lookup, parseRequest } from "../src/intel.ts";

const DAY = 24 * 60 * 60 * 1000;
const env = {} as Env;

/** A fake internet: just enough of each service for the lookups to run offline. */
function fakeNetwork(registeredDaysAgo: number) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
    if (url.startsWith("https://data.iana.org/rdap/dns.json")) return json({ services: [[["test"], ["https://rdap.registry.test/"]]] });
    if (url === "https://rdap.registry.test/domain/fresh.test") {
      return json({
        events: [{ eventAction: "registration", eventDate: new Date(Date.now() - registeredDaysAgo * DAY).toISOString() }],
        entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "Cheap Names Ltd"]]] }],
      });
    }
    if (url.startsWith("https://rdap.registry.test/domain/")) return json({}, 404);
    if (url.startsWith("https://cloudflare-dns.com/")) {
      return url.includes("gone.test") ? json({ Status: 3 }) : json({ Status: 0, Answer: [{ type: 15 }] });
    }
    if (url === "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt") {
      return new Response("https://evil.test/login\nhttps://storage.googleapis.com/kit/index.html\nhttps://drive.google.com/file/d/bad/view\n");
    }
    if (url.startsWith("https://www.virustotal.com/api/v3/files/")) {
      // The hash's first digit says how many engines flag it.
      const engines = Number(url.split("/").at(-1)![0]);
      return json({ data: { attributes: { last_analysis_stats: { malicious: engines } } } });
    }
    throw new Error(`Unexpected request to ${url}`);
  });
}

beforeEach(() => vi.stubGlobal("fetch", fakeNetwork(3)));
afterEach(() => vi.unstubAllGlobals());

describe("parseRequest", () => {
  it("keeps well-formed indicators, strips query strings and drops the rest", () => {
    expect(
      parseRequest({
        domains: ["Fresh.test", "not a domain", "x", 42],
        urls: ["https://evil.test/login?u=alex%40inbox.example#top", "javascript:alert(1)", "ftp://files.test"],
        hashes: ["A".repeat(64), "not-a-hash"],
      }),
    ).toEqual({ domains: ["fresh.test"], urls: ["https://evil.test/login"], hashes: ["a".repeat(64)] });
  });

  it("rejects anything that isn't an object", () => {
    expect(parseRequest("domains")).toBeNull();
    expect(parseRequest(null)).toBeNull();
  });
});

describe("lookup", () => {
  it("reads registration dates, dead domains and blocklists", async () => {
    const result = await lookup({ domains: ["fresh.test", "gone.test"], urls: ["https://evil.test/login", "https://storage.googleapis.com/other/page.html"], hashes: [] }, {});
    const fresh = result.domains.find((d) => d.domain === "fresh.test")!;
    expect(fresh.registrar).toBe("Cheap Names Ltd");
    expect(Date.now() - new Date(fresh.registered!).getTime()).toBeLessThan(4 * DAY);
    expect(result.domains.find((d) => d.domain === "gone.test")).toMatchObject({ exists: false, mailbox: false });
    expect(result.urls).toEqual([
      { url: "https://evil.test/login", listings: [{ source: "OpenPhish", threat: "phishing" }] },
      // One bad page on shared hosting doesn't condemn every other page on it.
      { url: "https://storage.googleapis.com/other/page.html", listings: [] },
    ]);
    expect(result.sources).toEqual(["DNS", "OpenPhish", "RDAP"]);
  });

  it("matches big shared platforms by exact page only", async () => {
    const result = await lookup({ domains: [], urls: ["https://drive.google.com/file/d/bad/view", "https://drive.google.com/file/d/other/view"], hashes: [] }, {});
    expect(result.urls.map((u) => u.listings.length)).toEqual([1, 0]);
  });

  it("needs several antivirus engines to agree before calling a file malware", async () => {
    const one = "1".repeat(64);
    const five = "5".repeat(64);
    const result = await lookup({ domains: [], urls: [], hashes: [one, five] }, { VT_KEY: "test-key" });
    expect(result.hashes).toEqual([
      { sha256: one, listings: [] },
      { sha256: five, listings: [{ source: "VirusTotal", threat: "flagged by 5 antivirus engines" }] },
    ]);
  });

  it("reports a failing service instead of failing the whole check", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new Error("offline"))));
    const result = await lookup({ domains: ["fresh.test"], urls: ["https://evil.test/"], hashes: [] }, {});
    expect(result.domains[0]).toMatchObject({ domain: "fresh.test", registered: null, exists: null });
    expect(result.unavailable).toEqual(["DNS", "RDAP"]);
    // The blocklist downloaded by the previous test is kept for an hour, so it still answers offline.
    expect(result.sources).toEqual(["OpenPhish"]);
    expect(result.urls[0]?.listings).toEqual([{ source: "OpenPhish", threat: "phishing" }]);
  });
});

describe("POST /api/intel", () => {
  const post = (body: string) => worker.fetch(new Request("https://phish.test/api/intel", { method: "POST", body, headers: { "cf-connecting-ip": "203.0.113.9" } }), env);

  it("answers with lookup results", async () => {
    const res = await post(JSON.stringify({ domains: ["fresh.test"], urls: [], hashes: [] }));
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const body = (await res.json()) as { domains: { domain: string }[] };
    expect(body.domains[0]?.domain).toBe("fresh.test");
  });

  it("rejects other methods, bad JSON and oversized bodies", async () => {
    expect((await worker.fetch(new Request("https://phish.test/api/intel"), env)).status).toBe(405);
    expect((await post("{not json")).status).toBe(400);
    expect((await post(JSON.stringify({ domains: ["a".repeat(40_000)] }))).status).toBe(413);
  });

  it("limits how often one visitor can check", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 32; i++) {
      const res = await worker.fetch(
        new Request("https://phish.test/api/intel", { method: "POST", body: "{}", headers: { "cf-connecting-ip": "198.51.100.200" } }),
        env,
      );
      statuses.push(res.status);
    }
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
  });
});
