import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index.ts";

const env = {} as Env;

describe("worker", () => {
  it("reports health", async () => {
    const res = await worker.fetch(new Request("https://phish.test/api/health"), env);
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toMatchObject({ ok: true, service: "phish-check" });
  });

  it("rejects other methods on health", async () => {
    const res = await worker.fetch(new Request("https://phish.test/api/health", { method: "POST" }), env);
    expect(res.status).toBe(405);
  });

  it("returns JSON 404 for unknown API routes", async () => {
    const res = await worker.fetch(new Request("https://phish.test/api/nope"), env);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "Not found" });
  });
});
