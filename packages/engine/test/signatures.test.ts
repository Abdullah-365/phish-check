import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dkimSign } from "mailauth/lib/dkim/sign.js";
import { describe, expect, it } from "vitest";
import { analyzeEmail, analyzeParsed, applyIntel, intelRequest, parseEmail, verifyDkim, type DkimKey, type IntelResponse } from "../src/index.ts";

// What DKIM signatures, checked here against the keys domains publish, say about an email.
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privateKey = rsa.privateKey.export({ type: "pkcs8", format: "pem" });
const RECORD = `v=DKIM1; k=rsa; p=${rsa.publicKey.export({ type: "spki", format: "der" }).toString("base64")}`;
const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
const WRONG = `v=DKIM1; k=rsa; p=${other.publicKey.export({ type: "spki", format: "der" }).toString("base64")}`;
const RECEIVED = new Date("2026-10-26T09:00:05Z");
const DAY = 24 * 60 * 60 * 1000;
const empty: IntelResponse = { domains: [], urls: [], hashes: [], sources: ["DNS"], unavailable: [] };

const MESSAGE = [
  "From: Shop News <news@shop.example>",
  "To: alex@inbox.example",
  "Subject: Your order has shipped",
  "Date: Mon, 26 Oct 2026 09:00:00 +0000",
  "Message-ID: <order-1@shop.example>",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Hello Alex,\r\n\r\nYour order is on its way. Track it from your account page.\r\n",
].join("\r\n");

/** The message as the reader's provider stored it: its own Received and Authentication-Results lines on top of what was signed. */
async function delivered(results: string | null, signers = ["shop.example"]): Promise<string> {
  const signed = await dkimSign(MESSAGE, {
    canonicalization: "relaxed/relaxed",
    algorithm: "rsa-sha256",
    signatureData: signers.map((signingDomain) => ({ signingDomain, selector: "s1", privateKey })),
  });
  return [
    "Received: from mail.shop.example (mail.shop.example [192.0.2.10]) by mx.inbox.example with ESMTPS; Mon, 26 Oct 2026 09:00:05 +0000",
    ...(results ? [`Authentication-Results: mx.inbox.example; ${results}`] : []),
    `${signed.signatures}${MESSAGE}`,
  ].join("\r\n");
}

const PASSED = "spf=pass smtp.mailfrom=shop.example; dkim=pass header.d=shop.example header.s=s1; dmarc=pass header.from=shop.example";
const key = (record: string | null = RECORD, domain = "shop.example"): DkimKey[] => [{ domain, selector: "s1", record }];

async function check(raw: string, keys: DkimKey[], now = RECEIVED) {
  const email = await parseEmail(raw);
  const analysis = await analyzeParsed(email);
  return { analysis, updated: applyIntel(analysis, empty, now, await verifyDkim(email, keys)) };
}

describe("DKIM signatures as evidence", () => {
  it("trusts a signature from the sender's own domain once it verifies, even with no provider results", async () => {
    const { analysis, updated } = await check(await delivered(null), key());
    expect(analysis.auth.dkim).toBe("unknown");
    expect(updated.auth).toMatchObject({ dkim: "pass", verified: true });
    expect(updated.checks.find((c) => c.id === "dkim")).toMatchObject({ value: "Pass", explanation: expect.stringContaining("phish-check checked it itself") });
    expect(updated.findings.filter((f) => f.lensLabel === "Authentication")).toEqual([]);
  });

  it("asks only for keys that can prove or disprove something", async () => {
    const analysis = await analyzeEmail(await delivered("dkim=pass header.d=esp.example", ["other.example", "esp.example", "shop.example"]));
    // The sender's own domain first, then the one the header vouches for; a third party's says nothing.
    expect(intelRequest(analysis).dkim).toEqual([
      { domain: "shop.example", selector: "s1" },
      { domain: "esp.example", selector: "s1" },
    ]);
    // A plain forward's signatures are the forward's own, so nothing is asked.
    const forward = await analyzeEmail(readFileSync(new URL("../../../samples/inline-forward.eml", import.meta.url)));
    expect(forward.partial).toBe(true);
    expect(intelRequest(forward).dkim).toEqual([]);
  });

  it("catches a header that vouches for a signature that doesn't verify", async () => {
    const { analysis, updated } = await check(await delivered(PASSED), key(WRONG));
    expect(analysis.auth).toMatchObject({ spf: "pass", dkim: "pass", dmarc: "pass" });
    const finding = updated.findings.find((f) => f.rule === "auth-signature-fail")!;
    expect(finding).toMatchObject({ severity: "medium", category: "intel", real: { text: "claims dkim=pass for shop.example · the signature doesn't verify" } });
    // None of the header's passes can be believed now.
    expect(updated.auth).toMatchObject({ spf: "unknown", dkim: "fail", dmarc: "unknown", verified: false });
    expect(updated.checks.slice(0, 3).map((c) => c.value)).toEqual(["Unknown", "Unknown", "Fail"]);
    expect(updated.stats.failedChecks).toBe(1);
  });

  it("names the key a domain doesn't publish", async () => {
    const { updated } = await check(await delivered(PASSED), key(null));
    expect(updated.findings.find((f) => f.rule === "auth-signature-fail")?.real?.text).toBe('claims dkim=pass for shop.example · it publishes no key "s1"');
  });

  it("doesn't hold an old email's signature against it, since keys change", async () => {
    const { analysis, updated } = await check(await delivered(PASSED), key(WRONG), new Date(RECEIVED.getTime() + 90 * DAY));
    expect(updated.findings.some((f) => f.rule === "auth-signature-fail")).toBe(false);
    expect(updated.auth).toEqual(analysis.auth);
  });

  it("lets a genuine signature stand when only the body changed, without calling it verified", async () => {
    const raw = (await delivered(PASSED)).replace("Track it from your account page.", "Track it here: https://safelinks.example/?u=shop");
    const { analysis, updated } = await check(raw, key());
    expect(updated.findings.some((f) => f.rule === "auth-signature-fail")).toBe(false);
    expect(updated.auth).toEqual(analysis.auth);
  });

  it("changes nothing when no keys could be looked up", async () => {
    const { analysis, updated } = await check(await delivered(PASSED), []);
    expect(updated.auth).toEqual(analysis.auth);
    expect(updated.findings).toEqual(analysis.findings);
  });

  it("catches a header claiming SPF passed for a server the domain doesn't allow", async () => {
    const claims = "spf=pass (sender IP is 192.0.2.10) smtp.mailfrom=shop.example; dkim=pass header.d=shop.example; dmarc=pass header.from=shop.example";
    const analysis = await analyzeEmail(await delivered(claims));
    expect(intelRequest(analysis).spf).toEqual({ domain: "shop.example", ip: "192.0.2.10" });
    const answer = (result: "pass" | "fail" | "none", ip = "192.0.2.10"): IntelResponse => ({ ...empty, spf: { domain: "shop.example", ip, result } });

    const refused = applyIntel(analysis, answer("fail"), RECEIVED);
    expect(refused.findings.find((f) => f.rule === "auth-spf-mismatch")).toMatchObject({
      severity: "medium",
      real: { text: "claims spf=pass for shop.example from 192.0.2.10 · shop.example doesn't allow that server" },
    });
    // SPF now says what the domain says; the header's other passes can't be believed.
    expect(refused.auth).toMatchObject({ spf: "fail", dkim: "unknown", dmarc: "unknown" });
    expect(applyIntel(analysis, answer("none"), RECEIVED).findings.find((f) => f.rule === "auth-spf-mismatch")?.real?.text).toContain("publishes no SPF record");

    // A matching answer, an answer about another server, or an old email: nothing to hold against it.
    for (const updated of [applyIntel(analysis, answer("pass"), RECEIVED), applyIntel(analysis, answer("fail", "192.0.2.99"), RECEIVED), applyIntel(analysis, answer("fail"), new Date(RECEIVED.getTime() + 90 * DAY))]) {
      expect(updated.findings.some((f) => f.rule === "auth-spf-mismatch")).toBe(false);
      expect(updated.auth).toEqual(analysis.auth);
    }
  });

  it("reports a false DKIM claim and a false SPF claim side by side", async () => {
    const claims = "spf=pass (sender IP is 192.0.2.10) smtp.mailfrom=shop.example; dkim=pass header.d=shop.example; dmarc=pass header.from=shop.example";
    const raw = await delivered(claims);
    const email = await parseEmail(raw);
    const analysis = await analyzeParsed(email);
    const updated = applyIntel(analysis, { ...empty, spf: { domain: "shop.example", ip: "192.0.2.10", result: "fail" } }, RECEIVED, await verifyDkim(email, key(WRONG)));
    expect(updated.findings.filter((f) => f.lensLabel === "Authentication").map((f) => f.rule).sort()).toEqual(["auth-signature-fail", "auth-spf-mismatch"]);
    expect(updated.auth).toMatchObject({ spf: "fail", dkim: "fail", dmarc: "unknown" });
    expect(updated.verdict).toBe("suspicious");
  });

  it("catches an SPF claim naming a server the email's delivery record never mentions, offline", async () => {
    // The Received line says 192.0.2.10 delivered it; the header claims PayPal's server passed.
    const analysis = await analyzeEmail(await delivered("spf=pass (sender IP is 203.0.113.77) smtp.mailfrom=paypal.com; dkim=pass header.d=shop.example; dmarc=pass header.from=shop.example"));
    expect(analysis.findings.find((f) => f.rule === "auth-forged")).toMatchObject({
      id: "auth-forged-spf",
      severity: "high",
      real: { text: "claims spf=pass for paypal.com from 203.0.113.77 · no Received line records that server" },
    });
    expect(analysis.auth).toMatchObject({ spf: "unknown", dkim: "unknown", dmarc: "unknown" });
    expect(intelRequest(analysis).spf).toBeUndefined();
    // The same claim naming the server that really delivered it is left for the online check.
    const honest = await analyzeEmail(await delivered("spf=pass (sender IP is 192.0.2.10) smtp.mailfrom=shop.example; dkim=pass header.d=shop.example"));
    expect(honest.findings.some((f) => f.rule === "auth-forged")).toBe(false);
  });

  it("catches a header claiming a signature the email doesn't carry, offline", async () => {
    const analysis = await analyzeEmail(await delivered("spf=pass; dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com"));
    expect(analysis.findings.find((f) => f.rule === "auth-forged")).toMatchObject({ severity: "high", real: { text: "claims dkim=pass for paypal.com · no signature from it" } });
    expect(analysis.auth).toMatchObject({ spf: "unknown", dkim: "unknown", dmarc: "unknown" });
  });
});
