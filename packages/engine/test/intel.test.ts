import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { analyzeEmail, applyIntel, inspectUrl, intelRequest, sharedHost, type IntelResponse } from "../src/index.ts";

const sample = (file: string) => analyzeEmail(readFileSync(new URL(`../../../samples/${file}`, import.meta.url)));
const DAY = 24 * 60 * 60 * 1000;

const empty: IntelResponse = { domains: [], urls: [], hashes: [], sources: ["RDAP", "DNS", "OpenPhish"], unavailable: [] };

describe("intelRequest", () => {
  it("asks about the sender and link domains, without query strings", async () => {
    const request = intelRequest(await sample("lookalike-paypal.eml"));
    expect(request.domains).toEqual(["paypa1-security.test"]);
    expect(request.urls).toEqual(["http://paypa1-security.test/login/verify"]);
    expect(request.urls.join(" ")).not.toContain("alex");
  });

  it("skips domains that belong to big brands or mailbox providers", async () => {
    const request = intelRequest(await sample("bec-gift-cards.eml"));
    expect(request.domains).toEqual(["freemail.test"]);
  });

  it("checks pages on free hosting by URL only, since the platform's age says nothing", async () => {
    const analysis = await sample("legit-order-confirmation.eml");
    const file = { id: "a0", filename: "notice.pdf", size: 9000, kind: "PDF document", risky: false, sha256: "ef".repeat(32), links: ["https://redirect44.z13.web.core.windows.net/"] };
    const request = intelRequest({ ...analysis, attachments: [file] });
    expect(request.urls).toContain("https://redirect44.z13.web.core.windows.net/");
    expect(request.domains).not.toContain("windows.net");
  });

  it("includes attachment fingerprints, never the files", async () => {
    const request = intelRequest(await sample("macro-invoice.eml"));
    expect(request.hashes).toHaveLength(1);
    expect(request.hashes[0]).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("applyIntel", () => {
  it("flags a sender domain registered days before the email", async () => {
    const analysis = await sample("bec-gift-cards.eml");
    expect(analysis.verdict).toBe("suspicious");
    const sent = new Date(analysis.date!).getTime();
    const updated = applyIntel(analysis, {
      ...empty,
      domains: [{ domain: "freemail.test", registered: new Date(sent - 4 * DAY).toISOString(), registrar: "Cheap Names Ltd", exists: true, mailbox: true }],
    });
    const fresh = updated.findings.find((f) => f.rule === "intel-new-sender-domain")!;
    expect(fresh.severity).toBe("high");
    expect(fresh.explanation).toContain("4 days before this email");
    // Two strong findings now: the gift-card request and the brand-new domain.
    expect(updated.verdict).toBe("phishing");
    expect(updated.intel).toEqual({ sources: ["RDAP", "DNS", "OpenPhish"], unavailable: [] });
  });

  it("puts blocklisted links on the link itself", async () => {
    const analysis = await sample("lookalike-paypal.eml");
    const updated = applyIntel(analysis, {
      ...empty,
      urls: [{ url: "http://paypa1-security.test/login/verify", listings: [{ source: "OpenPhish", threat: "phishing" }] }],
    });
    const listed = updated.findings.find((f) => f.rule === "intel-blocklisted")!;
    const button = analysis.content.blocks.flatMap((b) => b.inlines).find((i) => i.type === "link")!;
    expect(listed.target).toEqual({ kind: "node", id: "id" in button ? button.id : "" });
  });

  it("lists a link only the blocklist knew about, even when the email looked clean", async () => {
    const analysis = await sample("legit-order-confirmation.eml");
    expect(analysis.indicators).toEqual([]);
    const updated = applyIntel(analysis, {
      ...empty,
      urls: [{ url: "https://www.shop.example/account/orders/48213", listings: [{ source: "OpenPhish", threat: "phishing" }] }],
    });
    expect(updated.verdict).toBe("suspicious");
    expect(updated.indicators).toEqual(
      expect.arrayContaining([
        { type: "email", value: "orders@shop[.]example", note: "From address" },
        { type: "url", value: "hxxps://www[.]shop[.]example/account/orders/48213", note: "Blocklisted link, query removed" },
      ]),
    );
  });

  it("records an attachment that only a malware database recognises", async () => {
    const analysis = await sample("legit-order-confirmation.eml");
    const file = { id: "a0", filename: "receipt.pdf", size: 1200, kind: "PDF document", risky: false, sha256: "ab".repeat(32), links: [] };
    const updated = applyIntel({ ...analysis, attachments: [file] }, { ...empty, hashes: [{ sha256: file.sha256, listings: [{ source: "MalwareBazaar", threat: "malware" }] }] });
    expect(updated.indicators).toContainEqual({ type: "sha256", value: file.sha256, note: "receipt.pdf" });
  });

  it("checks links hidden inside attachments and pins hits on the file", async () => {
    const analysis = await sample("legit-order-confirmation.eml");
    const file = { id: "a0", filename: "invoice.pdf", size: 9000, kind: "PDF document", risky: false, sha256: "cd".repeat(32), links: ["https://evil.example/login?u=alex"] };
    const withFile = { ...analysis, attachments: [file] };
    const request = intelRequest(withFile);
    expect(request.urls).toContain("https://evil.example/login");
    expect(request.domains).toContain("evil.example");

    const updated = applyIntel(withFile, { ...empty, urls: [{ url: "https://evil.example/login", listings: [{ source: "OpenPhish", threat: "phishing" }] }] });
    const listed = updated.findings.find((f) => f.rule === "intel-blocklisted")!;
    expect(listed.title).toBe("A link inside invoice.pdf is on a phishing blocklist");
    expect(listed.target).toEqual({ kind: "node", id: "a0" });
    expect(updated.indicators).toContainEqual({ type: "url", value: "hxxps://evil[.]example/login", note: "Blocklisted link in an attachment, query removed" });
  });

  it("measures age from the provider's delivery time, so a backdated Date header can't hide a new domain", async () => {
    const analysis = await sample("bec-gift-cards.eml");
    const delivered = new Date(analysis.receivedAt!).getTime();
    const backdated = { ...analysis, date: "2020-01-01T00:00:00.000Z" };
    const updated = applyIntel(backdated, {
      ...empty,
      domains: [{ domain: "freemail.test", registered: new Date(delivered - 4 * DAY).toISOString(), registrar: null, exists: true, mailbox: true }],
    });
    expect(updated.findings.map((f) => f.rule)).toContain("intel-new-sender-domain");
  });

  it("never sends the reader's own address inside a link path", async () => {
    const analysis = await sample("legit-order-confirmation.eml");
    const links = ["https://evil.example/alex@inbox.example/login", `https://kit.example/r/${btoa("alex@inbox.example").replace(/=+$/, "")}`];
    const file = { id: "a0", filename: "notice.pdf", size: 9000, kind: "PDF document", risky: false, sha256: "ab".repeat(32), links };
    const request = intelRequest({ ...analysis, recipient: "alex@inbox.example", attachments: [file] });
    expect(request.urls).toEqual(expect.arrayContaining(["https://evil.example/", "https://kit.example/"]));
    expect(request.urls.join(" ")).not.toMatch(/alex|YWxleEBpbmJveC/);
  });

  it("treats big file-sharing and brand hosts as shared", () => {
    expect(sharedHost(inspectUrl("https://drive.google.com/file/d/abc/view")!)).toBe(true);
    expect(sharedHost(inspectUrl("https://contoso-my.sharepoint.com/:b:/g/doc")!)).toBe(true);
    expect(sharedHost(inspectUrl("https://evil-login.example/verify")!)).toBe(false);
  });

  it("ignores ages that don't make sense and leaves honest mail alone", async () => {
    const analysis = await sample("legit-order-confirmation.eml");
    const sent = new Date(analysis.date!).getTime();
    const updated = applyIntel(analysis, {
      ...empty,
      domains: [
        { domain: "shop.example", registered: "2009-03-01T00:00:00Z", registrar: null, exists: true, mailbox: true },
        // Re-registered after the email was sent: says nothing about the sender at the time.
        { domain: "other.example", registered: new Date(sent + 30 * DAY).toISOString(), registrar: null, exists: true, mailbox: true },
      ],
    });
    expect(updated.findings).toEqual([]);
    expect(updated.verdict).toBe("no-red-flags");
  });

  it("replaces earlier online findings instead of piling them up", async () => {
    const analysis = await sample("lookalike-paypal.eml");
    const intel = { ...empty, urls: [{ url: "http://paypa1-security.test/login/verify", listings: [{ source: "OpenPhish", threat: "phishing" }] }] };
    const twice = applyIntel(applyIntel(analysis, intel), intel);
    expect(twice.findings.filter((f) => f.rule === "intel-blocklisted")).toHaveLength(1);
  });
});
