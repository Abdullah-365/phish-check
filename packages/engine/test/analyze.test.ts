import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { analyzeEmail } from "../src/index.ts";
import type { Analysis, Verdict } from "../src/index.ts";

interface SampleEntry {
  file: string;
  expected: Verdict;
  findings: string[];
  partial?: boolean;
}

const samplesDir = new URL("../../../samples/", import.meta.url);
const manifest: SampleEntry[] = JSON.parse(readFileSync(new URL("manifest.json", samplesDir), "utf8"));
const analyse = (file: string) => analyzeEmail(readFileSync(new URL(file, samplesDir)));

describe.each(manifest)("$file", (sample) => {
  it(`is judged ${sample.expected} for the expected reasons`, async () => {
    const analysis = await analyse(sample.file);
    expect(analysis.verdict).toBe(sample.expected);
    expect(analysis.findings.map((f) => f.rule).sort()).toEqual([...sample.findings].sort());
    expect(analysis.partial).toBe(sample.partial ?? false);
  });

  it("points every finding at something in the reading view", async () => {
    const analysis = await analyse(sample.file);
    const ids = new Set([
      ...analysis.content.blocks.flatMap((b) => [b.id, ...b.inlines.map((i) => ("id" in i ? i.id : ""))]),
      ...analysis.attachments.map((a) => a.id),
    ]);
    for (const finding of analysis.findings) {
      if (finding.target.kind === "node") expect(ids, finding.id).toContain(finding.target.id);
    }
  });
});

describe("analysis details", () => {
  let paypal: Analysis;
  const finding = (rule: string) => paypal.findings.find((f) => f.rule === rule)!;

  it("explains the PayPal look-alike in plain words", async () => {
    paypal = await analyse("lookalike-paypal.eml");
    expect(paypal.headline).toBe("It says PayPal. It isn't PayPal.");

    const sender = finding("sender-disguise");
    expect(sender.seen?.text).toBe("PayPal Service");
    expect(sender.real?.text).toBe("service@paypa1-security.test");
    // Only the swapped character is highlighted.
    const [start, end] = sender.real!.marks![0]!;
    expect(sender.real!.text.slice(start, end)).toBe("1");
    expect(sender.explanation).toContain('the number "1" for the letter "l"');

    const link = finding("link-mismatch");
    expect(link.title).toBe("The button lies about where it goes");
    expect(link.explanation).toContain("fake PayPal sign-in page, with your email address already filled in");
    const [hs, he] = link.real!.marks![0]!;
    expect(link.real!.text.slice(hs, he)).toBe("paypa1-security.test");
  });

  it("summarises the checks and stats", () => {
    expect(paypal.checks.map((c) => `${c.id}:${c.value}`)).toEqual(["dmarc:Fail", "spf:Softfail", "dkim:Missing", "reply-to:Elsewhere"]);
    expect(paypal.stats).toEqual({ tricks: 6, failedChecks: 3, trackers: 1 });
    expect(paypal.route.at(0)?.from).toBe("vps-77.hosting.test");
  });

  it("defangs indicators and drops query strings that carry the recipient's address", () => {
    const values = paypal.indicators.map((i) => i.value);
    expect(values).toContain("paypa1-security[.]test");
    expect(values).toContain("hxxp://paypa1-security[.]test/login/verify");
    expect(values).toContain("198.51.100[.]77");
    expect(values.join(" ")).not.toContain("alex");
    // Notes are copied too, so hostnames in them are defanged as well.
    expect(paypal.indicators.find((i) => i.type === "ip")?.note).toBe("Sending server, vps-77[.]hosting[.]test");
  });

  it("marks wording in the reading view", () => {
    const phrases = paypal.content.blocks.flatMap((b) => b.inlines).filter((i) => i.type === "phrase");
    expect(phrases.map((p) => p.type === "phrase" && p.text)).toEqual(
      expect.arrayContaining(["Dear Customer", "within 24 hours", "permanently suspended"]),
    );
  });

  it("judges the original of a forward-as-attachment, not the forward", async () => {
    const analysis = await analyse("forwarded-as-attachment.eml");
    expect(analysis.forwarded).toEqual({ mode: "attachment", by: "alex@inbox.example" });
    expect(analysis.sender?.address).toBe("service@paypa1-security.test");
  });

  it("works from the quoted sender when an inline forward lost the headers", async () => {
    const analysis = await analyse("inline-forward.eml");
    expect(analysis.forwarded?.mode).toBe("inline");
    expect(analysis.sender).toEqual({ name: "Microsoft 365 Admin", address: "it.helpdesk.notice@freemail.test" });
    expect(analysis.checks.find((c) => c.id === "dmarc")?.status).toBe("unknown");
    expect(analysis.route).toEqual([]);
  });

  it("finds nothing wrong with an honest email and gives no indicators", async () => {
    const analysis = await analyse("legit-order-confirmation.eml");
    expect(analysis.findings).toEqual([]);
    expect(analysis.indicators).toEqual([]);
    expect(analysis.checks.every((c) => c.status === "pass")).toBe(true);
  });

  it("hashes risky attachments", async () => {
    const analysis = await analyse("macro-invoice.eml");
    expect(analysis.attachments).toEqual([
      {
        id: "a0",
        filename: "INV-20931.docm",
        size: expect.any(Number),
        kind: "Macro-enabled Word document",
        risky: true,
        sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        links: [],
      },
    ]);
    expect(analysis.indicators.find((i) => i.type === "sha256")?.value).toMatch(/^[0-9a-f]{64}$/);
  });
});
