import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { EmailParseError, MAX_EMAIL_BYTES, parseEmail } from "../src/index.ts";
import type { Verdict } from "../src/index.ts";

interface SampleEntry {
  file: string;
  expected: Verdict;
  description: string;
  embeddedMessages?: number;
}

const samplesDir = new URL("../../../samples/", import.meta.url);
const manifest: SampleEntry[] = JSON.parse(readFileSync(new URL("manifest.json", samplesDir), "utf8"));
const emlFiles = readdirSync(samplesDir).filter((f) => f.endsWith(".eml"));

function loadSample(file: string): Uint8Array {
  return readFileSync(new URL(file, samplesDir));
}

describe("sample corpus", () => {
  it("lists every .eml file in the manifest, and nothing else", () => {
    expect(manifest.map((s) => s.file).sort()).toEqual([...emlFiles].sort());
  });

  it("uses only reserved domains, so no sample points at real infrastructure", () => {
    const reserved = /\.(test|example|invalid)$|^example\.(com|net|org)$/;
    // Brands named in visible link text are allowed; they're never contacted.
    const brandText = new Set(["www.paypal.com"]);
    for (const file of emlFiles) {
      const raw = new TextDecoder().decode(loadSample(file));
      for (const [, host] of raw.matchAll(/(?:@|https?:\/\/)([a-z0-9.-]+\.[a-z]{2,})/gi)) {
        if (brandText.has(host!.toLowerCase())) continue;
        expect(host, `${file}: ${host}`).toMatch(reserved);
      }
    }
  });
});

describe.each(manifest)("$file", (sample) => {
  it("parses with headers, a sender and authentication results", async () => {
    const email = await parseEmail(loadSample(sample.file));
    expect(email.headers.length).toBeGreaterThan(0);
    expect(email.subject).not.toBe("");
    expect(email.from?.address).toMatch(/@/);
    expect(email.received.length).toBeGreaterThan(0);
    expect(email.authenticationResults.length).toBeGreaterThan(0);
    expect(email.text || email.html).not.toBe("");
  });

  it("unwraps forwarded originals", async () => {
    const email = await parseEmail(loadSample(sample.file));
    expect(email.embeddedMessages).toHaveLength(sample.embeddedMessages ?? 0);
  });
});

describe("parseEmail", () => {
  it("keeps the original sender of a forward-as-attachment", async () => {
    const email = await parseEmail(loadSample("forwarded-as-attachment.eml"));
    expect(email.from?.address).toBe("alex@inbox.example");
    const original = email.embeddedMessages[0]!;
    expect(original.from).toEqual({ name: "PayPal Service", address: "service@paypa1-security.test" });
    expect(original.authenticationResults[0]).toContain("dmarc=fail");
    // The forwarded original is not double-counted as an attachment.
    expect(email.attachments).toHaveLength(0);
  });

  it("reads attachment metadata and bytes", async () => {
    const email = await parseEmail(loadSample("macro-invoice.eml"));
    expect(email.attachments).toHaveLength(1);
    const [doc] = email.attachments;
    expect(doc!.filename).toBe("INV-20931.docm");
    expect(doc!.declaredType).toBe("application/vnd.ms-word.document.macroenabled.12");
    expect(doc!.size).toBe(doc!.content.byteLength);
    expect(new TextDecoder().decode(doc!.content)).toContain("harmless placeholder");
  });

  it("keeps headers in document order, newest hop first", async () => {
    const email = await parseEmail(loadSample("lookalike-paypal.eml"));
    expect(email.received[0]).toMatch(/^by 2002:/);
    expect(email.received.at(-1)).toMatch(/^from vps-77\.hosting\.test/);
    expect(email.replyTo).toEqual([{ name: "", address: "account-review@mailbox.test" }]);
    expect(email.subject).toBe("Action required: your account has been limited");
  });

  it("rejects text with no headers", async () => {
    await expect(parseEmail("Hi, just the body of an email pasted here.")).rejects.toBeInstanceOf(EmailParseError);
    await expect(parseEmail("")).rejects.toBeInstanceOf(EmailParseError);
  });

  it("rejects oversized input before parsing", async () => {
    await expect(parseEmail(new Uint8Array(MAX_EMAIL_BYTES + 1))).rejects.toThrow(/larger than/);
  });
});
