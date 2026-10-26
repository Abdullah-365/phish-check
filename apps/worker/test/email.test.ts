import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import forwardedAsAttachment from "../../../samples/forwarded-as-attachment.eml?raw";
import inlineForward from "../../../samples/inline-forward.eml?raw";
import legitOrder from "../../../samples/legit-order-confirmation.eml?raw";
import lookalikePaypal from "../../../samples/lookalike-paypal.eml?raw";
import { handleEmail, MAX_FORWARD, skipReason } from "../src/email.ts";
import { defang } from "../src/reply.ts";

const SAMPLES: Record<string, string> = {
  "forwarded-as-attachment.eml": forwardedAsAttachment,
  "inline-forward.eml": inlineForward,
  "legit-order-confirmation.eml": legitOrder,
  "lookalike-paypal.eml": lookalikePaypal,
};
const sample = (file: string) => new TextEncoder().encode(SAMPLES[file]!);

interface Sent {
  from: string;
  subject: string;
  text: string;
  html: string;
  headers?: Record<string, string>;
}

/** A Cloudflare inbound email, as Email Routing hands it to the Worker. */
function inbound(raw: Uint8Array | string, options: { from?: string; headers?: Record<string, string>; rawSize?: number; reply?: (sent: Sent) => Promise<unknown> } = {}) {
  const bytes = typeof raw === "string" ? new TextEncoder().encode(raw) : raw;
  const sent: Sent[] = [];
  const message = {
    from: options.from ?? "alex@inbox.example",
    to: "check@abdullah1.dev",
    headers: new Headers({ subject: "Fwd: Action required", "message-id": "<fwd-1@inbox.example>", ...options.headers }),
    raw: new Blob([bytes as Uint8Array<ArrayBuffer>]).stream(),
    rawSize: options.rawSize ?? bytes.length,
    setReject: vi.fn(),
    forward: vi.fn(),
    reply: vi.fn(async (reply: Sent) => {
      if (options.reply) return options.reply(reply);
      sent.push(reply);
      return { messageId: "<reply@abdullah1.dev>" };
    }),
  };
  return { message: message as unknown as ForwardableEmailMessage, sent, reply: message.reply };
}

// The lookups go offline: these tests are about the email, not the network.
beforeEach(() => vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new Error("offline")))));
afterEach(() => vi.unstubAllGlobals());

describe("forward-to-check by email", () => {
  it("answers a forward-as-attachment with the original's verdict", async () => {
    const { message, sent } = inbound(sample("forwarded-as-attachment.eml"), { from: "fwd-attach@inbox.example" });
    await handleEmail(message, {});
    expect(sent).toHaveLength(1);
    const reply = sent[0]!;
    expect(reply.from).toBe("check@abdullah1.dev");
    expect(reply.subject).toBe("phish-check verdict: Likely phishing");
    expect(reply.headers).toEqual({ "Auto-Submitted": "auto-replied" });
    expect(reply.text).toMatch(/^phish-check verdict: Likely phishing/);
    expect(reply.html).toContain("Likely phishing");
    // Nothing taken from the phish is clickable: the scammer's reply address only appears defanged...
    expect(reply.text).toContain("your answer goes to mailbox[.]test");
    expect(`${reply.text}\n${reply.html}`).not.toMatch(/mailbox\.test|paypa1-security\.test|https?:\/\/(?!phish\.abdullah1\.dev)/);
    // ...while the advice keeps the real site readable.
    expect(reply.text).toContain("Type paypal.com into your browser yourself");
  });

  it("answers a plain inline forward, and says the check was partial", async () => {
    const { message, sent } = inbound(sample("inline-forward.eml"), { from: "fwd-inline@inbox.example" });
    await handleEmail(message, {});
    expect(sent[0]?.text).toMatch(/^phish-check verdict: Likely phishing/);
    expect(sent[0]?.text).toContain("forwarded as plain text");
  });

  it("reads an email attached as a file", async () => {
    const attached = btoa(String.fromCharCode(...sample("lookalike-paypal.eml"))).replace(/.{76}/g, "$&\r\n");
    const raw = [
      "From: Alex Chen <alex@inbox.example>",
      "To: check@abdullah1.dev",
      "Subject: Is this real?",
      "MIME-Version: 1.0",
      'Content-Type: multipart/mixed; boundary="b"',
      "",
      "--b",
      "Content-Type: text/plain",
      "",
      "Found this in my inbox.",
      "--b",
      'Content-Type: application/octet-stream; name="suspicious.eml"',
      'Content-Disposition: attachment; filename="suspicious.eml"',
      "Content-Transfer-Encoding: base64",
      "",
      attached,
      "--b--",
      "",
    ].join("\r\n");
    const { message, sent } = inbound(raw, { from: "fwd-file@inbox.example" });
    await handleEmail(message, {});
    expect(sent[0]?.text).toMatch(/^phish-check verdict: Likely phishing/);
  });

  it("checks the original's signature against the key its domain publishes", async () => {
    // The original's own header vouches for a shop.test signature, but shop.test publishes no such key.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input).includes("._domainkey.")) return new Response(JSON.stringify({ Status: 3 }));
        throw new Error("offline");
      }),
    );
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-24T18:00:00Z"));
    try {
      const original = [
        "Received: from mail.shop.test (mail.shop.test [198.51.100.20]) by mx.inbox.example with ESMTPS; Sat, 24 Oct 2026 09:00:00 +0000",
        "Authentication-Results: mx.inbox.example; spf=pass smtp.mailfrom=shop.test; dkim=pass header.d=shop.test; dmarc=pass header.from=shop.test",
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=shop.test; s=s1; h=from:to:subject:date; bh=placeholder; b=placeholder",
        "From: Shop <orders@shop.test>",
        "To: alex@inbox.example",
        "Subject: Your order",
        "Date: Sat, 24 Oct 2026 09:00:00 +0000",
        "",
        "Your order has shipped.",
      ].join("\r\n");
      const raw = [
        "From: Alex Chen <alex@inbox.example>",
        "To: check@abdullah1.dev",
        "Subject: Fwd: Your order",
        'Content-Type: multipart/mixed; boundary="b1"',
        "",
        "--b1",
        "Content-Type: text/plain",
        "",
        "Is this real?",
        "--b1",
        "Content-Type: message/rfc822",
        "",
        original,
        "--b1--",
      ].join("\r\n");
      const { message, sent } = inbound(raw, { from: "fwd-dkim@inbox.example" });
      await handleEmail(message, {});
      expect(sent[0]?.text).toContain("Its signature doesn't check out");
    } finally {
      vi.useRealTimers();
    }
  });

  it("explains how to forward when there's no forwarded email in the message", async () => {
    const { message, sent } = inbound(sample("legit-order-confirmation.eml"), { from: "not-a-forward@inbox.example" });
    await handleEmail(message, {});
    expect(sent[0]?.text).toMatch(/^We couldn't find a forwarded email/);
    expect(sent[0]?.text).toContain("Your message had no attachments.");
  });

  it("says which attachments it found when none of them is an email", async () => {
    // Gmail's API turns an attached .eml into an unnamed HTML file when it sends the message.
    const raw = [
      "From: Alex Chen <alex@inbox.example>",
      "To: check@abdullah1.dev",
      "Subject: Is this real?",
      'Content-Type: multipart/mixed; boundary="b1"',
      "",
      "--b1",
      "Content-Type: text/plain",
      "",
      "See attached.",
      "--b1",
      'Content-Type: text/html; charset="utf-8"',
      "Content-Disposition: attachment",
      "",
      "<p>Dear Customer, visit evil.example now</p>",
      "--b1--",
    ].join("\r\n");
    const { message, sent } = inbound(raw, { from: "html-file@inbox.example" });
    await handleEmail(message, {});
    expect(sent[0]?.text).toContain("Your message had one attachment, an unnamed file (text/html, 1 KB), but it isn't an email.");
  });

  it("says so when the forward can't be read", async () => {
    const { message, sent } = inbound("This is not an email at all, just some words.", { from: "garbage@inbox.example" });
    await handleEmail(message, {});
    expect(sent[0]?.text).toMatch(/^We couldn't read the email you forwarded/);
  });

  it("turns away oversized forwards without reading them", async () => {
    const { message, sent } = inbound("x", { from: "huge@inbox.example", rawSize: MAX_FORWARD + 1 });
    Object.defineProperty(message, "raw", { get: () => { throw new Error("read an oversized forward"); } });
    await handleEmail(message, {});
    expect(sent[0]?.text).toMatch(/^That email is too large/);
  });

  it("never answers bounces, auto-replies, mailing lists or itself", async () => {
    const cases = [
      inbound(sample("inline-forward.eml"), { from: "mailer-daemon@inbox.example" }),
      inbound(sample("inline-forward.eml"), { from: "auto@inbox.example", headers: { "auto-submitted": "auto-replied" } }),
      inbound(sample("inline-forward.eml"), { from: "list@inbox.example", headers: { "list-id": "<news.inbox.example>" } }),
      inbound(sample("inline-forward.eml"), { from: "check@abdullah1.dev" }),
    ];
    for (const { message } of cases) expect(skipReason(message)).not.toBeNull();
    for (const { message, reply } of cases) {
      await handleEmail(message, {});
      expect(reply).not.toHaveBeenCalled();
    }
    expect(skipReason(inbound("x", { headers: { "auto-submitted": "no" } }).message)).toBeNull();
  });

  it("limits how many replies one sender gets", async () => {
    let replies = 0;
    for (let i = 0; i < 12; i++) {
      const { message, sent } = inbound("Not an email.", { from: "busy@inbox.example" });
      await handleEmail(message, {});
      replies += sent.length;
    }
    expect(replies).toBe(10);
  });

  it("still replies when Cloudflare refuses the extra header", async () => {
    let calls = 0;
    const { message, reply } = inbound("Not an email.", {
      from: "strict@inbox.example",
      reply: async (sent) => {
        calls++;
        if (sent.headers) throw new Error("header not allowed");
        return { messageId: "<ok@abdullah1.dev>" };
      },
    });
    await handleEmail(message, {});
    expect(calls).toBe(2);
    expect(reply.mock.calls[1]?.[0]).not.toHaveProperty("headers");
  });
});

describe("defang", () => {
  it("makes addresses unclickable but leaves ordinary numbers alone", () => {
    expect(defang("Visit https://evil.example/x, mail someone@evil.example, open invoice.zip from 203.0.113.50, pay 1.99")).toBe(
      "Visit hxxps://evil[.]example/x, mail someone@evil[.]example, open invoice[.]zip from 203.0.113[.]50, pay 1.99",
    );
  });
});
