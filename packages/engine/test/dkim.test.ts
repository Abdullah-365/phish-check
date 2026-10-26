import { generateKeyPairSync } from "node:crypto";
import { dkimSign } from "mailauth/lib/dkim/sign.js";
import { describe, expect, it } from "vitest";
import { dkimSignatures, verifySignatures, type DkimKey } from "../src/dkim.ts";

// Real key pairs, and a real DKIM signer (mailauth) as an independent reference implementation.
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ed = generateKeyPairSync("ed25519");
const rsaRecord = `v=DKIM1; k=rsa; p=${rsa.publicKey.export({ type: "spki", format: "der" }).toString("base64")}`;
// An Ed25519 key's SubjectPublicKeyInfo ends with the 32 raw key bytes, which is what DKIM publishes.
const edRecord = `v=DKIM1; k=ed25519; p=${ed.publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("base64")}`;

const MESSAGE = [
  "From: Shop News <news@shop.example>",
  "To: alex@inbox.example",
  "Subject: Your   order\r\n  has shipped",
  "Date: Mon, 26 Oct 2026 09:00:00 +0000",
  "Message-ID: <order-1@shop.example>",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Hello Alex,  \r\n\r\nYour order   is on its way.\t\r\n\r\n\r\n",
].join("\r\n");

async function sign(canonicalization: string, algorithm = "rsa-sha256", message = MESSAGE, maxBodyLength?: number): Promise<Uint8Array> {
  const privateKey = algorithm === "ed25519-sha256" ? ed.privateKey.export({ type: "pkcs8", format: "pem" }) : rsa.privateKey.export({ type: "pkcs8", format: "pem" });
  const result = await dkimSign(message, {
    canonicalization,
    algorithm,
    signatureData: [{ signingDomain: "shop.example", selector: "s1", privateKey, ...(maxBodyLength ? { maxBodyLength } : {}) }],
  });
  expect(result.errors).toEqual([]);
  return new TextEncoder().encode(result.signatures + message);
}

const keys = (record: string | null = rsaRecord): DkimKey[] => [{ domain: "shop.example", selector: "s1", record }];
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
const bytes = (value: string) => new TextEncoder().encode(value);

describe("DKIM verification", () => {
  for (const canonicalization of ["relaxed/relaxed", "simple/simple", "relaxed/simple", "simple/relaxed"]) {
    it(`verifies a genuine ${canonicalization} RSA signature`, async () => {
      expect(await verifySignatures(await sign(canonicalization), keys())).toEqual([{ domain: "shop.example", selector: "s1", result: "pass" }]);
    });
  }

  it("verifies Ed25519 signatures", async () => {
    expect((await verifySignatures(await sign("relaxed/relaxed", "ed25519-sha256"), keys(edRecord)))[0]?.result).toBe("pass");
  });

  it("lists the signatures to look up", async () => {
    expect(dkimSignatures(await sign("relaxed/relaxed"))).toEqual([{ domain: "shop.example", selector: "s1" }]);
  });

  it("calls a changed signed header a failure, and a changed body just changed", async () => {
    const signed = text(await sign("relaxed/relaxed"));
    expect((await verifySignatures(bytes(signed.replace("has shipped", "is delayed")), keys()))[0]?.result).toBe("fail");
    expect((await verifySignatures(bytes(signed.replace("on its way", "held at customs")), keys()))[0]?.result).toBe("body-changed");
  });

  it("fails against the wrong key, and says when there's no key", async () => {
    const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const wrong = `v=DKIM1; p=${other.publicKey.export({ type: "spki", format: "der" }).toString("base64")}`;
    const signed = await sign("relaxed/relaxed");
    expect((await verifySignatures(signed, keys(wrong)))[0]?.result).toBe("fail");
    expect((await verifySignatures(signed, keys(null)))[0]?.result).toBe("no-key");
    expect((await verifySignatures(signed, keys("v=DKIM1; p=")))[0]?.result).toBe("no-key");
  });

  it("calls a made-up signature a failure, whatever the body says", async () => {
    // Someone faking a signature can't compute b=, and rarely bothers with a matching bh= either.
    const signed = text(await sign("relaxed/relaxed"));
    const forged = signed.replace(/\bb=[A-Za-z0-9+/=\s]+?(?=\r\n[^ \t])/, "b=Zm9yZ2VkIHNpZ25hdHVyZQ==").replace("on its way", "held at customs");
    expect(forged).toContain("b=Zm9yZ2VkIHNpZ25hdHVyZQ==\r\nFrom:");
    expect((await verifySignatures(bytes(forged), keys()))[0]?.result).toBe("fail");
  });

  it("says when no key was looked up", async () => {
    expect((await verifySignatures(await sign("relaxed/relaxed"), []))[0]?.result).toBe("unchecked");
  });

  it("doesn't count a body with content added past the signed length as verified", async () => {
    const signed = await sign("relaxed/relaxed", "rsa-sha256", MESSAGE, 20);
    expect(text(signed)).toMatch(/\bl=20\b/);
    expect((await verifySignatures(signed, keys()))[0]?.result).toBe("body-changed");
  });

  it("still verifies after a company gateway tags the subject", async () => {
    const signed = text(await sign("relaxed/relaxed"));
    for (const tag of ["[EXTERNAL]", "(External Sender)", "[CAUTION: External email]", "***SPAM***", "EXT:", "[Suspected Phishing] [EXTERNAL]"]) {
      const tagged = signed.replace("Subject: Your", `Subject: ${tag} Your`);
      expect((await verifySignatures(bytes(tagged), keys()))[0]?.result, tag).toBe("pass");
    }
    // Any other change to the subject still breaks it.
    expect((await verifySignatures(bytes(signed.replace("Subject: Your", "Subject: [URGENT] Your")), keys()))[0]?.result).toBe("fail");
  });

  it("ignores signatures that don't cover the From line", async () => {
    const unsigned = text(await sign("relaxed/relaxed")).replace(/\bh=([^;]*)/, (_, list: string) => `h=${list.split(":").filter((h) => h.trim().toLowerCase() !== "from").join(":")}`);
    expect((await verifySignatures(bytes(unsigned), keys()))[0]?.result).toBe("unsupported");
  });

  it("accepts keys published as bare PKCS#1, and messages saved with LF line endings", async () => {
    const pkcs1 = `v=DKIM1; k=rsa; p=${rsa.publicKey.export({ type: "pkcs1", format: "der" }).toString("base64")}`;
    const signed = await sign("simple/simple");
    expect((await verifySignatures(signed, keys(pkcs1)))[0]?.result).toBe("pass");
    expect((await verifySignatures(bytes(text(signed).replace(/\r\n/g, "\n")), keys()))[0]?.result).toBe("pass");
  });
});
