import { deflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { analyzeEmail } from "../src/index.ts";
import { attachmentChecks } from "../src/attachments.ts";
import { impossibleDomain } from "../src/checks.ts";
import { extractContent } from "../src/content.ts";
import { latinize } from "../src/domains.ts";
import { evasionFindings } from "../src/evasion.ts";
import { providerFindings } from "../src/provider.ts";
import { parseRoute } from "../src/route.ts";
import type { AttachmentInfo, ParsedEmail } from "../src/types.ts";
import { inspectUrl, looksRandom } from "../src/urls.ts";
import { headline } from "../src/verdict.ts";
import { markWording, subjectGroups, wordingFindings } from "../src/wording.ts";

const headers = (pairs: [string, string][], authenticationResults: string[] = []) =>
  ({ headers: pairs.map(([name, value]) => ({ name, value })), authenticationResults }) as unknown as ParsedEmail;

/** A minimal email around a body, so detectors run end to end. */
const email = (body: string, extra = "", from = "Shop <news@shop.example>", subject = "Hello") =>
  analyzeEmail(`From: ${from}\r\nTo: alex@inbox.example\r\nSubject: ${subject}\r\nDate: Mon, 19 Oct 2026 10:00:00 +0000\r\n${extra}Content-Type: text/html; charset=utf-8\r\n\r\n${body}`);

const rules = async (p: Promise<{ findings: { rule: string }[] }>) => (await p).findings.map((f) => f.rule);

describe("provider verdicts", () => {
  it("reads Microsoft's spam score and phishing category", () => {
    expect(providerFindings(headers([["x-ms-exchange-organization-scl", "9"]]))[0]).toMatchObject({ rule: "provider-flagged", severity: "high" });
    expect(providerFindings(headers([["x-ms-exchange-organization-scl", "5"]]))[0]).toMatchObject({ severity: "medium" });
    expect(providerFindings(headers([["x-forefront-antispam-report", "CIP:1.2.3.4;CAT:PHSH;SFV:SPM;SCL:9"]]))[0]?.real?.text).toBe("Microsoft: phishing");
    expect(providerFindings(headers([["x-ms-exchange-organization-scl", "-1"]]))).toEqual([]);
  });

  it("reads SpamAssassin-style flags and Microsoft's spoof check", () => {
    expect(providerFindings(headers([["x-spam-flag", "YES"]]))[0]).toMatchObject({ severity: "medium" });
    expect(providerFindings(headers([["x-spam-status", "No, score=-1.2"]]))).toEqual([]);
    const spoof = providerFindings(headers([], ["spf=none; dkim=none; dmarc=none; compauth=fail reason=001"]));
    expect(spoof[0]).toMatchObject({ rule: "spoof-check", real: { text: "compauth=fail reason=001" } });
  });
});

describe("URL analysis", () => {
  it("unwraps redirects to find the real destination", () => {
    const google = inspectUrl("https://www.google.com/url?q=https%3A%2F%2Fevil.test%2Flogin&sa=D")!;
    expect(google).toMatchObject({ host: "evil.test", via: "www.google.com" });
    const bing = inspectUrl(`https://www.bing.com/ck/a?!&&p=x&u=a1${btoa("https://evil.test/x").replace(/=+$/, "")}`)!;
    expect(bing.host).toBe("evil.test");
  });

  it("treats the reader's own security wrapper as protection, not a redirect", () => {
    const wrapped = inspectUrl(`https://eur01.safelinks.protection.outlook.com/?url=${encodeURIComponent("https://shop.example/a")}&data=1`)!;
    expect(wrapped).toMatchObject({ host: "shop.example", via: null, protectedBy: "eur01.safelinks.protection.outlook.com" });
  });

  it("tags disposable hosting, cheap endings, IPs, tricks and downloads", () => {
    const tags = (href: string) => [...inspectUrl(href)!.tags].sort();
    expect(tags("https://kit-login.web.app/")).toEqual(["disposable", "lure-host"]);
    expect(tags("http://juliodedansk.icu/x")).toEqual(["cheap-tld"]);
    expect(tags("http://5duuevrmkuz.fasteshop.site/")).toEqual(["cheap-tld", "random"]);
    expect(tags("http://20.196.139.106.static.hostiran.name/")).toContain("ip-host");
    expect(tags("http://paypal.com@evil.test/")).toContain("userinfo");
    expect(tags("https://files.test/invoice.zip")).toContain("download");
  });

  it("tells random strings from real names", () => {
    expect(["5duuevrmkuz", "ndagauz7qjw", "dt3-161255673571", "gw0b043ph9w3wu242ntj"].map(looksRandom)).toEqual([true, true, true, true]);
    expect(["wellsfargo", "mobiusvc", "czyborra", "anonovovamos", "fasteshop", "juliodedansk"].map(looksRandom)).toEqual([false, false, false, false, false, false]);
  });
});

describe("multilingual lures", () => {
  const groups = (html: string) => {
    const content = extractContent(html, "");
    return wordingFindings(markWording(content), new Map()).map((f) => f.rule);
  };

  it("reads scams in several languages", () => {
    expect(groups("<p>Sua entrega foi retida. Pague a taxa de entrega.</p>")).toContain("delivery");
    expect(groups("<p>Ihr Konto wurde gesperrt.</p>")).toContain("pressure");
    expect(groups("<p>Votre colis est en attente.</p>")).toContain("delivery");
    expect(groups("<p>Almacenamiento lleno. Archivos eliminándose.</p>")).toContain("storage");
    expect(groups("<p>Ontmoet Russische schoonheden vanavond.</p>")).toContain("dating");
    expect(groups("<p>Notificação extrajudicial: infração e multa pendente.</p>")).toContain("fines");
  });

  it("sees through look-alike letters", () => {
    // Cyrillic е, і, о and а inside Latin words
    expect(groups("<p>Vеrіfy yоur dеtаils within 24 hours</p>")).toEqual(expect.arrayContaining(["pressure"]));
    expect(latinize("Ꮮеdgеr")).toBe("Ledger");
  });

  it("needs a prize next to the congratulations", () => {
    expect(groups("<p>Congratulations on the new job!</p>")).not.toContain("prize");
    expect(groups("<p>Congratulations! You are our lucky winner.</p>")).toContain("prize");
    expect(groups("<p>I think you won the argument.</p>")).not.toContain("prize");
  });

  it("raises a lure that's laid on thick", () => {
    const findings = wordingFindings(markWording(extractContent("<p>Free spins! Casino welcome bonus. Jackpot slot machines.</p>", "")), new Map());
    expect(findings.find((f) => f.rule === "gambling")?.severity).toBe("high");
  });

  it("checks the subject line too, and quotes it when the body is clean", () => {
    expect(new Set(subjectGroups("Última advertencia. Almacenamiento lleno").keys())).toEqual(new Set(["pressure", "storage"]));
    const findings = wordingFindings(markWording(extractContent("<p>Hello</p>", "")), subjectGroups("Microsoft account unusual sign-in activity"));
    expect(findings.find((f) => f.rule === "pressure")?.seen?.text).toMatch(/^".+"$/);
  });

  it("reads brand names spelled out with spaces", () => {
    expect(latinize("C o i n b a s e")).toBe("Coinbase");
    expect(latinize("Plan A or B")).toBe("Plan A or B");
  });
});

describe("evasion tricks", () => {
  const run = (html: string, extra: Partial<Parameters<typeof evasionFindings>[0]> = {}) =>
    evasionFindings({ content: extractContent(html, ""), subject: "Hi", senderName: "", recipient: "alex@inbox.example", headerText: "", recipients: [], mailingList: false, ...extra }).map((f) => f.rule);

  it("finds hidden filler, styled letters and spaced-out brands", () => {
    expect(run(`<p>Hi</p><div style="display:none">${"filler words ".repeat(40)}</div>`)).toContain("evasion-hidden-text");
    expect(run("<p>Hi</p>", { subject: "𝐋𝐎𝐎𝐊𝐈𝐍𝐆 𝐅𝐎𝐑 𝐁𝐄𝐓𝐓𝐄𝐑" })).toContain("evasion-styled-letters");
    expect(run("<p>Your e b a y receipt</p>")).toContain("evasion-spaced-letters");
  });

  it("finds spam-tool leftovers and mass-mail greetings", () => {
    expect(run("<p>1. __Ranodm_anm[10,s]</p>")).toContain("evasion-placeholder");
    expect(run("<p>Hallo alex@inbox.example, your gift is waiting</p>")).toContain("evasion-addressed-by-email");
    expect(run('<p>Hello</p>', { senderName: "Ꮮеdgеr" })).toContain("evasion-mixed-script");
  });

  it("shows which letters are impostors and which words are styled", () => {
    const findings = evasionFindings({ content: extractContent("<p>Hi</p>", ""), subject: "𝐋𝐎𝐎𝐊𝐈𝐍𝐆 𝐅𝐎𝐑 𝐁𝐄𝐓𝐓𝐄𝐑", senderName: "Lоwеs", recipient: null, headerText: "", recipients: [], mailingList: false });
    const mixed = findings.find((f) => f.rule === "evasion-mixed-script")!;
    // Cyrillic о and е sit at 1 and 3 in "Lоwеs".
    expect(mixed.seen).toEqual({ text: "Lоwеs", marks: [[1, 2], [3, 4]] });
    expect(mixed.real?.text).toBe("2 Cyrillic letters posing as Latin ones");
    const styled = findings.find((f) => f.rule === "evasion-styled-letters")!;
    expect(styled.seen?.text).toBe("𝐋𝐎𝐎𝐊𝐈𝐍𝐆 𝐅𝐎𝐑 𝐁𝐄𝐓𝐓𝐄𝐑");
    expect(styled.target).toEqual({ kind: "header", field: "subject" });
  });

  it("unmasks a brand spelled out with spaces in the sender's name", async () => {
    const analysis = await email("<p>Your account has been restricted.</p>", "", "C o i n b a s e <noreply@shangrila.example>");
    expect(analysis.findings.find((f) => f.rule === "sender-disguise")?.brand).toBe("Coinbase");
    expect(analysis.findings.find((f) => f.rule === "evasion-spaced-letters")?.target).toEqual({ kind: "header", field: "from" });
  });

  it("spots image-only emails, but not a preview line in a normal newsletter", () => {
    expect(run('<a href="https://x.test/"><img src="https://x.test/a.png"></a>')).toContain("evasion-image-only");
    expect(run(`<div style="display:none">Preview text for the inbox list</div><p>${"A real newsletter paragraph. ".repeat(5)}</p>`)).toEqual([]);
  });
});

describe("hostile input", () => {
  it("survives malformed encoding in redirect links", async () => {
    expect(inspectUrl("https://urldefense.proofpoint.com/v2/url?u=http-3A__x-ZZ&d=1")?.host).toBe("urldefense.proofpoint.com");
    expect(inspectUrl("https://r.example/?url=https%253a%252F%252Fx%25ZZ")?.host).toBe("r.example");
    const analysis = await email('<p><a href="https://urldefense.proofpoint.com/v2/url?u=http-3A__x-ZZ">Sign in</a></p>');
    expect(analysis.verdict).toBeDefined();
  });

  it("survives HTML nested tens of thousands deep, and still reads it", async () => {
    const analysis = await email(`${"<span>".repeat(60_000)}Verify your account within 24 hours${"</span>".repeat(60_000)}`);
    expect(analysis.findings.map((f) => f.rule)).toContain("pressure");
  });

  it("doesn't let a fake 'Forwarded message' block swap out the real sender", async () => {
    const auth = "Authentication-Results: mx.inbox.example; spf=fail smtp.mailfrom=evil.example; dkim=none; dmarc=fail header.from=evil.example\r\nX-MS-Exchange-Organization-SCL: 9\r\n";
    const fake = "<p>---------- Forwarded message ---------<br>From: Apple &lt;noreply@apple.com&gt;<br>Subject: Apple ID locked</p><p>Your Apple ID is locked. Verify your account within 24 hours.</p>";
    for (const subject of ["Apple ID locked", "Fwd: Apple ID locked"]) {
      const analysis = await email(fake, auth, "Apple Support <support@evil.example>", subject);
      expect(analysis.partial).toBe(false);
      expect(analysis.sender?.address).toBe("support@evil.example");
      expect(analysis.verdict).toBe("phishing");
    }
  });
});

describe("delivery route", () => {
  it("reads TLS from the protocol, not from host names", () => {
    const hop = (clause: string) => parseRoute([`from smtps1.host.example (smtps1.host.example [198.51.100.7]) by mx.inbox.example ${clause}; Mon, 19 Oct 2026 10:00:00 +0000`])[0]!.tls;
    expect(hop("with ESMTP id x")).toBe(false);
    expect(hop("with ESMTPS id x")).toBe(true);
    expect(hop("(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384) with ESMTP id x")).toBe(true);
  });
});

describe("link evidence", () => {
  it("keeps the real owner of a long host in view", async () => {
    const analysis = await email('<p><a href="http://jo4dh9l5i5c422fb6xcfintmarqbj.blr1.cdn.digitaloceanspaces.com/index.html">Sign in to PayPal</a></p>');
    const finding = analysis.findings.find((f) => f.rule === "link-brand")!;
    const [start, end] = finding.real!.marks![0]!;
    expect(finding.real!.text.slice(start, end)).toBe("jo4dh9l5….blr1.cdn.digitaloceanspaces.com");
  });

  it("trims link text that runs on for a paragraph", async () => {
    const analysis = await email(`<p><a href="https://bit.ly/abc">${"Congratulations, you were selected. ".repeat(6)}</a></p>`);
    const seen = analysis.findings.find((f) => f.rule === "link-shortener")?.seen?.text ?? "";
    expect([...seen].length).toBeLessThanOrEqual(90);
    expect(seen.endsWith("…")).toBe(true);
  });
});

describe("headlines", () => {
  it("doesn't claim nothing was found while listing a minor finding", () => {
    const minor = { id: "prize", rule: "prize", category: "wording", severity: "medium", title: "", explanation: "", lensLabel: "", target: { kind: "header", field: "subject" } } as const;
    expect(headline("no-red-flags", [minor]).headline).toBe("One small thing stood out, but nothing that marks it as phishing.");
    expect(headline("no-red-flags", []).headline).toBe("Nothing we checked looks wrong.");
  });
});

describe("sender forensics", () => {
  it("knows which domains can't exist", () => {
    expect(impossibleDomain("detran979190")).toMatch(/no ending/);
    expect(impossibleDomain("%avisos.com")).toMatch(/characters/);
    expect(impossibleDomain("")).toMatch(/no domain/);
    expect(impossibleDomain("shop.example")).toBeNull();
    expect(impossibleDomain("mail.google.com")).toBeNull();
  });

  it("flags impossible and machine-generated senders end to end", async () => {
    expect(await rules(email("<p>Hi</p>", "", "Correios <contato@correios>"))).toEqual(expect.arrayContaining(["sender-invalid", "sender-disguise"]));
    expect(await rules(email("<p>Hi</p>", "", "Deals <x@gw0b043ph9w3wu242ntj.com>"))).toContain("sender-random");
  });
});

describe("attachment inspection", () => {
  const file = (filename: string, content: string | Uint8Array, declaredType = "application/octet-stream"): AttachmentInfo => {
    const bytes = typeof content === "string" ? new TextEncoder().encode(content) : content;
    return { filename, declaredType, disposition: "attachment", size: bytes.length, content: bytes };
  };
  const check = async (f: AttachmentInfo) => (await attachmentChecks([f], "")).findings.map((x) => x.rule);

  it("reads links inside PDFs, including compressed ones", async () => {
    expect(await check(file("invoice.pdf", "%PDF-1.4\n1 0 obj << /A << /S /URI /URI (https://secure-login.web.app/x) >> >> endobj\n%%EOF"))).toContain("attachment-link");
    const packed = deflateSync(Buffer.from("<< /S /URI /URI (https://kit-verify.pages.dev/) >>"));
    const pdf = Buffer.concat([Buffer.from("%PDF-1.7\n2 0 obj << /Length 9 /Filter /FlateDecode >>\nstream\n"), packed, Buffer.from("\nendstream\nendobj\n%%EOF")]);
    expect(await check(file("statement.pdf", new Uint8Array(pdf)))).toContain("attachment-link");
  });

  it("flags PDFs that run code", async () => {
    expect(await check(file("doc.pdf", "%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj"))).toContain("attachment-pdf-active");
  });

  it("finds programs hidden in archives and macros hidden in Office files", async () => {
    expect(await check(file("docs.zip", zip(["readme.txt", "invoice.pdf.exe"])))).toContain("attachment-archive-program");
    expect(await check(file("report.docx", zip(["[Content_Types].xml", "word/vbaProject.bin"])))).toContain("attachment-macro");
    expect(await check(file("photos.zip", zip(["a.jpg"], true)))).toContain("attachment-locked");
  });

  it("doesn't call a readable, unlocked ZIP locked just because the email mentions a password", async () => {
    const plain = await attachmentChecks([file("policy.zip", zip(["password-policy.pdf"]))], "The new password policy is attached.");
    expect(plain.findings.map((f) => f.rule)).not.toContain("attachment-locked");
    // A RAR can't be listed, so the hint in the body still counts.
    const rar = await attachmentChecks([file("invoice.rar", "Rar!\x1a\x07\x00")], "The password is 1234.");
    expect(rar.findings.map((f) => f.rule)).toContain("attachment-locked");
  });

  it("scans a PDF stuffed with stream keywords in one quick pass", async () => {
    const stuffed = `%PDF-1.7\n${"/FlateDecode ".repeat(40_000)}${"x".repeat(2_000_000)}`;
    const started = performance.now();
    await attachmentChecks([file("big.pdf", stuffed)], "");
    // The old pattern scan took minutes on files like this.
    expect(performance.now() - started).toBeLessThan(2000);
  });

  it("flags iOS configuration profiles and sign-in pages", async () => {
    expect(await check(file("account sync settings", "<?xml version=\"1.0\"?><plist><dict><key>PayloadType</key></dict></plist>"))).toContain("attachment-profile");
    const page = await attachmentChecks([file("scan.html", '<html><form action="https://evil.test/p"><input type="password"></form></html>')], "");
    expect(page.findings[0]?.explanation).toMatch(/sign-in form/);
  });
});

/** Builds a ZIP with empty entries: enough for the central directory to be read. */
function zip(names: string[], encrypted = false): Uint8Array {
  const enc = new TextEncoder();
  const locals: number[] = [];
  const central: number[] = [];
  const u16 = (n: number) => [n & 255, (n >> 8) & 255];
  const u32 = (n: number) => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255];
  for (const name of names) {
    const bytes = [...enc.encode(name)];
    const flags = encrypted ? 1 : 0;
    const offset = locals.length;
    locals.push(...u32(0x04034b50), ...u16(20), ...u16(flags), ...u16(0), ...u32(0), ...u32(0), ...u32(0), ...u32(0), ...u16(bytes.length), ...u16(0), ...bytes);
    central.push(...u32(0x02014b50), ...u16(20), ...u16(20), ...u16(flags), ...u16(0), ...u32(0), ...u32(0), ...u32(0), ...u32(0), ...u16(bytes.length), ...u16(0), ...u16(0), ...u16(0), ...u16(0), ...u32(0), ...u32(offset), ...bytes);
  }
  const end = [...u32(0x06054b50), ...u16(0), ...u16(0), ...u16(names.length), ...u16(names.length), ...u32(central.length), ...u32(locals.length), ...u16(0)];
  return new Uint8Array([...locals, ...central, ...end]);
}
