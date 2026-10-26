import { describe, expect, it } from "vitest";
import { claimedDkimDomains, readAuth } from "../src/auth.ts";
import { BRANDS } from "../src/brands.ts";
import { extractContent } from "../src/content.ts";
import { belongsTo, claimedHost, imitatedBrand, registrable, unicodeHost } from "../src/domains.ts";
import type { ParsedEmail } from "../src/types.ts";

const brand = (name: string) => BRANDS.find((b) => b.name === name)!;
const marked = (host: string, name: string) => {
  const match = imitatedBrand(host, [brand(name)]);
  return match && { kind: match.kind, marked: match.marks.map(([s, e]) => match.display.slice(s, e)) };
};

describe("look-alike domains", () => {
  it("catches swapped characters and names the swap", () => {
    expect(marked("paypa1-security.test", "PayPal")).toEqual({ kind: "swap", marked: ["1"] });
    expect(marked("rnicrosoft-login.test", "Microsoft")).toEqual({ kind: "swap", marked: ["rn"] });
    expect(imitatedBrand("paypa1.test", [brand("PayPal")])?.swap).toBe('the number "1" for the letter "l"');
  });

  it("catches one-letter typos and brand names inside other domains", () => {
    expect(marked("paypai.test", "PayPal")).toEqual({ kind: "typo", marked: ["i"] });
    expect(marked("paypal.com.account-check.test", "PayPal")).toEqual({ kind: "contains", marked: ["paypal"] });
    expect(marked("login-m365-keep.test", "Microsoft")).toEqual({ kind: "contains", marked: ["m365"] });
  });

  it("decodes punycode so letters from other alphabets can be shown", () => {
    // "pаypal" with a Cyrillic а
    expect(unicodeHost("xn--pypal-4ve.com")).toBe("pаypal.com");
    expect(marked("xn--pypal-4ve.com", "PayPal")).toEqual({ kind: "swap", marked: ["а"] });
  });

  it("leaves the brand's own domains alone", () => {
    expect(imitatedBrand("email.paypal.com", [brand("PayPal")])).toBeNull();
    expect(belongsTo("paypal.ca", brand("PayPal"))).toBe(true);
    expect(belongsTo("paypal.support", brand("PayPal"))).toBe(false);
  });

  it("doesn't flag short brand names inside ordinary words", () => {
    expect(imitatedBrand("groups.example", [brand("UPS")])).toBeNull();
    expect(imitatedBrand("ups-delivery.test", [brand("UPS")])?.kind).toBe("contains");
  });
});

describe("domain helpers", () => {
  it("finds the registrable domain", () => {
    expect(registrable("mail.shop.example")).toBe("shop.example");
    expect(registrable("www.amazon.co.uk")).toBe("amazon.co.uk");
  });

  it("reads the domain a link's text claims", () => {
    expect(claimedHost("https://www.paypal.com/signin")).toBe("www.paypal.com");
    expect(claimedHost("PayPal.com")).toBe("paypal.com");
    expect(claimedHost("Sign in now")).toBeNull();
  });
});

describe("reading view", () => {
  it("spots buttons, including coloured table cells", () => {
    const content = extractContent(
      `<p><a href="https://a.test" style="background-color:#0070ba">Pay now</a></p>
       <table><tr><td bgcolor="#1a73e8"><a href="https://b.test">Open</a></td></tr></table>
       <p><a href="https://c.test">plain link</a></p>`,
      "",
    );
    const links = content.blocks.flatMap((b) => b.inlines).filter((i) => i.type === "link");
    expect(links.map((l) => l.type === "link" && l.button)).toEqual([true, true, false]);
  });

  it("finds tracking pixels and drops hidden preview text", () => {
    const content = extractContent(
      `<div style="display:none">Preview text</div><p>Hello</p><img src="https://t.test/o.gif" width="1" height="1">`,
      "",
    );
    const inlines = content.blocks.flatMap((b) => b.inlines);
    expect(inlines.some((i) => i.type === "text" && i.text.includes("Preview"))).toBe(false);
    expect(inlines.find((i) => i.type === "image")).toMatchObject({ tracker: true });
  });

  it("joins lines a mail app wrapped, but keeps short lines apart", () => {
    const content = extractContent("", "I'm in meetings all day and can't take calls. I need you to pick up\n5 gift cards today.\n\nThanks,\nSam");
    const [first, second] = content.blocks;
    expect(first!.inlines).toEqual([{ type: "text", text: "I'm in meetings all day and can't take calls. I need you to pick up 5 gift cards today." }]);
    expect(second!.inlines.map((i) => i.type)).toEqual(["text", "break", "text"]);
  });

  it("autolinks addresses in plain text", () => {
    const content = extractContent("", "Go to <https://example.test/a> now.");
    const link = content.blocks[0]!.inlines.find((i) => i.type === "link");
    expect(link).toMatchObject({ href: "https://example.test/a", text: "https://example.test/a" });
  });
});

describe("authentication results", () => {
  const email = (authenticationResults: string[], extra: { name: string; value: string }[] = []) =>
    ({ authenticationResults, headers: extra }) as unknown as ParsedEmail;

  it("reads the top header and prefers any passing DKIM signature", () => {
    const auth = readAuth(email(["mx.google.com; dkim=fail header.d=a.test; dkim=pass header.d=b.test; spf=pass; dmarc=pass"]));
    expect(auth).toEqual({ spf: "pass", dkim: "pass", dmarc: "pass", recordedBy: "mx.google.com", verified: false });
  });

  it("reads which domains a header claims passed DKIM", () => {
    expect(claimedDkimDomains("mx.google.com; dkim=pass header.i=@PayPal.com header.s=pp1; dkim=fail header.d=x.test; dkim=pass (signature was verified) header.d=mail.shop.example")).toEqual([
      "paypal.com",
      "mail.shop.example",
    ]);
    expect(claimedDkimDomains(undefined)).toEqual([]);
  });

  it("doesn't treat Microsoft's bestguesspass as a real DMARC pass", () => {
    expect(readAuth(email(["spf=pass; dkim=none; dmarc=bestguesspass action=none"])).dmarc).toBe("none");
  });

  it("falls back to Received-SPF when there are no results", () => {
    expect(readAuth(email([], [{ name: "received-spf", value: "Softfail (domain does not designate)" }])).spf).toBe("softfail");
  });
});
