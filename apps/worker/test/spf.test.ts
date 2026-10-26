import { describe, expect, it } from "vitest";
import type { DnsAnswer, DnsType } from "../src/dns.ts";
import { evaluateSpf } from "../src/spf.ts";

/** A fake DNS zone: TXT records as text, A/AAAA as addresses, MX as host names. */
function zone(records: Record<string, Partial<Record<DnsType, string[]>>>) {
  const asked: string[] = [];
  const types = { A: 1, AAAA: 28, MX: 15, TXT: 16 } as const;
  const lookup = async (name: string, type: DnsType): Promise<DnsAnswer> => {
    asked.push(`${type} ${name}`);
    const entry = records[name.toLowerCase()];
    if (!entry) return { status: 3, records: [] };
    if (name === "servfail.test") return { status: 2, records: [] };
    // TXT data comes back quoted, long records split into strings, as DNS over HTTPS returns it.
    const data = (entry[type] ?? []).map((value) => (type === "TXT" ? `"${value.match(/.{1,255}/g)!.join('" "')}"` : type === "MX" ? `10 ${value}.` : value));
    return { status: 0, records: data.map((d) => ({ type: types[type], data: d })) };
  };
  return { lookup, asked };
}

describe("SPF", () => {
  it("passes a server the record lists, through includes and redirects", async () => {
    const dns = zone({
      "shop.test": { TXT: ["v=spf1 include:_spf.mailer.test -all"] },
      "_spf.mailer.test": { TXT: ["v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 redirect=_more.mailer.test"] },
      "_more.mailer.test": { TXT: ["v=spf1 ip4:198.51.100.7 ~all"] },
    });
    expect(await evaluateSpf("shop.test", "192.0.2.44", dns.lookup)).toBe("pass");
    expect(await evaluateSpf("shop.test", "2001:db8::25", dns.lookup)).toBe("pass");
    expect(await evaluateSpf("shop.test", "198.51.100.7", dns.lookup)).toBe("pass");
    // An include that doesn't match falls through to the outer record's -all.
    expect(await evaluateSpf("shop.test", "203.0.113.9", dns.lookup)).toBe("fail");
  });

  it("reads each qualifier, and neutral when nothing matches", async () => {
    for (const [all, result] of [["-all", "fail"], ["~all", "softfail"], ["?all", "neutral"], ["", "neutral"], ["+all", "pass"]]) {
      const dns = zone({ "shop.test": { TXT: [`v=spf1 ip4:192.0.2.1 ${all}`.trim()] } });
      expect(await evaluateSpf("shop.test", "203.0.113.9", dns.lookup), all).toBe(result);
    }
  });

  it("matches a and mx mechanisms, with prefix lengths", async () => {
    const dns = zone({
      "shop.test": { TXT: ["v=spf1 a/30 mx:mail.test -all"], A: ["192.0.2.8"] },
      "mail.test": { MX: ["mx1.mail.test", "mx2.mail.test"] },
      "mx1.mail.test": { A: ["198.51.100.1"] },
      "mx2.mail.test": { A: ["198.51.100.2"] },
    });
    expect(await evaluateSpf("shop.test", "192.0.2.11", dns.lookup)).toBe("pass");
    expect(await evaluateSpf("shop.test", "192.0.2.12", dns.lookup)).toBe("fail");
    expect(await evaluateSpf("shop.test", "198.51.100.2", dns.lookup)).toBe("pass");
  });

  it("expands macros, such as the reversed address in exists", async () => {
    const dns = zone({
      "shop.test": { TXT: ["v=spf1 exists:%{ir}.%{v}._spf.%{d} -all"] },
      "9.113.0.203.in-addr._spf.shop.test": { A: ["127.0.0.2"] },
    });
    expect(await evaluateSpf("shop.test", "203.0.113.9", dns.lookup)).toBe("pass");
    expect(dns.asked).toContain("A 9.113.0.203.in-addr._spf.shop.test");
    expect(await evaluateSpf("shop.test", "203.0.113.10", dns.lookup)).toBe("fail");
  });

  it("says none without a record, and permerror for broken ones", async () => {
    const dns = zone({
      "plain.test": { TXT: ["google-site-verification=abc"] },
      "twice.test": { TXT: ["v=spf1 -all", "v=spf1 +all"] },
      "typo.test": { TXT: ["v=spf1 ipv4:192.0.2.1 -all"] },
      "loop.test": { TXT: ["v=spf1 include:loop.test -all"] },
      "dangling.test": { TXT: ["v=spf1 include:nowhere.test -all"] },
      "voids.test": { TXT: ["v=spf1 a:x1.test a:x2.test a:x3.test -all"] },
    });
    expect(await evaluateSpf("nowhere.test", "192.0.2.1", dns.lookup)).toBe("none");
    expect(await evaluateSpf("plain.test", "192.0.2.1", dns.lookup)).toBe("none");
    expect(await evaluateSpf("twice.test", "192.0.2.1", dns.lookup)).toBe("permerror");
    expect(await evaluateSpf("typo.test", "192.0.2.1", dns.lookup)).toBe("permerror");
    // Endless includes run into the 10-lookup limit.
    expect(await evaluateSpf("loop.test", "192.0.2.1", dns.lookup)).toBe("permerror");
    expect(await evaluateSpf("dangling.test", "192.0.2.1", dns.lookup)).toBe("permerror");
    // More than two lookups that find nothing.
    expect(await evaluateSpf("voids.test", "192.0.2.1", dns.lookup)).toBe("permerror");
  });

  it("calls a DNS failure temperror, never a fail", async () => {
    const dns = zone({ "shop.test": { TXT: ["v=spf1 include:servfail.test -all"] }, "servfail.test": {} });
    expect(await evaluateSpf("shop.test", "192.0.2.1", dns.lookup)).toBe("temperror");
    const broken = async (): Promise<DnsAnswer> => {
      throw new Error("offline");
    };
    expect(await evaluateSpf("shop.test", "192.0.2.1", broken)).toBe("temperror");
  });

  it("only trusts a pass when a term needed something unknown here", async () => {
    // ptr needs a reverse lookup, and %{l} the sender's mailbox: either might have matched.
    const dns = zone({
      "ptr.test": { TXT: ["v=spf1 ptr ip4:192.0.2.1 -all"] },
      "local.test": { TXT: ["v=spf1 exists:%{l}.allow.local.test ip4:192.0.2.1 -all"] },
    });
    expect(await evaluateSpf("ptr.test", "192.0.2.1", dns.lookup)).toBe("pass");
    expect(await evaluateSpf("ptr.test", "203.0.113.9", dns.lookup)).toBe("temperror");
    expect(await evaluateSpf("local.test", "192.0.2.1", dns.lookup)).toBe("pass");
    expect(await evaluateSpf("local.test", "203.0.113.9", dns.lookup)).toBe("temperror");
  });

  it("stops after a dozen DNS queries", async () => {
    // Each include costs three queries (its record, its MX, the MX host's address) and two lookups.
    const records: Record<string, Partial<Record<DnsType, string[]>>> = { "wide.test": { TXT: [`v=spf1 ${Array.from({ length: 4 }, (_, i) => `include:i${i}.test`).join(" ")} -all`] } };
    for (let i = 0; i < 4; i++) {
      records[`i${i}.test`] = { TXT: ["v=spf1 mx -all"], MX: [`mx.i${i}.test`] };
      records[`mx.i${i}.test`] = { A: ["198.51.100.9"] };
    }
    const dns = zone(records);
    expect(await evaluateSpf("wide.test", "192.0.2.1", dns.lookup)).toBe("temperror");
    expect(dns.asked.length).toBeLessThanOrEqual(12);
  });

  it("treats an IP address where a domain belongs as a broken record, as RFC 7208 does", async () => {
    const dns = zone({ "shop.test": { TXT: ["v=spf1 ip4:192.0.2.1 a:198.51.100.7 -all"] } });
    expect(await evaluateSpf("shop.test", "192.0.2.1", dns.lookup)).toBe("permerror");
  });
});
