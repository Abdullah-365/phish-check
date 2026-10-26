import { parse } from "tldts";
import { BRANDS, FREE_MAIL, ROLE_NAME, type Brand } from "./brands.ts";
import { images, links } from "./content.ts";
import { addressDomain, belongsTo, claimedHost, imitatedBrand, latinize, registrable, unicodeHost, type BrandMatch } from "./domains.ts";
import type { Content, Finding, Mailbox, Severity, Snippet } from "./types.ts";
import { inspectUrl, looksRandom, type UrlInfo, type UrlTag } from "./urls.ts";

export interface CheckContext {
  sender: Mailbox | null;
  replyTo: Mailbox | null;
  recipient: string | null;
  content: Content;
  /** Brands the email mentions anywhere: only these are checked for look-alikes. */
  brands: Brand[];
  /** The brand the sender's display name claims, if any. */
  claimed: Brand | null;
  /** Mailing lists set Reply-To to the list on purpose. */
  mailingList: boolean;
}

/** An address shown the way a reader sees it, with its domain marked. */
function addressSnippet(address: string, marks?: [number, number][]): Snippet {
  const at = address.lastIndexOf("@") + 1;
  const domain = unicodeHost(address.slice(at).toLowerCase());
  const text = address.slice(0, at) + domain;
  return { text, marks: (marks ?? [[0, domain.length]]).map(([s, e]) => [s + at, e + at]) };
}

function imitationReason(match: BrandMatch): string {
  const name = match.brand.name;
  if (match.kind === "swap" && match.swap) return `swaps ${match.swap}`;
  if (match.kind === "typo") return `is one letter off from ${name}'s real domain`;
  return `puts ${name}'s name inside a domain ${name} doesn't own`;
}

const RESERVED_TLD = /\.(test|example|invalid|localhost)$/;

/** Why a sender domain can't exist on the internet, or null when it can. */
export function impossibleDomain(domain: string): string | null {
  if (!domain) return "it has no domain at all";
  let ascii: string;
  try {
    ascii = new URL(`http://${domain}`).hostname;
  } catch {
    return `"${domain}" contains characters no domain can have`;
  }
  if (!ascii.includes(".")) return `"${domain}" has no ending like .com, so it isn't a complete domain`;
  if (RESERVED_TLD.test(ascii)) return null;
  const info = parse(ascii);
  if (info.isIp) return null;
  if (!info.domain || (!info.isIcann && !info.isPrivate)) return `"${domain}" doesn't end in any real domain ending`;
  return null;
}

export function senderFindings(ctx: CheckContext): Finding[] {
  const sender = ctx.sender;
  if (!sender?.address) {
    return [
      {
        id: "sender-missing",
        rule: "sender-missing",
        category: "sender",
        severity: "high",
        title: "It hides who sent it",
        ...(sender?.name ? { seen: { text: sender.name } } : {}),
        real: { text: "no sender address" },
        explanation: "The From line has a name but no address. Real services always say who they are; spam tools leave it blank so it can't be traced or blocked.",
        lensLabel: "Real sender",
        target: { kind: "header", field: "from" },
      },
    ];
  }
  const out: Finding[] = [];
  const domain = addressDomain(sender.address);
  const owner = registrable(domain);
  const name = sender.name.trim();

  const impossible = impossibleDomain(domain);
  if (impossible) {
    out.push({
      id: "sender-invalid",
      rule: "sender-invalid",
      category: "sender",
      severity: "high",
      title: "The sender's address can't exist",
      ...(name ? { seen: { text: name } } : {}),
      real: addressSnippet(sender.address),
      explanation: `It came from ${sender.address}, but ${impossible}. No real organisation can send from it, so the address was forged by a spam tool.`,
      lensLabel: "Real sender",
      target: { kind: "header", field: "from" },
    });
  }

  const label = parse(domain).domainWithoutSuffix ?? "";
  if (!impossible && label.split(/[.-]/).some(looksRandom)) {
    out.push({
      id: "sender-random",
      rule: "sender-random",
      category: "sender",
      severity: "medium",
      title: "The sender's domain looks machine-generated",
      ...(name ? { seen: { text: name } } : {}),
      real: addressSnippet(sender.address),
      explanation: `${owner} is a jumble of letters and numbers, the kind of throwaway domain spam campaigns register in bulk and abandon a day later.`,
      lensLabel: "Real sender",
      target: { kind: "header", field: "from" },
    });
  }

  // Mailing lists rewrite the From line to "someone@example.com via the list"; that's not a disguise.
  const nameAddress = ctx.mailingList ? undefined : name.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/)?.[0];
  if (nameAddress && nameAddress.toLowerCase() !== sender.address.toLowerCase()) {
    out.push({
      id: "sender-name-address",
      rule: "sender-name-address",
      category: "sender",
      severity: "high",
      title: "The sender's name is a fake address",
      seen: { text: name },
      real: addressSnippet(sender.address),
      explanation: `The name shows ${nameAddress}, but the email really came from ${sender.address}.`,
      lensLabel: "Real sender",
      target: { kind: "header", field: "from" },
    });
  }

  const claimed = ctx.claimed;
  if (claimed && !belongsTo(domain, claimed)) {
    const match = imitatedBrand(domain, [claimed]);
    const how = match
      ? `The address ${imitationReason(match)}, and ${claimed.name}'s mail servers never sent it.`
      : FREE_MAIL.has(owner)
        ? `It came from a free ${owner} account, and ${claimed.name} doesn't send email from those.`
        : impossible
          ? `${claimed.name} would never send from an address that can't exist.`
          : `The address belongs to ${owner}, which isn't ${claimed.name}.`;
    out.push({
      id: "sender-disguise",
      rule: "sender-disguise",
      category: "sender",
      severity: "high",
      title: "The sender is wearing a disguise",
      seen: { text: name },
      real: addressSnippet(sender.address, match?.marks),
      explanation: `Anyone can type any name. ${how}`,
      lensLabel: "Real sender",
      target: { kind: "header", field: "from" },
      brand: claimed.name,
    });
  } else if (!claimed) {
    const match = imitatedBrand(domain, ctx.brands);
    if (match) {
      out.push({
        id: "sender-lookalike",
        rule: "sender-lookalike",
        category: "sender",
        severity: "high",
        title: `The address imitates ${match.brand.name}`,
        seen: { text: name || sender.address },
        real: addressSnippet(sender.address, match.marks),
        explanation: `The email talks about ${match.brand.name}, but the address ${imitationReason(match)}.`,
        lensLabel: "Real sender",
        target: { kind: "header", field: "from" },
        brand: match.brand.name,
      });
    } else if (FREE_MAIL.has(owner) && ROLE_NAME.test(name)) {
      out.push({
        id: "sender-role-freemail",
        rule: "sender-role-freemail",
        category: "sender",
        severity: "medium",
        title: "A personal account posing as staff",
        seen: { text: name },
        real: addressSnippet(sender.address),
        explanation: `"${name}" sounds official, but it came from a free ${owner} account that anyone can open.`,
        lensLabel: "Real sender",
        target: { kind: "header", field: "from" },
      });
    }
  }
  return out;
}

/** Whether replies would go to a different organisation than the sender. */
export function replyCheck(ctx: CheckContext): { finding: Finding | null; elsewhere: boolean; domain: string | null } {
  const reply = ctx.replyTo;
  if (!reply?.address || !ctx.sender?.address) return { finding: null, elsewhere: false, domain: null };
  const replyOwner = registrable(addressDomain(reply.address));
  if (ctx.mailingList || replyOwner === registrable(addressDomain(ctx.sender.address))) {
    return { finding: null, elsewhere: false, domain: replyOwner };
  }
  return {
    elsewhere: true,
    domain: replyOwner,
    finding: {
      id: "reply-elsewhere",
      rule: "reply-elsewhere",
      category: "sender",
      // Newsletters often reply from a helpdesk domain; replies to a free mailbox or behind a brand disguise are the tell.
      severity: FREE_MAIL.has(replyOwner) || ctx.claimed ? "medium" : "low",
      title: "Replies go somewhere else",
      seen: { text: ctx.sender.name || ctx.sender.address },
      real: addressSnippet(reply.address),
      explanation: `If you hit reply, your answer goes to ${replyOwner}, not to the address the email came from.`,
      lensLabel: "Real reply-to",
      target: { kind: "header", field: "from" },
    },
  };
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

const MAX_URL = 64;
/** Hosts longer than this lose the middle of their subdomains; the end, which names the real owner, always stays. */
const MAX_HOST = 44;
/** Link text can be a whole paragraph; its start is enough to recognise it. */
const MAX_LINK_TEXT = 90;

function clip(text: string, max = MAX_LINK_TEXT): string {
  const chars = [...text];
  return chars.length > max ? `${chars.slice(0, max - 1).join("").trimEnd()}…` : text;
}

interface ReadableUrl {
  text: string;
  /** Where the host sits in `text`, for highlighting. */
  host: [number, number];
  /** Moves a range within the full host to where it ended up in `text`; null if it was cut out. */
  place(start: number, end: number): [number, number] | null;
}

/** A readable version of a URL that never cuts off the part of the host naming who owns it. */
function readableUrl(url: URL): ReadableUrl {
  const full = unicodeHost(url.hostname);
  const owner = unicodeHost(registrable(url.hostname)).length;
  let host = full;
  let cut: [number, number] | null = null;
  if (full.length > MAX_HOST) {
    // Resume at a dot, so the end shown is whole labels: "jo4dh9l5….blr1.cdn.digitaloceanspaces.com".
    const from = full.length - Math.max(MAX_HOST - 10, owner);
    const dot = full.indexOf(".", from);
    const resume = dot !== -1 && dot < full.length - owner ? dot : from;
    if (resume > 9) {
      cut = [8, resume];
      host = `${full.slice(0, 8)}…${full.slice(resume)}`;
    }
  }
  const at = url.protocol.length + 2;
  let text = `${url.protocol}//${host}${safeDecode(url.pathname)}${safeDecode(url.search)}`;
  if (text.length > MAX_URL) text = `${text.slice(0, Math.max(MAX_URL - 1, at + host.length))}…`;
  const move = (i: number) => (!cut || i <= cut[0] ? i : i >= cut[1] ? i - (cut[1] - cut[0]) + 1 : cut[0]);
  return {
    text,
    host: [at, at + host.length],
    place: (start, end) => (move(end) > move(start) ? [at + move(start), at + move(end)] : null),
  };
}

/** A link's real destination as the reader should see it, or null for links that aren't web addresses. */
export function readableDestination(href: string): string | null {
  const info = inspectUrl(href);
  return info ? readableUrl(info.url).text : null;
}

const SIGN_IN_PATH = /\/(log-?in|sign-?in|verify|account|secure|auth|owa|session|password|webmail)/i;

/** Link text that asks the reader to do something with an account, not just read an article. */
const ACTION_TEXT =
  /\b(sign ?in|log ?in|verify|confirm|unlock|restore|reactivate|reset (?:your |my )?password|update (?:your |my )?(?:account|payment|billing|details|information)|claim|redeem|activate|resgat\w*|acessar|entrar|regularizar|bestätigen|anmelden|verificar|iniciar sesión|connexion|valider)\b/i;

interface LinkRule {
  severity: Severity;
  title: (what: string) => string;
  explain: (info: UrlInfo) => string;
}

/** Lexical warning signs in a link's destination, strongest first. One finding per sign. */
const TAG_RULES: [UrlTag, string, LinkRule][] = [
  ["userinfo", "link-userinfo", { severity: "high", title: (w) => `A ${w} disguises its real address`, explain: (i) => `Everything before the "@" in this address is ignored. It really goes to ${i.host}.` }],
  ["download", "link-download", { severity: "high", title: (w) => `A ${w} downloads a risky file`, explain: () => "Clicking it downloads a program or archive straight to your computer instead of opening a page." }],
  ["ip", "link-ip", { severity: "medium", title: (w) => `A ${w} goes to a bare server address`, explain: () => "Real companies link to their own named websites, not to a raw numeric address." }],
  ["ip-host", "link-ip", { severity: "medium", title: (w) => `A ${w} goes to a bare server address`, explain: (i) => `${i.host} is a server's numeric address dressed up as a name. Real companies link to their own websites.` }],
  ["punycode", "link-unicode", { severity: "medium", title: (w) => `A ${w} uses letters from another alphabet`, explain: (i) => `The address reads as ${unicodeHost(i.host)}, but some of its letters only look like ours.` }],
  ["disposable", "link-disposable", { severity: "medium", title: (w) => `A ${w} goes to free website hosting`, explain: (i) => `${i.host} is on a free hosting service anyone can set up in minutes. Real companies don't put sign-in or payment pages there.` }],
  ["lure-host", "link-lure-host", { severity: "medium", title: (w) => `A ${w}'s address is stuffed with bait words`, explain: (i) => `${i.host} glues words like "login", "verify" or "airdrop" onto an unrelated domain, a pattern phishing kits use to look official.` }],
  ["random", "link-random", { severity: "medium", title: (w) => `A ${w} goes to a randomly generated address`, explain: (i) => `${i.host} looks machine-made, the kind of throwaway address spam campaigns register by the thousand.` }],
  ["cheap-tld", "link-cheap-tld", { severity: "low", title: (w) => `A ${w} uses a throwaway domain ending`, explain: (i) => `Domains ending in .${i.tld} cost almost nothing, and most of them are used for spam and scams.` }],
  ["shortener", "link-shortener", { severity: "low", title: (w) => `A ${w} hides where it goes`, explain: (i) => `${i.owner} is a link shortener, so you can't see the real destination until you click.` }],
];

export function linkFindings(ctx: CheckContext): Finding[] {
  const groups = new Map<string, { finding: Finding; count: number }>();
  const recipient = ctx.recipient?.toLowerCase() ?? null;
  const senderDomain = ctx.sender?.address ? addressDomain(ctx.sender.address) : "";

  const add = (key: string, make: () => Finding) => {
    const group = groups.get(key);
    if (group) group.count++;
    else groups.set(key, { finding: make(), count: 1 });
  };

  for (const link of links(ctx.content)) {
    const what = link.button ? "button" : "link";
    const What = link.button ? "Button" : "Link";
    if (/^(javascript|data|vbscript):/i.test(link.href)) {
      add("script", () => ({
        id: `link-script-${link.id}`,
        rule: "link-script",
        category: "link",
        severity: "low",
        title: `A ${what} runs code instead of opening a page`,
        seen: { text: clip(link.text) },
        real: { text: link.href.slice(0, MAX_URL) },
        explanation: "Links in an email should open web pages. This one is set up to run code in your browser.",
        lensLabel: "Real destination",
        target: { kind: "node", id: link.id },
      }));
      continue;
    }

    const info = inspectUrl(link.href);
    if (!info) continue;
    const { host, owner, url } = info;
    const readable = readableUrl(url);
    const filled = recipient !== null && safeDecode(link.href).toLowerCase().includes(recipient);
    const prefilled = filled ? ", with your email address already filled in" : "";
    const signIn = SIGN_IN_PATH.test(url.pathname);
    const hostMarks: [number, number][] = [readable.host];
    const imitation = imitatedBrand(host, ctx.brands);
    const destination = imitation
      ? `a fake ${imitation.brand.name} ${signIn ? "sign-in page" : "site"}`
      : `${signIn ? "a sign-in page" : "a page"} on ${owner}`;
    const viaNote = info.via ? ` It goes through ${info.via} first, which hides the real address.` : "";
    const base = { category: "link" as const, seen: { text: clip(link.text) }, lensLabel: "Real destination", target: { kind: "node" as const, id: link.id } };

    // The text names a site; it's only a lie if neither the link as written nor where it ends up is that site.
    const claimed = claimedHost(link.text);
    const outer = inspectUrl(link.href.replace(/\?.*$/, ""))?.owner ?? owner;
    const claimedOwner = claimed ? registrable(claimed) : null;
    const bareName = !!claimed && !/^https?:\/\//i.test(link.text.trim()) && !/\//.test(link.text.trim());
    const ownSite = !!senderDomain && owner === registrable(senderDomain) && bareName;
    if (claimedOwner && claimedOwner !== owner && claimedOwner !== outer && !ownSite) {
      add(`mismatch:${owner}`, () => ({
        ...base,
        id: `link-mismatch-${link.id}`,
        rule: "link-mismatch",
        severity: "high",
        title: `The ${what} lies about where it goes`,
        real: { text: readable.text, marks: hostMarks },
        explanation: `${What} text is only a label. This one opens ${destination}${prefilled}.${viaNote}`,
        ...(imitation && { brand: imitation.brand.name }),
      }));
    } else if (imitation) {
      add(`lookalike:${owner}`, () => ({
        ...base,
        id: `link-lookalike-${link.id}`,
        rule: "link-lookalike",
        severity: "high",
        title: `The ${what} leads to a fake ${imitation.brand.name} site`,
        real: { text: readable.text, marks: imitation.marks.flatMap(([s, e]) => { const placed = readable.place(s, e); return placed ? [placed] : []; }) },
        explanation: `The address ${imitationReason(imitation)}. It opens ${destination}${prefilled}.${viaNote}`,
        brand: imitation.brand.name,
      }));
    } else {
      const plain = latinize(link.text);
      const textBrand = BRANDS.find((b) => b.mentions.some((re) => re.test(plain)));
      const actsOnAccount = (ACTION_TEXT.test(plain) && plain.length <= 60) || ctx.claimed === textBrand;
      if (textBrand && actsOnAccount && !belongsTo(host, textBrand)) {
        add(`brand:${owner}`, () => ({
          ...base,
          id: `link-brand-${link.id}`,
          rule: "link-brand",
          severity: "high",
          title: `The ${what} says ${textBrand.name} but goes elsewhere`,
          real: { text: readable.text, marks: hostMarks },
          explanation: `${owner} has nothing to do with ${textBrand.name}. It opens ${destination}${prefilled}.${viaNote}`,
          brand: textBrand.name,
        }));
      }
    }

    // Lexical warning signs, but never for the sender's own domain: newsletters link home all the time.
    if (senderDomain && registrable(senderDomain) === owner && !info.tags.has("download")) continue;
    for (const [tag, rule, copy] of TAG_RULES) {
      if (!info.tags.has(tag)) continue;
      add(`${rule}`, () => ({
        ...base,
        id: `${rule}-${link.id}`,
        rule,
        severity: copy.severity,
        title: copy.title(what),
        real: { text: readable.text, marks: hostMarks },
        explanation: copy.explain(info) + viaNote,
      }));
      break;
    }
  }

  return [...groups.values()].map(({ finding, count }) =>
    count > 1
      ? { ...finding, explanation: `${finding.explanation} ${count - 1} more link${count > 2 ? "s do" : " does"} the same.` }
      : finding,
  );
}

export function trackerFindings(content: Content): { finding: Finding | null; count: number } {
  const trackers = images(content).filter((i) => i.tracker);
  const first = trackers[0];
  if (!first) return { finding: null, count: 0 };
  const host = inspectUrl(first.src.startsWith("//") ? `https:${first.src}` : first.src)?.host ?? "another server";
  const text = `a 1×1 image from ${host}`;
  return {
    count: trackers.length,
    finding: {
      id: "tracker",
      rule: "tracker",
      category: "tracker",
      severity: "info",
      title: "It tells the sender you opened it",
      seen: { text: "Nothing" },
      real: { text, marks: [[text.length - host.length, text.length]] },
      explanation:
        `An invisible image loads from ${host} the moment you open the email. It confirms your address is real and active.` +
        (trackers.length > 1 ? ` There are ${trackers.length} of them.` : ""),
      lensLabel: "Hidden tracker",
      target: { kind: "node", id: first.id },
    },
  };
}

export function formFindings(content: Content): Finding[] {
  const first = content.blocks[0];
  if (!content.formFields || !first) return [];
  return [
    {
      id: "form",
      rule: "form",
      category: "form",
      severity: "high",
      title: "It asks for your details inside the email",
      explanation: "It contains boxes for typing in passwords or card details. Real companies send you to their website instead of collecting secrets in an email.",
      lensLabel: "Form",
      target: { kind: "node", id: first.id },
    },
  ];
}

/**
 * A brand named in the subject or the first heading, while nothing in the email
 * (sender or links) actually belongs to that brand.
 */
export function brandClaimFinding(ctx: CheckContext, subject: string, heading: string, linkHosts: string[], lured: boolean): Finding | null {
  // A brand named in a subject is everyday news; it only counts when the email also uses a scam lure.
  if (!lured || ctx.claimed || !ctx.sender?.address) return null;
  const senderDomain = addressDomain(ctx.sender.address);
  const plainSubject = latinize(subject);
  const plainHeading = latinize(heading);
  const brand = BRANDS.find((b) => b.mentions.some((re) => re.test(plainSubject) || re.test(plainHeading)));
  if (!brand || belongsTo(senderDomain, brand) || linkHosts.some((h) => belongsTo(h, brand))) return null;
  return {
    id: "brand-claim",
    rule: "brand-claim",
    category: "sender",
    severity: "medium",
    title: `It talks like ${brand.name} but nothing comes from ${brand.name}`,
    seen: { text: brand.name },
    real: addressSnippet(ctx.sender.address),
    explanation: `It presents itself as ${brand.name}, yet neither the sender nor any link belongs to ${brand.name}.`,
    lensLabel: "Real sender",
    target: { kind: "header", field: "from" },
    brand: brand.name,
  };
}
