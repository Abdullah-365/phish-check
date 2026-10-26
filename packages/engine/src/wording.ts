import { latinize, latinizeSameLength } from "./domains.ts";
import { RULES, type Group } from "./lexicon.ts";
import type { Content, Finding, Inline, Severity } from "./types.ts";

export type WordingHits = Map<Group, { id: string; text: string }[]>;

/**
 * Finds suspicious phrases and turns them into phrase inlines in place, so the
 * reading view can highlight them underneath the lens.
 */
export function markWording(content: Content): WordingHits {
  const hits: WordingHits = new Map();
  let next = 0;
  for (const block of content.blocks) {
    const out: Inline[] = [];
    for (const inline of block.inlines) {
      if (inline.type !== "text") {
        out.push(inline);
        continue;
      }
      // Match against a copy with look-alike letters swapped back, so "Vеrіfy" (Cyrillic е, і) still reads as "Verify".
      const probe = latinizeSameLength(inline.text);
      const matches = RULES.flatMap((rule) =>
        [...probe.matchAll(rule.pattern)].map((m) => ({ start: m.index!, end: m.index! + m[0].length, rule })),
      ).sort((a, b) => a.start - b.start || b.end - a.end);
      let cursor = 0;
      for (const match of matches) {
        if (match.start < cursor) continue;
        if (match.start > cursor) out.push({ type: "text", text: inline.text.slice(cursor, match.start) });
        const id = `w${next++}`;
        const text = inline.text.slice(match.start, match.end);
        out.push({ type: "phrase", id, text, label: match.rule.label });
        const list = hits.get(match.rule.group) ?? [];
        list.push({ id, text });
        hits.set(match.rule.group, list);
        cursor = match.end;
      }
      if (cursor < inline.text.length) out.push({ type: "text", text: inline.text.slice(cursor) });
    }
    block.inlines = out;
  }
  return hits;
}

/** Groups a subject line can trigger on its own, since scams often put the lure there, with the phrase that did it. */
export function subjectGroups(subject: string): Map<Group, string> {
  const groups = new Map<Group, string>();
  const plain = latinize(subject);
  for (const rule of RULES) {
    // match() resets lastIndex on these global patterns; test() would leave it moved.
    const phrase = plain.match(rule.pattern)?.[0];
    if (phrase && !groups.has(rule.group)) groups.set(rule.group, phrase);
  }
  return groups;
}

interface Copy {
  rule: string;
  severity: Severity;
  title: string;
  explanation: string;
  lens: string;
}

/** What each kind of lure means, in plain words. Order is the order findings are listed in. */
const COPY: [Group, Copy][] = [
  ["sextortion", { rule: "sextortion", severity: "high", title: "It's a blackmail scam", explanation: "These emails claim to have recordings of you to scare you into paying. They go to millions of people at once, and the claims are made up.", lens: "Blackmail" }],
  ["advance-fee", { rule: "advance-fee", severity: "high", title: "It's an advance-fee story", explanation: "Tales of inheritances and unclaimed millions always end with a fee you have to pay first. The money never exists.", lens: "Advance-fee story" }],
  ["money", { rule: "money", severity: "high", title: "It asks for money the way scammers do", explanation: "Gift cards, wire transfers and crypto can't be traced or reversed, which is why scammers ask for them.", lens: "Money request" }],
  ["macro", { rule: "macro-lure", severity: "high", title: "It tells you to switch off a safety feature", explanation: "Enabling content lets hidden code inside the attachment run on your computer. Office blocks it for a reason.", lens: "Macro lure" }],
  ["callback", { rule: "callback", severity: "medium", title: "It wants you to call a phone number", explanation: "Fake receipts and renewals say you've been charged and give a number to call. Whoever answers will try to get into your computer or your bank account.", lens: "Call-back bait" }],
  ["crypto", { rule: "crypto", severity: "medium", title: "It promises crypto or investment profits", explanation: "Guaranteed returns, airdrops and wallet \"verification\" are the hallmarks of crypto scams. No one legitimate asks for your recovery phrase.", lens: "Crypto bait" }],
  ["delivery", { rule: "delivery", severity: "medium", title: "It claims a parcel is held up", explanation: "Fake delivery notices push you to pay a small fee or enter your card details. Check the tracking number on the carrier's own website.", lens: "Fake delivery" }],
  ["fines", { rule: "fines", severity: "medium", title: "It claims you owe a fine or tax", explanation: "Government agencies and courts don't demand payment through an email link. Check with the agency directly.", lens: "Fake fine or tax" }],
  ["storage", { rule: "storage", severity: "medium", title: "It claims your storage is full", explanation: "Fake storage warnings rush you into signing in to \"save\" your files. Check your account settings directly instead.", lens: "Fake storage alert" }],
  ["credentials", { rule: "credentials", severity: "medium", title: "It wants your login details", explanation: "Real companies don't ask you to confirm passwords or account details through an email. Go to their website yourself instead.", lens: "Asks for your login" }],
  ["prize", { rule: "prize", severity: "medium", title: "It dangles a prize you didn't enter", explanation: "Surprise prizes, rewards and gift cards are bait. The next step asks for your card details or personal data.", lens: "Prize bait" }],
  ["job", { rule: "job", severity: "medium", title: "It offers easy money for little work", explanation: "Too-good-to-be-true job offers often recruit people to move stolen money, which is a crime.", lens: "Easy-money offer" }],
  ["gambling", { rule: "gambling", severity: "medium", title: "It pushes online casino bonuses", explanation: "Unsolicited casino offers come from spam networks and usually lead to unlicensed gambling sites.", lens: "Casino spam" }],
  ["dating", { rule: "dating", severity: "medium", title: "It's a dating or adult come-on", explanation: "Unsolicited dating messages lead to scam sites that harvest payment details.", lens: "Dating come-on" }],
  ["invoice", { rule: "invoice", severity: "low", title: "It pressures you about a bill", explanation: "Fake invoices and failed-payment notices aim to get you to pay or sign in. Check your account on the company's own website.", lens: "Billing pressure" }],
  ["document", { rule: "document", severity: "low", title: "It invites you to open a shared file", explanation: "Fake shared documents lead to sign-in pages that steal your password.", lens: "Fake shared file" }],
  ["health", { rule: "health", severity: "low", title: "It sells a miracle health product", explanation: "Miracle cures sent out of the blue are spam, and the products can be unsafe.", lens: "Miracle cure" }],
];

const quote = (items: { text: string }[]) =>
  [...new Set(items.map((i) => i.text))]
    .slice(0, 3)
    .map((t) => `"${t}"`)
    .join(", ");

const STRONGER: Record<Severity, Severity> = { info: "low", low: "medium", medium: "high", high: "high" };

/** Lure types where one stray phrase is common in ordinary mail, so they need a second before counting fully. */
const NEEDS_TWO = new Set<Group>(["advance-fee", "sextortion"]);

/**
 * One matching phrase can be a coincidence; an email built around a lure repeats it.
 * Three or more distinct phrases of one kind raise its severity a level.
 */
function severityFor(group: Group, base: Severity, distinct: number): Severity {
  if (NEEDS_TWO.has(group)) return distinct >= 2 ? base : "medium";
  return distinct >= 3 ? STRONGER[base] : base;
}

export function wordingFindings(hits: WordingHits, subject: Map<Group, string>): Finding[] {
  const out: Finding[] = [];
  const at = (group: Group) => hits.get(group) ?? [];
  // What the reader sees: phrases from the body, or failing that the one in the subject line.
  const shown = (group: Group) => {
    const found = at(group);
    const inSubject = subject.get(group);
    return found.length ? { seen: { text: quote(found) } } : inSubject ? { seen: { text: quote([{ text: inSubject }]) } } : {};
  };

  for (const [group, copy] of COPY) {
    const found = at(group);
    if (!found.length && !subject.has(group)) continue;
    const distinct = new Set(found.map((f) => f.text.toLowerCase())).size + (subject.has(group) ? 1 : 0);
    out.push({
      id: copy.rule,
      rule: copy.rule,
      category: "wording",
      severity: severityFor(group, copy.severity, distinct),
      title: copy.title,
      ...shown(group),
      explanation:
        copy.explanation + (group === "money" && at("secrecy").length ? " Asking you to keep it quiet is part of the trick." : ""),
      lensLabel: copy.lens,
      target: found[0] ? { kind: "node", id: found[0].id } : { kind: "header", field: "subject" },
    });
  }

  if (!at("money").length && at("secrecy").length) {
    out.push({
      id: "secrecy",
      rule: "secrecy",
      category: "wording",
      severity: "medium",
      title: "It asks you to keep it quiet",
      seen: { text: quote(at("secrecy")) },
      explanation: "Secrecy stops you from checking with anyone who could spot the scam.",
      lensLabel: "Secrecy",
      target: { kind: "node", id: at("secrecy")[0]!.id },
    });
  }

  const greeting = at("greeting")[0];
  const pressure = at("pressure");
  if (pressure.length || subject.has("pressure")) {
    out.push({
      id: "pressure",
      rule: "pressure",
      category: "wording",
      severity: "medium",
      title: "It's trying to rush you",
      ...shown("pressure"),
      explanation:
        "Deadlines and threats are there to make you act before you think." +
        (greeting ? ` It also opens with "${greeting.text}", so it doesn't know your name.` : ""),
      lensLabel: "Pressure",
      target: pressure[0] ? { kind: "node", id: pressure[0].id } : { kind: "header", field: "subject" },
    });
  } else if (greeting) {
    out.push({
      id: "greeting",
      rule: "greeting",
      category: "wording",
      severity: "low",
      title: "It doesn't know your name",
      seen: { text: `"${greeting.text}"` },
      explanation: "Companies you have an account with usually greet you by name.",
      lensLabel: "Generic greeting",
      target: { kind: "node", id: greeting.id },
    });
  }
  return out;
}
