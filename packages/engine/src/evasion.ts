import { BRANDS, FREE_MAIL } from "./brands.ts";
import { links, plainText, STYLED_LETTERS, styledWords } from "./content.ts";
import type { Content, Finding, Severity } from "./types.ts";

/** Hidden preview text in honest newsletters stays well under this. */
const HIDDEN_TEXT_LIMIT = 300;

const GREETING =
  "(?:hi|hello|hey|dear|hallo|hoi|ol[áa]|oi|hola|bonjour|salut|ciao|hej|caro|cara|prezad[oa]|estimad[oa]|querid[oa]|liebe[r]?|beste|sehr geehrte[r]?|bom dia|boa tarde|boa noite|buenos d[ií]as|guten tag|gentile)";

/** Merge tags a bulk mailer was meant to replace with your name. */
const PLACEHOLDER = /%%[\w ]{2,30}%%|\{\{\s*[\w. ]{2,30}\s*\}\}|\*\|[A-Z_]{2,20}\|\*|\[(?:first ?name|last ?name|name|email|recipient)\]|\$\{\s*\w{2,20}\s*\}/i;

/** Macros from spam-sending tools that only show up when the tool misfires. Honest mail never has them. */
const SPAM_TOOL_MACRO = /__(?:Link|DynTag\d*|Ranodm|Random|RND|Rand)\w*|DynTag\d|\[%?RND[^\]]{0,20}\]|%RND\w*%|\{RND\w*\}|\[RANDOM[^\]]{0,20}\]|#rand(?:om)?\w*#/i;

const MIXED = /(?=[\p{L}\p{M}]*\p{Script=Latin})(?=[\p{L}\p{M}]*[\p{Script=Cyrillic}\p{Script=Greek}\p{Script=Cherokee}\p{Script=Armenian}])[\p{L}\p{M}]{3,}/u;

const LOOKALIKE_SCRIPTS: [string, RegExp][] = [
  ["Cyrillic", /\p{Script=Cyrillic}/u],
  ["Greek", /\p{Script=Greek}/u],
  ["Cherokee", /\p{Script=Cherokee}/u],
  ["Armenian", /\p{Script=Armenian}/u],
];

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Brand names written with a space between every letter, like "e b a y" or "P a y P a l". */
function spacedBrand(text: string): string | null {
  for (const match of text.matchAll(/(?<![\p{L}\p{N}])(?:\p{L} ){2,}\p{L}(?![\p{L}\p{N}])/gu)) {
    const joined = match[0].replace(/ /g, "").toLowerCase();
    if (BRANDS.some((b) => b.slugs.includes(joined) && joined.length >= 3)) return match[0];
  }
  return null;
}

interface Input {
  content: Content;
  subject: string;
  senderName: string;
  recipient: string | null;
  /** Raw From, To and Subject header values, where spam tools leave their macros. */
  headerText: string;
  /** Every address in To and Cc. */
  recipients: string[];
  mailingList: boolean;
}

export function evasionFindings({ content, subject, senderName, recipient, headerText, recipients, mailingList }: Input): Finding[] {
  const out: Finding[] = [];

  // Colleagues share a domain; a blast to a batch of harvested personal mailboxes doesn't.
  const domains = new Set(recipients.map((r) => r.split("@")[1]?.toLowerCase()).filter(Boolean));
  const personal = recipients.filter((r) => FREE_MAIL.has(r.split("@")[1]?.toLowerCase() ?? "")).length;
  if (!mailingList && recipients.length >= 5 && domains.size >= 3 && personal * 2 >= recipients.length) {
    out.push({
      id: "evasion-strangers",
      rule: "evasion-strangers",
      category: "evasion",
      severity: "medium",
      title: "It was sent to a list of strangers",
      real: { text: `${recipients.length} visible recipients across ${domains.size} unrelated domains` },
      explanation: "It went out to a batch of unrelated addresses at once, which is how harvested mailing lists get used. Personal or business mail goes to people who know each other.",
      lensLabel: "Mass mailing",
      target: { kind: "header", field: "from" },
    });
  }
  const firstBlock = content.blocks[0]?.id;
  const anywhere = firstBlock ? ({ kind: "node", id: firstBlock } as const) : ({ kind: "header", field: "subject" } as const);
  const text = plainText(content);

  const mixedHeader = [senderName, subject].map((s) => s.match(MIXED)?.[0]).find(Boolean);
  const mixed = [...new Set([...(mixedHeader ? [mixedHeader] : []), ...content.mixedScript])].slice(0, 3);
  if (mixed.length) {
    // Highlight the impostor letters themselves: on screen they're indistinguishable from ours.
    const shown = mixed.join(", ");
    const marks: [number, number][] = [];
    const scripts = new Set<string>();
    // Snippet marks are string offsets, so walk code units; the look-alike scripts are all outside the astral planes.
    for (let i = 0; i < shown.length; i++) {
      const script = LOOKALIKE_SCRIPTS.find(([, re]) => re.test(shown[i]!))?.[0];
      if (!script) continue;
      scripts.add(script);
      const last = marks.at(-1);
      if (last && last[1] === i) last[1] = i + 1;
      else marks.push([i, i + 1]);
    }
    const count = marks.reduce((sum, [s, e]) => sum + e - s, 0);
    out.push({
      id: "evasion-mixed-script",
      rule: "evasion-mixed-script",
      category: "evasion",
      severity: "high",
      title: "It uses look-alike letters from other alphabets",
      seen: { text: shown, marks },
      real: { text: `${count} ${[...scripts].join(" and ")} letter${count === 1 ? "" : "s"} posing as Latin ones` },
      explanation: "Some words mix normal letters with Cyrillic, Greek or other letters that look identical, so filters searching for those words miss them. Honest senders never do this.",
      lensLabel: "Look-alike letters",
      target: mixedHeader ? { kind: "header", field: senderName.includes(mixedHeader) ? "from" : "subject" } : anywhere,
    });
  }

  const styled = (subject.match(STYLED_LETTERS)?.length ?? 0) + (senderName.match(STYLED_LETTERS)?.length ?? 0) + content.styledLetters;
  if (styled >= 5) {
    const words = [...styledWords(senderName), ...styledWords(subject), ...content.styledWords].slice(0, 3);
    const inHeader = styledWords(senderName).length ? "from" : styledWords(subject).length ? "subject" : null;
    out.push({
      id: "evasion-styled-letters",
      rule: "evasion-styled-letters",
      category: "evasion",
      severity: "medium",
      title: "It writes words in fancy maths letters",
      ...(words.length ? { seen: { text: words.join(" ") } } : {}),
      real: { text: `${styled} maths symbols, not letters` },
      explanation: "Bold and script letters from the maths symbol set look like normal text to you, but spam filters see them as unknown symbols. That's why scammers use them.",
      lensLabel: "Styled letters",
      target: inHeader ? { kind: "header", field: inHeader } : anywhere,
    });
  }

  const spacedName = spacedBrand(senderName);
  const spacedSubject = spacedName ? null : spacedBrand(subject);
  const spaced = spacedName ?? spacedSubject ?? spacedBrand(text);
  if (spaced) {
    out.push({
      id: "evasion-spaced-letters",
      rule: "evasion-spaced-letters",
      category: "evasion",
      severity: "medium",
      title: "It spells a brand name with spaces between the letters",
      seen: { text: spaced },
      real: { text: spaced.replace(/ /g, "") },
      explanation: "Writing a name like this keeps filters from recognising a brand that the email is pretending to be.",
      lensLabel: "Spaced-out name",
      target: spacedName ? { kind: "header", field: "from" } : spacedSubject ? { kind: "header", field: "subject" } : anywhere,
    });
  }

  if (content.hiddenText >= HIDDEN_TEXT_LIMIT) {
    const outweighs = content.hiddenText >= 1000 && content.hiddenText > content.textLength * 1.5;
    out.push({
      id: "evasion-hidden-text",
      rule: "evasion-hidden-text",
      category: "evasion",
      severity: outweighs ? "high" : "medium",
      title: "It hides text from you",
      real: { text: `${content.hiddenText.toLocaleString("en")} characters of invisible text` },
      explanation: outweighs
        ? "There's more invisible text in it than visible text. That filler is only there to fool spam filters into reading it as a normal email."
        : "It's stuffed with text styled to be invisible, a trick to fool spam filters into reading it as a normal email.",
      lensLabel: "Hidden text",
      target: anywhere,
    });
  }

  if (content.zeroWidth >= 3) {
    out.push({
      id: "evasion-invisible-characters",
      rule: "evasion-invisible-characters",
      category: "evasion",
      severity: "medium",
      title: "It hides invisible characters inside words",
      real: { text: `${content.zeroWidth} invisible characters between letters` },
      explanation: "Invisible characters break words like \"password\" or \"account\" apart so filters can't match them. We removed them before checking the wording.",
      lensLabel: "Invisible characters",
      target: anywhere,
    });
  }

  if (content.textLength < 60 && content.images >= 1 && links(content).length >= 1) {
    out.push({
      id: "evasion-image-only",
      rule: "evasion-image-only",
      category: "evasion",
      severity: "medium",
      title: "It's almost all pictures",
      explanation: "There's barely any text, just images and a link. Spammers do this so filters can't read the message.",
      lensLabel: "Image-only email",
      target: anywhere,
    });
  }

  if (recipient && recipient.includes("@")) {
    const address = escape(recipient.toLowerCase());
    const greeted = new RegExp(`${GREETING}[\\s,:!]*${address}`, "iu").test(text);
    if (greeted || subject.toLowerCase().includes(recipient.toLowerCase())) {
      out.push({
        id: "evasion-addressed-by-email",
        rule: "evasion-addressed-by-email",
        category: "evasion",
        severity: "medium",
        title: "It addresses you by your email address",
        seen: { text: recipient },
        explanation: "Companies you deal with know your name. Mass mailers only have the address they sent to, so they paste it in where your name should be.",
        lensLabel: "Mass-mail greeting",
        target: greeted ? anywhere : { kind: "header", field: "subject" },
      });
    }
  }

  const macro = headerText.match(SPAM_TOOL_MACRO)?.[0] ?? text.match(SPAM_TOOL_MACRO)?.[0];
  const placeholder = macro ?? text.match(PLACEHOLDER)?.[0] ?? subject.match(PLACEHOLDER)?.[0];
  if (placeholder) {
    const severity: Severity = macro ? "medium" : "low";
    out.push({
      id: "evasion-placeholder",
      rule: "evasion-placeholder",
      category: "evasion",
      severity,
      title: macro ? "It contains leftovers from a spam-sending tool" : "It contains an unfilled template tag",
      seen: { text: placeholder.slice(0, 40) },
      explanation: macro
        ? "Codes like this belong to bulk spam software and only appear when it misfires. Legitimate mail never contains them."
        : "A tag like this should have been replaced by your name. It shows the message was blasted out by a bulk-mailing tool.",
      lensLabel: "Template tag",
      target: anywhere,
    });
  }
  return out;
}
