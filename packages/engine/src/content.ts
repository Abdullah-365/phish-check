import { parseDocument } from "htmlparser2";
import type { ChildNode, Element } from "domhandler";
import type { Block, Content, Inline } from "./types.ts";

/** Enough for any real email; keeps the reading view and the checks fast. */
const MAX_BLOCKS = 300;
const MAX_CHARS = 60_000;

const SKIP = new Set([
  "script", "style", "head", "title", "meta", "link", "noscript", "template", "svg", "math",
  "iframe", "object", "embed", "video", "audio", "canvas", "select", "option", "textarea", "map",
]);

const BLOCKS = new Set([
  "p", "div", "section", "article", "header", "footer", "main", "aside", "nav", "center",
  "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "blockquote", "pre", "table", "tbody",
  "thead", "tfoot", "tr", "td", "th", "dl", "dt", "dd", "figure", "figcaption", "address", "hr",
  "form", "fieldset", "body", "html",
]);

const URL_IN_TEXT = /\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi;

/** Zero-width and soft-hyphen characters hidden between letters to break up keywords. */
const INVISIBLE_IN_WORD = /(?<=\p{L})[​‌⁠﻿­]+(?=\p{L})/gu;
const INVISIBLE = /[​‌⁠﻿­]/g;
const LATIN = /\p{Script=Latin}/u;
const LOOKALIKE_SCRIPT = /[\p{Script=Cyrillic}\p{Script=Greek}\p{Script=Cherokee}\p{Script=Armenian}]/u;
/** Bold, italic and script letters from the maths block, used to slip words past filters. */
export const STYLED_LETTERS = /[\u{1D400}-\u{1D7FF}]/gu;

/** Words written at least partly in those letters, as they appear. */
export function styledWords(text: string): string[] {
  return (text.match(/[\p{L}\p{N}]+/gu) ?? []).filter((word) => /[\u{1D400}-\u{1D7FF}]/u.test(word));
}

/** Input names that ask for secrets rather than, say, a search term. */
const SECRET_FIELD = /pass|pwd|pin\b|otp|card|cvv|cvc|ccv|ssn|social|account|iban|login|user/i;

class Builder {
  blocks: Block[] = [];
  formFields = 0;
  hiddenText = 0;
  zeroWidth = 0;
  styledLetters = 0;
  styledWords: string[] = [];
  mixedScript = new Set<string>();
  images = 0;
  truncated = false;
  private inlines: Inline[] = [];
  private kind: Block["kind"] = "p";
  private chars = 0;
  private ids = { b: 0, l: 0, i: 0 };

  nextId(prefix: "l" | "i"): string {
    return `${prefix}${this.ids[prefix]++}`;
  }

  get textLength(): number {
    return this.chars;
  }

  text(raw: string): void {
    let text = this.clean(raw).replace(/\s+/g, " ");
    if (!text || this.full()) return;
    const last = this.inlines.at(-1);
    if (last?.type === "text") {
      if (last.text.endsWith(" ") && text.startsWith(" ")) text = text.slice(1);
      last.text += text;
    } else if (text !== " " || (last && last.type !== "break")) {
      this.inlines.push({ type: "text", text });
    }
    this.chars += text.trim().length;
  }

  /** Normalises look-alike forms and strips characters inserted to dodge keyword filters. */
  clean(raw: string): string {
    const found = raw.match(INVISIBLE_IN_WORD);
    if (found) this.zeroWidth += found.join("").length;
    const styled = raw.match(STYLED_LETTERS)?.length ?? 0;
    if (styled) {
      this.styledLetters += styled;
      if (this.styledWords.length < 3) this.styledWords.push(...styledWords(raw).slice(0, 3 - this.styledWords.length));
    }
    const text = raw.normalize("NFKC").replace(INVISIBLE, "");
    for (const word of text.match(/[\p{L}\p{M}]{3,}/gu) ?? []) {
      if (LATIN.test(word) && LOOKALIKE_SCRIPT.test(word) && this.mixedScript.size < 5) this.mixedScript.add(word);
    }
    return text;
  }

  push(inline: Inline, countText = true): void {
    if (this.full()) return;
    this.inlines.push(inline);
    if (inline.type === "link" && countText) this.chars += inline.text.length;
  }

  flush(kind: Block["kind"] = this.kind): void {
    const inlines = trimInlines(this.inlines);
    this.inlines = [];
    if (!inlines.length || this.full()) return;
    if (this.blocks.length >= MAX_BLOCKS) {
      this.truncated = true;
      return;
    }
    this.blocks.push({ id: `b${this.ids.b++}`, kind, inlines });
  }

  setKind(kind: Block["kind"]): void {
    this.kind = kind;
  }

  private full(): boolean {
    if (this.chars < MAX_CHARS) return false;
    this.truncated = true;
    return true;
  }
}

/** Far deeper than any real email's markup goes. */
const MAX_NESTING = 500;
const VOID_TAGS = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"]);
/** Tags whose end is optional: sloppy honest HTML leaves them open, and the parser closes them itself. */
const SELF_CLOSING = new Set(["p", "li", "td", "th", "tr", "dt", "dd", "option", "optgroup", "thead", "tbody", "tfoot", "colgroup", "html", "head", "body"]);

/**
 * The HTML parser slows down with the square of the nesting depth, so an email nested tens of
 * thousands deep could freeze the tab. Past a sane depth, tags are dropped; their text, links
 * and images stay.
 */
function limitNesting(html: string): string {
  // Each level needs its own tag, so short or tag-light HTML can't be too deep.
  if ((html.match(/</g)?.length ?? 0) <= MAX_NESTING) return html;
  let depth = 0;
  return html.replace(/<(\/?)([a-z][a-z0-9-]*)\b[^<>]{0,4000}>/gi, (tag: string, close: string, raw: string) => {
    const name = raw.toLowerCase();
    if (VOID_TAGS.has(name) || SELF_CLOSING.has(name) || tag.endsWith("/>")) return tag;
    const keep = name === "a";
    if (close) {
      const dropped = depth > MAX_NESTING;
      depth = Math.max(0, depth - 1);
      return dropped && !keep ? "" : tag;
    }
    depth++;
    return depth > MAX_NESTING && !keep ? "" : tag;
  });
}

/** Builds the reading view from the HTML part, falling back to plain text. */
export function extractContent(html: string, text: string): Content {
  const b = new Builder();
  if (html.trim()) {
    const doc = parseDocument(limitNesting(html), { decodeEntities: true, lowerCaseTags: true, lowerCaseAttributeNames: true });
    walk(doc.children, b);
    b.flush();
  }
  if (!b.blocks.length && text.trim()) textToBlocks(text, b);
  return {
    blocks: b.blocks,
    truncated: b.truncated,
    formFields: b.formFields,
    hiddenText: b.hiddenText,
    zeroWidth: b.zeroWidth,
    styledLetters: b.styledLetters,
    styledWords: b.styledWords,
    mixedScript: [...b.mixedScript],
    images: b.images,
    textLength: b.textLength,
  };
}

/** Pushes children so they pop off a stack in document order. */
function pushChildren(stack: (ChildNode | null)[], nodes: ChildNode[]): void {
  for (let i = nodes.length - 1; i >= 0; i--) stack.push(nodes[i]!);
}

/**
 * Walks the document with an explicit stack rather than recursion: a crafted email can nest
 * tags tens of thousands deep, which would overflow the call stack and stop the analysis.
 */
function walk(nodes: ChildNode[], b: Builder): void {
  // null marks the end of a block element.
  const stack: (ChildNode | null)[] = [];
  pushChildren(stack, nodes);
  while (stack.length) {
    const node = stack.pop()!;
    if (node === null) {
      b.flush();
      b.setKind("p");
      continue;
    }
    if (node.type === "text") {
      b.text(node.data);
      continue;
    }
    if (node.type !== "tag" && node.type !== "script" && node.type !== "style") continue;
    const el = node as Element;
    const name = el.name;

    if (name === "img") {
      image(el, b);
      continue;
    }
    if (name === "input") {
      const type = (el.attribs.type ?? "text").toLowerCase();
      const label = `${el.attribs.name ?? ""} ${el.attribs.id ?? ""} ${el.attribs.placeholder ?? ""}`;
      if (type === "password" || (["text", "email", "tel", "number"].includes(type) && SECRET_FIELD.test(label))) b.formFields++;
      continue;
    }
    if (SKIP.has(name)) continue;
    if (isHidden(el)) {
      b.hiddenText += collectText(el, true).replace(/\s+/g, " ").trim().length;
      continue;
    }

    if (name === "br") {
      b.push({ type: "break" });
      continue;
    }
    if (name === "a" && el.attribs.href) {
      // Link contents are flattened into the link's text, so nothing inside can nest.
      link(el, b);
      continue;
    }
    if (BLOCKS.has(name)) {
      b.flush();
      b.setKind(blockKind(name));
      stack.push(null);
      pushChildren(stack, el.children);
      continue;
    }
    pushChildren(stack, el.children);
  }
}

function link(el: Element, b: Builder): void {
  const text = b.clean(collectText(el)).replace(/\s+/g, " ").trim();
  const alt = findImageAlt(el);
  b.images += countImages(el);
  b.push(
    {
      type: "link",
      id: b.nextId("l"),
      href: el.attribs.href!.trim(),
      text: text || alt || "image",
      button: looksLikeButton(el),
    },
    // A picture's alt text or our placeholder isn't text the reader can see.
    !!text,
  );
}

function countImages(el: Element): number {
  let n = 0;
  const stack: (ChildNode | null)[] = [];
  pushChildren(stack, el.children);
  while (stack.length) {
    const child = stack.pop()!;
    if (child?.type !== "tag") continue;
    if (child.name === "img") {
      if (!isHidden(child)) n++;
    } else {
      pushChildren(stack, child.children);
    }
  }
  return n;
}

function image(el: Element, b: Builder): void {
  const src = (el.attribs.src ?? "").trim();
  const remote = /^(https?:)?\/\//i.test(src);
  const width = dimension(el, "width");
  const height = dimension(el, "height");
  const tiny = width !== null && height !== null && width <= 3 && height <= 3;
  // A remote image nobody can see has one job: telling the sender the email was opened.
  const tracker = remote && (tiny || isHidden(el));
  if (!tracker && isHidden(el)) return;
  if (!tracker) b.images++;
  b.push({ type: "image", id: b.nextId("i"), src, alt: (el.attribs.alt ?? "").trim(), tracker });
}

function blockKind(name: string): Block["kind"] {
  if (/^h[1-6]$/.test(name)) return "heading";
  if (name === "li") return "item";
  if (name === "blockquote") return "quote";
  return "p";
}

function collectText(el: Element, includeHidden = false): string {
  let out = "";
  const stack: (ChildNode | null)[] = [];
  pushChildren(stack, el.children);
  while (stack.length) {
    const child = stack.pop()!;
    if (child?.type === "text") out += child.data;
    else if (child?.type === "tag" && !SKIP.has(child.name) && (includeHidden || !isHidden(child))) {
      out += " ";
      pushChildren(stack, child.children);
    }
  }
  return out;
}

function findImageAlt(el: Element): string {
  const stack: (ChildNode | null)[] = [];
  pushChildren(stack, el.children);
  while (stack.length) {
    const child = stack.pop()!;
    if (child?.type !== "tag") continue;
    if (child.name === "img" && child.attribs.alt) return child.attribs.alt.trim();
    pushChildren(stack, child.children);
  }
  return "";
}

function styleOf(el: Element): string {
  return (el.attribs.style ?? "").toLowerCase().replace(/\s+/g, "");
}

/** Styles that keep text off screen: the classic way to stuff filler past spam filters. */
// Not mso-hide: that only hides content in desktop Outlook, and every other app shows it.
const HIDING_STYLE =
  /display:none|visibility:hidden|font-size:[0-2](\.\d+)?(px|pt)?(?![.\d%a-z])|max-height:0(?![.\d])|height:0(px)?;.*overflow:hidden|opacity:0(?![.\d])|color:transparent|text-indent:-\d{3,}|(^|;)(left|top):-\d{4,}/;

function isHidden(el: Element): boolean {
  return "hidden" in el.attribs || HIDING_STYLE.test(styleOf(el));
}

function dimension(el: Element, prop: "width" | "height"): number | null {
  const attr = el.attribs[prop];
  if (attr && /^\d+/.test(attr)) return parseInt(attr, 10);
  const match = styleOf(el).match(new RegExp(`(?:^|;)${prop}:(\\d+)(?:px)?(?:;|$)`));
  return match ? parseInt(match[1]!, 10) : null;
}

/** Emails draw buttons as coloured links or links inside coloured table cells. */
function looksLikeButton(el: Element): boolean {
  const filled = (style: string, bg?: string) =>
    !!bg || (/background(-color)?:/.test(style) && !/background(-color)?:(transparent|none|#fff(fff)?\b|white)/.test(style));
  if (filled(styleOf(el))) return true;
  if (/\b(btn|button|cta)\b/i.test(el.attribs.class ?? "") || el.attribs.role === "button") return true;
  let parent = el.parent;
  for (let depth = 0; depth < 3 && parent && parent.type === "tag"; depth++, parent = parent.parent) {
    const p = parent as Element;
    if ((p.name === "td" || p.name === "table") && filled(styleOf(p), p.attribs.bgcolor)) return true;
  }
  return false;
}

function trimInlines(inlines: Inline[]): Inline[] {
  inlines.forEach((inline, index) => {
    if (inline.type !== "text") return;
    const before = inlines[index - 1];
    const after = inlines[index + 1];
    if (!before || before.type === "break") inline.text = inline.text.trimStart();
    if (!after || after.type === "break") inline.text = inline.text.trimEnd();
  });
  const kept = inlines.filter((i) => i.type !== "text" || i.text !== "");
  while (kept[0]?.type === "break") kept.shift();
  while (kept.at(-1)?.type === "break") kept.pop();
  return kept;
}

/** Lines at least this long were most likely wrapped by the sender's mail app, not by the author. */
const SOFT_WRAP = 60;
/** Lines that start a new thought even after a long line: header fields, bullets, quotes, numbered items. */
const HARD_START = /^\s*([A-Z][\w-]{1,20}:\s|[-*•>]\s|\d+[.)]\s)/;

function textToBlocks(text: string, b: Builder): void {
  const paragraphs = text.replace(/\r\n?/g, "\n").split(/\n\s*\n/);
  for (const paragraph of paragraphs) {
    const lines = paragraph.split("\n");
    lines.forEach((line, index) => {
      if (index > 0) {
        if (lines[index - 1]!.length >= SOFT_WRAP && !HARD_START.test(line)) b.text(" ");
        else b.push({ type: "break" });
      }
      autolink(line, b);
    });
    b.flush("p");
  }
}

function autolink(line: string, b: Builder): void {
  let cursor = 0;
  for (const match of line.matchAll(URL_IN_TEXT)) {
    const url = match[0].replace(/[.,;:!?)\]>]+$/, "");
    const start = match.index!;
    b.text(line.slice(cursor, start));
    b.push({ type: "link", id: b.nextId("l"), href: url.startsWith("www.") ? `http://${url}` : url, text: url, button: false });
    cursor = start + url.length;
  }
  b.text(line.slice(cursor));
}

/** All visible text, block by block, for wording checks and brand mentions. */
export function plainText(content: Content): string {
  return content.blocks
    .map((block) =>
      block.inlines
        .map((i) => (i.type === "text" || i.type === "phrase" || i.type === "link" ? i.text : i.type === "break" ? "\n" : ""))
        .join(""),
    )
    .join("\n\n");
}

export function links(content: Content): Extract<Inline, { type: "link" }>[] {
  return content.blocks.flatMap((block) => block.inlines.filter((i): i is Extract<Inline, { type: "link" }> => i.type === "link"));
}

export function images(content: Content): Extract<Inline, { type: "image" }>[] {
  return content.blocks.flatMap((block) => block.inlines.filter((i): i is Extract<Inline, { type: "image" }> => i.type === "image"));
}
