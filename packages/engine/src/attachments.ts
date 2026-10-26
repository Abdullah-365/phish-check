import type { AttachmentInfo, AttachmentSummary, Finding, Severity } from "./types.ts";
import { inspectUrl, type UrlTag } from "./urls.ts";

type Family = "program" | "macro" | "webpage" | "onenote" | "profile" | "archive" | "legacy-office" | "calendar" | "pdf" | "other";

const FAMILIES: Record<string, { family: Family; kind: string }> = {};
const add = (family: Family, kind: string, exts: string) => {
  for (const ext of exts.split(" ")) FAMILIES[ext] = { family, kind };
};
add("program", "Windows program", "exe com scr pif cpl");
add("program", "Windows installer", "msi msix appx");
add("program", "Windows script", "bat cmd");
add("program", "PowerShell script", "ps1 psm1");
add("program", "Script that runs on double-click", "vbs vbe js jse wsf wsh");
add("program", "HTML application (a program)", "hta");
add("program", "Shortcut that can run commands", "lnk");
add("program", "Java program", "jar");
add("program", "Windows registry change", "reg");
add("program", "Disk image that can hide programs", "iso img vhd vhdx");
add("macro", "Macro-enabled Word document", "docm dotm");
add("macro", "Macro-enabled Excel workbook", "xlsm xltm xlam xlsb");
add("macro", "Macro-enabled PowerPoint file", "pptm potm ppam ppsm");
add("webpage", "Web page", "html htm shtml xhtml mht mhtml");
add("webpage", "Image that can contain code", "svg");
add("onenote", "OneNote file", "one onepkg");
add("profile", "Device configuration profile", "mobileconfig");
add("archive", "Compressed archive", "zip rar 7z gz tgz tar cab ace arj bz2 xz");
add("legacy-office", "Older Office file that can carry macros", "doc xls ppt");
add("calendar", "Calendar invite", "ics");
add("pdf", "PDF document", "pdf");

const PROGRAM_NAME = /\.(exe|scr|com|pif|cpl|msi|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|lnk|jar|reg|iso|img|vhdx?|html?|svg)$/i;

const SEVERITY: Record<Family, Severity | null> = {
  program: "high",
  macro: "high",
  webpage: "high",
  onenote: "high",
  profile: "high",
  archive: "medium",
  "legacy-office": "low",
  calendar: null,
  pdf: null,
  other: null,
};

const TITLES: Record<Family, string> = {
  program: "The attachment is a program",
  macro: "The attachment can run hidden code",
  webpage: "The attachment is a web page",
  onenote: "The attachment is a OneNote file",
  profile: "The attachment would change your device's settings",
  archive: "The attachment is a compressed archive",
  "legacy-office": "The attachment is an older Office file",
  calendar: "",
  pdf: "",
  other: "",
};

const EXPLANATIONS: Record<Family, string> = {
  program: "Opening it would run code on your computer. Real invoices and documents don't arrive as programs.",
  macro: "Its macros run code on your computer as soon as you click Enable Content.",
  webpage: "Opening it shows a page that can look like any sign-in screen and send what you type to the attacker.",
  onenote: "OneNote files are a popular way to hide harmful files behind a fake button.",
  profile: "Installing a configuration profile can let the sender read your internet traffic, add certificates or control settings on your iPhone or Mac.",
  archive: "Compressed files can hide programs from virus scanners.",
  "legacy-office": "Older Office formats can carry macros. Only open it if you expected it from someone you know.",
  calendar: "",
  pdf: "",
  other: "",
};

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/** Body images sent along with the email aren't attachments a reader would open. */
export function readerAttachments(attachments: AttachmentInfo[]): AttachmentInfo[] {
  return attachments.filter((a) => !(a.declaredType.startsWith("image/") && a.disposition !== "attachment"));
}

const latin1 = (bytes: Uint8Array) => {
  let out = "";
  for (let i = 0; i < bytes.length; i += 0x8000) out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return out;
};

/** What the first bytes say a file really is, regardless of its name. */
function sniff(bytes: Uint8Array): "program" | "webpage" | "zip" | "pdf" | "profile" | null {
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) return "program"; // MZ: Windows executable
  if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return "program"; // ELF
  if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) return "zip";
  const head = latin1(bytes.subarray(0, 1024)).trimStart().toLowerCase();
  if (head.startsWith("%pdf")) return "pdf";
  if (head.startsWith("<!doctype html") || head.startsWith("<html") || head.startsWith("<script")) return "webpage";
  if (head.includes("<plist") && head.includes("payloadtype")) return "profile";
  return null;
}

/** Decompresses at most `limit` bytes, so a crafted file can't blow up memory. */
async function inflate(data: Uint8Array, format: "deflate" | "deflate-raw", limit = 2_000_000): Promise<Uint8Array | null> {
  try {
    const reader = new Blob([data as Uint8Array<ArrayBuffer>]).stream().pipeThrough(new DecompressionStream(format)).getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      size += value.length;
      if (size >= limit) {
        await reader.cancel();
        break;
      }
    }
    const out = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk.subarray(0, size - offset), offset);
      offset += chunk.length;
      if (offset >= size) break;
    }
    return out;
  } catch {
    return null;
  }
}

interface PdfFacts {
  urls: string[];
  javascript: boolean;
  launch: boolean;
  embedded: boolean;
}

/** Reads a PDF's link targets and active parts, including ones inside compressed streams. */
async function pdfFacts(bytes: Uint8Array): Promise<PdfFacts> {
  const facts: PdfFacts = { urls: [], javascript: false, launch: false, embedded: false };
  const collect = (text: string) => {
    for (const m of text.matchAll(/\/URI\s*\(([^)]{4,500})\)/g)) facts.urls.push(m[1]!.replace(/\\(.)/g, "$1"));
    for (const m of text.matchAll(/\/URI\s*<([0-9a-fA-F]{8,1000})>/g)) {
      facts.urls.push(m[1]!.replace(/../g, (h) => String.fromCharCode(parseInt(h, 16))));
    }
    if (/\/(JavaScript|JS)\b/.test(text)) facts.javascript = true;
    if (/\/Launch\b/.test(text)) facts.launch = true;
    if (/\/EmbeddedFile\b/.test(text)) facts.embedded = true;
  };
  const text = latin1(bytes);
  collect(text);
  // One forward pass over the "stream" keywords, so a file stuffed with keywords can't make
  // this slow. Each stream's dictionary sits just before it and says whether it's compressed.
  let streams = 0;
  let keywords = 0;
  for (let from = 0; streams < 40 && keywords < 2000; ) {
    const at = text.indexOf("stream", from);
    if (at < 0) break;
    keywords++;
    from = at + 6;
    if (text.startsWith("end", at - 3)) continue;
    let start = at + 6;
    if (text[start] === "\r") start++;
    if (text[start] !== "\n") continue;
    start++;
    const before = text.slice(Math.max(0, at - 1024), at);
    const dictionary = before.slice(Math.max(before.lastIndexOf("endobj"), before.lastIndexOf("endstream")) + 1);
    if (!dictionary.includes("/FlateDecode")) continue;
    streams++;
    let end = text.indexOf("endstream", start);
    if (end < 0) break;
    from = end + 9;
    if (end - start > 1_000_000) continue;
    // The line break before "endstream" isn't part of the data, and the decompressor rejects trailing bytes.
    while (end > start && (text[end - 1] === "\n" || text[end - 1] === "\r")) end--;
    const inflated = await inflate(bytes.subarray(start, end), "deflate");
    if (inflated) collect(latin1(inflated));
  }
  facts.urls = [...new Set(facts.urls.filter((u) => /^https?:\/\//i.test(u)))];
  return facts;
}

interface ZipEntry {
  name: string;
  encrypted: boolean;
}

/** Lists a ZIP's files from its central directory, without extracting anything. */
function zipEntries(bytes: Uint8Array): ZipEntry[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65_557); i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return [];
  const count = Math.min(view.getUint16(eocd + 10, true), 2000);
  let offset = view.getUint32(eocd + 16, true);
  const entries: ZipEntry[] = [];
  for (let n = 0; n < count && offset + 46 <= bytes.length; n++) {
    if (view.getUint32(offset, true) !== 0x02014b50) break;
    const flags = view.getUint16(offset + 8, true);
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const name = new TextDecoder().decode(bytes.subarray(offset + 46, offset + 46 + nameLength));
    entries.push({ name, encrypted: (flags & 1) === 1 });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

/** What an HTML attachment does when opened. */
function htmlFacts(bytes: Uint8Array): { form: boolean; script: boolean; urls: string[] } {
  const text = new TextDecoder().decode(bytes.subarray(0, 2_000_000));
  return {
    form: /<input[^>]+type=["']?password|<form[^>]+action=["']?https?:/i.test(text),
    script: /window\.location|location\.(href|replace)|document\.write\(\s*(unescape|atob)|\batob\(|\beval\(|http-equiv=["']?refresh/i.test(text),
    urls: [...new Set([...text.matchAll(/(?:href|action|src|url)\s*=\s*["']?(https?:\/\/[^"'\s>]+)/gi)].map((m) => m[1]!))].slice(0, 50),
  };
}

const RISKY_LINK_TAGS: UrlTag[] = ["userinfo", "download", "ip", "ip-host", "disposable", "lure-host", "random", "punycode", "shortener", "cheap-tld"];

/** The first link in a file that looks like a phishing destination, with the reason. */
function riskyLink(urls: string[]): { url: string; host: string; reason: UrlTag } | null {
  for (const url of urls) {
    const info = inspectUrl(url);
    const reason = info && RISKY_LINK_TAGS.find((tag) => info.tags.has(tag));
    if (info && reason) return { url, host: info.host, reason };
  }
  return null;
}

/** Enough of a file's links for online checks; phishing PDFs carry one or two. */
const MAX_FILE_LINKS = 10;

const REASON: Partial<Record<UrlTag, string>> = {
  userinfo: "uses a trick to disguise its real address",
  download: "downloads a program",
  ip: "points to a bare server address",
  "ip-host": "points to a bare server address",
  disposable: "points to free website hosting",
  "lure-host": "points to an address stuffed with bait words",
  random: "points to a randomly generated address",
  punycode: "uses letters from another alphabet",
  shortener: "hides its destination behind a link shortener",
  "cheap-tld": "points to a throwaway domain",
};

export async function attachmentChecks(
  attachments: AttachmentInfo[],
  bodyText: string,
): Promise<{ findings: Finding[]; summaries: AttachmentSummary[] }> {
  const findings: Finding[] = [];
  const summaries: AttachmentSummary[] = [];
  const mentionsPassword = /\bpass(word|code)\b|\bsenha\b|\bpasswort\b|\bcontrase[ñn]a\b|\bmot de passe\b/i.test(bodyText);

  for (const [index, file] of readerAttachments(attachments).entries()) {
    const id = `a${index}`;
    const filename = file.filename ?? "unnamed attachment";
    const ext = filename.toLowerCase().match(/\.([a-z0-9]+)$/)?.[1] ?? "";
    const sniffed = sniff(file.content);
    let { family, kind } =
      FAMILIES[ext] ??
      (file.declaredType === "application/x-apple-aspen-config" || sniffed === "profile"
        ? { family: "profile" as Family, kind: "Device configuration profile" }
        : file.declaredType === "text/calendar"
          ? { family: "calendar" as Family, kind: "Calendar invite" }
          : sniffed === "pdf"
            ? { family: "pdf" as Family, kind: "PDF document" }
            : { family: "other" as Family, kind: file.declaredType || "File" });
    let rule = `attachment-${family}`;
    let severity = SEVERITY[family];
    let title = TITLES[family];
    let explanation = EXPLANATIONS[family];
    let urls: string[] = [];

    const doubled = /\.(pdf|docx?|xlsx?|pptx?|txt|rtf|csv|jpe?g|png|gif)\.[a-z0-9]+$/i.test(filename);
    if ((sniffed === "program" && family !== "program") || (doubled && family === "program")) {
      family = "program";
      rule = "attachment-disguised";
      severity = "high";
      kind = "Program in disguise";
      title = `${filename} is really a program`;
      explanation = "The name makes it look like a document, but opening it would run code on your computer.";
    } else if (sniffed === "webpage" && family !== "webpage") {
      family = "webpage";
      rule = "attachment-disguised";
      severity = "high";
      kind = "Web page in disguise";
      title = `${filename} is really a web page`;
      explanation = EXPLANATIONS.webpage;
    }

    if (family === "webpage") {
      const html = htmlFacts(file.content);
      urls = html.urls;
      if (html.form) explanation = "Opening it shows a sign-in form that sends what you type straight to the attacker.";
      else if (html.script) explanation = "Opening it runs hidden code that sends you to another site, usually a fake sign-in page.";
    } else if (sniffed === "zip" || family === "archive") {
      const entries = sniffed === "zip" ? zipEntries(file.content) : [];
      const program = entries.find((e) => PROGRAM_NAME.test(e.name));
      const macros = entries.some((e) => /vbaProject\.bin$/i.test(e.name));
      const locked = entries.some((e) => e.encrypted);
      if (macros && family !== "macro") {
        rule = "attachment-macro";
        severity = "high";
        kind = "Office file with hidden macros";
        title = "The attachment hides macros";
        explanation = "Its name says it's an ordinary Office file, but it carries macros: code that runs when you click Enable Content.";
      } else if (program) {
        rule = "attachment-archive-program";
        severity = "high";
        kind = `Archive containing ${program.name.split("/").pop()}`;
        title = "The archive hides a program";
        explanation = `Inside is ${program.name.split("/").pop()}, a file that runs code when opened. That's how malware travels in archives.`;
      } else if (family === "archive" && (locked || (mentionsPassword && !entries.length))) {
        // A password mentioned in the body only hints at a lock when the contents couldn't be listed to check.
        rule = "attachment-locked";
        severity = "high";
        title = "The attachment is a locked archive";
        explanation = "It's password-protected, so security scanners can't look inside. That's a common way to sneak malware past them.";
      }
    } else if (family === "pdf") {
      const pdf = await pdfFacts(file.content);
      urls = pdf.urls;
      if (pdf.javascript || pdf.launch) {
        rule = "attachment-pdf-active";
        severity = "high";
        kind = "PDF with hidden code";
        title = "The PDF contains code";
        explanation = pdf.launch
          ? "It's set up to launch another program when opened. Normal documents never do this."
          : "It contains JavaScript, which ordinary invoices and letters never need. It can run as soon as the PDF opens.";
      } else if (pdf.embedded) {
        rule = "attachment-pdf-embedded";
        severity = "medium";
        kind = "PDF with a file hidden inside";
        title = "The PDF has another file hidden inside";
        explanation = "Files tucked inside a PDF can be programs that get past scanners which only look at the PDF itself.";
      }
    } else if (family === "calendar") {
      urls = [...new Set(new TextDecoder().decode(file.content.subarray(0, 200_000)).match(/https?:\/\/[^\s"'<>\\]+/gi) ?? [])];
    }

    // Links inside a file get the same scrutiny as links in the email itself.
    const risky = riskyLink(urls);
    summaries.push({
      id,
      filename,
      size: file.size,
      kind,
      risky: severity === "high" || severity === "medium",
      sha256: await sha256(file.content),
      links: [...new Set([...(risky ? [risky.url] : []), ...urls])].slice(0, MAX_FILE_LINKS),
    });

    if (severity && title) {
      findings.push({
        id: `${rule}-${id}`,
        rule,
        category: "attachment",
        severity,
        title,
        seen: { text: filename },
        real: { text: `${kind} · ${formatSize(file.size)}` },
        explanation,
        lensLabel: "Attachment",
        target: { kind: "node", id },
      });
    }

    if (risky) {
      const what = family === "pdf" ? "The PDF" : family === "calendar" ? "The calendar invite" : "The attachment";
      findings.push({
        id: `attachment-link-${id}`,
        rule: "attachment-link",
        category: "attachment",
        severity: risky.reason === "cheap-tld" || risky.reason === "shortener" ? "low" : "medium",
        title: `${what} links somewhere suspicious`,
        seen: { text: filename },
        real: { text: risky.host },
        explanation: `${what} contains a link that ${REASON[risky.reason]}: ${risky.host}. Links inside files skip the checks your email app runs on normal links.`,
        lensLabel: "Attachment",
        target: { kind: "node", id },
        url: risky.url,
      });
    }
  }
  return { findings, summaries };
}

export async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
