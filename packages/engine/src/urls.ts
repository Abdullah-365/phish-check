import { parse } from "tldts";

export type UrlTag = "shortener" | "disposable" | "cheap-tld" | "ip" | "ip-host" | "userinfo" | "download" | "punycode" | "random" | "lure-host";

export interface UrlInfo {
  /** The real destination, after unwrapping redirects. */
  url: URL;
  host: string;
  owner: string;
  /** The redirect service the link went through first, if any. */
  via: string | null;
  /** True when the outer link was the reader's own security wrapper (Safe Links, URL Defense). */
  protectedBy: string | null;
  tags: Set<UrlTag>;
  tld: string;
}

export const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "is.gd", "v.gd", "rb.gy", "cutt.ly", "cutt.us", "ow.ly", "buff.ly", "rebrand.ly",
  "shorturl.at", "tiny.cc", "s.id", "t.ly", "goo.su", "short.io", "short.gy", "bl.ink", "lnkd.in", "bit.do", "shorte.st",
  "adf.ly", "u.to", "clck.ru", "qrco.de", "hotm.art", "spoo.me", "x.co", "tr.im", "soo.gd", "shorturl.gg", "linktr.ee",
]);

/** Free or self-serve hosting where anyone can publish a page in minutes. */
const DISPOSABLE = [
  "storage.googleapis.com", "firebasestorage.googleapis.com", ".web.app", ".firebaseapp.com", ".run.app", ".appspot.com",
  ".pages.dev", ".workers.dev", ".r2.dev", ".netlify.app", ".vercel.app", ".glitch.me", ".repl.co", ".replit.app",
  ".replit.dev", ".herokuapp.com", ".onrender.com", ".fly.dev", ".ngrok.io", ".ngrok-free.app", ".ngrok.app",
  ".trycloudflare.com", "ipfs.io", ".ipfs.dweb.link", ".ipfs.w3s.link", "cloudflare-ipfs.com", "gateway.pinata.cloud",
  ".weebly.com", ".wixsite.com", ".square.site", ".godaddysites.com", ".webflow.io", ".carrd.co",
  ".000webhostapp.com", ".azurewebsites.net", ".web.core.windows.net", ".blob.core.windows.net", ".s3.amazonaws.com",
  "sites.google.com", "forms.gle", "script.google.com", ".notion.site", ".framer.website", ".framer.app",
  ".surge.sh", ".neocities.org", ".tiiny.site", ".mystrikingly.com", ".jimdosite.com", ".yolasite.com",
  ".dropboxusercontent.com", ".translate.goog", ".linodeobjects.com", ".digitaloceanspaces.com", ".backblazeb2.com",
  ".typeform.com", ".jotform.com", ".formstack.com", ".wufoo.com",
];

/** Words phishing kits glue into hostnames, as in "lido-airdrop" or "secure-login2". */
const LURE_WORDS = /login|signin|logon|verif|secure|account|wallet|airdrop|claim|reward|unlock|recover|webmail|refund|billing|update/;

/** Domain endings that cost next to nothing and are dominated by spam and scams. */
const CHEAP_TLDS = new Set([
  "xyz", "top", "icu", "site", "online", "click", "shop", "live", "buzz", "rest", "cfd", "sbs", "cyou", "monster", "quest",
  "bond", "lol", "mom", "beauty", "hair", "skin", "makeup", "boats", "autos", "homes", "space", "fun", "store", "website",
  "tk", "ml", "ga", "cf", "gq", "cam", "work", "loan", "win", "bid", "date", "stream", "download", "racing", "review",
  "country", "kim", "science", "party", "gdn", "men", "pw", "su", "zip", "mov", "bar", "wang", "vip", "rocks", "uno",
  "lat", "best", "today", "life", "world", "ink", "digital", "pics", "baby", "help",
]);

const RISKY_DOWNLOAD = /\.(exe|scr|msi|bat|cmd|js|jse|vbs|vbe|wsf|hta|lnk|jar|iso|img|vhd|vhdx|zip|rar|7z|apk|dmg|pkg|ps1|cab|xll|one|docm|xlsm|pptm)$/i;

/** Wrappers added by the reader's own security tools. They protect, so they're unwrapped silently. */
const SECURITY_WRAPPERS = /(^|\.)safelinks\.protection\.outlook\.com$|^urldefense\.(proofpoint\.)?com$|(^|\.)mimecastprotect\.com$|^linkprotect\.cudasvc\.com$/;

/** Query parameters redirect services use to carry the real destination. */
const REDIRECT_PARAMS = ["url", "u", "q", "redirect", "redirect_url", "redirect_uri", "redir", "dest", "destination", "target", "to", "link", "goto", "next", "continue", "return", "returnurl", "rurl", "r", "uddg"];

function parseUrl(raw: string): URL | null {
  try {
    const url = new URL(raw.trim().startsWith("www.") ? `http://${raw.trim()}` : raw.trim());
    return /^https?:$/.test(url.protocol) ? url : null;
  } catch {
    return null;
  }
}

/** Percent-decoding that returns null on malformed input instead of throwing: links are attacker-written. */
function decode(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

function decodeBase64Url(value: string): string | null {
  try {
    return atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    return null;
  }
}

/** Pulls the real destination out of a redirect link, when it carries one. */
function inner(url: URL): URL | null {
  const host = url.hostname.toLowerCase();
  if (/^urldefense\.proofpoint\.com$/.test(host)) {
    const u = url.searchParams.get("u");
    const decoded = u ? decode(u.replace(/-/g, "%").replace(/_/g, "/")) : null;
    return decoded ? parseUrl(decoded) : null;
  }
  if (/^urldefense\.com$/.test(host)) {
    const match = url.pathname.match(/^\/v3\/__(.+?)__;/);
    return match ? parseUrl(match[1]!) : null;
  }
  if (/(^|\.)bing\.com$/.test(host) && url.pathname.startsWith("/ck/")) {
    const u = url.searchParams.get("u");
    const decoded = u?.startsWith("a1") ? decodeBase64Url(u.slice(2)) : null;
    return decoded ? parseUrl(decoded) : null;
  }
  if (/(^|\.)google\.[a-z.]+$/.test(host) && url.pathname.startsWith("/amp/s/")) {
    return parseUrl(`https://${url.pathname.slice(7)}`);
  }
  for (const name of REDIRECT_PARAMS) {
    for (const [key, value] of url.searchParams) {
      if (key.toLowerCase() !== name) continue;
      const candidate = /^https?%3a/i.test(value) ? decode(value) : value;
      if (candidate && /^https?:\/\//i.test(candidate)) return parseUrl(candidate);
    }
  }
  return null;
}

/**
 * Letter pairs making up 97% of real text (measured on a corpus of legitimate email),
 * plus a few Portuguese ones. Random strings are full of the other pairs.
 */
const COMMON_PAIRS = new Set(
  (
    "aa ab ac ad af ag ah ai ak al am an ap ar as at au av aw ay az ba be bg bi bl bo br bs bu ca cc ce ch ci ck cl cn co cr cs ct cu cy " +
    "da dd de di dl dm dn do dr ds dt du dv dy ea eb ec ed ee ef eg ei ek el em en eo ep eq er es et ev ew ex ey fa fc fe ff fi fl fo fr ft fu " +
    "ga gc ge gg gh gi gl gn go gr gs gu gy ha he hi hn ho hr ht hu hy ia ib ic id ie if ig ih ii ik il im in io ip ir is it iv iz ja je jo ju " +
    "ka ke kg ki kn ks kt la lb ld le li lk ll lm lo lp ls lt lu lv ly ma mb me mg mh mi ml mm mo mp ms mu na nb nc nd ne nf ng ni nk nl nn no " +
    "np ns nt nu nv ny oa ob oc od oe of og oi ok ol om on oo op or os ot ou ov ow ox pa pd pe pg ph pi pl pm po pp pr ps pt pu py qu ra rc rd " +
    "re rf rg ri rk rl rm rn ro rp rr rs rt ru rv ry sa sc se sh si sk sl sm sn so sp sr ss st su sw sy ta tc te th ti tl tm to tp tr ts tt tu " +
    "tw ty ua ub uc ud ue ug ui ul um un up ur us ut ux va ve vi vo wa we wh wi wn wo wr ws ww xe xp xt ya ye yi yl yo yp ys yt ze zo nh lh"
  ).split(/\s+/),
);

/** True for labels that look machine-generated, like "5duuevrmkuz" or "dt3-161255673571". */
export function looksRandom(label: string): boolean {
  const s = label.toLowerCase();
  if (/\d{7,}/.test(s)) return true;
  const letters = s.replace(/[^a-z]/g, "");
  if (letters.length < 8) return false;
  let rare = 0;
  for (let i = 0; i < letters.length - 1; i++) {
    if (!COMMON_PAIRS.has(letters.slice(i, i + 2))) rare++;
  }
  const ratio = rare / (letters.length - 1);
  const digits = (s.match(/\d/g) ?? []).length;
  // Short real names ("czyborra", "mobiusvc") can have a few odd pairs, so they need a higher bar.
  return (letters.length >= 10 ? ratio >= 0.4 : ratio >= 0.55) || (digits >= 2 && ratio >= 0.25);
}

export function inspectUrl(href: string): UrlInfo | null {
  let url = parseUrl(href);
  if (!url) return null;
  let via: string | null = null;
  let protectedBy: string | null = null;
  for (let depth = 0; depth < 4; depth++) {
    const next = inner(url);
    if (!next) break;
    const host = url.hostname.toLowerCase();
    if (SECURITY_WRAPPERS.test(host)) protectedBy ??= host;
    else via ??= host;
    url = next;
  }

  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const info = parse(host);
  const owner = (info.isIp ? host : info.domain) ?? host;
  const tld = (info.publicSuffix ?? "").split(".").at(-1) ?? "";
  const tags = new Set<UrlTag>();
  if (info.isIp) tags.add("ip");
  else if (/(\d{1,3}[.-]){3}\d{1,3}/.test(host)) tags.add("ip-host");
  if (SHORTENERS.has(owner) || SHORTENERS.has(host)) tags.add("shortener");
  if (DISPOSABLE.some((d) => (d.startsWith(".") ? host.endsWith(d) : host === d || host.endsWith(`.${d}`))) || (host === "docs.google.com" && url.pathname.startsWith("/forms"))) {
    tags.add("disposable");
  }
  if (CHEAP_TLDS.has(tld)) tags.add("cheap-tld");
  if (url.username) tags.add("userinfo");
  if (RISKY_DOWNLOAD.test(url.pathname)) tags.add("download");
  if (host.includes("xn--")) tags.add("punycode");
  const labels = (info.domainWithoutSuffix ?? "").split(".").concat((info.subdomain ?? "").split("."));
  if (!info.isIp && labels.some((label) => label.split("-").some(looksRandom))) tags.add("random");
  // A lone "login" or "secure" subdomain is normal; a compound like "lido-airdrop" or "verify2" is a kit's.
  if (!info.isIp && labels.some((label) => /[-\d]/.test(label) && LURE_WORDS.test(label))) tags.add("lure-host");

  return { url, host, owner, via, protectedBy, tags, tld };
}
