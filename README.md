# phish-check

**Live at [phish.abdullah1.dev](https://phish.abdullah1.dev)**

Check a suspicious email: paste its original source or drop the file (an `.eml`, or an Outlook `.msg`), and get a verdict (**Likely phishing**, **Suspicious**, or **No red flags found**) with the reasons behind it. The email is analysed in your browser and never leaves your device. Optional online checks look up only its domains, link addresses, file fingerprints, the public keys its signatures name and the sending server its headers name.

The signature feature is the **X-ray lens**: the email is drawn as it looked in your inbox, and a lens follows your cursor to show what's really underneath. You see the real sender address with the swapped character highlighted, where each button really goes, and the invisible tracking pixel.

## What it checks

The engine runs several independent detectors. Each finding has a severity, and the verdict needs agreement between them (see [Scoring](#scoring)).

| Detector | What it looks at |
|---|---|
| Mail provider verdicts | Spam and phishing verdicts the reader's own provider already wrote into the headers: Microsoft (SCL, CAT, SFV, compauth), SpamAssassin, Rspamd, Barracuda and Proofpoint. Only warnings count: a clean provider verdict never vouches for an email. |
| Sender | Brand names in the display name that the address doesn't back up; look-alike domains (swapped characters like `paypa1`, one-letter typos, brand names inside other domains, letters from other alphabets); impossible and machine-generated domains; missing or fake addresses; free-mail accounts posing as staff; Reply-To on another domain |
| Authentication | SPF, DKIM and DMARC from the **top** `Authentication-Results` header, the one written by the reader's own provider (lower ones could be forged by the sender). A DMARC failure counts for less when ARC passed, as it does for mailing lists. A header claiming a DKIM pass for a domain that signed nothing in the email is called out as forged. With online checks on, the DKIM signatures themselves are verified against the keys their domains publish (RSA and Ed25519, simple and relaxed), so a signature from the sender's own domain proves who sent it whatever the headers say, and a claimed pass whose signature doesn't verify is flagged. A claimed SPF pass is re-run against the domain's own SPF record, for the server address the header names. |
| Links | Text that shows one domain but leads to another; redirects and security wrappers unwrapped first; look-alike and brand-impersonating hosts; raw IP addresses, shorteners, free hosting, cheap TLDs and random-looking hosts; `javascript:` links; the reader's own address pre-filled in a link; login forms inside the email |
| Attachments | Programs, macro-enabled Office files (including macros inside `.docx`-style files), PDFs with links, JavaScript or launch actions (compressed streams included), what's inside ZIP files and whether they're password-locked, HTML files with login forms or redirects, iOS configuration profiles, calendar invites, double extensions, and files whose bytes don't match their name |
| Wording | Scam wording in 20 families (login requests, invoices, parcels, fines, prizes, crypto, sextortion, callback scams, invented deadlines and more) in English, Portuguese, Spanish, German, French, Dutch and Italian, matched on whole words |
| Evasion | Tricks that hide words from filters: letters from other alphabets, styled maths letters, s p a c e d letters, invisible characters, hidden text, image-only emails, mass mail to strangers, unfilled template placeholders |
| Online (optional) | Domain age and registrar (RDAP), whether a domain exists and can receive mail (DNS), DKIM public keys and SPF records (DNS), phishing feeds (OpenPhish; Google Safe Browsing and URLhaus with keys), and file fingerprints against MalwareBazaar and VirusTotal (with keys). Links found inside attachments, like the one link in a phishing PDF, are checked too. |
| Forwards | **Forward as attachment** is unwrapped, so the original is judged rather than the forward. Plain inline forwards fall back to the quoted sender and say the check is partial, but only when the outer email really is a forward (a "Fwd:" subject from a sender that authenticates), so a phish can't paste in a fake "Forwarded message" block to hide its real sender. |

Each finding comes as a plain-English title, a "You see / Really" pair and an explanation. An **Analyst** view adds the delivery route, the domains checked online, defanged indicators (query strings removed, since they often carry the recipient's address) and the key headers with the suspicious parts highlighted.

## Scoring

High-severity findings weigh 45, medium 20 and low 8. Each detector's total is capped, so a pile of weak hits of one kind can't decide alone.

- **Likely phishing**: two high-severity findings, or a score of 70 or more.
- **Suspicious**: one high-severity finding, or a score of 28 or more (a medium and a low together).
- **No red flags found**: anything below that. No verdict ever says "safe".

## Accuracy

Measured with `scripts/evaluate.mjs` against real phishing caught by honeypots ([rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot)) and legitimate mail from the [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/). The engine was tuned on the dev set only; the held-out set was set aside first and used only to report results.

| Set | Phishing caught | of which "Likely phishing" | Legitimate mail flagged |
|---|---|---|---|
| Dev: 841 phishing, 2,750 legitimate | 88.8% | 65.2% | 0.7% (0.1% "Likely phishing") |
| Held out: 500 phishing, 1,400 legitimate | **90.6%** | 64.2% | **0.7%** (none "Likely phishing") |
| Held out, engine only | 78.2% | 35.8% | 0.7% (none "Likely phishing") |

"Phishing caught" means a verdict of Likely phishing or Suspicious; an email the engine can't read counts as missed. Read the numbers with these limits in mind:

- **Most of the honeypot mail carries Microsoft's own spam verdict.** The "engine only" row removes every provider verdict and shows what the detectors find by themselves.
- **The legitimate mail is from 2002–2003.** It predates modern authentication headers, so header-based checks can't misfire on it. A modern inbox will see more false positives than this.
- **Online checks aren't counted.** The corpus emails are months or years old, and their domains have since expired or changed hands.

The corpora aren't included in this repo (one of them is real phishing). Download them yourself and point the script at the folders:

```bash
node scripts/evaluate.mjs --phish path/to/phish --ham path/to/easy_ham --ham path/to/hard_ham --out results.json
node scripts/evaluate.mjs --no-provider --phish path/to/phish   # engine only, provider verdicts removed
```

## How it works

One TypeScript analysis engine is shared by the browser and the Worker:

```
packages/engine        parse → reading view → detectors → score → plain-English report
apps/web               Vite + React UI: intake, X-ray lens, report
apps/worker            Cloudflare Worker: serves the app, /api/intel, and forward-to-check by email
samples/               synthetic test emails with expected verdicts and findings
scripts/evaluate.mjs   accuracy against labelled corpora
design/                the HTML mockups the UI was built from
```

The reading view is a style-free model of the email body. Links become inert text and remote images are never loaded, so rendering an email can't reach out to an attacker's server. The engine loads on demand: the page paints first, then the parsers arrive.

Online checks run after the local verdict is on screen. The browser asks the Worker's `POST /api/intel` about at most 10 domains, 20 links, 10 file fingerprints, 3 DKIM keys and one SPF claim, and the engine folds the answers in and re-scores. Domain age is measured to when the reader's provider received the email (its own Received header), not to the Date header, which the sender can backdate. The Worker caches answers, allows 30 checks a minute per visitor, stays within the free plan's 50 subrequests per check (blocklists first, then files, DKIM keys and SPF, domains and per-link services), and reports any service that didn't answer instead of failing.

DKIM keys are fetched only for signatures that can prove or disprove something: the sender's own domain's, and those the `Authentication-Results` header vouches for. The Worker returns the key records and the signatures are verified in the browser (`packages/engine/src/dkim.ts`, checked against [mailauth](https://github.com/postalsys/mailauth) on 688 real signatures with no disagreements). The signature over the headers is checked before the body, so a genuine signature on a body a mail system changed later (a footer, rewritten links) still counts as genuine, just not as a full pass. A failing signature or a missing key only counts against an email received in the last 30 days, since domains change their keys.

A claimed SPF pass is tested the same way. The header names the server it checked (Gmail writes "designates 192.0.2.1 as permitted sender", Microsoft "sender IP is 192.0.2.1"), and the Worker evaluates the claimed domain's SPF record for that address (`apps/worker/src/spf.ts`: RFC 7208 with include, redirect, a, mx, exists, macros and the 10-lookup limit). Terms it can't evaluate the way the receiving server did, such as `ptr` or the sender's mailbox in a macro, can only turn its answer into "unknown", never "fail". On the 638 distinct claims in the phishing corpora it agrees with mailauth's strict mode on 629; the other 9 are one record that strict mode rejects but receivers accept, and one header whose address was cut off. Only a contradiction on mail received in the last 30 days counts. On the corpus's recent mail, 11 of 13 genuine provider claims still checked out; the 2 that didn't came from throwaway phishing domains whose records had changed since.

Blocklists are matched by exact page, and also by whole host for sites that are dedicated to one owner. Shared platforms (big brands, mailbox providers, file-sharing sites, free hosting, shorteners) are matched by exact page only, so one bad file on Google Drive doesn't condemn every Drive link. VirusTotal counts a file as malware only when at least 3 engines flag it.

## Forward-to-check by email

Forward a suspicious email to **check@abdullah1.dev** and the verdict comes back as a reply: the headline, what was found, and what to do now. It's built for phones, where mail apps can't show an email's source.

- **What it reads:** "Forward as attachment" (the original arrives intact, so it's checked fully), an attached `.eml` or `.msg` file, or a plain forward (only the quoted sender survives, so the reply says the check was partial). A message with no forwarded email gets instructions instead.
- **What comes back:** the same engine and online checks as the website. Every address, link and filename taken from the checked email is defanged (`evil[.]example`), so nothing in the reply can be clicked by mistake. The only real link is to this site.
- **Safety:** Cloudflare only lets the Worker reply to a sender whose message passed DMARC, so a spammer can't forge someone's address to send them replies. Bounces, auto-replies (`Auto-Submitted`), bulk mail and mailing lists get no answer, which prevents mail loops, and replies are themselves marked `Auto-Submitted: auto-replied`. Each sender gets at most 10 replies an hour, and forwards over 5 MB aren't read.
- **Privacy:** the email is read, checked and answered in memory and never stored; Worker logs stay off.

The handler is `email()` in `apps/worker/src/index.ts` (code in `email.ts`, reply text in `reply.ts`). To switch it on, the domain needs one Email Routing rule, set in the Cloudflare dashboard: **Email** → **Email Routing** → **Routing rules** → **Create address**, custom address `check`, action **Send to a Worker**, destination `phish-check`.

**CPU time.** A forwarded email is analysed inside the Worker. On the free plan, Cloudflare gives each email 10 ms of CPU; a typical phishing email needs about 7 ms, but long or attachment-heavy ones need 20 ms or more, run out, and get no reply. The Workers Paid plan raises the limit to 30 seconds. The website's own checks run in the visitor's browser and aren't affected.

## Safety and privacy

- The email itself is never uploaded or stored. There are no cookies and no analytics.
- The Worker keeps no request logs: Workers Logs are switched off in `wrangler.jsonc`, so visitors' IP addresses aren't stored.
- Every response carries `Cache-Control: no-transform`, so Cloudflare can't rewrite pages, for example by injecting its Web Analytics script.
- With online checks on (the default, with a switch next to the intake), the browser sends only the domains of the sender and links, link addresses (including links found inside attachments) with their query strings removed, SHA-256 fingerprints of attachments, the names of the DKIM keys the email's signatures use (a selector and a domain, such as `s1._domainkey.example.com`), and, when its headers claim an SPF pass, that domain and the sending server's address the claim names. When a link's path carries the reader's own email address, plainly or in base64, only the site is sent. Domains of big brands, mailbox providers and shared hosting platforms aren't looked up.
- Neither the browser nor the Worker ever opens a link or loads an image from an analysed email. Online checks ask registries, DNS and blocklists about a link; they never visit it.
- Attachments are read as bytes and never run.
- The page ships with a strict Content Security Policy (`default-src 'none'`, self-hosted fonts, no inline scripts).

## Known limits

- **A carefully copied SPF claim.** SPF, DKIM and DMARC are read from the topmost `Authentication-Results` header, the one the reader's own provider adds when the email arrives (Gmail, Outlook and Yahoo always add one). A mail server that adds none leaves only headers the sender wrote. Forged DKIM passes are caught against the signatures themselves, and a forged SPF pass is caught when the server address it names isn't one the domain allows (see [How it works](#how-it-works)). A forger who copies a genuine header, a permitted address included, can still fake an SPF pass: which server really delivered the email is known only to the server that received it.
- **Signatures broken in transit.** Some company mail systems change an email after checking it, for example by tagging the subject or rewriting links. Common subject tags like `[EXTERNAL]` are allowed for and a changed body is never held against an email, but other changes to signed headers make a genuine signature fail, which phish-check reports as a medium warning, not as proof.
- **Links are never opened.** That keeps you safe, but a page that only turns malicious after a redirect chain, or only for some visitors, can't be seen. Blocklists and the link's own address are what's checked.
- **Rich-text-only Outlook files.** A `.msg` is read through its stored plain-text and HTML bodies. The rare file that stores its body only as rich text (RTF) is checked on its headers and attachments alone.

## Development

Requires Node 24+.

```bash
npm install
npm test            # engine + worker tests, including every sample's expected verdict
npm run typecheck
npm run dev         # web app with hot reload (online checks need the Worker below)
npm run worker:dev  # production build in the local Workers runtime (http://localhost:8787)
npm run design      # serve the design mockups
```

For local online checks with the optional services, put the keys in a `.dev.vars` file (git-ignored) using the names below.

## Deployment

- **Deploys:** Cloudflare Workers Builds (Git integration). A push to `main` builds and deploys. To connect it: Workers & Pages → Create → Import a repository → this repo. Build command: `npm run build`. Deploy command: `npx wrangler deploy`. The build runs on Node 24, pinned in `.node-version`.
- **Domain:** the Worker serves `phish.abdullah1.dev` through a custom-domain route in `wrangler.jsonc`. Cloudflare creates that DNS record and its certificate on the first deploy and leaves the zone's other records alone.
- **Tests:** GitHub Actions (`.github/workflows/test.yml`) runs type checks, tests and the build on every push and pull request. It needs no secrets.
- **API keys** are Worker secrets in Cloudflare, never in this repo. All three are optional: RDAP, DNS and OpenPhish work without any.

```bash
npx wrangler secret put ABUSECH_KEY   # URLhaus and MalwareBazaar (free key from auth.abuse.ch)
npx wrangler secret put GSB_KEY       # Google Safe Browsing
npx wrangler secret put VT_KEY        # VirusTotal, used for file fingerprints only
```

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Repo, parser, sample set | ✅ |
| 1 | Header checks: authentication, sender disguises, look-alike domains, Reply-To | ✅ |
| 2 | Content checks: links, attachments, wording, scoring and explanations | ✅ |
| 3 | Web app: X-ray lens, paste, drop and samples, help for finding the source, Analyst view, Outlook `.msg` files | ✅ |
| 4 | Engine tuned on real phishing; online checks through the Worker (domain age, DNS, phishing feeds, file reputation) | ✅ |
| 5 | Forward-to-check by email | ✅ Built (needs the Email Routing rule above) |
| 6 | Ship at `phish.abdullah1.dev` | ✅ Live |
