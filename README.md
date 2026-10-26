# phish-check

**Live at [phish.abdullah1.dev](https://phish.abdullah1.dev)**

Check a suspicious email: paste its original source or drop the file, and get a verdict (**Likely phishing**, **Suspicious**, or **No red flags found**) with the reasons behind it. The email is analysed in your browser and never leaves your device. Optional online checks look up only its domains, link addresses and file fingerprints.

The signature feature is the **X-ray lens**: the email is drawn as it looked in your inbox, and a lens follows your cursor to show what's really underneath. You see the real sender address with the swapped character highlighted, where each button really goes, and the invisible tracking pixel.

## What it checks

The engine runs several independent detectors. Each finding has a severity, and the verdict needs agreement between them (see [Scoring](#scoring)).

| Detector | What it looks at |
|---|---|
| Mail provider verdicts | Spam and phishing verdicts the reader's own provider already wrote into the headers: Microsoft (SCL, CAT, SFV, compauth), SpamAssassin, Rspamd, Barracuda and Proofpoint. Only warnings count: a clean provider verdict never vouches for an email. |
| Sender | Brand names in the display name that the address doesn't back up; look-alike domains (swapped characters like `paypa1`, one-letter typos, brand names inside other domains, letters from other alphabets); impossible and machine-generated domains; missing or fake addresses; free-mail accounts posing as staff; Reply-To on another domain |
| Authentication | SPF, DKIM and DMARC from the **top** `Authentication-Results` header, the one written by the reader's own provider (lower ones could be forged by the sender). A DMARC failure counts for less when ARC passed, as it does for mailing lists. |
| Links | Text that shows one domain but leads to another; redirects and security wrappers unwrapped first; look-alike and brand-impersonating hosts; raw IP addresses, shorteners, free hosting, cheap TLDs and random-looking hosts; `javascript:` links; the reader's own address pre-filled in a link; login forms inside the email |
| Attachments | Programs, macro-enabled Office files (including macros inside `.docx`-style files), PDFs with links, JavaScript or launch actions (compressed streams included), what's inside ZIP files and whether they're password-locked, HTML files with login forms or redirects, iOS configuration profiles, calendar invites, double extensions, and files whose bytes don't match their name |
| Wording | Scam wording in 20 families (login requests, invoices, parcels, fines, prizes, crypto, sextortion, callback scams, invented deadlines and more) in English, Portuguese, Spanish, German, French, Dutch and Italian, matched on whole words |
| Evasion | Tricks that hide words from filters: letters from other alphabets, styled maths letters, s p a c e d letters, invisible characters, hidden text, image-only emails, mass mail to strangers, unfilled template placeholders |
| Online (optional) | Domain age and registrar (RDAP), whether a domain exists and can receive mail (DNS), phishing feeds (OpenPhish; Google Safe Browsing and URLhaus with keys), and file fingerprints against MalwareBazaar and VirusTotal (with keys). Links found inside attachments, like the one link in a phishing PDF, are checked too. |
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
apps/worker            Cloudflare Worker: serves the app and /api/intel; email-in comes later
samples/               synthetic test emails with expected verdicts and findings
scripts/evaluate.mjs   accuracy against labelled corpora
design/                the HTML mockups the UI was built from
```

The reading view is a style-free model of the email body. Links become inert text and remote images are never loaded, so rendering an email can't reach out to an attacker's server. The engine loads on demand: the page paints first, then the parsers arrive.

Online checks run after the local verdict is on screen. The browser asks the Worker's `POST /api/intel` about at most 10 domains, 20 links and 10 file fingerprints, and the engine folds the answers in and re-scores. Domain age is measured to when the reader's provider received the email (its own Received header), not to the Date header, which the sender can backdate. The Worker caches answers, allows 30 checks a minute per visitor, stays within the free plan's 50 subrequests per check (blocklists first, then files, domains and per-link services), and reports any service that didn't answer instead of failing.

Blocklists are matched by exact page, and also by whole host for sites that are dedicated to one owner. Shared platforms (big brands, mailbox providers, file-sharing sites, free hosting, shorteners) are matched by exact page only, so one bad file on Google Drive doesn't condemn every Drive link. VirusTotal counts a file as malware only when at least 3 engines flag it.

## Safety and privacy

- The email itself is never uploaded or stored. There are no cookies and no analytics.
- The Worker keeps no request logs: Workers Logs are switched off in `wrangler.jsonc`, so visitors' IP addresses aren't stored.
- Every response carries `Cache-Control: no-transform`, so Cloudflare can't rewrite pages, for example by injecting its Web Analytics script.
- With online checks on (the default, with a switch next to the intake), the browser sends only the domains of the sender and links, link addresses (including links found inside attachments) with their query strings removed, and SHA-256 fingerprints of attachments. When a link's path carries the reader's own email address, plainly or in base64, only the site is sent. Domains of big brands, mailbox providers and shared hosting platforms aren't looked up.
- Neither the browser nor the Worker ever opens a link or loads an image from an analysed email. Online checks ask registries, DNS and blocklists about a link; they never visit it.
- Attachments are read as bytes and never run.
- The page ships with a strict Content Security Policy (`default-src 'none'`, self-hosted fonts, no inline scripts).

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
| 3 | Web app: X-ray lens, paste, drop and samples, help for finding the source, Analyst view | ✅ (Outlook `.msg` files not yet) |
| 4 | Engine tuned on real phishing; online checks through the Worker (domain age, DNS, phishing feeds, file reputation) | ✅ |
| 5 | Forward-to-check by email | |
| 6 | Ship at `phish.abdullah1.dev` | ✅ Live |
