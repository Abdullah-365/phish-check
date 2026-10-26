# Sample emails

Synthetic test emails for the analysis engine. They're written by hand to mimic common phishing patterns. None of them is a real captured phish.

- **No real infrastructure.** Every attacker domain uses the reserved `.test` TLD. Senders, recipients and providers use reserved example domains (`*.example`), and IPs come from the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Nothing here resolves or reaches a real server.
- **No live payloads.** Attachments are plain-text placeholders that only *claim* to be risky file types.
- **Signatures are placeholders.** `DKIM-Signature` values are not real, so these samples can't be used to test cryptographic DKIM verification.

`manifest.json` lists each file with the verdict the engine should eventually reach. Every `.eml` here must be listed there; the test suite enforces it.

## Adding a sample

1. Write or defang the email. Replace every real domain, address and IP with reserved ones, and strip any real attachment.
2. Add it to `manifest.json` with its expected verdict and a one-line reason.
3. Run `npm test`.
