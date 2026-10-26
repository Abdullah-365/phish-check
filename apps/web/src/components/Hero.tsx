import { useRef, useState, type RefObject } from "react";
import type { Analysis } from "@phish-check/engine";
import { SAMPLES, type Sample } from "../lib/samples.ts";
import { UploadIcon } from "./Icons.tsx";
import { XRay } from "./XRay.tsx";

export interface IntakeError {
  message: string;
  /** Show the "find your email's source" help next to the message. */
  help?: boolean;
}

interface Props {
  example: Analysis | null;
  busy: boolean;
  error: IntakeError | null;
  sourceRef: RefObject<HTMLTextAreaElement | null>;
  onInspect(raw: string, label: string): void;
  onFile(file: File): void;
  onSample(sample: Sample): void;
  onOpenSheet(): void;
  /** Whether domains, links and file fingerprints may be checked online. */
  online: boolean;
  onOnlineChange(on: boolean): void;
}

/** True when pasted text starts like the source of an email rather than its body. */
function looksLikeSource(text: string): boolean {
  const head = text.slice(0, 4000);
  return (head.match(/^(received|from|to|subject|date|return-path|delivered-to|message-id|mime-version|authentication-results|dkim-signature|x-[\w-]+):/gim) ?? []).length >= 3;
}

const isMac = typeof navigator !== "undefined" && /mac/i.test(navigator.userAgent);

export function Hero({ example, busy, error, sourceRef, onInspect, onFile, onSample, onOpenSheet, online, onOnlineChange }: Props) {
  const [source, setSource] = useState("");
  const [revealed, setRevealed] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  return (
    <section className="wrap hero" aria-labelledby="hero-title">
      <h1 className="h1" id="hero-title">
        <span className="line">
          <span>See through</span>
        </span>
        <span className="line">
          <span>
            any email<span className="dot">.</span>
          </span>
        </span>
      </h1>

      <div className="hero-grid">
        <div>
          <p className="lede">
            phish-check takes a suspicious email apart and shows you <b>who really sent it</b>, <b>where its links actually go</b>,
            and <b>what's hiding inside</b>. The email itself never leaves your device.
          </p>

          <form
            className={`intake${error ? " has-error" : ""}`}
            onSubmit={(e) => {
              e.preventDefault();
              onInspect(source, "Pasted email");
            }}
          >
            <label className="sr-only" htmlFor="intake-source">
              Email source
            </label>
            <textarea
              id="intake-source"
              ref={sourceRef}
              value={source}
              spellCheck={false}
              aria-invalid={!!error}
              aria-describedby={error ? "intake-error" : undefined}
              placeholder={"Paste the email's original source here.\nIt starts with lines like Received: and From:"}
              onChange={(e) => setSource(e.target.value)}
              onPaste={(e) => {
                // Pasting a whole email source into an empty box inspects it right away.
                const pasted = e.clipboardData.getData("text");
                if (!source.trim() && looksLikeSource(pasted)) setTimeout(() => onInspect(pasted, "Pasted email"));
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                  e.preventDefault();
                  onInspect(source, "Pasted email");
                }
              }}
            />
            <div className="intake-bar">
              <button className="file-btn" type="button" onClick={() => fileInput.current?.click()}>
                <UploadIcon />
                <span>
                  Choose a file
                  <span className="drop-hint">
                    , or drop a <b>.eml</b> anywhere
                  </span>
                </span>
              </button>
              <input
                ref={fileInput}
                type="file"
                accept=".eml,message/rfc822,.txt,.msg"
                hidden
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) onFile(file);
                  e.target.value = "";
                }}
              />
              <button className="btn" type="submit" aria-busy={busy}>
                {busy ? "Inspecting…" : "Inspect"} <kbd>{isMac ? "⌘" : "Ctrl"} ↵</kbd>
              </button>
            </div>
          </form>
          {error && (
            <p className="intake-error" id="intake-error" role="alert">
              {error.message}{" "}
              {error.help && (
                <button className="link" type="button" onClick={onOpenSheet}>
                  Find your email's source
                </button>
              )}
            </p>
          )}

          <div className="helper">
            <button className="link" type="button" onClick={onOpenSheet}>
              Where do I find the source?
            </button>
            <label className="online">
              <input type="checkbox" role="switch" checked={online} onChange={(e) => onOnlineChange(e.target.checked)} />
              <span className="switch" aria-hidden="true" />
              Check links and domains online
            </label>
          </div>
          <p className="receipt">
            <i aria-hidden="true" />
            {online
              ? "Your email never leaves this tab. Only its domains, link addresses and file fingerprints are looked up."
              : "Nothing leaves this tab: 0 bytes uploaded, nothing stored."}
          </p>

          <div className="samples">
            <p className="label" id="samples-label">
              Or open a sample
            </p>
            <div className="chips" role="group" aria-labelledby="samples-label">
              {SAMPLES.map((sample) => (
                <button key={sample.file} className="chip" type="button" onClick={() => onSample(sample)}>
                  {sample.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        <figure className="specimen">
          <div className="specimen-head">
            <span className="label">Sample · fake PayPal</span>
            <span className="label">X-ray lens</span>
          </div>
          {example ? <XRay analysis={example} tour revealed={revealed} /> : <div className="skeleton" style={{ height: 420 }} />}
          <figcaption className="specimen-foot">
            <span>Move over the email to look underneath.</span>
            <button className="ghost-btn" type="button" aria-pressed={revealed} onClick={() => setRevealed((v) => !v)}>
              {revealed ? "Back to the lens" : "Show everything"}
            </button>
          </figcaption>
        </figure>
      </div>
    </section>
  );
}
