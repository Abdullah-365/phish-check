import { useEffect, useState } from "react";
import { currentTheme, setTheme, type Theme } from "../lib/theme.ts";
import { onToast } from "../lib/toast.ts";
import { BrandMark, ThemeIcon } from "./Icons.tsx";

export const REPO_URL = "https://github.com/Abdullah-365/phish-check";

export function Nav({ onOpenSheet }: { onOpenSheet(): void }) {
  const [theme, setThemeState] = useState<Theme>(currentTheme);
  const next = theme === "dark" ? "light" : "dark";
  return (
    <header className="wrap nav">
      <a className="brand" href="#top">
        <BrandMark />
        phish-check
      </a>
      <nav className="nav-links" aria-label="Main">
        <a className="wide" href="#report">
          Example report
        </a>
        <button className="wide" type="button" onClick={onOpenSheet}>
          Find your email's source
        </button>
        <a href={REPO_URL}>GitHub</a>
        <button
          className="icon-btn"
          type="button"
          aria-label={`Switch to ${next} theme`}
          onClick={() => {
            setTheme(next);
            setThemeState(next);
          }}
        >
          <ThemeIcon />
        </button>
      </nav>
    </header>
  );
}

export function Footer() {
  return (
    <footer className="wrap">
      <div className="foot">
        <p className="foot-big">
          Your email never
          <br />
          <span>leaves this tab.</span>
        </p>
        <p className="privacy">
          phish-check reads the email inside your browser and never uploads or stores it. With online checks on, it looks up only
          the domains in the email, its link addresses (with personal details in them removed) and file fingerprints, to see how
          new they are and whether they're on phishing blocklists, plus the public keys its signatures name and the sending server its
          headers name, to check those claims.
          There are no cookies or analytics, and it never opens a link or loads an image from the emails it checks.
        </p>
        <div className="foot-row">
          <span>
            phish-check · open source · made by{" "}
            <a className="link" href="https://abdullah1.dev">
              Abdullah
            </a>
          </span>
          <nav aria-label="Footer">
            <a href={REPO_URL}>Source code</a>
            <a href="#report">Example report</a>
          </nav>
        </div>
      </div>
    </footer>
  );
}

export function DropOverlay() {
  return (
    <div className="dropper" aria-hidden="true">
      <div className="dropper-frame">
        <i />
        <i />
        <i />
        <i />
        <b>Drop to inspect</b>
        <span>It's read in this tab. Nothing is uploaded.</span>
      </div>
    </div>
  );
}

export function Toast() {
  const [text, setText] = useState("");
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    let timer = 0;
    const off = onToast((message) => {
      setText(message);
      setVisible(true);
      clearTimeout(timer);
      timer = window.setTimeout(() => setVisible(false), 2600);
    });
    return () => {
      off();
      clearTimeout(timer);
    };
  }, []);
  return (
    <div className={`toast${visible ? " show" : ""}`} role="status" aria-live="polite">
      {text}
    </div>
  );
}
