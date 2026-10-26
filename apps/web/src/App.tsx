import { useCallback, useEffect, useRef, useState } from "react";
import { DropOverlay, Footer, Nav, Toast } from "./components/Chrome.tsx";
import { Hero, type IntakeError } from "./components/Hero.tsx";
import { Report, type Result } from "./components/Report.tsx";
import { SourceSheet } from "./components/SourceSheet.tsx";
import { loadEngine } from "./lib/engine.ts";
import { checkOnline, onlineChecksEnabled, setOnlineChecks } from "./lib/intel.ts";
import { VERDICT_NAME } from "./lib/report.ts";
import { HERO_SAMPLE, loadSample, type Sample } from "./lib/samples.ts";

const MAX_FILE = 10 * 1024 * 1024;

export function App() {
  const [example, setExample] = useState<Result | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<IntakeError | null>(null);
  const [sheetOpen, setSheetOpen] = useState(false);
  const [announcement, setAnnouncement] = useState("");
  const [online, setOnline] = useState(onlineChecksEnabled);
  const onlineRef = useRef(online);
  onlineRef.current = online;
  const sourceRef = useRef<HTMLTextAreaElement>(null);
  const nextId = useRef(1);
  /** The result on screen, so late online answers for an older email stay quiet. */
  const shownId = useRef(0);

  // The hero lens and the example report both show the fake PayPal sample.
  useEffect(() => {
    let live = true;
    void (async () => {
      const [engine, raw] = await Promise.all([loadEngine(), loadSample(HERO_SAMPLE.file)]);
      const started = performance.now();
      const analysis = await engine.analyzeEmail(raw);
      if (live) setExample({ id: 0, analysis, ms: performance.now() - started, label: HERO_SAMPLE.label, kind: "example", intel: { status: "skipped" } });
    })();
    return () => {
      live = false;
    };
  }, []);

  const inspect = useCallback(async (raw: string | ArrayBuffer, label: string, kind: Result["kind"] = "yours") => {
    if (typeof raw === "string" && !raw.trim()) {
      setError({ message: "Paste the email's source first, or drop a .eml file.", help: true });
      return;
    }
    setBusy(true);
    setError(null);
    setAnnouncement("Checking the email…");
    const engine = await loadEngine().catch(() => null);
    if (!engine) {
      setBusy(false);
      setAnnouncement("");
      setError({ message: "The checks couldn't load. Check your connection and try again." });
      return;
    }
    try {
      const started = performance.now();
      const email = await engine.parseEmail(typeof raw === "string" ? raw : new Uint8Array(raw));
      const analysis = await engine.analyzeParsed(email);
      const id = nextId.current++;
      shownId.current = id;
      // Samples use made-up .test domains, so looking them up online would only find nothing.
      const checking = kind === "yours" && onlineRef.current;
      setResult({ id, analysis, ms: performance.now() - started, label, kind, intel: { status: checking ? "checking" : kind === "yours" ? "off" : "skipped" } });
      setAnnouncement(`Done. ${VERDICT_NAME[analysis.verdict]}. ${analysis.headline}`);
      // The verdict is on screen; online checks only refine it, so the button is free again.
      setBusy(false);
      if (checking) {
        try {
          const online = await checkOnline(analysis, email);
          // Only update the email still on screen: a slow answer mustn't overwrite a newer check.
          setResult((current) => (current?.id === id ? { ...current, analysis: online.analysis, intel: { status: "done", response: online.response } } : current));
          if (shownId.current === id && online.analysis.verdict !== analysis.verdict) {
            setAnnouncement(`Online checks changed the verdict to ${VERDICT_NAME[online.analysis.verdict]}. ${online.analysis.headline}`);
          }
        } catch {
          setResult((current) => (current?.id === id ? { ...current, intel: { status: "unavailable" } } : current));
        }
      }
    } catch (err) {
      setAnnouncement("");
      if (err instanceof engine.EmailParseError && /no email headers/i.test(err.message)) {
        setError({ message: "That looks like the text of an email, not its source. The source starts with lines like Received: and From:.", help: true });
      } else if (err instanceof engine.EmailParseError) {
        setError({ message: `${err.message}.` });
      } else {
        setError({ message: "Something went wrong reading this email. Try copying its full source again." });
      }
    } finally {
      setBusy(false);
    }
  }, []);

  const inspectFile = useCallback(
    async (file: File) => {
      if (file.size > MAX_FILE) {
        setError({ message: "That file is over 10 MB, which is bigger than any normal email." });
        return;
      }
      await inspect(await file.arrayBuffer(), file.name);
    },
    [inspect],
  );

  const openSample = useCallback(
    async (sample: Sample) => inspect(await loadSample(sample.file), sample.label, "sample"),
    [inspect],
  );

  // Drop an email file anywhere on the page.
  useEffect(() => {
    let depth = 0;
    const hasFiles = (e: DragEvent) => [...(e.dataTransfer?.types ?? [])].includes("Files");
    const setDragging = (on: boolean) => document.body.classList.toggle("dragging", on);
    const enter = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      depth++;
      setDragging(true);
    };
    const leave = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      depth = Math.max(0, depth - 1);
      if (!depth) setDragging(false);
    };
    const over = (e: DragEvent) => {
      if (hasFiles(e)) e.preventDefault();
    };
    const drop = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      depth = 0;
      setDragging(false);
      const file = e.dataTransfer?.files[0];
      if (file) void inspectFile(file);
    };
    addEventListener("dragenter", enter);
    addEventListener("dragleave", leave);
    addEventListener("dragover", over);
    addEventListener("drop", drop);
    return () => {
      removeEventListener("dragenter", enter);
      removeEventListener("dragleave", leave);
      removeEventListener("dragover", over);
      removeEventListener("drop", drop);
    };
  }, [inspectFile]);

  const shown = result ?? example;

  return (
    <>
      <a className="skip" href="#intake-source">
        Skip to the email check
      </a>
      <Nav onOpenSheet={() => setSheetOpen(true)} />
      <main id="top">
        <Hero
          example={example?.analysis ?? null}
          busy={busy}
          error={error}
          sourceRef={sourceRef}
          onInspect={(raw, label) => void inspect(raw, label)}
          onFile={(file) => void inspectFile(file)}
          onSample={(sample) => void openSample(sample)}
          onOpenSheet={() => setSheetOpen(true)}
          online={online}
          onOnlineChange={(on) => {
            setOnline(on);
            setOnlineChecks(on);
          }}
        />
        {shown && (
          <Report
            result={shown}
            onCheckAnother={() => {
              scrollTo({ top: 0, behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
              sourceRef.current?.focus({ preventScroll: true });
            }}
          />
        )}
      </main>
      <Footer />
      <SourceSheet open={sheetOpen} onClose={() => setSheetOpen(false)} />
      <DropOverlay />
      <Toast />
      <p className="sr-only" role="status" aria-live="polite">
        {announcement}
      </p>
    </>
  );
}
