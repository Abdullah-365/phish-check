import { Fragment, useEffect, useRef, useState } from "react";
import type { Analysis, Check, DomainIntel, Finding, Hop, IntelResponse, KeyHeader, NextStep } from "@phish-check/engine";
import type { IntelState } from "../lib/intel.ts";
import { copyText, downloadReport, indicatorText, summaryText, targetKey } from "../lib/report.ts";
import { toast } from "../lib/toast.ts";
import { useReveal } from "../lib/useReveal.ts";
import { NoticeIcon } from "./Icons.tsx";
import { SnippetView } from "./SnippetView.tsx";
import { XRay } from "./XRay.tsx";

export interface Result {
  id: number;
  analysis: Analysis;
  ms: number;
  /** Where the email came from, e.g. a file name or "Pasted email". */
  label: string;
  /** "example" is the report shown before anyone checks anything. */
  kind: "example" | "sample" | "yours";
  /** Domain age, DNS and blocklist lookups, run after the local analysis. */
  intel: IntelState;
}

function intelNote(intel: IntelState): string {
  switch (intel.status) {
    case "checking":
      return "checking links and domains online…";
    case "done":
      return intel.response.sources.length ? `online checks: ${intel.response.sources.join(", ")}` : "nothing to check online";
    case "unavailable":
      return "online checks unavailable";
    case "off":
      return "online checks off";
    case "skipped":
      return "0 bytes uploaded";
  }
}

interface Props {
  result: Result;
  onCheckAnother(): void;
}

const TITLES: Record<Result["kind"], string> = {
  example: "What you get back",
  sample: "Sample report",
  yours: "Your email",
};

export function Report({ result, onCheckAnother }: Props) {
  const example = result.kind === "example";
  const { analysis } = result;
  const [view, setView] = useState<"plain" | "analyst">("plain");
  const [active, setActive] = useState<string | null>(null);
  const [focus, setFocus] = useState<{ key: string } | null>(null);
  const headRef = useRef<HTMLHeadingElement>(null);
  const sectionRef = useRef<HTMLElement>(null);
  const head = useReveal<HTMLDivElement>();

  // A fresh result of the reader's own: bring it into view and move focus to it.
  useEffect(() => {
    if (example) return;
    const smooth = !matchMedia("(prefers-reduced-motion: reduce)").matches;
    sectionRef.current?.scrollIntoView({ behavior: smooth ? "smooth" : "auto", block: "start" });
    headRef.current?.focus({ preventScroll: true });
    setActive(null);
  }, [result.id, example]);

  const show = (finding: Finding) => {
    setActive(finding.id);
    setFocus({ key: targetKey(finding.target) });
  };

  const source = example ? "Example · fake PayPal sample" : result.kind === "sample" ? `${result.label} sample` : result.label;
  const meta = `${source} · checked in this tab in ${Math.max(1, Math.round(result.ms))} ms · ${intelNote(result.intel)}`;
  const activeKey = analysis.findings.find((f) => f.id === active);

  return (
    <section className="report" id="report" ref={sectionRef} aria-labelledby="report-title">
      <div className="wrap">
        <div className="report-head reveal" ref={head}>
          <div>
            <h2 className="h2" id="report-title" tabIndex={-1} ref={headRef}>
              {TITLES[result.kind]}
            </h2>
            <p className="label">{meta}</p>
          </div>
          {!example && (
            <button className="ghost-btn" type="button" onClick={onCheckAnother}>
              Check another email
            </button>
          )}
        </div>
        <Notices analysis={analysis} />
      </div>

      <Verdict key={result.id} analysis={analysis} />

      <div className="wrap">
        <div className="toolbar">
          <div className="seg" role="group" aria-label="Level of detail">
            <button type="button" aria-pressed={view === "plain"} onClick={() => setView("plain")}>
              Plain English
            </button>
            <button type="button" aria-pressed={view === "analyst"} onClick={() => setView("analyst")}>
              Analyst
            </button>
          </div>
          <div className="tools">
            <button
              className="ghost-btn"
              type="button"
              onClick={async () => toast((await copyText(summaryText(analysis))) ? "Summary copied" : "Couldn't reach the clipboard")}
            >
              Copy summary
            </button>
            <button className="ghost-btn" type="button" onClick={() => downloadReport(analysis)}>
              Download report
            </button>
          </div>
        </div>

        <div className="xray-grid">
          <div className="sticky">
            <XRay
              key={result.id}
              analysis={analysis}
              size="large"
              pins
              focus={focus}
              activeKey={activeKey ? targetKey(activeKey.target) : null}
              onRegion={(key) => setActive(analysis.findings.find((f) => targetKey(f.target) === key)?.id ?? null)}
              onPin={(finding) => {
                show(finding);
                document.getElementById(`finding-${finding.id}`)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
              }}
            />
            <p className="specimen-foot">
              {analysis.findings.length ? "Hover a finding to see where it hides." : "Move over the email to look underneath."}
            </p>
          </div>

          {analysis.findings.length ? (
            <ol className="findings" aria-label="What we found">
              {analysis.findings.map((finding, index) => (
                <li
                  key={finding.id}
                  id={`finding-${finding.id}`}
                  className={`finding${active === finding.id ? " on" : ""}`}
                  tabIndex={0}
                  onMouseEnter={() => show(finding)}
                  onFocus={() => show(finding)}
                >
                  <span className={`pin ${finding.severity}`} aria-hidden="true">
                    {index + 1}
                  </span>
                  <div>
                    <h3>{finding.title}</h3>
                    {(finding.seen || finding.real) && (
                      <dl className="seen">
                        {finding.seen && (
                          <>
                            <dt>You see</dt>
                            <dd>
                              <SnippetView snippet={finding.seen} />
                            </dd>
                          </>
                        )}
                        {finding.real && (
                          <>
                            <dt>Really</dt>
                            <dd className="real">
                              <SnippetView snippet={finding.real} />
                            </dd>
                          </>
                        )}
                      </dl>
                    )}
                    <p>{finding.explanation}</p>
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <p className="all-clear">
              <b>No tricks found</b>
              We looked for disguised senders, links that lie about where they go, risky attachments, and pressure or money
              requests in the wording. None turned up.
            </p>
          )}
        </div>

        <Checks checks={analysis.checks} />
        {view === "analyst" && <Analyst analysis={analysis} intel={result.intel.status === "done" ? result.intel.response : null} />}
        <NextSteps steps={analysis.nextSteps} />
      </div>
    </section>
  );
}

function Notices({ analysis }: { analysis: Analysis }) {
  const notices: React.ReactNode[] = [];
  if (analysis.forwarded?.mode === "inline") {
    notices.push(
      <>
        <b>This was forwarded as plain text, so the original headers are gone.</b> We checked the quoted sender, the links and
        the wording, but not where it really came from. For a full check, forward it as an attachment or download the original.
      </>,
    );
  } else if (analysis.forwarded?.mode === "attachment") {
    notices.push(
      <>
        <b>Forwarded by {analysis.forwarded.by}.</b> We checked the original email inside the forward, not the forward itself.
      </>,
    );
  }
  if (analysis.content.truncated) {
    notices.push(<>This email is very long, so the reading view and the wording checks cover the first part of it.</>);
  }
  return (
    <>
      {notices.map((notice, i) => (
        <p className="notice" key={i}>
          <NoticeIcon />
          <span>{notice}</span>
        </p>
      ))}
    </>
  );
}

const WORDS: Record<Analysis["verdict"], string[]> = {
  phishing: ["Likely", "phishing"],
  suspicious: ["Suspicious"],
  "no-red-flags": ["No red", "flags found"],
};

const plural = (n: number, one: string, many: string) => `${n === 1 ? one : many}`;

function Verdict({ analysis }: { analysis: Analysis }) {
  const ref = useReveal<HTMLDivElement>();
  const { tricks, failedChecks, trackers } = analysis.stats;
  const auth = analysis.checks.slice(0, 3);
  const checksUnknown = auth.every((c) => c.status === "unknown");
  // Neutral and unknown results aren't passes, so count passes rather than assume them.
  const passed = auth.filter((c) => c.status === "pass").length;
  return (
    <div className={`verdict ${analysis.verdict}`} ref={ref}>
      <div className="verdict-in">
        <div>
          <p className="label">Verdict</p>
          <p className="verdict-word">
            {WORDS[analysis.verdict].map((word, i) => (
              <Fragment key={word}>
                {i > 0 && <br />}
                {word}
              </Fragment>
            ))}
          </p>
        </div>
        <div>
          <p className="verdict-say">{analysis.headline}</p>
          <p className="verdict-sub">{analysis.summary}</p>
          <div className="stats">
            <div className="stat">
              <b>{tricks}</b>
              <span>{plural(tricks, "trick found", "tricks found")}</span>
            </div>
            <div className="stat">
              {checksUnknown ? (
                <>
                  <b>–</b>
                  <span>checks unavailable</span>
                </>
              ) : failedChecks ? (
                <>
                  <b>{failedChecks}</b>
                  <span>{plural(failedChecks, "check failed", "checks failed")}</span>
                </>
              ) : (
                <>
                  <b>{passed}</b>
                  <span>{plural(passed, "check passed", "checks passed")}</span>
                </>
              )}
            </div>
            <div className="stat">
              <b>{trackers}</b>
              <span>{plural(trackers, "hidden tracker", "hidden trackers")}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Checks({ checks }: { checks: Check[] }) {
  const ref = useReveal<HTMLDivElement>();
  return (
    <div className="checks reveal" ref={ref}>
      {checks.map((check) => (
        <div key={check.id} className={`check ${check.status}`}>
          <p className="label">{check.label}</p>
          <b>{check.value}</b>
          <p>{check.explanation}</p>
        </div>
      ))}
    </div>
  );
}

function describeRegistration(registered: string | null): string {
  const date = new Date(registered ?? "");
  if (Number.isNaN(date.getTime())) return "Registration date unknown";
  const days = Math.floor((Date.now() - date.getTime()) / 86_400_000);
  // Registries record dates in UTC: show the day a WHOIS lookup would.
  const when = `Registered ${date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" })}`;
  if (days >= 365) return when;
  return `${when} (${days < 1 ? "today" : days === 1 ? "1 day ago" : `${days} days ago`})`;
}

function domainFacts(d: DomainIntel): string {
  if (d.exists === false) return "Doesn't exist";
  return [describeRegistration(d.registered), d.registrar, d.mailbox === false ? "no mail server" : null].filter(Boolean).join(" · ");
}

function Analyst({ analysis, intel }: { analysis: Analysis; intel: IntelResponse | null }) {
  return (
    <div className="analyst">
      <div>
        <h3 className="h3">Delivery route</h3>
        <Route route={analysis.route} />
      </div>
      {intel && intel.domains.length > 0 && (
        <div>
          <h3 className="h3">Domains, checked online</h3>
          <table className="ioc">
            <tbody>
              {intel.domains.map((d) => (
                <tr key={d.domain}>
                  <td>Domain</td>
                  <td>{d.domain}</td>
                  <td>{domainFacts(d)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="analyst-cols">
        <div>
          <h3 className="h3">Indicators, defanged</h3>
          {analysis.indicators.length ? (
            <>
              <table className="ioc">
                <tbody>
                  {analysis.indicators.map((indicator) => (
                    <tr key={indicator.value}>
                      <td>{indicator.type}</td>
                      <td>{indicator.value}</td>
                      <td>{indicator.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <button
                className="ghost-btn"
                type="button"
                onClick={async () => toast((await copyText(indicatorText(analysis))) ? "Indicators copied" : "Couldn't reach the clipboard")}
              >
                Copy indicators
              </button>
            </>
          ) : (
            <p className="muted">Nothing worth blocking or sharing: no suspicious senders, links or files.</p>
          )}
        </div>
        <div>
          <h3 className="h3">Headers that matter</h3>
          {analysis.keyHeaders.length ? (
            <pre className="raw">
              {analysis.keyHeaders.map((header) => (
                <Fragment key={header.name}>
                  <span className="h">{header.name}:</span> <Flagged header={header} />
                  {"\n"}
                </Fragment>
              ))}
            </pre>
          ) : (
            <p className="muted">Not available: the original headers were lost when this was forwarded.</p>
          )}
        </div>
      </div>
    </div>
  );
}

function Flagged({ header }: { header: KeyHeader }) {
  const flags = header.flags.filter(Boolean);
  if (!flags.length) return <>{header.value}</>;
  const pattern = new RegExp(`(${flags.map((f) => f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`, "g");
  return (
    <>
      {header.value.split(pattern).map((part, i) =>
        flags.includes(part) ? (
          <span className="bad" key={i}>
            {part}
          </span>
        ) : (
          part
        ),
      )}
    </>
  );
}

function Route({ route }: { route: Hop[] }) {
  if (!route.length) return <p className="muted">Not available: the original headers were lost when this was forwarded.</p>;
  const origin = route.findIndex((hop) => hop.from && hop.ip);
  const first = route[Math.max(origin, 0)]!;
  const nodes: { label: string; name: string; detail: string; origin?: boolean }[] = [
    { label: "Origin", name: first.from ?? "unknown", detail: first.ip ?? "no address recorded", origin: true },
  ];
  const when = (date: string | null) => {
    if (!date) return "";
    const parsed = new Date(date);
    return Number.isNaN(parsed.getTime()) ? date : parsed.toLocaleString();
  };
  const hops = route.slice(Math.max(origin, 0));
  hops.forEach((hop, i) => {
    nodes.push({ label: i === hops.length - 1 ? "Delivered" : "Relay", name: hop.by ?? "unknown", detail: when(hop.date) });
  });
  // A hop with no "from" is a handoff inside the provider; TLS doesn't apply to it.
  const links = hops.map((hop) =>
    hop.from ? [hop.protocol, hop.tls === false ? "no TLS" : hop.tls ? "TLS" : null].filter(Boolean).join(" · ") : "internal handoff",
  );
  return (
    <div className="route">
      {nodes.map((node, i) => (
        <Fragment key={i}>
          {i > 0 && (
            <div className="hop-link">
              <span>{links[i - 1] || "→"}</span>
            </div>
          )}
          <div className={`hop${node.origin ? " origin" : ""}`}>
            <p className="label">{node.label}</p>
            <b>{node.name}</b>
            <span>{node.detail}</span>
          </div>
        </Fragment>
      ))}
    </div>
  );
}

function NextSteps({ steps }: { steps: NextStep[] }) {
  const ref = useReveal<HTMLDivElement>();
  return (
    <div className="next reveal" ref={ref}>
      <h2 className="h2">What to do now</h2>
      <ol>
        {steps.map((step, i) => (
          <li key={step.title}>
            <span aria-hidden="true">{String(i + 1).padStart(2, "0")}</span>
            <div>
              <b>{step.title}</b>
              <p>
                {step.detail.split(/(`[^`]+`)/).map((part, j) =>
                  part.startsWith("`") ? <kbd key={j}>{part.slice(1, -1)}</kbd> : part,
                )}
              </p>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
