import type { Analysis, Block, Finding, Hop, Inline } from "@phish-check/engine";
import { formatSize, formatWhen, targetKey } from "../lib/report.ts";
import { FileIcon, ImageIcon } from "./Icons.tsx";
import { SnippetView } from "./SnippetView.tsx";

interface Props {
  analysis: Analysis;
  /** "truth" renders the same layout in X-ray ink, plus overlays with what's really there. */
  mode: "surface" | "truth";
}

/**
 * A safe reading view of the email. Links are inert text and remote images are
 * never loaded, so nothing in it can phone home.
 */
export function MailView({ analysis, mode }: Props) {
  const truth = mode === "truth";
  const byTarget = new Map<string, Finding>();
  for (const finding of analysis.findings) {
    const key = targetKey(finding.target);
    if (!byTarget.has(key)) byTarget.set(key, finding);
  }
  const name = analysis.sender?.name || analysis.sender?.address || "Unknown sender";
  const when = formatWhen(analysis.date);

  return (
    <div className={`mail mail-${mode}`}>
      <div className="mail-from" data-target="from" data-label="Real sender">
        <span className="avatar">{(name.match(/[a-z0-9]/i)?.[0] ?? "?").toUpperCase()}</span>
        <span className="who">
          <b className="who-name">{name}</b>
          <span className="who-meta">to me{when && ` · ${when}`}</span>
        </span>
        {truth && <FromTruth analysis={analysis} />}
      </div>
      <div className="mail-subject" data-target="subject" data-label="Sent from">
        <b>{analysis.subject || "(no subject)"}</b>
        {truth && <RouteTruth route={analysis.route} partial={analysis.partial} />}
      </div>
      <div className="mail-body">
        {analysis.content.blocks.length ? (
          analysis.content.blocks.map((block) => <BlockView key={block.id} block={block} truth={truth} byTarget={byTarget} />)
        ) : (
          <p className="blk">This email has no readable text.</p>
        )}
      </div>
      {analysis.attachments.length > 0 && (
        <div className="mail-files">
          {analysis.attachments.map((file) => (
            <span key={file.id} className="file" data-target={file.id} data-label="Attachment">
              <FileIcon />
              <b>{file.filename}</b>
              <span>{formatSize(file.size)}</span>
              {truth && <span className={`x x-file${file.risky ? " risky" : ""}`}>{file.kind}</span>}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function FromTruth({ analysis }: { analysis: Analysis }) {
  const disguise = analysis.findings.find((f) => f.category === "sender" && f.rule !== "reply-elsewhere" && f.real);
  const reply = analysis.findings.find((f) => f.rule === "reply-elsewhere");
  const { spf, dkim, dmarc } = analysis.auth;
  const result = (label: string, value: string) =>
    value === "pass" ? `${label}=pass` : <em>{`${label}=${value}`}</em>;
  return (
    <span className="x x-from">
      <span className="x-row">
        <span className="x-k">From</span>
        <span>{disguise?.real ? <SnippetView snippet={disguise.real} /> : analysis.sender?.address}</span>
      </span>
      <span className="x-row">
        <span className="x-k">Auth</span>
        <span>
          {analysis.partial ? (
            "lost in forwarding"
          ) : (
            <>
              {result("dmarc", dmarc)} · {result("spf", spf)} · {result("dkim", dkim)}
            </>
          )}
        </span>
      </span>
      {reply?.real && (
        <span className="x-row">
          <span className="x-k">Reply</span>
          <span>
            <em>{reply.real.text}</em>
          </span>
        </span>
      )}
    </span>
  );
}

function RouteTruth({ route, partial }: { route: Hop[]; partial: boolean }) {
  const origin = route.find((hop) => hop.from && hop.ip) ?? route[0];
  return (
    <span className="x x-subject">
      <span className="x-row">
        <span className="x-k">Via</span>
        <span>
          {origin?.from ? (
            <>
              {origin.from}
              {origin.ip && ` · ${origin.ip}`}
              {origin.tls === false && <em> · not encrypted</em>}
            </>
          ) : partial ? (
            "unknown: headers lost in forwarding"
          ) : (
            "no delivery route recorded"
          )}
        </span>
      </span>
    </span>
  );
}

function BlockView({ block, truth, byTarget }: { block: Block; truth: boolean; byTarget: Map<string, Finding> }) {
  const pixelsOnly = block.inlines.every((i) => i.type === "image" && i.tracker);
  return (
    <p className={`blk blk-${block.kind}${pixelsOnly ? " pix-row" : ""}`} data-block={block.id}>
      {block.inlines.map((inline, index) => (
        <InlineView key={"id" in inline ? inline.id : index} inline={inline} truth={truth} finding={"id" in inline ? byTarget.get(inline.id) : undefined} />
      ))}
    </p>
  );
}

function hostOf(src: string): string {
  try {
    return new URL(src.startsWith("//") ? `https:${src}` : src).hostname;
  } catch {
    return "an embedded file";
  }
}

function InlineView({ inline, truth, finding }: { inline: Inline; truth: boolean; finding: Finding | undefined }) {
  switch (inline.type) {
    case "text":
      return <>{inline.text}</>;
    case "break":
      return <br />;
    case "link":
      return (
        <span className={`lnk${inline.button ? " btn-like" : ""}`} data-target={inline.id} data-label="Real destination">
          {inline.text}
          {truth && (
            <span className="x x-link">
              → {finding?.real ? <SnippetView snippet={finding.real} /> : (inline.destination ?? inline.href.slice(0, 72))}
            </span>
          )}
        </span>
      );
    case "image":
      return inline.tracker ? (
        <span className="pix" data-target={inline.id} data-label="Hidden tracker">
          {truth && <span className="x x-pix">1×1 tracker · {hostOf(inline.src)}</span>}
        </span>
      ) : (
        <span className="img" data-target={inline.id} data-label="Image">
          <ImageIcon />
          {inline.alt || "Image"} (not loaded)
          {truth && <span className="x x-img">from {hostOf(inline.src)}</span>}
        </span>
      );
    case "phrase":
      return (
        <span className="phr" data-target={inline.id} data-label={inline.label}>
          {inline.text}
          {truth && <span className="x x-tag">{inline.label}</span>}
        </span>
      );
  }
}
