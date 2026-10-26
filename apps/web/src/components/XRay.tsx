import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { Analysis, Finding } from "@phish-check/engine";
import { targetKey } from "../lib/report.ts";
import { useLens } from "../lib/useLens.ts";
import { MailView } from "./MailView.tsx";

interface Props {
  analysis: Analysis;
  size?: "large" | undefined;
  /** Let the lens visit the findings on its own while nobody is using it. */
  tour?: boolean | undefined;
  /** Numbered pins next to each finding, matching the findings list. */
  pins?: boolean | undefined;
  /** Moves the lens to a finding; a new object each time, so repeats still move it. */
  focus?: { key: string } | null | undefined;
  revealed?: boolean | undefined;
  onRegion?: ((key: string | null) => void) | undefined;
  onPin?: ((finding: Finding) => void) | undefined;
  activeKey?: string | null | undefined;
}

interface PinBox {
  finding: Finding;
  number: number;
  left: number;
  top: number;
}

/** The reading-view element a finding points at: a marked element, or a whole paragraph by its block id. */
const findTarget = (stage: HTMLElement, key: string) =>
  stage.querySelector<HTMLElement>(`.mail-surface [data-target="${CSS.escape(key)}"], .mail-surface [data-block="${CSS.escape(key)}"]`);

export function XRay({ analysis, size, tour, pins, focus, revealed, onRegion, onPin, activeKey }: Props) {
  const stageRef = useRef<HTMLDivElement>(null);
  const [expanded, setExpanded] = useState(false);
  const [clipped, setClipped] = useState(false);
  const [pinBoxes, setPinBoxes] = useState<PinBox[]>([]);

  const stops = useMemo(() => {
    const keys = analysis.findings.map((f) => targetKey(f.target));
    return [...new Set(keys.length ? keys : ["from", "subject"])];
  }, [analysis]);

  const lens = useLens(stageRef, { tour: tour ? stops : null, onRegion: (key) => onRegion?.(key) });
  const expandedRef = useRef(expanded);
  expandedRef.current = expanded;

  useEffect(() => {
    if (!focus) return;
    const stage = stageRef.current;
    const body = stage?.querySelector<HTMLElement>(".mail-surface .mail-body");
    const target = stage ? findTarget(stage, focus.key) : null;
    // Open the whole email first when the finding sits below the fold of the card.
    // Targets inside the body are positioned relative to it, so offsetTop is measured from its top.
    if (body?.contains(target ?? null) && target && !expandedRef.current && target.offsetTop > body.clientHeight - 24) {
      setExpanded(true);
      requestAnimationFrame(() => lens.current.focus(focus.key));
      return;
    }
    lens.current.focus(focus.key);
  }, [focus, lens]);

  useLayoutEffect(() => {
    const stage = stageRef.current;
    if (!stage) return;
    const measure = () => {
      const body = stage.querySelector<HTMLElement>(".mail-surface .mail-body");
      setClipped(!!body && !expanded && body.scrollHeight > body.clientHeight + 2);
      if (!pins) return;
      const s = stage.getBoundingClientRect();
      const bottom = body ? body.getBoundingClientRect().bottom - s.top : Infinity;
      const used = new Map<string, number>();
      const boxes: PinBox[] = [];
      analysis.findings.forEach((finding, index) => {
        const key = targetKey(finding.target);
        const el = findTarget(stage, key);
        if (!el) return;
        const r = el.getClientRects()[0] ?? el.getBoundingClientRect();
        const top = r.top - s.top + Math.min(r.height / 2, 20);
        const inBody = !!el.closest(".mail-body");
        if (inBody && top > bottom) return;
        const stacked = used.get(key) ?? 0;
        used.set(key, stacked + 1);
        boxes.push({ finding, number: index + 1, left: s.width - 26 - stacked * 30, top });
      });
      setPinBoxes(boxes);
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(stage);
    return () => observer.disconnect();
  }, [analysis, expanded, pins]);

  const classes = ["stage", size, pins && "with-pins", expanded && "expanded", clipped && "clipped", revealed && "revealed"]
    .filter(Boolean)
    .join(" ");

  return (
    <>
      {/* Hidden from assistive tech: the findings list carries the same information as text. */}
      <div ref={stageRef} className={classes} aria-hidden="true">
        <MailView analysis={analysis} mode="surface" />
        <div className="truth">
          <MailView analysis={analysis} mode="truth" />
        </div>
        <div className="lens">
          <span className="lens-tag">Real sender</span>
        </div>
        {pins && (
          <div className="pins">
            {pinBoxes.map(({ finding, number, left, top }) => (
              <button
                key={finding.id}
                type="button"
                tabIndex={-1}
                className={`pin ${finding.severity}${activeKey === targetKey(finding.target) ? " on" : ""}`}
                style={{ left, top }}
                onClick={() => onPin?.(finding)}
              >
                {number}
              </button>
            ))}
          </div>
        )}
      </div>
      {(clipped || expanded) && (
        <button className="ghost-btn more" type="button" onClick={() => setExpanded((v) => !v)}>
          {expanded ? "Show less" : "Show the whole email"}
        </button>
      )}
    </>
  );
}
