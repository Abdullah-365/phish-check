import { useEffect, useRef, type RefObject } from "react";

export interface LensControls {
  /** Glides the lens to an element of the reading view, by data-target or block id. */
  focus(key: string): void;
}

interface Options {
  /** When set, the lens visits these targets on its own until someone takes over. */
  tour: string[] | null;
  onRegion(key: string | null): void;
}

const reduceMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

/**
 * Drives the X-ray lens: follows the pointer, eases toward focus targets, tours
 * the findings while idle, and reports which element sits under its centre.
 * Positions are written straight to CSS variables, so moving it never re-renders React.
 */
export function useLens(stageRef: RefObject<HTMLDivElement | null>, options: Options): RefObject<LensControls> {
  const controls = useRef<LensControls>({ focus() {} });
  const latest = useRef(options);
  latest.current = options;

  useEffect(() => {
    const stage = stageRef.current;
    if (!stage) return;
    const tag = stage.querySelector<HTMLElement>(".lens-tag");
    const pos = { x: 0, y: 0 };
    const goal = { x: 0, y: 0 };
    let radius = 84;
    let current: string | null | undefined;
    let visible = false;
    let raf = 0;
    let tourIndex = 0;
    let tourTimer = 0;
    let resumeTimer = 0;
    let anchor = "from";
    /** The element the lens was sent to; it names the region until the pointer takes over. */
    let pinned: HTMLElement | null = null;

    const find = (key: string) =>
      stage.querySelector<HTMLElement>(
        `.mail-surface [data-target="${CSS.escape(key)}"], .mail-surface [data-block="${CSS.escape(key)}"]`,
      );

    // Overlays start at the element's left edge, so the circle opens just before it
    // rather than centring on it: labels and the start of each value stay in view.
    const centreOf = (el: HTMLElement) => {
      const s = stage.getBoundingClientRect();
      const r = el.getClientRects()[0] ?? el.getBoundingClientRect();
      return { x: r.left - s.left + radius - 12, y: r.top - s.top + r.height / 2 };
    };

    /** The smallest marked element under a point, so a phrase wins over its paragraph. */
    const regionAt = (x: number, y: number) => {
      const s = stage.getBoundingClientRect();
      let best: { el: HTMLElement; area: number } | null = null;
      for (const el of stage.querySelectorAll<HTMLElement>(".mail-surface [data-target]")) {
        for (const r of el.getClientRects()) {
          const left = r.left - s.left - 8;
          const top = r.top - s.top - 8;
          if (x < left || x > left + r.width + 16 || y < top || y > top + r.height + 16) continue;
          const area = r.width * r.height;
          if (!best || area < best.area) best = { el, area };
        }
      }
      return best?.el ?? null;
    };

    const clamp = (v: number, size: number) => Math.min(Math.max(v, radius + 6), Math.max(radius + 6, size - radius - 6));

    const tick = () => {
      const k = reduceMotion() ? 1 : 0.14;
      pos.x += (goal.x - pos.x) * k;
      pos.y += (goal.y - pos.y) * k;
      // The circle stays whole inside the card; near the edges the pointer is still inside it.
      const cx = clamp(pos.x, stage.offsetWidth);
      const cy = clamp(pos.y, stage.offsetHeight);
      stage.style.setProperty("--x", `${cx.toFixed(1)}px`);
      stage.style.setProperty("--y", `${cy.toFixed(1)}px`);
      stage.classList.toggle("tag-up", cy > stage.offsetHeight - radius - 60);

      const region = pinned ?? regionAt(pos.x, pos.y);
      const key = region?.dataset.target ?? region?.dataset.block ?? null;
      if (key !== current) {
        current = key;
        if (tag) tag.textContent = region?.dataset.label ?? "Underneath";
        latest.current.onRegion(key);
      }
      const settled = Math.abs(goal.x - pos.x) < 0.3 && Math.abs(goal.y - pos.y) < 0.3;
      raf = visible && !settled ? requestAnimationFrame(tick) : 0;
    };

    const go = (point: { x: number; y: number }) => {
      goal.x = point.x;
      goal.y = point.y;
      if (!raf && visible) raf = requestAnimationFrame(tick);
    };

    const goTo = (key: string) => {
      const el = find(key);
      if (!el) return;
      anchor = key;
      pinned = el;
      go(centreOf(el));
    };

    const stopTour = () => {
      clearTimeout(tourTimer);
      clearTimeout(resumeTimer);
    };

    const step = () => {
      const stops = (latest.current.tour ?? []).filter((key) => find(key));
      if (!stops.length) return;
      goTo(stops[tourIndex++ % stops.length]!);
      tourTimer = window.setTimeout(step, 2600);
    };

    const startTour = (delay: number) => {
      if (!latest.current.tour || reduceMotion()) return;
      stopTour();
      tourTimer = window.setTimeout(step, delay);
    };

    const follow = (e: PointerEvent) => {
      const s = stage.getBoundingClientRect();
      pinned = null;
      go({ x: e.clientX - s.left, y: e.clientY - s.top });
    };

    const onMove = (e: PointerEvent) => {
      if (e.pointerType === "touch" && !e.buttons) return;
      stopTour();
      follow(e);
    };
    const onDown = (e: PointerEvent) => {
      if ((e.target as HTMLElement).closest(".pin")) return;
      stopTour();
      follow(e);
    };
    const onLeave = () => startTour(1800);

    stage.addEventListener("pointermove", onMove);
    stage.addEventListener("pointerdown", onDown);
    stage.addEventListener("pointerleave", onLeave);

    const resize = new ResizeObserver(() => {
      radius = parseFloat(getComputedStyle(stage).getPropertyValue("--r")) || 84;
      goTo(anchor);
    });
    resize.observe(stage);

    const seen = new IntersectionObserver(([entry]) => {
      visible = !!entry?.isIntersecting;
      if (visible) go(goal);
    });
    seen.observe(stage);

    const start = find("from");
    if (start) {
      const p = centreOf(start);
      pos.x = goal.x = p.x;
      pos.y = goal.y = p.y;
    }
    startTour(1400);
    controls.current.focus = (key) => {
      stopTour();
      goTo(key);
    };

    return () => {
      stopTour();
      cancelAnimationFrame(raf);
      resize.disconnect();
      seen.disconnect();
      stage.removeEventListener("pointermove", onMove);
      stage.removeEventListener("pointerdown", onDown);
      stage.removeEventListener("pointerleave", onLeave);
    };
  }, [stageRef]);

  return controls;
}
