import type * as Engine from "@phish-check/engine";

let engine: Promise<typeof Engine> | null = null;

/** The engine is its own chunk, so the page paints before the parsers download. */
export function loadEngine(): Promise<typeof Engine> {
  engine ??= import("@phish-check/engine").catch((err: unknown) => {
    // A failed download (say, a deploy replaced the file) mustn't stick: the next try fetches again.
    engine = null;
    throw err;
  });
  return engine;
}
