import type { Snippet } from "@phish-check/engine";

/** Renders text with its highlighted ranges as <mark>. */
export function SnippetView({ snippet }: { snippet: Snippet }) {
  const marks = [...(snippet.marks ?? [])].sort((a, b) => a[0] - b[0]);
  if (!marks.length) return <>{snippet.text}</>;
  const parts: React.ReactNode[] = [];
  let cursor = 0;
  for (const [start, end] of marks) {
    if (start < cursor) continue;
    if (start > cursor) parts.push(snippet.text.slice(cursor, start));
    parts.push(<mark key={start}>{snippet.text.slice(start, end)}</mark>);
    cursor = end;
  }
  parts.push(snippet.text.slice(cursor));
  return <>{parts}</>;
}
