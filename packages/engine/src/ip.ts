/** An IP address as bytes: 4 for IPv4, 16 for IPv6. An IPv4 address written as IPv6 counts as IPv4. */
export function parseIp(text: string): Uint8Array | null {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (v4) {
    const bytes = v4.slice(1).map(Number);
    return bytes.every((b) => b <= 255) ? Uint8Array.from(bytes) : null;
  }
  if (!text.includes(":") || !/^[0-9a-f:.]+$/i.test(text)) return null;
  let body = text;
  let tail: Uint8Array | null = null;
  if (body.includes(".")) {
    const at = body.lastIndexOf(":");
    tail = parseIp(body.slice(at + 1));
    if (!tail || tail.length !== 4) return null;
    body = `${body.slice(0, at + 1)}0:0`;
  }
  const halves = body.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...rest];
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return null;
  const out = new Uint8Array(16);
  groups.forEach((g, i) => {
    const n = parseInt(g, 16);
    out[i * 2] = n >> 8;
    out[i * 2 + 1] = n & 0xff;
  });
  if (tail) out.set(tail, 12);
  const mapped = out.subarray(0, 10).every((b) => b === 0) && out[10] === 0xff && out[11] === 0xff;
  return mapped ? out.slice(12) : out;
}

/** Whether two addresses are the same, however each was written. */
export function sameIp(a: string, b: string): boolean {
  const x = parseIp(a);
  const y = parseIp(b);
  return !!x && !!y && x.length === y.length && x.every((byte, i) => byte === y[i]);
}

/**
 * The server addresses an email's Received lines record in their "from" part: [192.0.2.1],
 * [IPv6:2001:db8::1], or Microsoft's (192.0.2.1). Null when none records an address at all.
 */
export function recordedAddresses(received: string[]): string[] | null {
  const out: string[] = [];
  for (const line of received) {
    const from = line.replace(/\s+/g, " ").split(/\sby\s/i)[0] ?? "";
    for (const m of from.matchAll(/[[(](?:ipv6:)?([0-9a-f:.]{3,})[\])]/gi)) if (parseIp(m[1]!)) out.push(m[1]!);
  }
  return out.length ? out : null;
}
