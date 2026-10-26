/**
 * Test helper: builds Outlook-style .msg files (OLE compound files) for the reader to parse.
 */

export interface Node {
  name: string;
  data?: Uint8Array;
  children?: Node[];
}

const END = 0xfffffffe;
const FREE = 0xffffffff;
const NONE = 0xffffffff;

export function compoundFile(root: Node[]): Uint8Array {
  interface Flat {
    name: string;
    type: number;
    data: Uint8Array | null;
    left: number;
    right: number;
    child: number;
    start: number;
    size: number;
  }
  const entries: Flat[] = [{ name: "Root Entry", type: 5, data: null, left: NONE, right: NONE, child: NONE, start: END, size: 0 }];
  const add = (nodes: Node[], parent: number) => {
    let previous = -1;
    for (const node of nodes) {
      const index = entries.length;
      entries.push({ name: node.name, type: node.children ? 1 : 2, data: node.data ?? null, left: NONE, right: NONE, child: NONE, start: END, size: node.data?.length ?? 0 });
      if (previous < 0) entries[parent]!.child = index;
      else entries[previous]!.right = index;
      previous = index;
      if (node.children) add(node.children, index);
    }
  };
  add(root, 0);

  // Streams under 4096 bytes live in the mini stream, in 64-byte sectors with their own FAT.
  const mini: number[] = [];
  const miniFat: number[] = [];
  const large: Flat[] = [];
  for (const entry of entries) {
    if (!entry.data) continue;
    if (entry.size >= 4096) {
      large.push(entry);
      continue;
    }
    const first = mini.length / 64;
    const count = Math.max(1, Math.ceil(entry.size / 64));
    for (let i = 0; i < count; i++) miniFat.push(i === count - 1 ? END : first + i + 1);
    mini.push(...entry.data, ...new Array(count * 64 - entry.size).fill(0));
    entry.start = entry.size ? first : END;
  }

  const sectorsFor = (bytes: number) => Math.ceil(bytes / 512);
  const dirSectors = sectorsFor(entries.length * 128);
  const miniFatSectors = sectorsFor(miniFat.length * 4);
  const miniSectors = sectorsFor(mini.length);
  const largeSectors = large.reduce((n, e) => n + sectorsFor(e.size), 0);
  const others = dirSectors + miniFatSectors + miniSectors + largeSectors;
  let fatSectors = 1;
  while (fatSectors * 128 < fatSectors + others) fatSectors++;
  const total = fatSectors + others;

  const fat = new Array<number>(fatSectors * 128).fill(FREE);
  for (let i = 0; i < fatSectors; i++) fat[i] = 0xfffffffd;
  let next = fatSectors;
  const chain = (count: number) => {
    const first = count ? next : END;
    for (let i = 0; i < count; i++) fat[next + i] = i === count - 1 ? END : next + i + 1;
    next += count;
    return first;
  };
  const dirStart = chain(dirSectors);
  const miniFatStart = chain(miniFatSectors);
  const miniStart = chain(miniSectors);
  for (const entry of large) entry.start = chain(sectorsFor(entry.size));
  entries[0]!.start = mini.length ? miniStart : END;
  entries[0]!.size = mini.length;

  const out = new Uint8Array(512 * (1 + total));
  const view = new DataView(out.buffer);
  [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].forEach((b, i) => (out[i] = b));
  view.setUint16(0x18, 0x3e, true);
  view.setUint16(0x1a, 3, true);
  view.setUint16(0x1c, 0xfffe, true);
  view.setUint16(0x1e, 9, true);
  view.setUint16(0x20, 6, true);
  view.setUint32(0x2c, fatSectors, true);
  view.setUint32(0x30, dirStart, true);
  view.setUint32(0x38, 4096, true);
  view.setUint32(0x3c, miniFatStart, true);
  view.setUint32(0x40, miniFatSectors, true);
  view.setUint32(0x44, END, true);
  for (let i = 0; i < 109; i++) view.setUint32(0x4c + i * 4, i < fatSectors ? i : FREE, true);

  const sector = (id: number) => 512 * (id + 1);
  fat.forEach((value, i) => view.setUint32(sector(0) + i * 4, value, true));
  entries.forEach((entry, i) => {
    const at = sector(dirStart) + i * 128;
    for (let c = 0; c < entry.name.length; c++) view.setUint16(at + c * 2, entry.name.charCodeAt(c), true);
    view.setUint16(at + 0x40, (entry.name.length + 1) * 2, true);
    view.setUint8(at + 0x42, entry.type);
    view.setUint8(at + 0x43, 1);
    view.setUint32(at + 0x44, entry.left, true);
    view.setUint32(at + 0x48, entry.right, true);
    view.setUint32(at + 0x4c, entry.child, true);
    view.setUint32(at + 0x74, entry.start, true);
    view.setUint32(at + 0x78, entry.size, true);
  });
  miniFat.forEach((value, i) => view.setUint32(sector(miniFatStart) + i * 4, value, true));
  out.set(mini, sector(miniStart));
  for (const entry of large) out.set(entry.data!, sector(entry.start));
  return out;
}

// --- MAPI properties, the way Outlook stores them.

export const unicode = (text: string) => {
  const out = new Uint8Array((text.length + 1) * 2);
  for (let i = 0; i < text.length; i++) new DataView(out.buffer).setUint16(i * 2, text.charCodeAt(i), true);
  return out;
};
export const bytes = (text: string) => new TextEncoder().encode(text);
export const prop = (tag: string, data: Uint8Array): Node => ({ name: `__substg1.0_${tag}`, data });
/** The fixed-size property stream; `header` is 32 bytes for the top message, 24 for an attached one. */
export const fixedProps = (header: number) => ({ name: "__properties_version1.0", data: new Uint8Array(header) });
