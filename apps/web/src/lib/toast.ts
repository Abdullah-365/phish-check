type Listener = (text: string) => void;

const listeners = new Set<Listener>();

export function toast(text: string): void {
  listeners.forEach((listener) => listener(text));
}

export function onToast(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
