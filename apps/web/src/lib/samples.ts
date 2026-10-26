const files = import.meta.glob<string>("../../../../samples/*.eml", { query: "?raw", import: "default" });

export interface Sample {
  file: string;
  label: string;
}

/** The demo email the hero lens and the example report use. */
export const HERO_SAMPLE: Sample = { file: "lookalike-paypal.eml", label: "Fake PayPal" };

export const SAMPLES: Sample[] = [
  HERO_SAMPLE,
  { file: "bec-gift-cards.eml", label: "Boss wants gift cards" },
  { file: "macro-invoice.eml", label: "Invoice with a macro" },
  { file: "display-name-microsoft.eml", label: "Fake Microsoft 365" },
  { file: "inline-forward.eml", label: "A forwarded phish" },
  { file: "legit-order-confirmation.eml", label: "A real order email" },
];

export async function loadSample(file: string): Promise<string> {
  const load = files[`../../../../samples/${file}`];
  if (!load) throw new Error(`Unknown sample: ${file}`);
  return load();
}
