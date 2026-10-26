import { useEffect, useRef, useState } from "react";
import { CloseIcon } from "./Icons.tsx";

interface Guide {
  id: string;
  label: string;
  steps: React.ReactNode[];
  alt?: React.ReactNode;
}

const GUIDES: Guide[] = [
  {
    id: "gmail",
    label: "Gmail",
    steps: [
      "Open the email on a computer.",
      <>Click <kbd>⋮</kbd> next to the reply arrow.</>,
      <>Choose <kbd>Download message</kbd>. You get an <code>.eml</code> file.</>,
      "Drop that file anywhere on this page.",
    ],
    alt: <>Rather copy and paste? Choose <kbd>Show original</kbd> instead, click <kbd>Copy to clipboard</kbd>, and paste it into the box.</>,
  },
  {
    id: "outlook",
    label: "Outlook",
    steps: [
      "Open the email in Outlook on the web or the new Outlook app.",
      <>Click <kbd>⋯</kbd> for more actions.</>,
      <>Choose <kbd>View</kbd>, then <kbd>View message source</kbd>.</>,
      "Select everything, copy it, and paste it into the box.",
    ],
    alt: (
      <>
        Classic Outlook on Windows: drag the email from your inbox onto your desktop. That saves a <code>.msg</code> file you can
        drop onto this page.
      </>
    ),
  },
  {
    id: "apple",
    label: "Apple Mail",
    steps: [
      "Select the email.",
      <>Choose <kbd>View</kbd>, then <kbd>Message</kbd>, then <kbd>Raw Source</kbd>.</>,
      "Select everything, copy it, and paste it into the box.",
    ],
    alt: <>Faster: drag the email from Mail onto your desktop, then drop the file onto this page.</>,
  },
  {
    id: "yahoo",
    label: "Yahoo",
    steps: [
      "Open the email.",
      <>Click <kbd>⋯</kbd> for more.</>,
      <>Choose <kbd>View raw message</kbd>.</>,
      "Select everything, copy it, and paste it into the box.",
    ],
  },
  {
    id: "phone",
    label: "On a phone",
    steps: [
      <>Forward the email to <code>check@abdullah1.dev</code>. The verdict comes back by email within a minute.</>,
      <>A plain forward loses the original's headers, so the sender can't be fully checked. On a computer, <kbd>Forward as attachment</kbd> gives the full check.</>,
      "No reply? Look in Spam: a reply about a phish can look like one.",
    ],
  },
];

interface Props {
  open: boolean;
  onClose(): void;
}

export function SourceSheet({ open, onClose }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [tab, setTab] = useState(GUIDES[0]!.id);

  useEffect(() => {
    const el = dialog.current;
    if (!el) return;
    if (open && !el.open) el.showModal();
    if (!open && el.open) el.close();
  }, [open]);

  const moveTab = (step: number) => {
    const index = GUIDES.findIndex((g) => g.id === tab);
    const next = GUIDES[(index + step + GUIDES.length) % GUIDES.length]!;
    setTab(next.id);
    document.getElementById(`tab-${next.id}`)?.focus();
  };

  return (
    <dialog
      ref={dialog}
      className="sheet"
      aria-labelledby="sheet-title"
      onClose={onClose}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="sheet-head">
        <h2 id="sheet-title">Find your email's source</h2>
        <button className="icon-btn" type="button" aria-label="Close" onClick={onClose}>
          <CloseIcon />
        </button>
      </div>
      <div className="sheet-body">
        <div
          className="tabs"
          role="tablist"
          aria-label="Email app"
          onKeyDown={(e) => {
            if (e.key === "ArrowRight") moveTab(1);
            if (e.key === "ArrowLeft") moveTab(-1);
          }}
        >
          {GUIDES.map((guide) => (
            <button
              key={guide.id}
              id={`tab-${guide.id}`}
              type="button"
              role="tab"
              aria-selected={tab === guide.id}
              aria-controls={`panel-${guide.id}`}
              tabIndex={tab === guide.id ? 0 : -1}
              onClick={() => setTab(guide.id)}
            >
              {guide.label}
            </button>
          ))}
        </div>
        {GUIDES.map((guide) => (
          <div key={guide.id} id={`panel-${guide.id}`} role="tabpanel" aria-labelledby={`tab-${guide.id}`} hidden={tab !== guide.id}>
            <ol className="steps">
              {guide.steps.map((step, i) => (
                <li key={i}>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
            {guide.alt && <p className="alt">{guide.alt}</p>}
          </div>
        ))}
        <p className="why">
          Why the source? The email you see hides the parts that matter most: the real sender, the servers it passed through, and
          where its links lead.
        </p>
      </div>
    </dialog>
  );
}
