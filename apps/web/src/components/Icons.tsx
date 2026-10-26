const base = { viewBox: "0 0 24 24", fill: "none", "aria-hidden": true } as const;

export function BrandMark() {
  return (
    <svg {...base}>
      <defs>
        <clipPath id="brand-lens">
          <circle cx="15.5" cy="14.5" r="6.75" />
        </clipPath>
      </defs>
      <rect x="1.75" y="4.75" width="16.5" height="12.5" rx="2" stroke="currentColor" strokeWidth="1.5" />
      <path d="M2.6 6.2l7.4 5.4 7.4-5.4" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="15.5" cy="14.5" r="6.75" fill="currentColor" />
      <g clipPath="url(#brand-lens)" className="brand-cut" strokeWidth="1.5">
        <rect x="1.75" y="4.75" width="16.5" height="12.5" rx="2" />
        <path d="M2.6 6.2l7.4 5.4 7.4-5.4" />
      </g>
    </svg>
  );
}

export function ThemeIcon() {
  return (
    <svg {...base}>
      <circle cx="12" cy="12" r="8.25" stroke="currentColor" strokeWidth="1.5" />
      <path d="M12 3.75a8.25 8.25 0 0 1 0 16.5z" fill="currentColor" />
    </svg>
  );
}

export function CloseIcon() {
  return (
    <svg {...base}>
      <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

export function UploadIcon() {
  return (
    <svg {...base}>
      <path d="M12 15V4m0 0L7.5 8.5M12 4l4.5 4.5M5 14v4.25c0 .97.78 1.75 1.75 1.75h10.5c.97 0 1.75-.78 1.75-1.75V14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function FileIcon() {
  return (
    <svg {...base}>
      <path d="M13.5 3.75H7.25c-.97 0-1.75.78-1.75 1.75v13c0 .97.78 1.75 1.75 1.75h9.5c.97 0 1.75-.78 1.75-1.75V8.75m-5-5l5 5m-5-5v3.5c0 .83.67 1.5 1.5 1.5h3.5" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

export function ImageIcon() {
  return (
    <svg {...base} width="14" height="14">
      <rect x="3.75" y="4.75" width="16.5" height="14.5" rx="2" stroke="currentColor" strokeWidth="1.5" />
      <path d="M4 16l4.5-4.5 4 4 2.5-2.5 5 5" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

export function NoticeIcon() {
  return (
    <svg {...base}>
      <circle cx="12" cy="12" r="8.25" stroke="currentColor" strokeWidth="1.5" />
      <path d="M12 7.75v5.5M12 16.25v.01" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}
