import type { ReactNode } from "react";

export type IconName = "grid" | "shield" | "activity" | "flask" | "fingerprint" | "arrow";

export function PageHeading({
  kicker,
  title,
  description,
  action,
}: {
  kicker: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <p className="kicker">{kicker}</p>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="page-heading__action">{action}</div>}
    </div>
  );
}

export function JsonEditor({
  label,
  value,
  onChange,
  compact = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  compact?: boolean;
}) {
  const id = label.toLowerCase().replaceAll(" ", "-");
  return (
    <section className={`json-editor ${compact ? "json-editor--compact" : ""}`}>
      <div className="json-editor__heading">
        <label htmlFor={id}>{label}</label>
        <span>JSON</span>
      </div>
      <textarea
        id={id}
        spellCheck="false"
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </section>
  );
}

export function EmptyState({
  icon,
  title,
  detail,
  compact = false,
}: {
  icon: IconName;
  title: string;
  detail: string;
  compact?: boolean;
}) {
  return (
    <section className={`empty-state ${compact ? "empty-state--compact" : ""}`}>
      <Icon name={icon} />
      <h2>{title}</h2>
      <p>{detail}</p>
    </section>
  );
}

export function Icon({ name }: { name: IconName }) {
  const paths: Record<IconName, ReactNode> = {
    grid: (
      <>
        <rect x="3" y="3" width="7" height="7" />
        <rect x="14" y="3" width="7" height="7" />
        <rect x="3" y="14" width="7" height="7" />
        <rect x="14" y="14" width="7" height="7" />
      </>
    ),
    shield: <path d="M12 3 20 6v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6l8-3Zm-3 9 2 2 4-5" />,
    activity: <path d="M3 12h4l2.5-6 5 12 2.5-6h4" />,
    flask: <path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-9V3M8 15h8" />,
    fingerprint: <path d="M12 11a3 3 0 0 1 3 3c0 3-1 5-2 7M8 21c1-2 1-4 1-7a3 3 0 0 1 6 0M5 18c.5-1.5.5-2.5.5-4a6.5 6.5 0 0 1 13 0c0 2-.2 4-1 6M5 9a8 8 0 0 1 14-2M3 14v-1" />,
    arrow: <path d="M5 12h14m-5-5 5 5-5 5" />,
  };
  return (
    <svg
      className="icon"
      viewBox="0 0 24 24"
      aria-hidden="true"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {paths[name]}
    </svg>
  );
}
