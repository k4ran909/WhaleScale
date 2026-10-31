import { ReactNode, useCallback, useEffect, useState } from "react";
import { ApiError } from "./api";

export function timeAgo(iso?: string): string {
  if (!iso) return "—";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 0) return "in " + duration(-s);
  if (s < 45) return "just now";
  return duration(s) + " ago";
}

export function timeUntil(iso?: string): string {
  if (!iso) return "—";
  const s = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  return s <= 0 ? "expired" : "in " + duration(s);
}

function duration(s: number): string {
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min`;
  if (s < 86400) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} d`;
}

/** useLoad fetches data, re-fetching every `refreshMs` and on reload(). */
export function useLoad<T>(fn: () => Promise<T>, refreshMs = 0) {
  const [data, setData] = useState<T | undefined>();
  const [error, setError] = useState<string>();
  const reload = useCallback(() => {
    fn().then(
      (d) => {
        setData(d);
        setError(undefined);
      },
      (e: unknown) => setError(e instanceof Error ? e.message : String(e)),
    );
  }, []);
  useEffect(() => {
    reload();
    if (!refreshMs) return;
    const t = setInterval(reload, refreshMs);
    return () => clearInterval(t);
  }, [reload, refreshMs]);
  return { data, error, reload };
}

export function errText(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  return e instanceof Error ? e.message : String(e);
}

export function Page(props: { title: string; actions?: ReactNode; children: ReactNode; lead?: ReactNode }) {
  return (
    <section className="page">
      <header className="page-head">
        <div>
          <h1>{props.title}</h1>
          {props.lead && <p className="lead">{props.lead}</p>}
        </div>
        {props.actions && <div className="actions">{props.actions}</div>}
      </header>
      {props.children}
    </section>
  );
}

export function Banner(props: { kind: "error" | "warn" | "ok"; children: ReactNode }) {
  return <div className={`banner ${props.kind}`} role={props.kind === "error" ? "alert" : "status"}>{props.children}</div>;
}

export function Empty(props: { children: ReactNode }) {
  return <div className="empty">{props.children}</div>;
}

/** A button that asks for a second click before doing something destructive. */
export function ConfirmButton(props: { label: string; confirm: string; onConfirm: () => Promise<unknown> | void }) {
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const t = setTimeout(() => setArmed(false), 4000);
    return () => clearTimeout(t);
  }, [armed]);
  return (
    <button
      className={armed ? "btn danger" : "btn ghost"}
      disabled={busy}
      onClick={async () => {
        if (!armed) return setArmed(true);
        setBusy(true);
        try {
          await props.onConfirm();
        } finally {
          setBusy(false);
          setArmed(false);
        }
      }}
    >
      {armed ? props.confirm : props.label}
    </button>
  );
}

/** Shows a secret once, with a copy button. */
export function SecretBox(props: { title: string; secret: string; hint: ReactNode; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="secret" role="dialog" aria-label={props.title}>
      <div className="secret-head">
        <strong>{props.title}</strong>
        <button className="btn ghost" onClick={props.onClose}>Done</button>
      </div>
      <p className="muted">{props.hint}</p>
      <div className="secret-row">
        <code>{props.secret}</code>
        <button
          className="btn"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(props.secret);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            } catch {
              /* clipboard can be blocked; the text is selectable */
            }
          }}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
    </div>
  );
}

export function Dot(props: { on?: boolean; label?: string }) {
  return (
    <span className="dot-wrap">
      <span className={props.on ? "dot on" : "dot"} aria-hidden="true" />
      {props.label}
    </span>
  );
}
