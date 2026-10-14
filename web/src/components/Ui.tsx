// Небольшие общие элементы интерфейса.
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import type { AlertStatus, IncidentStatus, Severity } from "../api";
import { incidentStatusLabel, severityLabel, statusLabel } from "../format";
import { Icon } from "./Icons";

export function SeverityBadge({ s }: { s: Severity }) {
  return <span className={`badge sev-${s}`}>{severityLabel[s] ?? s}</span>;
}

export function StatusBadge({ s }: { s: AlertStatus }) {
  return <span className={`badge st-${s}`}>{statusLabel[s] ?? s}</span>;
}

export function IncidentStatusBadge({ s }: { s: IncidentStatus }) {
  return <span className={`badge ist-${s}`}>{incidentStatusLabel[s] ?? s}</span>;
}

export function Card({
  title,
  actions,
  children,
  className = "",
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          <h3>{title}</h3>
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Spinner({ label = "Загрузка…" }: { label?: string }) {
  return (
    <div className="spinner-wrap" role="status">
      <span className="spinner" />
      {label}
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="error-box" role="alert">
      <Icon name="alert" />
      <span>{error}</span>
      {onRetry && (
        <button className="btn btn-sm" onClick={onRetry}>
          Повторить
        </button>
      )}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function CopyButton({ text, label = "Копировать" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // без HTTPS clipboard API может быть недоступен — запасной путь
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    setDone(true);
    window.setTimeout(() => setDone(false), 1500);
  };
  return (
    <button className="btn btn-sm" onClick={copy} type="button">
      <Icon name={done ? "check" : "copy"} size={14} />
      {done ? "Скопировано" : label}
    </button>
  );
}

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    ref.current?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="modal-back" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}>
        <header className="modal-head">
          <h3>{title}</h3>
          <button className="icon-btn" onClick={onClose} aria-label="Закрыть">
            <Icon name="x" />
          </button>
        </header>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

// Загрузка данных с повтором и отменой устаревших запросов.
export function useAsync<T>(fn: (signal: AbortSignal) => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);
  const reload = useCallback(() => setNonce((n) => n + 1), []);
  useEffect(() => {
    const ctl = new AbortController();
    setLoading(true);
    fn(ctl.signal)
      .then((d) => {
        if (!ctl.signal.aborted) {
          setData(d);
          setError(null);
        }
      })
      .catch((e: Error) => {
        if (!ctl.signal.aborted && e.name !== "AbortError") setError(e.message);
      })
      .finally(() => {
        if (!ctl.signal.aborted) setLoading(false);
      });
    return () => ctl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);
  return { data, error, loading, reload, setData };
}

// Периодический вызов (например, обновлять статистику раз в 10 с, пока вкладка видна).
export function useInterval(fn: () => void, ms: number) {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") ref.current();
    }, ms);
    return () => window.clearInterval(id);
  }, [ms]);
}
