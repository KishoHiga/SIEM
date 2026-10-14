// Свой маленький маршрутизатор на History API (вместо сторонней библиотеки).
import { useEffect, useSyncExternalStore, type AnchorHTMLAttributes, type MouseEvent } from "react";

const listeners = new Set<() => void>();

function subscribe(fn: () => void) {
  listeners.add(fn);
  window.addEventListener("popstate", fn);
  return () => {
    listeners.delete(fn);
    window.removeEventListener("popstate", fn);
  };
}

function snapshot() {
  return window.location.pathname + window.location.search;
}

export function navigate(to: string, replace = false) {
  if (to === snapshot()) return;
  if (replace) window.history.replaceState(null, "", to);
  else window.history.pushState(null, "", to);
  listeners.forEach((l) => l());
}

export interface Location {
  path: string;
  query: URLSearchParams;
}

export function useLocation(): Location {
  const full = useSyncExternalStore(subscribe, snapshot);
  const q = full.indexOf("?");
  return {
    path: q < 0 ? full : full.slice(0, q),
    query: new URLSearchParams(q < 0 ? "" : full.slice(q + 1)),
  };
}

// Сопоставить путь с шаблоном вида "/alerts/:id". Возвращает параметры или null.
export function match(pattern: string, path: string): Record<string, string> | null {
  const a = pattern.split("/").filter(Boolean);
  const b = path.split("/").filter(Boolean);
  if (a.length !== b.length) return null;
  const out: Record<string, string> = {};
  for (let i = 0; i < a.length; i++) {
    if (a[i].startsWith(":")) out[a[i].slice(1)] = decodeURIComponent(b[i]);
    else if (a[i] !== b[i]) return null;
  }
  return out;
}

export function Link({ to, onClick, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { to: string }) {
  const handle = (e: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(e);
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    navigate(to);
  };
  return <a href={to} onClick={handle} {...rest} />;
}

export function useTitle(title: string) {
  useEffect(() => {
    document.title = title ? `${title} · Sentinel` : "Sentinel SIEM";
  }, [title]);
}
