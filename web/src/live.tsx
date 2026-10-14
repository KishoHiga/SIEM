// Живая лента через WebSocket: раз в секунду сервер присылает сводку
// (сколько событий пришло, последние события, новые алерты). Сам переподключается.
// При открытии и после переподключения лента сразу заполняется последними событиями из базы,
// чтобы не было пусто, если события пришли до того, как открыли панель.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, type Alert, type SiemEvent } from "./api";

export interface Tick {
  type: "tick";
  t: string;
  events: number;
  recent: SiemEvent[];
  alerts: Alert[];
}

export type LiveState = "connecting" | "online" | "offline";

interface LiveCtx {
  state: LiveState;
  // последние события и алерты (новые сверху)
  recent: SiemEvent[];
  alerts: Alert[];
  // сколько алертов пришло по ленте с момента открытия панели
  alertCount: number;
  // событий в секунду за последние 60 тиков
  rate: number[];
  // подписка на каждый тик (например, обновить таблицу алертов)
  subscribe: (fn: (t: Tick) => void) => () => void;
}

const Ctx = createContext<LiveCtx | null>(null);

const MAX_RECENT = 200;
const MAX_ALERTS = 100;
const RATE_POINTS = 60;

export function LiveProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<LiveState>("connecting");
  const [recent, setRecent] = useState<SiemEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [alertCount, setAlertCount] = useState(0);
  const [rate, setRate] = useState<number[]>(() => new Array(RATE_POINTS).fill(0));
  const subs = useRef(new Set<(t: Tick) => void>());

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry = 0;
    let timer: number | undefined;
    let closed = false;
    let lastTick = 0;
    let watchdog: number | undefined;

    // последние события из базы — без повторов с тем, что уже пришло по ленте
    const backfill = () => {
      api
        .events({ limit: 30 })
        .then((p) => {
          if (closed) return;
          setRecent((r) => {
            const seen = new Set(r.map((e) => e.id));
            const add = p.items.filter((e) => !seen.has(e.id));
            if (!add.length) return r;
            return [...r, ...add].sort((a, b) => b.id - a.id).slice(0, MAX_RECENT);
          });
        })
        .catch(() => undefined);
    };

    const connect = async () => {
      if (closed) return;
      setState("connecting");
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      // Одноразовый билет: Safari не всегда отдаёт cookie входа в WebSocket.
      // Старый сервер без билетов — подключаемся как раньше, по cookie.
      let ticket = "";
      try {
        ticket = (await api.wsTicket()).ticket;
      } catch {
        ticket = "";
      }
      if (closed) return;
      ws = new WebSocket(`${proto}//${window.location.host}/ws/live${ticket ? `?ticket=${ticket}` : ""}`);
      ws.onopen = () => {
        retry = 0;
        lastTick = Date.now();
        setState("online");
        backfill();
      };
      ws.onmessage = (m) => {
        let t: Tick;
        try {
          t = JSON.parse(m.data as string) as Tick;
        } catch {
          return;
        }
        if (t.type !== "tick") return;
        const now = Date.now();
        // если тики шли с паузой (пульс раз в 5 с), заполняем пропущенные секунды нулями
        const gap = lastTick ? Math.min(RATE_POINTS, Math.max(1, Math.round((now - lastTick) / 1000))) : 1;
        lastTick = now;
        setRate((r) => {
          const next = r.concat(new Array(gap - 1).fill(0), [t.events]);
          return next.slice(-RATE_POINTS);
        });
        if (t.recent.length) setRecent((r) => [...t.recent.slice().reverse(), ...r].slice(0, MAX_RECENT));
        if (t.alerts.length) {
          setAlerts((a) => [...t.alerts.slice().reverse(), ...a].slice(0, MAX_ALERTS));
          setAlertCount((c) => c + t.alerts.length);
        }
        subs.current.forEach((fn) => fn(t));
      };
      ws.onclose = () => {
        ws = null;
        if (closed) return;
        setState("offline");
        retry = Math.min(retry + 1, 6);
        timer = window.setTimeout(() => void connect(), 500 * 2 ** retry); // 1 с, 2 с, 4 с ... до 32 с
      };
      ws.onerror = () => ws?.close();
    };
    void connect();
    // сервер шлёт пульс раз в 5 с; если 15 с тишина — связь потеряна, переподключаемся
    watchdog = window.setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN && Date.now() - lastTick > 15000) ws.close();
    }, 5000);
    return () => {
      closed = true;
      window.clearTimeout(timer);
      window.clearInterval(watchdog);
      ws?.close();
    };
  }, []);

  const subscribe = useCallback((fn: (t: Tick) => void) => {
    subs.current.add(fn);
    return () => {
      subs.current.delete(fn);
    };
  }, []);

  const value = useMemo(
    () => ({ state, recent, alerts, alertCount, rate, subscribe }),
    [state, recent, alerts, alertCount, rate, subscribe],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useLive(): LiveCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useLive outside LiveProvider");
  return c;
}

// Вызвать fn на каждом тике, в котором есть новые алерты.
export function useOnNewAlerts(fn: () => void) {
  const { subscribe } = useLive();
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => subscribe((t) => t.alerts.length > 0 && ref.current()), [subscribe]);
}
