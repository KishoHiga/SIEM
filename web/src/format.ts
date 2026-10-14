// Форматирование чисел, дат и подписи на русском.
import type { AlertStatus, IncidentStatus, Severity } from "./api";

const nf = new Intl.NumberFormat("ru-RU");

export function num(n: number | undefined | null): string {
  if (n === undefined || n === null || Number.isNaN(n)) return "—";
  return nf.format(Math.round(n));
}

export function compact(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(1).replace(/\.0$/, "") + " млрд";
  if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, "") + " млн";
  if (n >= 1e4) return (n / 1e3).toFixed(0) + " тыс";
  return nf.format(n);
}

export function bytes(n: number): string {
  const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

const pad = (n: number) => String(n).padStart(2, "0");

export function dateTime(iso: string | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function timeOnly(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function hm(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function ago(iso: string | undefined, now = Date.now()): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 5) return "только что";
  if (s < 60) return `${s} с назад`;
  if (s < 3600) return `${Math.floor(s / 60)} мин назад`;
  if (s < 86400) return `${Math.floor(s / 3600)} ч назад`;
  return `${Math.floor(s / 86400)} дн назад`;
}

export function duration(sec: number): string {
  if (sec < 60) return `${sec} с`;
  if (sec < 3600) return `${Math.floor(sec / 60)} мин`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} ч ${Math.floor((sec % 3600) / 60)} мин`;
  return `${Math.floor(sec / 86400)} дн ${Math.floor((sec % 86400) / 3600)} ч`;
}

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const severityLabel: Record<Severity, string> = {
  critical: "Критический",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  info: "Инфо",
};

export const STATUSES: AlertStatus[] = ["new", "acknowledged", "resolved", "false_positive"];

export const statusLabel: Record<AlertStatus, string> = {
  new: "Новый",
  acknowledged: "В работе",
  resolved: "Решён",
  false_positive: "Ложный",
};

export const INCIDENT_STATUSES: IncidentStatus[] = ["open", "in_progress", "resolved", "false_positive"];

export const incidentStatusLabel: Record<IncidentStatus, string> = {
  open: "Открыт",
  in_progress: "В работе",
  resolved: "Решён",
  false_positive: "Ложная тревога",
};

export const roleLabel: Record<string, string> = {
  read: "Только чтение",
  analyst: "Аналитик",
  admin: "Администратор",
  ingest: "Агент",
};

export const ruleTypeLabel: Record<string, string> = {
  match: "Совпадение",
  threshold: "Порог",
  sequence: "Цепочка",
};

// Поля события с понятными подписями (порядок — как в карточке события).
export const FIELD_LABELS: [string, string][] = [
  ["source", "Источник"],
  ["type", "Тип"],
  ["host", "Хост"],
  ["process", "Процесс"],
  ["src_ip", "IP источника"],
  ["src_port", "Порт источника"],
  ["dst_ip", "IP назначения"],
  ["dst_port", "Порт назначения"],
  ["proto", "Протокол"],
  ["user", "Пользователь"],
  ["action", "Действие"],
  ["outcome", "Результат"],
  ["http.method", "HTTP метод"],
  ["http.path", "HTTP путь"],
  ["http.status", "HTTP статус"],
  ["http.user_agent", "User-Agent"],
  ["http.referer", "Referer"],
  ["bytes", "Байт"],
];

// Поля, которые сервер добавляет сам (страна, сеть, чёрные списки) — с понятными подписями.
export const EXTRA_LABELS: Record<string, string> = {
  "geo.country": "Страна",
  "geo.city": "Город",
  "geo.asn": "Сеть (ASN)",
  "geo.org": "Владелец сети",
  "ti.listed": "В чёрном списке",
  "ti.lists": "Чёрные списки",
};

// Русское склонение: plural(5, "алерт", "алерта", "алертов") -> "алертов".
export function plural(n: number, one: string, few: string, many: string): string {
  const d10 = n % 10,
    d100 = n % 100;
  if (d10 === 1 && d100 !== 11) return one;
  if (d10 >= 2 && d10 <= 4 && (d100 < 12 || d100 > 14)) return few;
  return many;
}
