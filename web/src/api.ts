// Связь панели с сервером SentinelCore.
// Вход — по ключу, дальше браузер сам носит HttpOnly-cookie сессии (скрипты её не видят).
// Каждый запрос несёт заголовок X-Requested-With: sentinel — без него сервер не примет
// изменяющие запросы (защита от подделки запросов с чужих сайтов).

export type Role = "read" | "analyst" | "admin" | "ingest";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type AlertStatus = "new" | "acknowledged" | "resolved" | "false_positive";
export type IncidentStatus = "open" | "in_progress" | "resolved" | "false_positive";

export interface Me {
  name: string;
  role: Role;
  can_change_alerts: boolean;
  is_admin: boolean;
}

export interface SiemEvent {
  id: number;
  ts: string;
  ts_ms?: number;
  received?: string;
  source?: string;
  type?: string;
  host?: string;
  process?: string;
  src_ip?: string;
  src_port?: string;
  dst_ip?: string;
  dst_port?: string;
  proto?: string;
  user?: string;
  action?: string;
  outcome?: string;
  "http.method"?: string;
  "http.path"?: string;
  "http.status"?: string;
  "http.user_agent"?: string;
  "http.referer"?: string;
  bytes?: string;
  message?: string;
  raw?: string;
  extra?: Record<string, string>;
}

export interface Alert {
  id: number;
  ts: string;
  created: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  status: AlertStatus;
  src_ip: string;
  user: string;
  host: string;
  message: string;
  count: number;
  incident_id?: number;
  event_ids: number[];
  fields: Record<string, string>;
}

export interface Incident {
  id: number;
  title: string;
  key: string;
  src_ip: string;
  user: string;
  host: string;
  severity: Severity;
  status: IncidentStatus;
  active: boolean;
  assignee: string;
  created: string;
  updated: string;
  first_alert: string;
  last_alert: string;
  alert_count: number;
  notes_count: number;
  merged_into?: number;
  rules: { rule_id: string; rule_name: string; severity: Severity; count: number }[];
  hosts: string[];
  users: string[];
  notes?: { id: number; ts: string; by: string; text: string }[];
  history?: { ts: string; by: string; kind: "status" | "assign" | "merged_into" | "merged_from"; value: string }[];
}

export interface IncidentCard {
  incident: Incident;
  alerts: Alert[];
  alerts_shown: number;
  ip?: {
    ip: string;
    internal: boolean;
    country: string;
    city: string;
    org: string;
    asn: string;
    lists: string[];
    block: Block | null;
  };
}

export interface Stats {
  uptime_sec: number;
  events_since_start: number;
  events_24h: number;
  events_per_sec: number;
  alerts_24h: number;
  alerts_open_24h: number;
  alerts_by_severity_24h: Record<Severity, number>;
  alerts_by_status_24h: Record<AlertStatus, number>;
  incidents?: { active: number; unassigned: number; by_severity: Record<Severity, number> };
  timeline: { t: string; events: number; alerts: number }[];
  top_ips: { ip: string; count: number; country?: string; listed?: boolean }[];
  top_countries?: { country: string; count: number }[];
  top_sources: { source: string; count: number }[];
  by_type: { type: string; count: number }[];
  storage: {
    events: number;
    segments: number;
    bytes_on_disk: number;
    compression_ratio: number;
    pending: number;
    corrupt_blocks: number;
  };
  pipeline: {
    accepted: number;
    rejected: number;
    queued: number;
    alerts_emitted: number;
    alerts_suppressed: number;
    detection_state_keys: number;
    detect_threads?: number;
    global_thread?: boolean;
    sharded_rules?: number;
    global_rules?: number;
    shard_events?: number[];
  };
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  type: "match" | "threshold" | "sequence";
  enabled: boolean;
  file: string;
  threshold?: number;
  window_seconds?: number;
  distinct?: string;
  within_seconds?: number;
  steps?: number;
  tags: string[];
  group_by?: string[];
  tests?: number;
  alerts_24h?: { total: number; open: number; false_positive: number; last: string | null };
}

export interface RulesList {
  rules: Rule[];
  total: number;
  editable: boolean;
  errors: string[];
}

export interface RuleSource {
  file: string;
  source: string;
  rule: Rule;
  rules_in_file: string[];
  used_by: string[];
  versions: number;
}

export interface RuleCheck {
  ok: boolean;
  error: string;
  errors: string[];
  file: string;
  test_cases: number;
  rule_ids: string[];
  test_failures: { rule_id: string; line: string; expected_alert: boolean }[];
}

export interface RuleTry {
  ok: boolean;
  error: string;
  errors: string[];
  tested: string[];
  helpers: string[];
  events: number;
  alerts_total: number;
  alerts_by_rule: Record<string, number>;
  distinct_ips: number;
  took_ms: number;
  truncated: boolean;
  first_ts: string | null;
  last_ts: string | null;
  alerts: Alert[];
  lines?: { index: number; parsed: boolean; event?: SiemEvent; alerts: number[] }[];
  tests?: { cases: number; failures: { rule_id: string; line: string; expected_alert: boolean }[] };
}

export interface RuleVersion {
  version: string;
  ts: string;
  action: string;
  by: string;
}

export interface Agent {
  key_name: string;
  host: string;
  agent: string;
  remote_addr: string;
  first_seen: string;
  last_seen: string;
  seconds_since_last: number;
  online: boolean;
  events: number;
  requests: number;
  firewall?: string; // "nftables; applied=12" | "nginx; error=..." | "none"
  blocks_synced?: string;
}

export interface Block {
  ip: string;
  reason: string;
  rule_id: string;
  alert_id: number;
  by: string; // "auto" или имя ключа
  created: string;
  expires: string | null; // null — бессрочно
  hits: number;
}

export interface BlockList {
  version: number;
  policy: {
    auto_block: boolean;
    min_severity: Severity;
    duration_seconds: number;
    block_private: boolean;
    max_per_minute: number;
    rules: string[];
    allowlist: string[];
  };
  stats: {
    active: number;
    auto_added: number;
    manual_added: number;
    skipped_allowlist: number;
    skipped_private: number;
    skipped_limit: number;
    expired: number;
  };
  blocks: Block[];
}

export interface NotifyChannel {
  name: string; // telegram | webhook | email
  target: string;
  sent: number;
  failed: number;
  last_ok: string | null;
  last_error_at: string | null;
  last_error: string;
}

export interface NotifyStatus {
  enabled: boolean;
  min_severity?: Severity;
  mode?: "alerts" | "incidents";
  queued?: number;
  suppressed?: number;
  dropped?: number;
  digests?: number;
  channels: NotifyChannel[];
}

export interface EnrollToken {
  token: string;
  expires: string;
  uses: number;
  server: string;
  pin: string;
  command: string;
}

export interface IpCard {
  ip: string;
  internal: boolean;
  country: string;
  city: string;
  asn: string;
  org: string;
  lists: string[];
  geo_available: boolean;
  geo_attribution: string;
  block: Block | null;
  events: {
    count: number;
    capped: boolean;
    failures: number;
    first_seen: string | null;
    last_seen: string | null;
    by_day: { day: string; count: number }[];
    paths: TopItem[];
    users: TopItem[];
    hosts: TopItem[];
    types: TopItem[];
    sources: TopItem[];
    statuses: TopItem[];
    actions: TopItem[];
    user_agents: TopItem[];
  };
  alerts: {
    count: number;
    capped: boolean;
    by_rule: { rule_id: string; rule_name: string; count: number }[];
    recent: Alert[];
  };
}

export interface TopItem {
  value: string;
  count: number;
}

export interface ThreatStatus {
  geo: { available: boolean; country_ranges: number; asn_ranges: number; built: string | null };
  lists: {
    name: string;
    source: string;
    entries: number;
    cached: boolean;
    updated: string | null;
    last_try: string | null;
    last_error: string;
  }[];
}

export interface Page<T> {
  items: T[];
  next_before_id: number | null;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public data: unknown = null,
  ) {
    super(message);
  }
}

// Вызывается, когда сессия кончилась (сервер ответил 401) — панель вернётся на экран входа.
let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

async function request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const headers: Record<string, string> = { "X-Requested-With": "sentinel", Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let resp: Response;
  try {
    resp = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
      signal,
    });
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    throw new ApiError(0, "Сервер недоступен. Проверьте, что sentinel-server запущен.");
  }
  const text = await resp.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (!resp.ok) {
    const msg = (data as { error?: string } | null)?.error ?? `HTTP ${resp.status}`;
    if (resp.status === 401 && path !== "/api/v1/login") onUnauthorized();
    throw new ApiError(resp.status, msg, data);
  }
  return data as T;
}

function qs(params: Record<string, string | number | undefined | null>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export type ExportKind = "events" | "alerts" | "incidents";

// Ссылка на выгрузку (браузер скачает файл сам). tz — чтобы время в файле было местным.
export function exportUrl(kind: ExportKind, params: Record<string, string | number | undefined | null>): string {
  return `/api/v1/export/${kind}${qs({ ...params, tz: -new Date().getTimezoneOffset() })}`;
}

export interface Report {
  from: string;
  to: string;
  generated: string;
  tz_minutes: number;
  days: { day: string; events: number; alerts: number; incidents: number }[];
  events: {
    total: number;
    partial: boolean;
    data_from: string;
    top_ips: { ip: string; count: number; country?: string }[];
    top_sources: { source: string; count: number }[];
    by_type: { type: string; count: number }[];
    top_countries: { country: string; count: number }[];
  };
  alerts: {
    total: number;
    by_severity: Record<Severity, number>;
    by_status: Record<AlertStatus, number>;
    top_rules: { rule_id: string; rule_name: string; severity: Severity; count: number; false_positive: number }[];
    top_ips: { ip: string; count: number }[];
  };
  incidents: {
    created: number;
    resolved: number;
    false_positive: number;
    active_now: number;
    unassigned_now: number;
    median_close_sec: number;
    by_severity: Record<Severity, number>;
    top: {
      id: number;
      title: string;
      severity: Severity;
      status: IncidentStatus;
      assignee: string;
      alert_count: number;
      created: string;
    }[];
  };
  blocks: { active: number; new_auto: number; new_manual: number };
  storage: { events: number; bytes_on_disk: number };
}

export interface ReportMail {
  enabled: boolean;
  next?: string;
  last_sent?: string;
  recipients?: number;
  last_error?: string;
}

export const api = {
  login: (key: string) => request<{ name: string; role: Role }>("POST", "/api/v1/login", { key }),
  logout: () => request<{ ok: boolean }>("POST", "/api/v1/logout"),
  me: () => request<Me>("GET", "/api/v1/me"),
  wsTicket: () => request<{ ticket: string }>("POST", "/api/v1/ws-ticket"),
  stats: (minutes = 60, signal?: AbortSignal) => request<Stats>("GET", `/api/v1/stats${qs({ minutes })}`, undefined, signal),

  alerts: async (
    f: { status?: string; severity?: string; rule?: string; src_ip?: string; limit?: number; before_id?: number | null },
    signal?: AbortSignal,
  ): Promise<Page<Alert>> => {
    const r = await request<{ alerts: Alert[]; next_before_id: number | null }>(
      "GET",
      `/api/v1/alerts${qs(f)}`,
      undefined,
      signal,
    );
    return { items: r.alerts, next_before_id: r.next_before_id };
  },
  alert: (id: number) => request<{ alert: Alert; events: SiemEvent[] }>("GET", `/api/v1/alerts/${id}`),
  setAlertStatus: (id: number, status: AlertStatus) =>
    request<{ id: number; status: AlertStatus }>("POST", `/api/v1/alerts/${id}/status`, { status }),

  events: async (
    f: { q?: string; from?: string; to?: string; limit?: number; before_id?: number | null; fields?: Record<string, string> },
    signal?: AbortSignal,
  ): Promise<Page<SiemEvent>> => {
    const { fields, ...rest } = f;
    const r = await request<{ events: SiemEvent[]; next_before_id: number | null }>(
      "GET",
      `/api/v1/events${qs({ ...rest, ...(fields ?? {}) })}`,
      undefined,
      signal,
    );
    return { items: r.events, next_before_id: r.next_before_id };
  },
  event: (id: number) => request<SiemEvent>("GET", `/api/v1/events/${id}`),

  rules: () => request<RulesList>("GET", "/api/v1/rules"),
  rule: (id: string) => request<RuleSource>("GET", `/api/v1/rules/${encodeURIComponent(id)}`),
  // Сохранение: при ошибке проверки сервер отвечает 422 с подробностями — возвращаем их, а не исключение.
  saveRule: (id: string | null, source: string) =>
    checkResult(
      id === null
        ? request<RuleCheck>("POST", "/api/v1/rules", { source })
        : request<RuleCheck>("PUT", `/api/v1/rules/${encodeURIComponent(id)}`, { source }),
    ),
  deleteRule: (id: string) => checkResult(request<RuleCheck>("DELETE", `/api/v1/rules/${encodeURIComponent(id)}`)),
  setRuleEnabled: (id: string, enabled: boolean) =>
    checkResult(request<RuleCheck>("POST", `/api/v1/rules/${encodeURIComponent(id)}/enabled`, { enabled })),
  checkRule: (source: string, id?: string, signal?: AbortSignal) =>
    request<RuleCheck>("POST", "/api/v1/rules/check", { source, id }, signal),
  tryRule: (source: string, lines: string, format: string) =>
    request<RuleTry>("POST", "/api/v1/rules/try", { source, lines, format, tz_minutes: -new Date().getTimezoneOffset() }),
  tryRuleHistory: (source: string, hours: number) =>
    request<RuleTry>("POST", "/api/v1/rules/try-history", { source, hours }),
  ruleHistory: (id: string) =>
    request<{ versions: RuleVersion[] }>("GET", `/api/v1/rules/${encodeURIComponent(id)}/history`),
  ruleVersion: (id: string, version: string) =>
    request<{ version: string; source: string }>(
      "GET",
      `/api/v1/rules/${encodeURIComponent(id)}/history/${encodeURIComponent(version)}`,
    ),
  incidents: async (
    f: {
      status?: string;
      active?: string;
      severity?: string;
      q?: string;
      assignee?: string;
      limit?: number;
      before_id?: number | null;
    },
    signal?: AbortSignal,
  ): Promise<Page<Incident> & { active: number; unassigned: number }> => {
    const r = await request<{ incidents: Incident[]; next_before_id: number | null; active: number; unassigned: number }>(
      "GET",
      `/api/v1/incidents${qs(f)}`,
      undefined,
      signal,
    );
    return { items: r.incidents, next_before_id: r.next_before_id, active: r.active, unassigned: r.unassigned };
  },
  incident: (id: number, signal?: AbortSignal) =>
    request<IncidentCard>("GET", `/api/v1/incidents/${id}`, undefined, signal),
  incidentStatus: (id: number, status: IncidentStatus, close_alerts = true) =>
    request<{ incident: Incident; alerts_changed: number }>("POST", `/api/v1/incidents/${id}/status`, {
      status,
      close_alerts,
    }),
  incidentAssign: (id: number, assignee: string) =>
    request<{ incident: Incident }>("POST", `/api/v1/incidents/${id}/assign`, { assignee }),
  incidentNote: (id: number, text: string) =>
    request<{ incident: Incident }>("POST", `/api/v1/incidents/${id}/notes`, { text }),
  incidentMerge: (id: number, into: number) =>
    request<{ incident: Incident }>("POST", `/api/v1/incidents/${id}/merge`, { into }),
  report: (from: string, to: string, signal?: AbortSignal) =>
    request<{ report: Report; mail: ReportMail }>(
      "GET",
      `/api/v1/report${qs({ from, to, tz: -new Date().getTimezoneOffset() })}`,
      undefined,
      signal,
    ),
  reportSend: () => request<{ ok: boolean; recipients: number }>("POST", "/api/v1/report/send"),
  agents: () => request<{ agents: Agent[] }>("GET", "/api/v1/agents"),
  ip: (addr: string, signal?: AbortSignal) =>
    request<IpCard>("GET", `/api/v1/ip/${encodeURIComponent(addr)}`, undefined, signal),
  threat: (signal?: AbortSignal) => request<ThreatStatus>("GET", "/api/v1/threat", undefined, signal),
  blocks: (signal?: AbortSignal) => request<BlockList>("GET", "/api/v1/blocks", undefined, signal),
  blockFor: (ip: string) => request<{ blocked: boolean; block?: Block }>("GET", `/api/v1/blocks${qs({ ip })}`),
  block: (ip: string, duration: string, reason: string) =>
    request<{ result: string; block: Block }>("POST", "/api/v1/blocks", { ip, duration, reason }),
  unblock: (ip: string) => request<{ ok: boolean }>("DELETE", `/api/v1/blocks${qs({ ip })}`),
  notify: (signal?: AbortSignal) => request<NotifyStatus>("GET", "/api/v1/notify", undefined, signal),
  notifyTest: () => request<{ results: { name: string; ok: boolean; error: string }[] }>("POST", "/api/v1/notify/test"),
  createEnrollToken: (ttl_hours: number, uses: number, label: string) =>
    request<EnrollToken>("POST", "/api/v1/enroll-tokens", { ttl_hours, uses, label }),
};

async function checkResult(p: Promise<RuleCheck>): Promise<RuleCheck> {
  try {
    return await p;
  } catch (e) {
    if (e instanceof ApiError && e.status === 422 && e.data) return e.data as RuleCheck;
    throw e;
  }
}
