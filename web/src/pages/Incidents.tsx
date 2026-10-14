// Инциденты: алерты одной атаки собраны в одну карточку — с ответственным, статусом и заметками.
import { useEffect, useMemo, useRef, useState } from "react";
import { api, type Alert, type Incident, type IncidentCard, type IncidentStatus, type Me } from "../api";
import { Bars } from "../components/Charts";
import { Icon } from "../components/Icons";
import { IpLink } from "../components/IpLink";
import { Card, Empty, ErrorBox, IncidentStatusBadge, Modal, SeverityBadge, Spinner, useAsync } from "../components/Ui";
import { countryName, flag } from "../countries";
import { ago, dateTime, INCIDENT_STATUSES, incidentStatusLabel, num, plural, SEVERITIES, severityLabel } from "../format";
import { useOnNewAlerts } from "../live";
import { Link, navigate, useLocation, useTitle } from "../router";
import { BlockModal } from "./Response";
import { ExportMenu } from "../components/ExportMenu";

const PAGE = 50;

function withParam(query: URLSearchParams, key: string, value: string): string {
  const q = new URLSearchParams(query);
  if (value) q.set(key, value);
  else q.delete(key);
  const s = q.toString();
  return `/incidents${s ? `?${s}` : ""}`;
}

// Кто или что атакует: IP, иначе пользователь на сервере, иначе сервер.
function Who({ i }: { i: Incident }) {
  if (i.src_ip) return <IpLink ip={i.src_ip} />;
  if (i.user)
    return (
      <span className="mono">
        {i.user}
        {i.host && <span className="muted">@{i.host}</span>}
      </span>
    );
  return <span className="mono">{i.host || "—"}</span>;
}

function mainRule(i: Incident): string {
  let best = i.rules[0];
  for (const r of i.rules) if (SEVERITIES.indexOf(r.severity) < SEVERITIES.indexOf(best.severity)) best = r;
  return best ? best.rule_name : "Инцидент";
}

export function IncidentsPage({ me }: { me: Me }) {
  useTitle("Инциденты");
  const { query } = useLocation();
  const view = query.get("view") ?? ""; // "" — активные, all — все, или статус
  const filter = {
    view,
    severity: query.get("severity") ?? "",
    q: query.get("q") ?? "",
    assignee: query.get("assignee") ?? "",
  };
  const params = {
    active: view === "" ? "1" : undefined,
    status: view && view !== "all" ? view : undefined,
    severity: filter.severity || undefined,
    q: filter.q || undefined,
    assignee: filter.assignee === "me" ? me.name : filter.assignee || undefined,
  };
  const key = JSON.stringify(filter);
  const [rows, setRows] = useState<Incident[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [moreBusy, setMoreBusy] = useState(false);
  const [qDraft, setQDraft] = useState(filter.q);
  useEffect(() => setQDraft(filter.q), [filter.q]);
  const first = useAsync((signal) => api.incidents({ ...params, limit: PAGE }, signal), [key, me.name]);
  const extended = useRef(false);
  useEffect(() => {
    extended.current = false;
    setRows([]);
    setNext(null);
  }, [key]);
  useEffect(() => {
    const page = first.data;
    if (!page) return;
    if (!extended.current) {
      setRows(page.items);
      setNext(page.next_before_id);
      return;
    }
    const minFresh = page.items.length ? page.items[page.items.length - 1].id : Infinity;
    setRows((old) => page.items.concat(old.filter((a) => a.id < minFresh)));
  }, [first.data]);
  useOnNewAlerts(first.reload);

  const loadMore = async () => {
    if (next === null) return;
    setMoreBusy(true);
    try {
      const p = await api.incidents({ ...params, limit: PAGE, before_id: next });
      extended.current = true;
      setRows((r) => r.concat(p.items));
      setNext(p.next_before_id);
    } finally {
      setMoreBusy(false);
    }
  };

  const take = async (i: Incident) => {
    try {
      const r = await api.incidentAssign(i.id, "me");
      setRows((rs) => rs.map((x) => (x.id === i.id ? r.incident : x)));
    } catch (e) {
      window.alert((e as Error).message);
    }
  };

  const views: [string, string][] = [
    ["", "Активные"],
    ...INCIDENT_STATUSES.map((s): [string, string] => [s, incidentStatusLabel[s]]),
    ["all", "Все"],
  ];

  return (
    <div className="page">
      <div className="page-head">
        <h1>Инциденты</h1>
        {first.data && (
          <span className="muted">
            активных: <b>{num(first.data.active)}</b>
            {first.data.unassigned > 0 && (
              <>
                {" "}
                · без ответственного: <b className="warn">{num(first.data.unassigned)}</b>
              </>
            )}
          </span>
        )}
        <span className="grow" />
        <ExportMenu kind="incidents" params={() => ({ ...params })} />
        <button className="btn btn-sm" onClick={first.reload}>
          <Icon name="refresh" size={14} /> Обновить
        </button>
      </div>
      <p className="hint page-hint">
        Инцидент — все алерты одной атаки: с одного IP (или от одного пользователя на сервере), пока атака не затихнет на час.
        Возьмите инцидент себе, разберитесь и закройте — алерты внутри закроются вместе с ним.
      </p>

      <Card>
        <div className="filters">
          <div className="seg">
            {views.map(([v, label]) => (
              <button key={v || "active"} className={view === v ? "active" : ""} onClick={() => navigate(withParam(query, "view", v))}>
                {label}
              </button>
            ))}
          </div>
          <div className="seg">
            {[
              ["", "Все"],
              ["me", "Мои"],
              ["-", "Без ответственного"],
            ].map(([v, label]) => (
              <button
                key={v || "any"}
                className={filter.assignee === v ? "active" : ""}
                onClick={() => navigate(withParam(query, "assignee", v))}
              >
                {label}
              </button>
            ))}
          </div>
          <label className="inline">
            Важность от
            <select value={filter.severity} onChange={(e) => navigate(withParam(query, "severity", e.target.value))}>
              <option value="">любой</option>
              {SEVERITIES.slice()
                .reverse()
                .map((s) => (
                  <option key={s} value={s}>
                    {severityLabel[s]}
                  </option>
                ))}
            </select>
          </label>
          <form
            className="inline grow-form"
            onSubmit={(e) => {
              e.preventDefault();
              navigate(withParam(query, "q", qDraft.trim()));
            }}
          >
            <input
              value={qDraft}
              onChange={(e) => setQDraft(e.target.value)}
              placeholder="Поиск: IP, пользователь, сервер, правило"
            />
          </form>
        </div>
      </Card>

      {first.error && <ErrorBox error={first.error} onRetry={first.reload} />}
      {first.loading && rows.length === 0 ? (
        <Spinner />
      ) : rows.length === 0 ? (
        <Empty>{view === "" ? "Активных инцидентов нет — всё спокойно." : "По выбранным фильтрам инцидентов нет."}</Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Важность</th>
                <th>Инцидент</th>
                <th>Источник</th>
                <th>Алертов</th>
                <th>Последний</th>
                <th>Ответственный</th>
                <th>Статус</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((i) => (
                <tr key={i.id} className="clickable" onClick={() => navigate(`/incidents/${i.id}`)}>
                  <td>
                    <SeverityBadge s={i.severity} />
                  </td>
                  <td className="msg">
                    <b>
                      <span className="muted">#{i.id}</span> {mainRule(i)}
                    </b>
                    <small>
                      {i.rules.length > 1
                        ? `ещё: ${i.rules
                            .filter((r) => r.rule_name !== mainRule(i))
                            .slice(0, 3)
                            .map((r) => r.rule_name)
                            .join(", ")}${i.rules.length > 4 ? "…" : ""}`
                        : i.hosts.length
                          ? `сервер: ${i.hosts.join(", ")}`
                          : ""}
                    </small>
                  </td>
                  <td onClick={(e) => i.src_ip && e.stopPropagation()}>
                    <Who i={i} />
                  </td>
                  <td>{num(i.alert_count)}</td>
                  <td className="nowrap" title={dateTime(i.last_alert)}>
                    {ago(i.last_alert)}
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    {i.assignee ? (
                      <span className={`assignee ${i.assignee === me.name ? "me" : ""}`}>
                        <Icon name="user" size={13} /> {i.assignee}
                      </span>
                    ) : me.can_change_alerts && i.active ? (
                      <button className="btn btn-sm" onClick={() => take(i)}>
                        Взять себе
                      </button>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td>
                    <IncidentStatusBadge s={i.status} />
                    {i.merged_into && <small className="muted">в #{i.merged_into}</small>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {next !== null && (
            <div className="more">
              <button className="btn" onClick={loadMore} disabled={moreBusy}>
                {moreBusy ? "Загрузка…" : "Показать ещё"}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------- карточка инцидента ----------------

type Entry =
  | { kind: "alert"; ts: string; alert: Alert }
  | { kind: "note"; ts: string; by: string; text: string; id: number }
  | { kind: "change"; ts: string; by: string; what: string; value: string };

function changeText(what: string, value: string, by: string) {
  switch (what) {
    case "status":
      return (
        <>
          сменил(а) статус на <b>{incidentStatusLabel[value as IncidentStatus] ?? value}</b>
        </>
      );
    case "assign":
      if (!value) return <>снял(а) ответственного</>;
      if (value === by) return <>взял(а) инцидент себе</>;
      return (
        <>
          назначил(а) ответственным <b>{value}</b>
        </>
      );
    case "merged_into":
      return (
        <>
          объединил(а) с инцидентом <Link to={`/incidents/${value}`}>#{value}</Link>
        </>
      );
    case "merged_from":
      return (
        <>
          присоединил(а) сюда инцидент <Link to={`/incidents/${value}`}>#{value}</Link>
        </>
      );
    default:
      return <>{what}</>;
  }
}

function MergeModal({ id, onClose, onDone }: { id: number; onClose: () => void; onDone: (into: number) => void }) {
  const [into, setInto] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const submit = async () => {
    const n = Number(into.replace("#", "").trim());
    if (!Number.isInteger(n) || n < 1) return setErr("Укажите номер инцидента");
    setBusy(true);
    setErr(null);
    try {
      await api.incidentMerge(id, n);
      onDone(n);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title={`Объединить инцидент #${id}`} onClose={onClose}>
      <p className="hint">
        Все алерты этого инцидента перейдут в другой, а этот закроется со ссылкой на него. Удобно, когда одна атака идёт
        с нескольких адресов.
      </p>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <label>
          В инцидент №
          <input autoFocus value={into} onChange={(e) => setInto(e.target.value)} placeholder="например, 12" />
        </label>
        {err && <div className="form-error">{err}</div>}
        <div className="form-actions">
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button className="btn btn-primary" disabled={busy}>
            {busy ? "Объединяю…" : "Объединить"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

const STATUS_ACTIONS: { to: IncidentStatus; label: string; from: IncidentStatus[] }[] = [
  { to: "in_progress", label: "В работу", from: ["open"] },
  { to: "resolved", label: "Решён", from: ["open", "in_progress"] },
  { to: "false_positive", label: "Ложная тревога", from: ["open", "in_progress"] },
  { to: "open", label: "Открыть снова", from: ["resolved", "false_positive"] },
];

export function IncidentDetailPage({ id, me }: { id: number; me: Me }) {
  useTitle(`Инцидент #${id}`);
  const res = useAsync((s) => api.incident(id, s), [id]);
  useOnNewAlerts(res.reload);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [closeAlerts, setCloseAlerts] = useState(true);
  const [merging, setMerging] = useState(false);
  const [blocking, setBlocking] = useState(false);
  const [show, setShow] = useState(60);
  const [onlyNotes, setOnlyNotes] = useState(false);

  const entries = useMemo<Entry[]>(() => {
    const c = res.data;
    if (!c) return [];
    const out: Entry[] = [];
    if (!onlyNotes) for (const a of c.alerts) out.push({ kind: "alert", ts: a.ts || a.created, alert: a });
    for (const n of c.incident.notes ?? []) out.push({ kind: "note", ts: n.ts, by: n.by, text: n.text, id: n.id });
    for (const h of c.incident.history ?? []) out.push({ kind: "change", ts: h.ts, by: h.by, what: h.kind, value: h.value });
    out.sort((x, y) => (x.ts < y.ts ? 1 : x.ts > y.ts ? -1 : 0));
    return out;
  }, [res.data, onlyNotes]);

  if (res.loading && !res.data) return <Spinner />;
  if (!res.data)
    return (
      <div className="page">
        <Link to="/incidents" className="back">
          <Icon name="back" size={16} /> Инциденты
        </Link>
        <ErrorBox error={res.error ?? "не найден"} onRetry={res.reload} />
      </div>
    );
  const c: IncidentCard = res.data;
  const i = c.incident;

  const run = async (fn: () => Promise<unknown>, ok?: string) => {
    setBusy(true);
    setErr(null);
    setMsg(null);
    try {
      await fn();
      if (ok) setMsg(ok);
      res.reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const setStatus = (st: IncidentStatus) =>
    run(async () => {
      const r = await api.incidentStatus(i.id, st, closeAlerts);
      if (r.alerts_changed) setMsg(`Статус изменён. Алертов обновлено: ${r.alerts_changed}`);
    }, "Статус изменён");
  const addNote = () => {
    const t = note.trim();
    if (!t) return;
    void run(async () => {
      await api.incidentNote(i.id, t);
      setNote("");
    });
  };

  const rulesBars = i.rules.map((r) => ({ label: r.rule_name, value: r.count, title: r.rule_id }));
  const ip = c.ip;

  return (
    <div className="page">
      <Link to="/incidents" className="back">
        <Icon name="back" size={16} /> Инциденты
      </Link>
      <div className="alert-head">
        <SeverityBadge s={i.severity} />
        <div>
          <h1>
            <span className="muted">#{i.id}</span> {i.title}
          </h1>
          <p className="alert-msg">
            {num(i.alert_count)} {plural(i.alert_count, "алерт", "алерта", "алертов")} · с {dateTime(i.first_alert)} по {dateTime(i.last_alert)}
            {i.merged_into && (
              <>
                {" "}
                · объединён с <Link to={`/incidents/${i.merged_into}`}>инцидентом #{i.merged_into}</Link>
              </>
            )}
          </p>
        </div>
        <IncidentStatusBadge s={i.status} />
      </div>

      <div className="incident-bar">
        <div className="assign-box">
          <Icon name="user" size={15} />
          {i.assignee ? (
            <>
              Ответственный: <b className={i.assignee === me.name ? "me" : ""}>{i.assignee}</b>
            </>
          ) : (
            <span className="muted">Ответственного нет</span>
          )}
          {me.can_change_alerts && !i.merged_into && (
            <>
              {i.assignee !== me.name && (
                <button className="btn btn-sm btn-primary" disabled={busy} onClick={() => run(() => api.incidentAssign(i.id, "me"))}>
                  Взять себе
                </button>
              )}
              {i.assignee && (
                <button className="btn btn-sm btn-ghost" disabled={busy} onClick={() => run(() => api.incidentAssign(i.id, ""))}>
                  Снять
                </button>
              )}
            </>
          )}
        </div>
        {me.can_change_alerts && !i.merged_into && (
          <div className="status-actions">
            {STATUS_ACTIONS.filter((a) => a.from.includes(i.status)).map((a) => (
              <button key={a.to} className={`btn btn-sm st-btn-${a.to}`} disabled={busy} onClick={() => setStatus(a.to)}>
                {a.label}
              </button>
            ))}
            <label className="check small" title="Алерты инцидента получат такой же статус">
              <input type="checkbox" checked={closeAlerts} onChange={(e) => setCloseAlerts(e.target.checked)} /> и алерты тоже
            </label>
            <button className="btn btn-sm btn-ghost" disabled={busy} onClick={() => setMerging(true)}>
              <Icon name="merge" size={14} /> Объединить…
            </button>
          </div>
        )}
      </div>
      {msg && <div className="note-ok">{msg}</div>}
      {err && <div className="form-error">{err}</div>}

      <div className="incident-grid">
        <div className="incident-main">
          <Card
            title="Ход расследования"
            actions={
              <div className="seg">
                <button className={!onlyNotes ? "active" : ""} onClick={() => setOnlyNotes(false)}>
                  Всё
                </button>
                <button className={onlyNotes ? "active" : ""} onClick={() => setOnlyNotes(true)}>
                  Заметки и действия
                </button>
              </div>
            }
          >
            {me.can_change_alerts && (
              <form
                className="note-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  addNote();
                }}
              >
                <textarea
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder="Заметка: что выяснили, что сделали (видна всем)"
                  rows={2}
                  maxLength={10000}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                      e.preventDefault();
                      addNote();
                    }
                  }}
                />
                <button className="btn btn-sm" disabled={busy || !note.trim()}>
                  <Icon name="note" size={14} /> Добавить
                </button>
              </form>
            )}
            {entries.length === 0 ? (
              <Empty>Пока ничего нет.</Empty>
            ) : (
              <ul className="itl">
                {entries.slice(0, show).map((e, k) => (
                  <li key={k} className={`itl-${e.kind}`}>
                    <span className="itl-dot" />
                    <time title={dateTime(e.ts)}>{dateTime(e.ts)}</time>
                    {e.kind === "alert" ? (
                      <div className="itl-body clickable" onClick={() => navigate(`/alerts/${e.alert.id}`)}>
                        <SeverityBadge s={e.alert.severity} /> <b>{e.alert.rule_name}</b>
                        <small>{e.alert.message}</small>
                      </div>
                    ) : e.kind === "note" ? (
                      <div className="itl-body itl-note">
                        <b>{e.by}</b>
                        <p>{e.text}</p>
                      </div>
                    ) : (
                      <div className="itl-body">
                        <b>{e.by}</b> {changeText(e.what, e.value, e.by)}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
            {entries.length > show && (
              <div className="more">
                <button className="btn btn-sm" onClick={() => setShow((n) => n + 100)}>
                  Показать ещё ({entries.length - show})
                </button>
              </div>
            )}
            {i.alert_count > c.alerts_shown && !onlyNotes && (
              <p className="hint">
                Показаны последние {c.alerts_shown} из {num(i.alert_count)} алертов.{" "}
                {i.src_ip && <Link to={`/alerts?src_ip=${encodeURIComponent(i.src_ip)}`}>Все алерты этого адреса</Link>}
              </p>
            )}
          </Card>
        </div>
        <div className="incident-side">
          {ip && (
            <Card title="Адрес атакующего">
              <div className="ip-summary">
                <Link to={`/ip/${encodeURIComponent(ip.ip)}`} className="mono big-ip">
                  {ip.ip}
                </Link>
                {ip.country && (
                  <div>
                    <span className="flag">{flag(ip.country)}</span> {countryName(ip.country)}
                    {ip.city && `, ${ip.city}`}
                  </div>
                )}
                {ip.org && (
                  <div className="muted small">
                    {ip.asn && `AS${ip.asn} · `}
                    {ip.org}
                  </div>
                )}
                {ip.internal && <span className="badge">внутренняя сеть</span>}
                {ip.lists.length > 0 && (
                  <div>
                    {ip.lists.map((l) => (
                      <span key={l} className="tag tag-danger">
                        {l}
                      </span>
                    ))}
                  </div>
                )}
                <div className="block-state">
                  {ip.block ? (
                    <span className="tag tag-danger">
                      заблокирован{ip.block.ip !== ip.ip ? ` (сеть ${ip.block.ip})` : ""}
                      {ip.block.expires ? ` до ${dateTime(ip.block.expires)}` : " навсегда"}
                    </span>
                  ) : (
                    me.can_change_alerts &&
                    !ip.internal && (
                      <button className="btn btn-sm" onClick={() => setBlocking(true)}>
                        <Icon name="ban" size={14} /> Заблокировать
                      </button>
                    )
                  )}
                </div>
                <div className="small">
                  <Link to={`/ip/${encodeURIComponent(ip.ip)}`}>Карточка адреса</Link>
                  {" · "}
                  <Link to={`/events?src_ip=${encodeURIComponent(ip.ip)}`}>события</Link>
                </div>
              </div>
            </Card>
          )}
          <Card title="Сработавшие правила">
            <Bars
              wide
              items={rulesBars}
              onClick={(name) => {
                const r = i.rules.find((x) => x.rule_name === name);
                if (r) navigate(`/rules/${encodeURIComponent(r.rule_id)}`);
              }}
            />
          </Card>
          <Card title="Подробности">
            <dl className="kv">
              <dt>Открыт</dt>
              <dd className="mono">{dateTime(i.created)}</dd>
              <dt>Изменён</dt>
              <dd>{ago(i.updated)}</dd>
              {i.hosts.length > 0 && (
                <>
                  <dt>Серверы</dt>
                  <dd className="mono">{i.hosts.join(", ")}</dd>
                </>
              )}
              {i.users.length > 0 && (
                <>
                  <dt>Пользователи</dt>
                  <dd className="mono">{i.users.join(", ")}</dd>
                </>
              )}
              <dt>Заметок</dt>
              <dd>{num(i.notes_count)}</dd>
            </dl>
          </Card>
        </div>
      </div>

      {merging && (
        <MergeModal
          id={i.id}
          onClose={() => setMerging(false)}
          onDone={(into) => {
            setMerging(false);
            navigate(`/incidents/${into}`);
          }}
        />
      )}
      {blocking && ip && (
        <BlockModal
          initialIp={ip.ip}
          initialReason={`${i.title} (инцидент #${i.id})`}
          onClose={() => setBlocking(false)}
          onDone={(m) => {
            setBlocking(false);
            setMsg(m);
            res.reload();
          }}
        />
      )}
    </div>
  );
}
