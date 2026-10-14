// Отчёт за период: что происходило, сколько было атак и как с ними справились.
// Кнопка «Печать / PDF» — печать браузера (в PDF сохраняет любой браузер), стили печати светлые.
import { useState } from "react";
import { api, type Me, type Report } from "../api";
import { Bars } from "../components/Charts";
import { Icon } from "../components/Icons";
import { IpLink } from "../components/IpLink";
import { Card, Empty, ErrorBox, IncidentStatusBadge, SeverityBadge, Spinner, useAsync } from "../components/Ui";
import { countryName, flag } from "../countries";
import { bytes, compact, dateTime, duration, num, plural, SEVERITIES } from "../format";
import { Link, navigate, useLocation, useTitle } from "../router";

const DAY = 86400000;

function startOfDay(d: Date): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate());
}

function ymd(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function dmy(iso: string): string {
  const d = new Date(iso);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()}`;
}

// Готовые периоды: «до» — конец сегодняшнего дня (или начало, для прошлых недель/месяцев).
function presets(): { key: string; label: string; from: Date; to: Date }[] {
  const today = startOfDay(new Date());
  const tomorrow = new Date(today.getTime() + DAY);
  const dow = (today.getDay() + 6) % 7; // 0 — понедельник
  const weekStart = new Date(today.getTime() - dow * DAY);
  const monthStart = new Date(today.getFullYear(), today.getMonth(), 1);
  return [
    { key: "7d", label: "7 дней", from: new Date(tomorrow.getTime() - 7 * DAY), to: tomorrow },
    { key: "30d", label: "30 дней", from: new Date(tomorrow.getTime() - 30 * DAY), to: tomorrow },
    { key: "lastweek", label: "Прошлая неделя", from: new Date(weekStart.getTime() - 7 * DAY), to: weekStart },
    { key: "month", label: "Этот месяц", from: monthStart, to: tomorrow },
    {
      key: "lastmonth",
      label: "Прошлый месяц",
      from: new Date(today.getFullYear(), today.getMonth() - 1, 1),
      to: monthStart,
    },
  ];
}

function DayChart({ r }: { r: Report }) {
  const days = r.days;
  const max = Math.max(1, ...days.map((d) => d.alerts));
  if (days.length === 0) return <Empty>Нет дней в периоде.</Empty>;
  return (
    <div className="report-days">
      {days.map((d) => (
        <div key={d.day} className="report-day" title={`${dmy(d.day)}: алертов ${d.alerts}, инцидентов ${d.incidents}, событий ${d.events}`}>
          <span className="rd-val">{d.alerts ? compact(d.alerts) : ""}</span>
          <div className="rd-bar">
            <span style={{ height: `${d.alerts ? Math.max(3, (d.alerts / max) * 100) : 0}%` }} />
          </div>
          <span className="rd-label">{dmy(d.day).slice(0, 5)}</span>
          {days.length <= 14 && <span className="rd-ev">{d.events ? compact(d.events) : "—"}</span>}
        </div>
      ))}
    </div>
  );
}

export function ReportPage({ me }: { me: Me }) {
  const { query } = useLocation();
  const ps = presets();
  const fromQ = query.get("from");
  const toQ = query.get("to");
  const preset = ps.find((p) => p.key === (query.get("period") ?? (fromQ ? "" : "7d")));
  const from = preset ? preset.from.toISOString() : (fromQ ?? ps[0].from.toISOString());
  const to = preset ? preset.to.toISOString() : (toQ ?? ps[0].to.toISOString());
  const res = useAsync((s) => api.report(from, to, s), [from, to]);
  const [fromDraft, setFromDraft] = useState(ymd(new Date(from)));
  const [toDraft, setToDraft] = useState(ymd(new Date(new Date(to).getTime() - 1)));
  const [sendMsg, setSendMsg] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const title = `Отчёт за ${dmy(from)} — ${dmy(new Date(new Date(to).getTime() - 1).toISOString())}`;
  useTitle(title);

  const applyCustom = () => {
    const f = new Date(fromDraft + "T00:00:00");
    const t = new Date(new Date(toDraft + "T00:00:00").getTime() + DAY);
    if (Number.isNaN(f.getTime()) || Number.isNaN(t.getTime()) || f >= t) return;
    navigate(`/report?from=${encodeURIComponent(f.toISOString())}&to=${encodeURIComponent(t.toISOString())}`);
  };
  const send = async () => {
    setSending(true);
    setSendMsg(null);
    try {
      const r = await api.reportSend();
      setSendMsg(`Отчёт за последние 7 дней отправлен (адресов: ${r.recipients})`);
    } catch (e) {
      setSendMsg((e as Error).message);
    } finally {
      setSending(false);
    }
  };

  const data = res.data;
  const r = data?.report;
  const hot = r ? r.incidents.by_severity.critical + r.incidents.by_severity.high : 0;

  return (
    <div className="page report-page">
      <div className="page-head no-print">
        <h1>Отчёт</h1>
        <div className="seg">
          {ps.map((p) => (
            <button key={p.key} className={preset?.key === p.key ? "active" : ""} onClick={() => navigate(`/report?period=${p.key}`)}>
              {p.label}
            </button>
          ))}
        </div>
        <form
          className="inline"
          onSubmit={(e) => {
            e.preventDefault();
            applyCustom();
          }}
        >
          с <input type="date" value={fromDraft} onChange={(e) => setFromDraft(e.target.value)} />
          по <input type="date" value={toDraft} onChange={(e) => setToDraft(e.target.value)} />
          <button className="btn btn-sm">Показать</button>
        </form>
        <span className="grow" />
        {me.is_admin && data?.mail.enabled && (
          <button className="btn btn-sm" onClick={send} disabled={sending} title="Письмо за последние 7 дней — тем же адресатам, что и еженедельное">
            <Icon name="send" size={14} /> {sending ? "Отправляю…" : "Отправить на почту"}
          </button>
        )}
        <button className="btn btn-sm btn-primary" onClick={() => window.print()} disabled={!r}>
          <Icon name="printer" size={14} /> Печать / PDF
        </button>
      </div>
      {sendMsg && <div className="note-ok no-print">{sendMsg}</div>}
      {data?.mail.enabled && (
        <p className="hint no-print">
          Еженедельное письмо: следующее — {dateTime(data.mail.next)}
          {data.mail.last_sent && `, прошлое — ${dateTime(data.mail.last_sent)}`}
          {data.mail.last_error && <span className="danger"> · ошибка отправки: {data.mail.last_error}</span>}
        </p>
      )}

      {res.error && <ErrorBox error={res.error} onRetry={res.reload} />}
      {!r ? (
        !res.error && <Spinner label="Собираю отчёт…" />
      ) : (
        <>
          <div className="print-head">
            <h1>{title}</h1>
            <p className="muted">
              SentinelCore SIEM · сформирован {dateTime(r.generated)} · пользователь {me.name}
            </p>
          </div>

          <div className="stat-grid">
            <div className="stat">
              <div className="stat-label">Событий</div>
              <div className="stat-value">{compact(r.events.total)}</div>
              <div className="stat-sub">
                {r.events.partial
                  ? r.events.data_from
                    ? `статистика есть с ${dateTime(r.events.data_from)}`
                    : "статистики за период нет"
                  : `хранится всего: ${compact(r.storage.events)}`}
              </div>
            </div>
            <div className="stat">
              <div className="stat-label">Алертов</div>
              <div className={`stat-value ${r.alerts.by_severity.critical ? "danger" : ""}`}>{num(r.alerts.total)}</div>
              <div className="stat-sub">
                критических: {num(r.alerts.by_severity.critical)} · ложных: {num(r.alerts.by_status.false_positive)}
              </div>
            </div>
            <div className="stat">
              <div className="stat-label">Новых инцидентов</div>
              <div className={`stat-value ${hot ? "danger" : ""}`}>{num(r.incidents.created)}</div>
              <div className="stat-sub">
                серьёзных: {num(hot)} · решено: {num(r.incidents.resolved)}
              </div>
            </div>
            <div className="stat">
              <div className="stat-label">Открыто сейчас</div>
              <div className={`stat-value ${r.incidents.active_now ? "warn" : "ok"}`}>{num(r.incidents.active_now)}</div>
              <div className="stat-sub">
                {r.incidents.median_close_sec
                  ? `обычно закрываются за ${duration(r.incidents.median_close_sec)}`
                  : `без ответственного: ${num(r.incidents.unassigned_now)}`}
              </div>
            </div>
          </div>

          <Card title="Алерты по дням" actions={r.days.length <= 14 ? <span className="muted small">внизу — событий за день</span> : undefined}>
            <DayChart r={r} />
          </Card>

          <div className="grid-2">
            <Card title="Алерты по важности">
              <table className="table compact">
                <tbody>
                  {SEVERITIES.map((s) => (
                    <tr key={s}>
                      <td>
                        <SeverityBadge s={s} />
                      </td>
                      <td className="num">{num(r.alerts.by_severity[s])}</td>
                      <td className="num muted">инцидентов: {num(r.incidents.by_severity[s])}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
            <Card title="Как разобрали">
              <dl className="kv">
                <dt>Инцидентов решено</dt>
                <dd>{num(r.incidents.resolved)}</dd>
                <dt>Ложных тревог</dt>
                <dd>{num(r.incidents.false_positive)}</dd>
                <dt>Обычное время до закрытия</dt>
                <dd>{r.incidents.median_close_sec ? duration(r.incidents.median_close_sec) : "—"}</dd>
                <dt>Открыто сейчас</dt>
                <dd>
                  {num(r.incidents.active_now)}
                  {r.incidents.unassigned_now > 0 && <span className="warn"> (без ответственного: {num(r.incidents.unassigned_now)})</span>}
                </dd>
                <dt>Блокировок действует</dt>
                <dd>{num(r.blocks.active)}</dd>
                <dt>Новых блокировок</dt>
                <dd>
                  автоматически {num(r.blocks.new_auto)}, вручную {num(r.blocks.new_manual)}
                </dd>
              </dl>
            </Card>
          </div>

          <Card title="Главные инциденты периода">
            {r.incidents.top.length === 0 ? (
              <Empty>Новых инцидентов за период не было.</Empty>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>№</th>
                    <th>Инцидент</th>
                    <th>Важность</th>
                    <th>Алертов</th>
                    <th>Ответственный</th>
                    <th>Статус</th>
                  </tr>
                </thead>
                <tbody>
                  {r.incidents.top.map((i) => (
                    <tr key={i.id} className="clickable" onClick={() => navigate(`/incidents/${i.id}`)}>
                      <td className="muted">#{i.id}</td>
                      <td className="msg">
                        <b>{i.title}</b>
                        <small>{dateTime(i.created)}</small>
                      </td>
                      <td>
                        <SeverityBadge s={i.severity} />
                      </td>
                      <td>{num(i.alert_count)}</td>
                      <td>{i.assignee || <span className="muted">—</span>}</td>
                      <td>
                        <IncidentStatusBadge s={i.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>

          <Card title="Чаще всего срабатывали правила">
            {r.alerts.top_rules.length === 0 ? (
              <Empty>Алертов за период не было.</Empty>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>Правило</th>
                    <th>Важность</th>
                    <th className="num">Алертов</th>
                    <th className="num">Ложных</th>
                  </tr>
                </thead>
                <tbody>
                  {r.alerts.top_rules.map((x) => (
                    <tr key={x.rule_id}>
                      <td className="msg">
                        <Link to={`/alerts?rule=${encodeURIComponent(x.rule_id)}`}>
                          <b>{x.rule_name}</b>
                        </Link>
                        <small className="mono">{x.rule_id}</small>
                      </td>
                      <td>
                        <SeverityBadge s={x.severity} />
                      </td>
                      <td className="num">{num(x.count)}</td>
                      <td className="num">
                        {x.false_positive ? (
                          <span className={x.false_positive * 3 > x.count ? "warn" : ""}>
                            {num(x.false_positive)} ({Math.round((x.false_positive / x.count) * 100)}%)
                          </span>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {r.alerts.top_rules.some((x) => x.false_positive * 3 > x.count && x.count >= 5) && (
              <p className="hint">У правил, выделенных цветом, больше трети алертов — ложные. Их стоит донастроить.</p>
            )}
          </Card>

          <div className="grid-3">
            <Card title="Адреса с наибольшим числом алертов">
              {r.alerts.top_ips.length === 0 ? (
                <Empty>—</Empty>
              ) : (
                <table className="table compact">
                  <tbody>
                    {r.alerts.top_ips.map((x) => (
                      <tr key={x.ip}>
                        <td>
                          <IpLink ip={x.ip} />
                        </td>
                        <td className="num">
                          {num(x.count)} {plural(x.count, "алерт", "алерта", "алертов")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
            <Card title="Самые активные адреса (события)">
              {r.events.top_ips.length === 0 ? (
                <Empty>—</Empty>
              ) : (
                <table className="table compact">
                  <tbody>
                    {r.events.top_ips.map((x) => (
                      <tr key={x.ip}>
                        <td>
                          <IpLink ip={x.ip} country={x.country} />
                        </td>
                        <td className="num">{compact(x.count)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
            <Card title="Страны">
              {r.events.top_countries.length === 0 ? (
                <Empty>База стран не загружена или событий не было.</Empty>
              ) : (
                <Bars
                  items={r.events.top_countries.map((c) => ({
                    label: `${flag(c.country)} ${countryName(c.country)}`,
                    value: c.count,
                  }))}
                />
              )}
            </Card>
          </div>

          <div className="grid-2">
            <Card title="Источники логов">
              <Bars items={r.events.top_sources.map((x) => ({ label: x.source, value: x.count }))} />
            </Card>
            <Card title="Типы событий">
              <Bars items={r.events.by_type.map((x) => ({ label: x.type, value: x.count }))} />
            </Card>
          </div>
          <p className="hint">
            Хранилище: {compact(r.storage.events)} событий, {bytes(r.storage.bytes_on_disk)} на диске. Цифры событий — из
            почасовой статистики (последние 32 дня); алерты и инциденты — за весь срок хранения.
          </p>
        </>
      )}
    </div>
  );
}
