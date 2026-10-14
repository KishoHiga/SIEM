// Карточка IP-адреса: откуда он, в каких чёрных списках, заблокирован ли и что делал.
import { useState } from "react";
import { api, type Me, type TopItem } from "../api";
import { Bars } from "../components/Charts";
import { Icon } from "../components/Icons";
import { Card, Empty, ErrorBox, SeverityBadge, Spinner, useAsync } from "../components/Ui";
import { countryName, flag } from "../countries";
import { ago, dateTime, num } from "../format";
import { Link, navigate, useTitle } from "../router";
import { BlockModal } from "./Response";

function Top({ title, items, field, ip }: { title: string; items: TopItem[]; field?: string; ip: string }) {
  return (
    <Card title={title}>
      <Bars
        items={items.map((i) => ({ label: i.value, value: i.count }))}
        onClick={
          field
            ? (v) => navigate(`/events?src_ip=${encodeURIComponent(ip)}&${field}=${encodeURIComponent(v)}`)
            : undefined
        }
      />
    </Card>
  );
}

export function IpPage({ addr, me }: { addr: string; me: Me }) {
  useTitle(addr);
  const res = useAsync((s) => api.ip(addr, s), [addr]);
  const [blocking, setBlocking] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (res.loading && !res.data) return <Spinner label="Собираю сведения об адресе…" />;
  if (!res.data)
    return (
      <div className="page">
        <ErrorBox error={res.error ?? "нет данных"} onRetry={res.reload} />
      </div>
    );
  const c = res.data;
  const ev = c.events;

  const unblock = async () => {
    if (!c.block || !window.confirm(`Снять блокировку ${c.block.ip}?`)) return;
    setBusy(true);
    try {
      await api.unblock(c.block.ip);
      setMsg("Блокировка снята");
      res.reload();
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const days = ev.by_day.slice(-30);
  const maxDay = Math.max(1, ...days.map((d) => d.count));

  return (
    <div className="page">
      <div className="page-head ip-head">
        <h1 className="mono">{c.ip}</h1>
        {c.country && (
          <span className="ip-country" title={c.country}>
            <span className="flag">{flag(c.country)}</span> {countryName(c.country)}
            {c.city && `, ${c.city}`}
          </span>
        )}
        {c.internal && <span className="badge">внутренняя сеть</span>}
        {c.lists.map((l) => (
          <span key={l} className="tag tag-danger" title="Адрес есть в этом чёрном списке">
            {l}
          </span>
        ))}
        <span className="grow" />
        <Link to={`/events?src_ip=${encodeURIComponent(c.ip)}`} className="btn">
          <Icon name="search" size={15} /> Все события
        </Link>
        {me.can_change_alerts &&
          (c.block ? (
            <button className="btn" onClick={unblock} disabled={busy}>
              Разблокировать
            </button>
          ) : (
            !c.internal && (
              <button className="btn btn-primary" onClick={() => setBlocking(true)}>
                <Icon name="ban" size={15} /> Заблокировать
              </button>
            )
          ))}
      </div>
      {msg && <div className="note-ok">{msg}</div>}

      <div className="stat-grid">
        <div className="stat">
          <div className="stat-label">Сеть</div>
          <div className="stat-value small-value">{c.asn ? `AS${c.asn}` : "—"}</div>
          <div className="stat-sub">{c.org || (c.geo_available ? "нет в базе" : "база стран не загружена")}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Событий</div>
          <div className="stat-value">
            {num(ev.count)}
            {ev.capped && "+"}
          </div>
          <div className="stat-sub">
            {ev.failures ? <span className="warn">неудачных: {num(ev.failures)}</span> : "неудачных нет"}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Алертов</div>
          <div className={`stat-value ${c.alerts.count ? "danger" : ""}`}>{num(c.alerts.count)}</div>
          <div className="stat-sub">правил сработало: {c.alerts.by_rule.length}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Блокировка</div>
          <div className={`stat-value small-value ${c.block ? "danger" : ""}`}>
            {c.block ? (c.block.ip !== c.ip ? `сеть ${c.block.ip}` : "заблокирован") : "нет"}
          </div>
          <div className="stat-sub">
            {c.block ? (c.block.expires ? `до ${dateTime(c.block.expires)}` : "навсегда") + (c.block.reason ? ` · ${c.block.reason}` : "") : " "}
          </div>
        </div>
      </div>

      <div className="grid-2">
        <Card title="Активность по дням">
          {days.length === 0 ? (
            <Empty>От этого адреса событий не было.</Empty>
          ) : (
            <>
              <div className="day-bars" role="img" aria-label="События по дням">
                {days.map((d) => (
                  <div key={d.day} className="day-bar" title={`${d.day}: ${num(d.count)}`}>
                    <span style={{ height: `${Math.max(4, (d.count / maxDay) * 100)}%` }} />
                  </div>
                ))}
              </div>
              <div className="day-axis">
                <span>{days[0].day.slice(8, 10)}.{days[0].day.slice(5, 7)}</span>
                {days.length > 1 && (
                  <span>
                    {days[days.length - 1].day.slice(8, 10)}.{days[days.length - 1].day.slice(5, 7)}
                  </span>
                )}
              </div>
              <p className="hint">
                Впервые: {dateTime(ev.first_seen ?? undefined)} · последний раз: {ago(ev.last_seen ?? undefined)}
                {ev.capped && " (по последним событиям)"}
              </p>
            </>
          )}
        </Card>
        <Card title="Сработавшие правила">
          {c.alerts.by_rule.length === 0 ? (
            <Empty>Алертов по этому адресу нет.</Empty>
          ) : (
            <Bars
              wide
              items={c.alerts.by_rule.map((r) => ({ label: r.rule_name, value: r.count, title: r.rule_id }))}
              onClick={(name) => {
                const r = c.alerts.by_rule.find((x) => x.rule_name === name);
                if (r) navigate(`/alerts?src_ip=${encodeURIComponent(c.ip)}&rule=${encodeURIComponent(r.rule_id)}`);
              }}
            />
          )}
        </Card>
      </div>

      {ev.count > 0 && (
        <div className="grid-3">
          {ev.paths.length > 0 && <Top title="Адреса на сайте" items={ev.paths} ip={c.ip} />}
          {ev.users.length > 0 && <Top title="Пользователи" items={ev.users} field="user" ip={c.ip} />}
          {ev.hosts.length > 0 && <Top title="Серверы" items={ev.hosts} field="host" ip={c.ip} />}
          {ev.actions.length > 0 && <Top title="Действия" items={ev.actions} ip={c.ip} />}
          {ev.statuses.length > 0 && <Top title="Ответы сайта" items={ev.statuses} field="http.status" ip={c.ip} />}
          {ev.user_agents.length > 0 && <Top title="Программы (User-Agent)" items={ev.user_agents} ip={c.ip} />}
        </div>
      )}

      {c.alerts.recent.length > 0 && (
        <Card title="Последние алерты">
          <ul className="feed">
            {c.alerts.recent.map((a) => (
              <li key={a.id} onClick={() => navigate(`/alerts/${a.id}`)}>
                <SeverityBadge s={a.severity} />
                <span className="feed-text">
                  <b>{a.rule_name}</b>
                  <small>{a.message}</small>
                </span>
                <span className="muted nowrap small">{ago(a.created)}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
      {c.geo_attribution && <p className="hint">{c.geo_attribution}</p>}

      {blocking && (
        <BlockModal
          initialIp={c.ip}
          initialReason={c.lists.length ? `в чёрных списках: ${c.lists.join(", ")}` : ""}
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
