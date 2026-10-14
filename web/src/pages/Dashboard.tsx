// Обзор: главные цифры, график событий, алерты по важности, топ IP и живая лента.
import { useState } from "react";
import { api, type Severity } from "../api";
import { Bars, Donut, Sparkline, Timeline } from "../components/Charts";
import { Icon } from "../components/Icons";
import { Card, Empty, ErrorBox, SeverityBadge, Spinner, useAsync, useInterval } from "../components/Ui";
import { ago, bytes, compact, dateTime, duration, num, SEVERITIES, severityLabel, timeOnly } from "../format";
import { useLive, useOnNewAlerts } from "../live";
import { countryName, flag } from "../countries";
import { Link, navigate, useTitle } from "../router";

const SEV_COLORS: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

const RANGES = [
  { m: 60, label: "1 ч" },
  { m: 360, label: "6 ч" },
  { m: 1440, label: "24 ч" },
];

export function DashboardPage() {
  useTitle("Обзор");
  const [minutes, setMinutes] = useState(60);
  const stats = useAsync((s) => api.stats(minutes, s), [minutes]);
  useInterval(stats.reload, 10000);
  const live = useLive();
  const s = stats.data;
  const perSec = live.rate[live.rate.length - 1] ?? 0;

  if (!s && stats.loading) return <Spinner />;
  if (!s) return <ErrorBox error={stats.error ?? "нет данных"} onRetry={stats.reload} />;

  const critical = s.alerts_by_severity_24h.critical + s.alerts_by_severity_24h.high;

  return (
    <div className="page">
      <div className="page-head">
        <h1>Обзор</h1>
        <span className="muted">работает {duration(s.uptime_sec)}</span>
      </div>
      {stats.error && <ErrorBox error={stats.error} onRetry={stats.reload} />}

      <div className="stat-grid">
        <div className="stat">
          <div className="stat-label">
            <Icon name="activity" size={16} /> Событий в секунду
          </div>
          <div className="stat-value">{num(live.state === "online" ? perSec : s.events_per_sec)}</div>
          <Sparkline values={live.rate} />
        </div>
        <div className="stat">
          <div className="stat-label">
            <Icon name="search" size={16} /> Событий за 24 ч
          </div>
          <div className="stat-value">{compact(s.events_24h)}</div>
          <div className="stat-sub">всего: {compact(s.events_since_start)}</div>
        </div>
        <Link className="stat stat-link" to="/alerts?status=new">
          <div className="stat-label">
            <Icon name="alert" size={16} /> Открытых алертов (24 ч)
          </div>
          <div className={`stat-value ${s.alerts_open_24h ? "warn" : ""}`}>{num(s.alerts_open_24h)}</div>
          <div className="stat-sub">всего за 24 ч: {num(s.alerts_24h)}</div>
        </Link>
        {s.incidents ? (
          <Link className="stat stat-link" to="/incidents">
            <div className="stat-label">
              <Icon name="layers" size={16} /> Активных инцидентов
            </div>
            <div
              className={`stat-value ${
                s.incidents.by_severity.critical + s.incidents.by_severity.high
                  ? "danger"
                  : s.incidents.active
                    ? "warn"
                    : "ok"
              }`}
            >
              {num(s.incidents.active)}
            </div>
            <div className="stat-sub">
              {s.incidents.active
                ? s.incidents.unassigned
                  ? `без ответственного: ${num(s.incidents.unassigned)}`
                  : "все разбираются"
                : "всё спокойно"}
              {critical > 0 && ` · критич. и высоких алертов: ${num(critical)}`}
            </div>
          </Link>
        ) : (
          <Link className="stat stat-link" to="/alerts?severity=high">
            <div className="stat-label">
              <Icon name="shield" size={16} /> Критических и высоких
            </div>
            <div className={`stat-value ${critical ? "danger" : "ok"}`}>{num(critical)}</div>
            <div className="stat-sub">{critical ? "требуют внимания" : "всё спокойно"}</div>
          </Link>
        )}
      </div>

      <div className="grid-main">
        <Card
          title="События и алерты"
          actions={
            <div className="seg">
              {RANGES.map((r) => (
                <button key={r.m} className={minutes === r.m ? "active" : ""} onClick={() => setMinutes(r.m)}>
                  {r.label}
                </button>
              ))}
            </div>
          }
        >
          <Timeline points={s.timeline} />
          <div className="legend">
            <span className="lg-events">события в минуту</span>
            <span className="lg-alerts">алерты</span>
          </div>
        </Card>

        <Card title="Алерты по важности (24 ч)">
          <div className="donut-wrap">
            <Donut
              parts={SEVERITIES.map((sv) => ({ label: severityLabel[sv], value: s.alerts_by_severity_24h[sv], color: SEV_COLORS[sv] }))}
            />
            <ul className="donut-legend">
              {SEVERITIES.map((sv) => (
                <li key={sv}>
                  <Link to={`/alerts?severity=${sv}`}>
                    <i style={{ background: SEV_COLORS[sv] }} />
                    {severityLabel[sv]}
                    <b>{num(s.alerts_by_severity_24h[sv])}</b>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </Card>
      </div>

      <div className="grid-3">
        <Card title="Самые активные IP">
          <Bars
            items={s.top_ips.map((i) => ({
              label: i.ip,
              value: i.count,
              tag: i.listed ? `${i.country ?? ""} ЧС`.trim() : i.country,
              title: i.country ? `${i.ip} — ${countryName(i.country)}${i.listed ? ", в чёрном списке" : ""}` : i.ip,
            }))}
            onClick={(ip) => navigate(`/ip/${encodeURIComponent(ip)}`)}
          />
        </Card>
        {s.top_countries && s.top_countries.length > 0 && (
          <Card title="Страны">
            <Bars
              items={s.top_countries.map((c) => ({ label: `${flag(c.country)} ${countryName(c.country)}`, value: c.count, title: c.country }))}
              onClick={(label) => {
                const c = s.top_countries!.find((x) => `${flag(x.country)} ${countryName(x.country)}` === label);
                if (c) navigate(`/events?geo.country=${encodeURIComponent(c.country)}`);
              }}
            />
          </Card>
        )}
        <Card title="Источники">
          <Bars
            items={s.top_sources.map((i) => ({ label: i.source, value: i.count }))}
            onClick={(src) => navigate(`/events?source=${encodeURIComponent(src)}`)}
          />
        </Card>
        <Card title="Хранилище">
          <dl className="kv">
            <dt>Событий на диске</dt>
            <dd>{num(s.storage.events)}</dd>
            <dt>Размер</dt>
            <dd>{bytes(s.storage.bytes_on_disk)}</dd>
            <dt>Сжатие</dt>
            <dd>{s.storage.compression_ratio ? `в ${s.storage.compression_ratio.toFixed(1)} раза` : "—"}</dd>
            <dt>В очереди</dt>
            <dd>{num(s.pipeline.queued)}</dd>
            <dt>Отклонено</dt>
            <dd className={s.pipeline.rejected ? "warn" : ""}>{num(s.pipeline.rejected)}</dd>
            {s.pipeline.detect_threads !== undefined && (
              <>
                <dt>Обнаружение</dt>
                <dd title="События делятся между потоками по IP источника; правила, считающие по другим полям, проверяет отдельный поток">
                  {s.pipeline.detect_threads === 1
                    ? "1 поток"
                    : `${s.pipeline.detect_threads} потока по IP${s.pipeline.global_thread ? " + 1 общий" : ""}`}
                </dd>
              </>
            )}
            {s.storage.corrupt_blocks > 0 && (
              <>
                <dt>Повреждённых блоков</dt>
                <dd className="danger">{num(s.storage.corrupt_blocks)}</dd>
              </>
            )}
          </dl>
        </Card>
      </div>

      <div className="grid-2">
        <LiveAlerts />
        <LiveEvents />
      </div>
    </div>
  );
}

function LiveAlerts() {
  // последние алерты из хранилища; при новом алерте в живой ленте — перечитываем
  const res = useAsync((s) => api.alerts({ limit: 12 }, s), []);
  useOnNewAlerts(res.reload);
  const alerts = res.data?.items ?? [];
  return (
    <Card title="Последние алерты" actions={<Link to="/alerts">Все алерты</Link>}>
      {alerts.length === 0 ? (
        <Empty>Пока тихо. Новые алерты появятся здесь сразу.</Empty>
      ) : (
        <ul className="feed">
          {alerts.slice(0, 12).map((a) => (
            <li key={a.id} className="feed-alert" onClick={() => navigate(`/alerts/${a.id}`)}>
              <SeverityBadge s={a.severity} />
              <span className="feed-text">
                <b>{a.rule_name}</b>
                <small>{a.message}</small>
              </span>
              <time title={dateTime(a.created)}>{ago(a.created)}</time>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function LiveEvents() {
  const { recent, state } = useLive();
  const [paused, setPaused] = useState<typeof recent | null>(null);
  const list = paused ?? recent;
  return (
    <Card
      title={
        <>
          Живая лента <span className={`live-badge ${state}`}>
            {state === "online" ? "LIVE" : state === "connecting" ? "подключение…" : "нет связи"}
          </span>
        </>
      }
      actions={
        <button className="btn btn-sm" onClick={() => setPaused(paused ? null : recent)}>
          <Icon name={paused ? "play" : "pause"} size={14} />
          {paused ? "Продолжить" : "Пауза"}
        </button>
      }
    >
      {list.length === 0 ? (
        <Empty>
          {state === "offline"
            ? "Нет связи с сервером ленты. Обновите страницу; если не поможет — перезапустите сервер в меню приложения."
            : (
              <>
                Пока событий нет. Как только на сайт кто-то зайдёт, строки появятся здесь. Сайт ещё не подключён?{" "}
                <Link to="/connect">Подключить сайт</Link>
              </>
            )}
        </Empty>
      ) : (
        <ul className="feed feed-events">
          {list.slice(0, 40).map((e) => (
            <li key={e.id} onClick={() => navigate(`/events?id=${e.id}`)}>
              <time>{timeOnly(e.ts)}</time>
              <span className="tag">{e.source ?? "?"}</span>
              {e.src_ip && <span className="ip">{e.src_ip}{e.extra?.["geo.country"] ? ` ${e.extra["geo.country"]}` : ""}</span>}
              <span className={`feed-msg ${e.outcome === "failure" ? "fail" : ""}`}>{e.message}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
