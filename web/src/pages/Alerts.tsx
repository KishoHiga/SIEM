// Список алертов с фильтрами. Новые алерты подтягиваются сами (через живую ленту).
import { IpLink } from "../components/IpLink";
import { useEffect, useRef, useState } from "react";
import { api, type Alert, type Me } from "../api";
import { Icon } from "../components/Icons";
import { Card, Empty, ErrorBox, SeverityBadge, Spinner, StatusBadge, useAsync } from "../components/Ui";
import { ago, dateTime, num, SEVERITIES, severityLabel, STATUSES, statusLabel } from "../format";
import { useOnNewAlerts } from "../live";
import { navigate, useLocation, useTitle } from "../router";
import { ExportMenu } from "../components/ExportMenu";

const PAGE = 50;

function withParam(query: URLSearchParams, key: string, value: string): string {
  const q = new URLSearchParams(query);
  if (value) q.set(key, value);
  else q.delete(key);
  const s = q.toString();
  return `/alerts${s ? `?${s}` : ""}`;
}

export function AlertsPage({ me }: { me: Me }) {
  useTitle("Алерты");
  const { query } = useLocation();
  const filter = {
    status: query.get("status") ?? "",
    severity: query.get("severity") ?? "",
    rule: query.get("rule") ?? "",
    src_ip: query.get("src_ip") ?? "",
  };
  const key = JSON.stringify(filter);
  const [rows, setRows] = useState<Alert[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [moreBusy, setMoreBusy] = useState(false);
  const [ipDraft, setIpDraft] = useState(filter.src_ip);
  useEffect(() => setIpDraft(filter.src_ip), [filter.src_ip]);

  const first = useAsync((signal) => api.alerts({ ...filter, limit: PAGE }, signal), [key]);
  // extended — пользователь нажимал "Показать ещё": тогда при автообновлении
  // не теряем подгруженный хвост, а только обновляем верх списка
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
      const p = await api.alerts({ ...filter, limit: PAGE, before_id: next });
      extended.current = true;
      setRows((r) => r.concat(p.items));
      setNext(p.next_before_id);
    } finally {
      setMoreBusy(false);
    }
  };

  const quickStatus = async (a: Alert, status: Alert["status"]) => {
    try {
      await api.setAlertStatus(a.id, status);
      setRows((r) => r.map((x) => (x.id === a.id ? { ...x, status } : x)));
    } catch (e) {
      window.alert((e as Error).message);
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <h1>Алерты</h1>
        <span className="grow" />
        <ExportMenu kind="alerts" params={() => ({ ...filter })} />
        <button className="btn btn-sm" onClick={first.reload}>
          <Icon name="refresh" size={14} /> Обновить
        </button>
      </div>

      <Card>
        <div className="filters">
          <div className="seg">
            <button className={!filter.status ? "active" : ""} onClick={() => navigate(withParam(query, "status", ""))}>
              Все
            </button>
            {STATUSES.map((s) => (
              <button
                key={s}
                className={filter.status === s ? "active" : ""}
                onClick={() => navigate(withParam(query, "status", s))}
              >
                {statusLabel[s]}
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
            className="inline"
            onSubmit={(e) => {
              e.preventDefault();
              navigate(withParam(query, "src_ip", ipDraft.trim()));
            }}
          >
            IP
            <input value={ipDraft} onChange={(e) => setIpDraft(e.target.value)} placeholder="203.0.113.9" size={16} />
          </form>
          {filter.rule && (
            <span className="chip">
              Правило: <b>{filter.rule}</b>
              <button onClick={() => navigate(withParam(query, "rule", ""))} aria-label="Убрать фильтр">
                <Icon name="x" size={12} />
              </button>
            </span>
          )}
        </div>
      </Card>

      {first.error && <ErrorBox error={first.error} onRetry={first.reload} />}
      {first.loading && rows.length === 0 ? (
        <Spinner />
      ) : rows.length === 0 ? (
        <Empty>Алертов нет — по выбранным фильтрам ничего не сработало.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Важность</th>
                <th>Правило</th>
                <th>Источник угрозы</th>
                <th>Событий</th>
                <th>Когда</th>
                <th>Статус</th>
                {me.can_change_alerts && <th />}
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} className="clickable" onClick={() => navigate(`/alerts/${a.id}`)}>
                  <td>
                    <SeverityBadge s={a.severity} />
                  </td>
                  <td className="msg">
                    <b>{a.rule_name}</b>
                    <small>{a.message}</small>
                  </td>
                  <td>
                    <IpLink
                      ip={a.src_ip}
                      country={a.fields?.["geo.country"]}
                      listed={!!a.fields?.["ti.lists"]}
                    />
                    {a.user && <small>{a.user}</small>}
                  </td>
                  <td>{num(a.count)}</td>
                  <td className="nowrap" title={dateTime(a.created)}>
                    {ago(a.created)}
                  </td>
                  <td>
                    <StatusBadge s={a.status} />
                  </td>
                  {me.can_change_alerts && (
                    <td className="row-actions" onClick={(e) => e.stopPropagation()}>
                      {a.status === "new" && (
                        <button className="btn btn-sm" onClick={() => quickStatus(a, "acknowledged")}>
                          В работу
                        </button>
                      )}
                      {(a.status === "new" || a.status === "acknowledged") && (
                        <button className="btn btn-sm" onClick={() => quickStatus(a, "resolved")}>
                          Решён
                        </button>
                      )}
                    </td>
                  )}
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
