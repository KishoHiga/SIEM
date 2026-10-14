// Карточка алерта: что сработало, кто источник, связанные события, смена статуса.
import { useEffect, useState } from "react";
import { api, type AlertStatus, type Block, type Me } from "../api";
import { Icon } from "../components/Icons";
import { Card, Empty, ErrorBox, SeverityBadge, Spinner, StatusBadge, useAsync } from "../components/Ui";
import { dateTime, num, STATUSES, statusLabel } from "../format";
import { Link, useTitle } from "../router";
import { IpLink } from "../components/IpLink";
import { EventDetails } from "./Events";
import { BlockModal } from "./Response";

export function AlertDetailPage({ id, me }: { id: number; me: Me }) {
  useTitle(`Алерт #${id}`);
  const res = useAsync(() => api.alert(id), [id]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const srcIp = res.data?.alert.src_ip ?? "";
  const [block, setBlock] = useState<Block | null | undefined>(undefined); // undefined — ещё не знаем
  const [blocking, setBlocking] = useState(false);
  const [blockMsg, setBlockMsg] = useState<string | null>(null);
  const [blockNonce, setBlockNonce] = useState(0);
  useEffect(() => {
    if (!srcIp) return;
    let alive = true;
    api
      .blockFor(srcIp)
      .then((r) => alive && setBlock(r.blocked ? (r.block ?? null) : null))
      .catch(() => alive && setBlock(undefined));
    return () => {
      alive = false;
    };
  }, [srcIp, blockNonce]);

  if (res.loading && !res.data) return <Spinner />;
  if (res.error || !res.data)
    return (
      <div className="page">
        <Link to="/alerts" className="back">
          <Icon name="back" size={16} /> Алерты
        </Link>
        <ErrorBox error={res.error ?? "не найден"} onRetry={res.reload} />
      </div>
    );

  const { alert: a, events } = res.data;

  const setStatus = async (status: AlertStatus) => {
    setBusy(true);
    setErr(null);
    try {
      await api.setAlertStatus(a.id, status);
      res.setData({ alert: { ...a, status }, events });
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <Link to="/alerts" className="back">
        <Icon name="back" size={16} /> Алерты
      </Link>
      <div className="alert-head">
        <SeverityBadge s={a.severity} />
        <div>
          <h1>{a.rule_name}</h1>
          <p className="alert-msg">{a.message}</p>
        </div>
        <StatusBadge s={a.status} />
      </div>
      {a.incident_id && (
        <Link to={`/incidents/${a.incident_id}`} className="btn btn-sm incident-link">
          <Icon name="layers" size={14} /> Часть инцидента #{a.incident_id} — открыть
        </Link>
      )}

      {me.can_change_alerts && (
        <div className="status-actions">
          <span className="muted">Сменить статус:</span>
          {STATUSES.filter((s) => s !== a.status).map((s) => (
            <button key={s} className={`btn btn-sm st-btn-${s}`} disabled={busy} onClick={() => setStatus(s)}>
              {statusLabel[s]}
            </button>
          ))}
          {err && <span className="form-error">{err}</span>}
        </div>
      )}

      <div className="grid-2">
        <Card title="Подробности">
          <dl className="kv">
            <dt>Правило</dt>
            <dd>
              <Link to={`/alerts?rule=${encodeURIComponent(a.rule_id)}`} className="mono">
                {a.rule_id}
              </Link>
            </dd>
            <dt>Время события</dt>
            <dd className="mono">{dateTime(a.ts)}</dd>
            <dt>Алерт создан</dt>
            <dd className="mono">{dateTime(a.created)}</dd>
            {a.src_ip && (
              <>
                <dt>IP источника</dt>
                <dd>
                  <IpLink ip={a.src_ip} country={a.fields["geo.country"]} listed={!!a.fields["ti.lists"]} />{" "}
                  <Link to={`/events?src_ip=${encodeURIComponent(a.src_ip)}`}>все события</Link>
                  {" · "}
                  <Link to={`/alerts?src_ip=${encodeURIComponent(a.src_ip)}`}>все алерты</Link>
                  <div className="block-state">
                    {block ? (
                      <>
                        <span className="tag tag-danger">
                          заблокирован{block.ip !== a.src_ip ? ` (сеть ${block.ip})` : ""}
                          {block.expires ? ` до ${dateTime(block.expires)}` : " навсегда"}
                        </span>
                        <Link to="/response">реагирование</Link>
                      </>
                    ) : (
                      block === null &&
                      me.can_change_alerts && (
                        <button className="btn btn-sm" onClick={() => setBlocking(true)}>
                          <Icon name="ban" size={14} /> Заблокировать IP
                        </button>
                      )
                    )}
                    {blockMsg && <span className="ok small">{blockMsg}</span>}
                  </div>
                </dd>
              </>
            )}
            {a.user && (
              <>
                <dt>Пользователь</dt>
                <dd>
                  <span className="mono">{a.user}</span>{" "}
                  <Link to={`/events?user=${encodeURIComponent(a.user)}`}>события</Link>
                </dd>
              </>
            )}
            {a.host && (
              <>
                <dt>Хост</dt>
                <dd className="mono">{a.host}</dd>
              </>
            )}
            <dt>Событий</dt>
            <dd>{num(a.count)}</dd>
          </dl>
        </Card>
        <Card title="Поля">
          {Object.keys(a.fields).length === 0 ? (
            <Empty>Нет дополнительных полей</Empty>
          ) : (
            <dl className="kv">
              {Object.entries(a.fields).map(([k, v]) => (
                <div key={k} className="kv-row">
                  <dt>{k}</dt>
                  <dd className="mono">{v}</dd>
                </div>
              ))}
            </dl>
          )}
        </Card>
      </div>

      {blocking && (
        <BlockModal
          initialIp={a.src_ip}
          initialReason={`${a.rule_name} (алерт #${a.id})`}
          onClose={() => setBlocking(false)}
          onDone={(msg) => {
            setBlocking(false);
            setBlockMsg(msg);
            setBlockNonce((n) => n + 1);
          }}
        />
      )}

      <Card title={`Связанные события (${events.length}${a.event_ids.length > events.length ? ` из ${a.event_ids.length}` : ""})`}>
        {events.length === 0 ? (
          <Empty>События уже удалены по сроку хранения.</Empty>
        ) : (
          <ul className="related">
            {events.map((e) => (
              <li key={e.id} className={open === e.id ? "open" : ""}>
                <button className="related-row" onClick={() => setOpen(open === e.id ? null : e.id)}>
                  <Icon name="chevron" size={14} className="chev" />
                  <span className="mono nowrap">{dateTime(e.ts)}</span>
                  <span className="tag">{e.source ?? "?"}</span>
                  <span className="msg">{e.message ?? e.raw}</span>
                </button>
                {open === e.id && <EventDetails e={e} />}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
