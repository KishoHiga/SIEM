// Реагирование: заблокированные адреса (ручные и автоматические) и каналы уведомлений.
import { useMemo, useState, type FormEvent } from "react";
import { api, type Block, type Me, type NotifyStatus } from "../api";
import { Icon } from "../components/Icons";
import { IpLink } from "../components/IpLink";
import { Card, Empty, ErrorBox, Modal, Spinner, useAsync, useInterval } from "../components/Ui";
import { ago, dateTime, duration, num, severityLabel } from "../format";
import { Link, useTitle } from "../router";

const DURATIONS: { v: string; label: string }[] = [
  { v: "1h", label: "1 час" },
  { v: "24h", label: "сутки" },
  { v: "7d", label: "неделя" },
  { v: "30d", label: "30 дней" },
  { v: "0", label: "навсегда" },
];

const RESULT_TEXT: Record<string, string> = {
  added: "Адрес заблокирован",
  extended: "Блокировка продлена",
  unchanged: "Адрес уже заблокирован",
};

const CHANNEL_LABEL: Record<string, string> = { telegram: "Telegram", webhook: "Webhook", email: "Почта" };

export function ResponsePage({ me }: { me: Me }) {
  useTitle("Реагирование");
  const blocks = useAsync((s) => api.blocks(s), []);
  const notify = useAsync((s) => api.notify(s), []);
  useInterval(blocks.reload, 10000);
  useInterval(notify.reload, 30000);
  const [adding, setAdding] = useState(false);
  const [filter, setFilter] = useState("");
  const [busyIp, setBusyIp] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const list = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const all = blocks.data?.blocks ?? [];
    if (!f) return all;
    return all.filter((b) => b.ip.includes(f) || b.reason.toLowerCase().includes(f) || b.rule_id.toLowerCase().includes(f));
  }, [blocks.data, filter]);

  const unblock = async (b: Block) => {
    if (!window.confirm(`Снять блокировку ${b.ip}?`)) return;
    setBusyIp(b.ip);
    setErr(null);
    try {
      await api.unblock(b.ip);
      blocks.reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusyIp(null);
    }
  };

  const pol = blocks.data?.policy;
  const st = blocks.data?.stats;

  return (
    <div className="page">
      <div className="page-head">
        <h1>Реагирование</h1>
        {st && <span className="muted">заблокировано адресов: {num(st.active)}</span>}
        <span className="grow" />
        {me.can_change_alerts && (
          <button className="btn btn-primary" onClick={() => setAdding(true)}>
            <Icon name="ban" size={16} /> Заблокировать адрес
          </button>
        )}
      </div>

      {blocks.error && <ErrorBox error={blocks.error} onRetry={blocks.reload} />}

      {pol && st && (
        <div className="grid-2">
          <Card title="Автоблокировка">
            <dl className="kv">
              <dt>Состояние</dt>
              <dd>{pol.auto_block ? <span className="ok">включена</span> : <span className="muted">выключена</span>}</dd>
              {pol.auto_block && (
                <>
                  <dt>Когда</dt>
                  <dd>
                    алерт уровня «{severityLabel[pol.min_severity]}» и выше
                    {pol.rules.length > 0 && <> или правила {pol.rules.join(", ")}</>}
                  </dd>
                  <dt>На сколько</dt>
                  <dd>{pol.duration_seconds ? duration(pol.duration_seconds) : "навсегда"}</dd>
                  <dt>Не блокировать</dt>
                  <dd className="mono">
                    {pol.allowlist.length ? pol.allowlist.join(", ") : "—"}
                    {!pol.block_private && <span className="muted"> + внутренние сети</span>}
                  </dd>
                  <dt>Предел</dt>
                  <dd>{pol.max_per_minute} новых адресов в минуту</dd>
                </>
              )}
            </dl>
            <p className="hint">Настраивается в разделе <code>response:</code> файла sentinel.yaml.</p>
          </Card>
          <Card title="Счётчики">
            <dl className="kv">
              <dt>Автоматически</dt>
              <dd>{num(st.auto_added)}</dd>
              <dt>Вручную</dt>
              <dd>{num(st.manual_added)}</dd>
              <dt>Истекло</dt>
              <dd>{num(st.expired)}</dd>
              <dt>Пропущено</dt>
              <dd>
                белый список {num(st.skipped_allowlist)}, внутренние сети {num(st.skipped_private)}, предел{" "}
                {num(st.skipped_limit)}
              </dd>
            </dl>
            <p className="hint">
              Список применяют агенты, у которых в <code>agent.yaml</code> включён <code>firewall:</code> — состояние видно в
              разделе <Link to="/agents">Серверы</Link>.
            </p>
          </Card>
        </div>
      )}

      <div className="section-head">
        <h2>Заблокированные адреса</h2>
        <span className="grow" />
        <input
          className="filter-input"
          placeholder="Поиск по адресу, причине, правилу"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>
      {err && <div className="form-error">{err}</div>}
      {blocks.loading && !blocks.data ? (
        <Spinner />
      ) : list.length === 0 ? (
        <Card>
          <Empty>
            {filter ? "Ничего не найдено." : "Сейчас ни один адрес не заблокирован. Критичные атаки будут блокироваться автоматически."}
          </Empty>
        </Card>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Адрес</th>
                <th>Причина</th>
                <th>Кто</th>
                <th>Когда</th>
                <th>До</th>
                <th>Повторы</th>
                {me.can_change_alerts && <th />}
              </tr>
            </thead>
            <tbody>
              {list.map((b) => (
                <tr key={b.ip}>
                  <td className="mono nowrap">
                    <IpLink ip={b.ip} />
                  </td>
                  <td className="msg reason">
                    {b.reason || "—"}
                    {b.alert_id > 0 && (
                      <small>
                        <Link to={`/alerts/${b.alert_id}`}>алерт #{b.alert_id}</Link>
                        {b.rule_id && <> · {b.rule_id}</>}
                      </small>
                    )}
                  </td>
                  <td>{b.by === "auto" ? <span className="tag">авто</span> : <span className="mono">{b.by}</span>}</td>
                  <td className="nowrap" title={dateTime(b.created)}>
                    {ago(b.created)}
                  </td>
                  <td className="nowrap mono">{b.expires ? dateTime(b.expires) : <span className="muted">навсегда</span>}</td>
                  <td>{num(b.hits)}</td>
                  {me.can_change_alerts && (
                    <td className="row-actions">
                      <button className="btn btn-sm" disabled={busyIp === b.ip} onClick={() => unblock(b)}>
                        Разблокировать
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ThreatCard />

      <NotifyCard me={me} data={notify.data} error={notify.error} loading={notify.loading} reload={notify.reload} />

      {adding && (
        <BlockModal
          onClose={() => setAdding(false)}
          onDone={() => {
            setAdding(false);
            blocks.reload();
          }}
        />
      )}
    </div>
  );
}

function NotifyCard({
  me,
  data,
  error,
  loading,
  reload,
}: {
  me: Me;
  data: NotifyStatus | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}) {
  const [testing, setTesting] = useState(false);
  const [results, setResults] = useState<{ name: string; ok: boolean; error: string }[] | null>(null);
  const [testErr, setTestErr] = useState<string | null>(null);

  const test = async () => {
    setTesting(true);
    setTestErr(null);
    setResults(null);
    try {
      setResults((await api.notifyTest()).results);
      reload();
    } catch (e) {
      setTestErr((e as Error).message);
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card
      title="Уведомления"
      actions={
        me.is_admin && data?.enabled ? (
          <button className="btn btn-sm" disabled={testing} onClick={test}>
            <Icon name="send" size={14} /> {testing ? "Отправка…" : "Тест"}
          </button>
        ) : undefined
      }
    >
      {error && <ErrorBox error={error} onRetry={reload} />}
      {loading && !data ? (
        <Spinner />
      ) : !data?.enabled ? (
        <Empty>
          Каналы не настроены. Добавьте в sentinel.yaml раздел <code>notify:</code> с Telegram, почтой или webhook (Slack,
          Discord) — пример в README.
        </Empty>
      ) : (
        <>
          <p className="muted">
            {data.mode === "incidents" ? (
              <>
                Режим инцидентов: сообщение приходит, когда появился новый инцидент уровня «
                {severityLabel[data.min_severity ?? "high"]}» и выше или когда инцидент стал серьёзнее.
              </>
            ) : (
              <>
                Присылаются алерты уровня «{severityLabel[data.min_severity ?? "high"]}» и выше. Повторы одной атаки
                объединяются.
              </>
            )}{" "}
            Если сообщений много сразу — приходит одна сводка. Отправлено сводок: {num(data.digests ?? 0)},
            подавлено повторов: {num(data.suppressed ?? 0)}
            {data.dropped ? <span className="danger">, потеряно: {num(data.dropped)}</span> : null}.
          </p>
          <div className="table-wrap flat">
            <table className="table">
              <thead>
                <tr>
                  <th>Канал</th>
                  <th>Куда</th>
                  <th>Отправлено</th>
                  <th>Ошибок</th>
                  <th>Последняя доставка</th>
                  <th>Последняя ошибка</th>
                </tr>
              </thead>
              <tbody>
                {data.channels.map((c) => {
                  const r = results?.find((x) => x.name === c.name);
                  return (
                    <tr key={c.name}>
                      <td>
                        <b>{CHANNEL_LABEL[c.name] ?? c.name}</b>
                        {r && (r.ok ? <small className="ok">тест доставлен</small> : <small className="danger">тест: {r.error}</small>)}
                      </td>
                      <td className="mono">{c.target}</td>
                      <td>{num(c.sent)}</td>
                      <td className={c.failed ? "danger" : ""}>{num(c.failed)}</td>
                      <td className="nowrap">{c.last_ok ? ago(c.last_ok) : "—"}</td>
                      <td className="msg">
                        {c.last_error ? (
                          <>
                            <span className="danger">{c.last_error}</span>
                            {c.last_error_at && <small>{dateTime(c.last_error_at)}</small>}
                          </>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
      {testErr && <div className="form-error">{testErr}</div>}
    </Card>
  );
}

export function BlockModal({
  initialIp = "",
  initialReason = "",
  onClose,
  onDone,
}: {
  initialIp?: string;
  initialReason?: string;
  onClose: () => void;
  onDone: (msg: string) => void;
}) {
  const [ip, setIp] = useState(initialIp);
  const [dur, setDur] = useState("24h");
  const [reason, setReason] = useState(initialReason);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api.block(ip.trim(), dur, reason.trim());
      onDone(RESULT_TEXT[r.result] ?? r.result);
    } catch (err) {
      setError(blockErrorText((err as Error).message));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="Заблокировать адрес" onClose={onClose}>
      <form className="form" onSubmit={submit}>
        <label>
          IP-адрес или подсеть
          <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="203.0.113.7 или 203.0.113.0/24" required autoFocus={!initialIp} />
        </label>
        <div className="form-field">
          <span>На сколько</span>
          <div className="seg">
            {DURATIONS.map((d) => (
              <button type="button" key={d.v} className={dur === d.v ? "active" : ""} onClick={() => setDur(d.v)}>
                {d.label}
              </button>
            ))}
          </div>
        </div>
        <label>
          Причина
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="например: перебор паролей" maxLength={300} />
        </label>
        <p className="hint">
          Адрес попадёт в брандмауэр всех серверов с включённым <code>firewall:</code> в течение ~15 секунд.
        </p>
        {error && <div className="form-error">{error}</div>}
        <div className="form-actions">
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button className="btn btn-primary" disabled={busy || !ip.trim()}>
            {busy ? "Блокировка…" : "Заблокировать"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// Ответы сервера — по-английски; показываем понятный текст.
export function blockErrorText(msg: string): string {
  const m = msg.toLowerCase();
  if (m.includes("allowlist")) return "Адрес в белом списке (response.allowlist) — его блокировать нельзя.";
  if (m.includes("private")) return "Это внутренний адрес. Блокировка внутренних сетей выключена (response.block_private).";
  if (m.includes("invalid") || m.includes("bad"))
    return "Неверный адрес или диапазон, который нельзя блокировать (localhost, служебные и слишком широкие сети). Пример: 203.0.113.7 или 203.0.113.0/24.";
  if (m.includes("full")) return "Список блокировок переполнен.";
  return msg;
}

// Чёрные списки адресов и база стран: что загружено, когда обновлено, ошибки скачивания.
function ThreatCard() {
  const res = useAsync((s) => api.threat(s), []);
  useInterval(res.reload, 60000);
  const t = res.data;
  return (
    <Card title="Чёрные списки и база стран">
      {res.error && <ErrorBox error={res.error} onRetry={res.reload} />}
      {!t ? (
        <Spinner />
      ) : (
        <>
          <p className="muted">
            {t.geo.available ? (
              <>
                База стран загружена: {num(t.geo.country_ranges)} диапазонов стран и {num(t.geo.asn_ranges)} сетей
                {t.geo.built && <> (собрана {dateTime(t.geo.built)})</>}.
              </>
            ) : (
              <>
                База стран не загружена — у адресов не будет страны и сети. Скачайте бесплатную базу DB-IP Lite и выполните{" "}
                <code>sentinel-server geo-import dbip-country-lite.csv dbip-asn-lite.csv</code>.
              </>
            )}
          </p>
          {t.lists.length === 0 ? (
            <Empty>
              Чёрные списки не подключены. Добавьте раздел <code>threat_intel:</code> в sentinel.yaml (FireHOL, Spamhaus DROP,
              выходные узлы Tor — пример в README).
            </Empty>
          ) : (
            <div className="table-wrap flat">
              <table className="table">
                <thead>
                  <tr>
                    <th>Список</th>
                    <th>Адресов и сетей</th>
                    <th>Обновлён</th>
                    <th>Состояние</th>
                  </tr>
                </thead>
                <tbody>
                  {t.lists.map((l) => (
                    <tr key={l.name}>
                      <td>
                        <b>{l.name}</b>
                        <small className="mono">{l.source}</small>
                      </td>
                      <td>{num(l.entries)}</td>
                      <td className="nowrap">
                        {l.updated ? ago(l.updated) : l.cached ? "копия с диска" : "—"}
                      </td>
                      <td className="msg">
                        {l.last_error ? <span className="danger">{l.last_error}</span> : <span className="ok">в порядке</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </Card>
  );
}
