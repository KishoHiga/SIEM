// Поиск событий: текст + фильтры по полям + период. Всё состояние — в адресной строке,
// поэтому ссылкой на поиск можно поделиться. Подгрузка "ещё" — по before_id.
import { useEffect, useState, type FormEvent } from "react";
import { api, type SiemEvent } from "../api";
import { Icon } from "../components/Icons";
import { IpLink } from "../components/IpLink";
import { countryName } from "../countries";
import { Card, Empty, ErrorBox, Spinner, useAsync } from "../components/Ui";
import { dateTime, EXTRA_LABELS, FIELD_LABELS, num } from "../format";
import { navigate, useLocation, useTitle } from "../router";
import { ExportMenu } from "../components/ExportMenu";

const PAGE = 100;
const FILTER_FIELDS = FIELD_LABELS.map(([k]) => k);
const RANGES: { v: string; label: string; ms: number }[] = [
  { v: "15m", label: "15 минут", ms: 15 * 60e3 },
  { v: "1h", label: "1 час", ms: 3600e3 },
  { v: "24h", label: "24 часа", ms: 86400e3 },
  { v: "7d", label: "7 дней", ms: 7 * 86400e3 },
  { v: "", label: "Всё время", ms: 0 },
];

function withParam(query: URLSearchParams, key: string, value: string | null): string {
  const q = new URLSearchParams(query);
  if (value === null || value === "") q.delete(key);
  else q.set(key, value);
  if (key !== "id") q.delete("id"); // новый поиск закрывает карточку события
  const s = q.toString();
  return `/events${s ? `?${s}` : ""}`;
}

export function EventsPage() {
  useTitle("События");
  const { query } = useLocation();
  const text = query.get("q") ?? "";
  const range = query.get("range") ?? "24h";
  const openId = Number(query.get("id") ?? 0) || null;
  const fields: Record<string, string> = {};
  for (const f of FILTER_FIELDS) {
    const v = query.get(f);
    if (v) fields[f] = v;
  }
  const fieldsKey = JSON.stringify(fields);

  const [draft, setDraft] = useState(text);
  useEffect(() => setDraft(text), [text]);
  const [addField, setAddField] = useState("src_ip");
  const [addValue, setAddValue] = useState("");

  // "from" считаем от момента запроса, поэтому храним его вместе с результатом
  const [rows, setRows] = useState<SiemEvent[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [moreBusy, setMoreBusy] = useState(false);
  const [moreErr, setMoreErr] = useState<string | null>(null);
  const [from, setFrom] = useState<string | undefined>(undefined);

  const first = useAsync(
    async (signal) => {
      const r = RANGES.find((x) => x.v === range);
      const f = r && r.ms ? new Date(Date.now() - r.ms).toISOString() : undefined;
      const page = await api.events({ q: text, from: f, limit: PAGE, fields }, signal);
      return { page, from: f };
    },
    [text, range, fieldsKey],
  );
  useEffect(() => {
    if (!first.data) return;
    setRows(first.data.page.items);
    setNext(first.data.page.next_before_id);
    setFrom(first.data.from);
    setMoreErr(null);
  }, [first.data]);

  const loadMore = async () => {
    if (next === null) return;
    setMoreBusy(true);
    try {
      const p = await api.events({ q: text, from, limit: PAGE, before_id: next, fields });
      setRows((r) => r.concat(p.items));
      setNext(p.next_before_id);
      setMoreErr(null);
    } catch (e) {
      setMoreErr((e as Error).message);
    } finally {
      setMoreBusy(false);
    }
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    navigate(withParam(query, "q", draft.trim()));
  };

  const addFilter = (e: FormEvent) => {
    e.preventDefault();
    if (!addValue.trim()) return;
    navigate(withParam(query, addField, addValue.trim()));
    setAddValue("");
  };

  const label = (k: string) => FIELD_LABELS.find(([f]) => f === k)?.[1] ?? k;

  return (
    <div className="page">
      <div className="page-head">
        <h1>События</h1>
        {first.data && (
          <span className="muted">
            показано {num(rows.length)}
            {next !== null ? "+" : ""}
          </span>
        )}
        <span className="grow" />
        <ExportMenu
          kind="events"
          params={() => {
            const r = RANGES.find((x) => x.v === range);
            return {
              q: text || undefined,
              from: r && r.ms ? new Date(Date.now() - r.ms).toISOString() : undefined,
              ...fields,
            };
          }}
          note="С текущим поиском и периодом, до 100 000 событий (свежие первыми)."
        />
      </div>

      <Card>
        <form className="search-row" onSubmit={submit}>
          <div className="search-input">
            <Icon name="search" size={16} />
            <input
              placeholder="Текст в сообщении, например: Failed password"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
          </div>
          <select value={range} onChange={(e) => navigate(withParam(query, "range", e.target.value || "all"))}>
            {RANGES.map((r) => (
              <option key={r.v || "all"} value={r.v || "all"}>
                {r.label}
              </option>
            ))}
          </select>
          <button className="btn btn-primary">Найти</button>
        </form>

        <div className="filters">
          {Object.entries(fields).map(([k, v]) => (
            <span key={k} className="chip">
              {label(k)}: <b>{v}</b>
              <button onClick={() => navigate(withParam(query, k, null))} aria-label="Убрать фильтр">
                <Icon name="x" size={12} />
              </button>
            </span>
          ))}
          <form className="add-filter" onSubmit={addFilter}>
            <Icon name="filter" size={14} />
            <select value={addField} onChange={(e) => setAddField(e.target.value)}>
              {FIELD_LABELS.map(([k, l]) => (
                <option key={k} value={k}>
                  {l}
                </option>
              ))}
            </select>
            <span>=</span>
            <input value={addValue} onChange={(e) => setAddValue(e.target.value)} placeholder="значение" />
            <button className="btn btn-sm" disabled={!addValue.trim()}>
              <Icon name="plus" size={14} />
              Фильтр
            </button>
          </form>
        </div>
      </Card>

      {first.error && <ErrorBox error={first.error} onRetry={first.reload} />}
      {first.loading && !first.data ? (
        <Spinner />
      ) : rows.length === 0 ? (
        <Empty>Ничего не найдено. Попробуйте увеличить период или убрать фильтры.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="table events-table">
            <thead>
              <tr>
                <th>Время</th>
                <th>Источник</th>
                <th>Хост</th>
                <th>IP</th>
                <th>Пользователь</th>
                <th>Сообщение</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr
                  key={e.id}
                  className={`${openId === e.id ? "selected" : ""} ${e.outcome === "failure" ? "row-fail" : ""}`}
                  onClick={() => navigate(withParam(query, "id", String(e.id)))}
                >
                  <td className="nowrap mono">{dateTime(e.ts)}</td>
                  <td>
                    <span className="tag">{e.source ?? "—"}</span>
                  </td>
                  <td>{e.host ?? ""}</td>
                  <td>
                    <IpLink ip={e.src_ip} country={e.extra?.["geo.country"]} listed={e.extra?.["ti.listed"] === "true"} />
                  </td>
                  <td>{e.user ?? ""}</td>
                  <td className="msg">{e.message ?? e.raw}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {moreErr && <ErrorBox error={moreErr} onRetry={loadMore} />}
          {next !== null && (
            <div className="more">
              <button className="btn" onClick={loadMore} disabled={moreBusy}>
                {moreBusy ? "Загрузка…" : "Показать ещё"}
              </button>
            </div>
          )}
        </div>
      )}

      {openId !== null && (
        <EventDrawer
          id={openId}
          known={rows.find((r) => r.id === openId)}
          onClose={() => navigate(withParam(query, "id", null))}
          onFilter={(k, v) => navigate(withParam(query, k, v))}
        />
      )}
    </div>
  );
}

function EventDrawer({
  id,
  known,
  onClose,
  onFilter,
}: {
  id: number;
  known?: SiemEvent;
  onClose: () => void;
  onFilter: (field: string, value: string) => void;
}) {
  // в таблице уже есть полное событие; из живой ленты приходит только сводка — догружаем
  const full = useAsync(async () => (known?.raw !== undefined || known?.received ? known : api.event(id)), [id]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  const e = full.data;
  return (
    <aside className="drawer" aria-label="Событие">
      <header className="drawer-head">
        <h3>Событие #{id}</h3>
        <button className="icon-btn" onClick={onClose} aria-label="Закрыть">
          <Icon name="x" />
        </button>
      </header>
      {full.loading && !e ? (
        <Spinner />
      ) : full.error ? (
        <ErrorBox error={full.error} onRetry={full.reload} />
      ) : e ? (
        <EventDetails e={e} onFilter={onFilter} />
      ) : null}
    </aside>
  );
}

export function EventDetails({ e, onFilter }: { e: SiemEvent; onFilter?: (field: string, value: string) => void }) {
  const rec = e as unknown as Record<string, string | undefined>;
  return (
    <div className="event-details">
      <dl className="kv">
        <dt>Время события</dt>
        <dd className="mono">{dateTime(e.ts)}</dd>
        {e.received && (
          <>
            <dt>Получено</dt>
            <dd className="mono">{dateTime(e.received)}</dd>
          </>
        )}
        {FIELD_LABELS.map(([k, l]) =>
          rec[k] ? (
            <FieldRow key={k} label={l} value={rec[k]!} onFilter={onFilter ? () => onFilter(k, rec[k]!) : undefined} />
          ) : null,
        )}
        {e.extra &&
          Object.entries(e.extra).map(([k, v]) => (
            <FieldRow
              key={`x-${k}`}
              label={EXTRA_LABELS[k] ?? k}
              value={k === "geo.country" ? `${v} — ${countryName(v)}` : v}
              onFilter={onFilter ? () => onFilter(k, v) : undefined}
            />
          ))}
        {e.src_ip && (
          <>
            <dt>Карточка адреса</dt>
            <dd>
              <IpLink ip={e.src_ip} />
            </dd>
          </>
        )}
      </dl>
      {e.message && (
        <>
          <h4>Сообщение</h4>
          <pre className="raw">{e.message}</pre>
        </>
      )}
      {e.raw && e.raw !== e.message && (
        <>
          <h4>Исходная строка</h4>
          <pre className="raw">{e.raw}</pre>
        </>
      )}
    </div>
  );
}

function FieldRow({ label, value, onFilter }: { label: string; value: string; onFilter?: () => void }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>
        <span className="mono">{value}</span>
        {onFilter && (
          <button className="link-btn" onClick={onFilter} title="Искать события с этим значением">
            <Icon name="filter" size={12} />
          </button>
        )}
      </dd>
    </>
  );
}
