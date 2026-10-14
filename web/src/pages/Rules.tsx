// Правила обнаружения: список, поиск, сколько алертов дало каждое за сутки,
// включение/выключение (администратор) и переход в редактор.
import { useState, type MouseEvent } from "react";
import { api, type Me, type Rule } from "../api";
import { Icon } from "../components/Icons";
import { Card, Empty, ErrorBox, SeverityBadge, Spinner, useAsync } from "../components/Ui";
import { num, ruleTypeLabel, SEVERITIES } from "../format";
import { Link, navigate, useTitle } from "../router";
import { ruleErrorText } from "../rulesHelp";

function logic(r: Rule): string {
  if (r.type === "threshold") {
    const w = r.window_seconds ?? 0;
    const win = w >= 60 ? `${Math.round(w / 60)} мин` : `${w} с`;
    return r.distinct ? `≥ ${r.threshold} разных «${r.distinct}» за ${win}` : `≥ ${r.threshold} раз за ${win}`;
  }
  if (r.type === "sequence") {
    const w = r.within_seconds ?? 0;
    return `${r.steps} шага за ${w >= 60 ? `${Math.round(w / 60)} мин` : `${w} с`}`;
  }
  return "каждое совпадение";
}

export function RulesPage({ me }: { me: Me }) {
  useTitle("Правила");
  const res = useAsync(() => api.rules(), []);
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  if (res.loading && !res.data) return <Spinner />;
  if (!res.data) return <ErrorBox error={res.error ?? "нет данных"} onRetry={res.reload} />;

  const editable = res.data.editable && me.is_admin;
  const needle = q.trim().toLowerCase();
  const rules = res.data.rules
    .filter((r) => !type || (type === "off" ? !r.enabled : r.type === type))
    .filter(
      (r) =>
        !needle ||
        r.id.toLowerCase().includes(needle) ||
        r.name.toLowerCase().includes(needle) ||
        r.description.toLowerCase().includes(needle) ||
        r.tags.some((t) => t.toLowerCase().includes(needle)),
    )
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.id.localeCompare(b.id));

  const toggle = async (e: MouseEvent, r: Rule) => {
    e.stopPropagation();
    setBusy(r.id);
    setErr(null);
    try {
      const c = await api.setRuleEnabled(r.id, !r.enabled);
      if (!c.ok) setErr(`${r.id}: ${ruleErrorText(c.error)}`);
      res.reload();
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <h1>Правила</h1>
        <span className="muted">
          всего {res.data.total}, работают {res.data.rules.filter((r) => r.enabled).length}
        </span>
        <span className="grow" />
        {editable && (
          <button className="btn btn-primary" onClick={() => navigate("/rules/new")}>
            <Icon name="plus" size={16} /> Новое правило
          </button>
        )}
      </div>
      {res.data.errors.length > 0 && (
        <div className="warn-box">
          <Icon name="alert" size={16} />
          <div>
            Некоторые файлы в папке rules не загрузились (остальные правила работают):
            <ul>
              {res.data.errors.map((e, i) => (
                <li key={i} className="mono small">
                  {e}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
      <Card>
        <div className="filters">
          <input className="grow" placeholder="Поиск по названию, ID, тегу…" value={q} onChange={(e) => setQ(e.target.value)} />
          <div className="seg">
            {["", "match", "threshold", "sequence", "off"].map((t) => (
              <button key={t} className={type === t ? "active" : ""} onClick={() => setType(t)}>
                {t === "off" ? "Выключенные" : t ? ruleTypeLabel[t] : "Все"}
              </button>
            ))}
          </div>
        </div>
        <p className="hint">
          Нажмите на правило, чтобы открыть его текст, проверить на логах или на уже сохранённых событиях
          {editable ? " и изменить" : ""}. Правила можно менять и файлами в папке <code>rules/</code> на сервере — изменения
          подхватываются сами.
        </p>
      </Card>
      {err && <div className="form-error">{err}</div>}
      {rules.length === 0 ? (
        <Empty>Ничего не найдено.</Empty>
      ) : (
        <div className="rule-list">
          {rules.map((r) => {
            const a = r.alerts_24h;
            return (
              <article
                key={r.id}
                className={`rule clickable ${r.enabled ? "" : "disabled"}`}
                onClick={() => navigate(`/rules/${encodeURIComponent(r.id)}`)}
              >
                <header>
                  <SeverityBadge s={r.severity} />
                  <h3>{r.name}</h3>
                  {!r.enabled && <span className="badge">выключено</span>}
                  <span className="grow" />
                  {editable && (
                    <button
                      className={`switch ${r.enabled ? "on" : ""}`}
                      role="switch"
                      aria-checked={r.enabled}
                      aria-label={r.enabled ? "Выключить правило" : "Включить правило"}
                      title={r.enabled ? "Выключить" : "Включить"}
                      disabled={busy === r.id}
                      onClick={(e) => toggle(e, r)}
                    >
                      <span />
                    </button>
                  )}
                </header>
                <p>{r.description}</p>
                <footer>
                  <span className="mono">{r.id}</span>
                  <span className="tag">{ruleTypeLabel[r.type] ?? r.type}</span>
                  <span className="muted">{logic(r)}</span>
                  {r.tags.map((t) => (
                    <span key={t} className="tag tag-dim">
                      #{t}
                    </span>
                  ))}
                  <span className="grow" />
                  {a && a.total > 0 ? (
                    <Link
                      to={`/alerts?rule=${encodeURIComponent(r.id)}`}
                      onClick={(e) => e.stopPropagation()}
                      title={`за сутки: ${a.total}, открытых ${a.open}, ложных ${a.false_positive}`}
                    >
                      {num(a.total)} за сутки
                      {a.false_positive > 0 && <span className="warn"> · ложных {num(a.false_positive)}</span>}
                    </Link>
                  ) : (
                    <span className="muted">тихо за сутки</span>
                  )}
                </footer>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}
