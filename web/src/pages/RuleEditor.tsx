// Редактор правила: текст YAML с подсветкой, проверка на лету, пробный запуск на строках логов
// и на сохранённых событиях, версии, сохранение (администратор), включение и удаление.
import { useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, type Me, type RuleCheck, type RuleSource, type RuleTry, type RuleVersion } from "../api";
import { CodeEditor } from "../components/CodeEditor";
import { Icon } from "../components/Icons";
import { Card, Empty, ErrorBox, SeverityBadge, Spinner } from "../components/Ui";
import { dateTime, num, ruleTypeLabel, severityLabel } from "../format";
import { Link, navigate, useTitle } from "../router";
import { errorLineOf, KEYS, OPERATORS, ruleErrorText, TEMPLATES, TRANSFORMS } from "../rulesHelp";
import { FIELD_LABELS } from "../format";

type Tab = "logs" | "history" | "versions" | "help";

const ACTION_LABEL: Record<string, string> = {
  original: "исходная версия",
  create: "создано",
  update: "изменено",
  enable: "включено",
  disable: "выключено",
  delete: "удалено",
};

export function RuleEditorPage({ id, me }: { id: string | null; me: Me }) {
  const isNew = id === null;
  const [src, setSrc] = useState<RuleSource | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [text, setText] = useState(isNew ? TEMPLATES[0].text : "");
  const [saved, setSaved] = useState(isNew ? "" : "");
  const [check, setCheck] = useState<RuleCheck | null>(null);
  const [checking, setChecking] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [tab, setTab] = useState<Tab>(isNew ? "help" : "logs");
  const [nonce, setNonce] = useState(0);
  const canTest = me.can_change_alerts;
  const canSave = me.is_admin;
  const dirty = isNew ? true : text !== saved;
  useTitle(isNew ? "Новое правило" : `Правило ${id}`);

  // загрузка текста правила
  useEffect(() => {
    if (isNew) return;
    let alive = true;
    setLoadErr(null);
    api
      .rule(id!)
      .then((r) => {
        if (!alive) return;
        setSrc(r);
        setText(r.source);
        setSaved(r.source);
      })
      .catch((e: Error) => alive && setLoadErr(e.message));
    return () => {
      alive = false;
    };
  }, [id, isNew, nonce]);

  // проверка на лету (через 0.7 с после последнего изменения)
  useEffect(() => {
    if (!canTest || !text.trim()) return;
    const ctl = new AbortController();
    const t = window.setTimeout(() => {
      setChecking(true);
      api
        .checkRule(text, isNew ? undefined : id!, ctl.signal)
        .then((c) => setCheck(c))
        .catch((e: Error) => {
          if (e.name !== "AbortError") setCheck({ ok: false, error: e.message, errors: [], file: "", test_cases: 0, rule_ids: [], test_failures: [] });
        })
        .finally(() => setChecking(false));
    }, 700);
    return () => {
      window.clearTimeout(t);
      ctl.abort();
    };
  }, [text, canTest, id, isNew]);

  // не потерять правку при закрытии вкладки
  useEffect(() => {
    if (!dirty || isNew) return;
    const h = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", h);
    return () => window.removeEventListener("beforeunload", h);
  }, [dirty, isNew]);

  const save = async () => {
    if (!canSave || busy || (!dirty && !isNew)) return;
    setBusy(true);
    setMsg(null);
    try {
      const r = await api.saveRule(isNew ? null : id!, text);
      setCheck(r);
      if (!r.ok) {
        setMsg({ ok: false, text: ruleErrorText(r.error) });
        return;
      }
      const newId = r.rule_ids[0];
      setMsg({ ok: true, text: isNew ? "Правило создано и уже работает" : "Сохранено — новые правила уже работают" });
      setSaved(text);
      if (isNew || (newId && newId !== id && !r.rule_ids.includes(id!))) navigate(`/rules/${encodeURIComponent(newId)}`, true);
      else setNonce((n) => n + 1);
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };

  const toggle = async () => {
    if (!src || dirty) return;
    setBusy(true);
    setMsg(null);
    try {
      const r = await api.setRuleEnabled(id!, !src.rule.enabled);
      if (!r.ok) setMsg({ ok: false, text: ruleErrorText(r.error) });
      else {
        setMsg({ ok: true, text: src.rule.enabled ? "Правило выключено" : "Правило включено" });
        setNonce((n) => n + 1);
      }
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!src) return;
    if (!window.confirm(`Удалить правило ${id}? Файл ${src.file} будет удалён (копия останется в истории).`)) return;
    setBusy(true);
    try {
      const r = await api.deleteRule(id!);
      if (!r.ok) setMsg({ ok: false, text: ruleErrorText(r.error) });
      else navigate("/rules");
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };

  if (!isNew && loadErr)
    return (
      <div className="page">
        <Link to="/rules" className="back">
          <Icon name="back" size={16} /> Правила
        </Link>
        <ErrorBox error={loadErr === "rule not found" ? "Правило не найдено (возможно, его удалили)" : loadErr} />
      </div>
    );
  if (!isNew && !src) return <Spinner />;

  const rule = src?.rule;
  const errLine = check && !check.ok ? errorLineOf(check.error) : null;

  return (
    <div className="page rule-editor">
      <Link to="/rules" className="back">
        <Icon name="back" size={16} /> Правила
      </Link>
      <div className="page-head">
        {rule && <SeverityBadge s={rule.severity} />}
        <h1>{isNew ? "Новое правило" : rule?.name}</h1>
        {rule && <span className="mono muted">{rule.id}</span>}
        {rule && !rule.enabled && <span className="badge">выключено</span>}
        {dirty && !isNew && <span className="tag tag-warn">не сохранено</span>}
        <span className="grow" />
        {!isNew && canSave && (
          <>
            <button className="btn" onClick={toggle} disabled={busy || dirty} title={dirty ? "Сначала сохраните изменения" : undefined}>
              {rule?.enabled ? "Выключить" : "Включить"}
            </button>
            <button className="btn btn-danger-ghost" onClick={remove} disabled={busy}>
              <Icon name="trash" size={15} /> Удалить
            </button>
          </>
        )}
        {canSave && (
          <button className="btn btn-primary" onClick={save} disabled={busy || (!dirty && !isNew)} title="Ctrl+S">
            {busy ? "Сохранение…" : isNew ? "Создать" : "Сохранить"}
          </button>
        )}
      </div>
      {msg && <div className={msg.ok ? "note-ok" : "form-error"}>{msg.text}</div>}
      {!canSave && (
        <p className="hint">
          {canTest
            ? "Менять текст и проверять правило можно, а сохранять — только администратору."
            : "Только просмотр: проверять правила может аналитик, изменять — администратор."}
        </p>
      )}

      {isNew && (
        <div className="templates">
          {TEMPLATES.map((t) => (
            <button
              key={t.key}
              className={`template ${text === t.text ? "active" : ""}`}
              onClick={() =>
                (TEMPLATES.some((x) => x.text === text) || !text.trim() || window.confirm("Заменить ваш текст шаблоном?")) &&
                setText(t.text)
              }
            >
              <b>{t.title}</b>
              <span>{t.about}</span>
            </button>
          ))}
        </div>
      )}

      <div className="editor-grid">
        <div className="editor-main">
          <CodeEditor value={text} onChange={setText} readOnly={!canTest} errorLine={errLine} onSave={save} />
          <div className="editor-status">
            {src && (
              <span className="muted small mono">
                {src.file}
                {src.rules_in_file.length > 1 && ` · в файле правил: ${src.rules_in_file.length}`}
              </span>
            )}
            <span className="grow" />
            {canTest && <CheckState check={check} checking={checking} />}
          </div>
          {check && !check.ok && (check.errors.length > 1 || check.test_failures.length > 0) && (
            <ul className="check-list">
              {check.errors.slice(check.error === check.errors[0] ? 1 : 0).map((e, i) => (
                <li key={i}>{ruleErrorText(e)}</li>
              ))}
              {check.test_failures.map((f, i) => (
                <li key={`t${i}`}>
                  {f.expected_alert ? "Пример из match не вызывает алерт:" : "Пример из no_match вызывает алерт:"}{" "}
                  <code>{f.line}</code>
                </li>
              ))}
            </ul>
          )}
          {src && src.used_by.length > 0 && (
            <p className="hint">
              На это правило ссылаются цепочки:{" "}
              {src.used_by.map((u, i) => (
                <span key={u}>
                  {i > 0 && ", "}
                  <Link to={`/rules/${encodeURIComponent(u)}`}>{u}</Link>
                </span>
              ))}
              . Выключить или удалить его можно только вместе с ними.
            </p>
          )}
        </div>

        <aside className="editor-side">
          <div className="seg tabs">
            {canTest && (
              <button className={tab === "logs" ? "active" : ""} onClick={() => setTab("logs")}>
                На строках
              </button>
            )}
            {canTest && (
              <button className={tab === "history" ? "active" : ""} onClick={() => setTab("history")}>
                На событиях
              </button>
            )}
            {!isNew && (
              <button className={tab === "versions" ? "active" : ""} onClick={() => setTab("versions")}>
                Версии
              </button>
            )}
            <button className={tab === "help" ? "active" : ""} onClick={() => setTab("help")}>
              Справка
            </button>
          </div>
          {tab === "logs" && canTest && <TryLines text={text} />}
          {tab === "history" && canTest && <TryHistory text={text} />}
          {tab === "versions" && !isNew && (
            <Versions
              id={id!}
              refresh={nonce}
              onLoad={(t) => {
                setText(t);
                setMsg({ ok: true, text: "Версия загружена в редактор. Нажмите «Сохранить», чтобы вернуть её." });
              }}
            />
          )}
          {tab === "help" && <Help />}
        </aside>
      </div>

      {rule && (
        <Card title="Сейчас работает">
          <dl className="kv">
            <dt>Тип</dt>
            <dd>{ruleTypeLabel[rule.type] ?? rule.type}</dd>
            <dt>Важность</dt>
            <dd>{severityLabel[rule.severity]}</dd>
            <dt>Считается по</dt>
            <dd className="mono">{(rule.group_by ?? []).join(", ") || "—"}</dd>
            <dt>Алертов за сутки</dt>
            <dd>
              <Link to={`/alerts?rule=${encodeURIComponent(rule.id)}`}>{num(rule.alerts_24h?.total ?? 0)}</Link>
              {rule.alerts_24h?.false_positive ? (
                <span className="muted"> · ложных: {num(rule.alerts_24h.false_positive)}</span>
              ) : null}
            </dd>
            <dt>Примеров в tests</dt>
            <dd>{num(rule.tests ?? 0)}</dd>
          </dl>
        </Card>
      )}
    </div>
  );
}

function CheckState({ check, checking }: { check: RuleCheck | null; checking: boolean }) {
  if (checking && !check) return <span className="muted small">проверка…</span>;
  if (!check) return null;
  if (check.ok)
    return (
      <span className="ok small check-state">
        <Icon name="check" size={14} /> Правило в порядке
        {check.test_cases > 0 && `, примеров пройдено: ${check.test_cases}`}
        {checking && " · проверка…"}
      </span>
    );
  return (
    <span className="danger small check-state">
      <Icon name="alert" size={14} /> {ruleErrorText(check.error)}
    </span>
  );
}

const FORMATS = [
  ["auto", "авто"],
  ["nginx", "nginx / apache"],
  ["syslog", "syslog"],
  ["json", "JSON"],
  ["kv", "key=value"],
];

function TryLines({ text }: { text: string }) {
  const [lines, setLines] = useState("");
  const [format, setFormat] = useState("auto");
  const [res, setRes] = useState<RuleTry | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const inputLines = useMemo(() => lines.split("\n"), [lines]);

  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      setRes(await api.tryRule(text, lines, format));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="try">
      <p className="hint">
        Вставьте строки логов — правило проверит их по порядку, как живой поток (порог и цепочки тоже считаются).
      </p>
      <textarea
        className="try-input mono"
        value={lines}
        onChange={(e) => setLines(e.target.value)}
        placeholder={'Oct 12 11:00:01 web-01 sshd[1]: Failed password for root from 203.0.113.9 port 51022 ssh2\n203.0.113.5 - - [12/Oct/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 403 0 "-" "curl/8.0"'}
        spellCheck={false}
        rows={7}
      />
      <div className="try-bar">
        <select value={format} onChange={(e) => setFormat(e.target.value)} aria-label="Формат">
          {FORMATS.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
        <span className="grow" />
        <button className="btn btn-primary btn-sm" onClick={run} disabled={busy || !lines.trim()}>
          <Icon name="play" size={13} /> {busy ? "Проверка…" : "Проверить"}
        </button>
      </div>
      {err && <div className="form-error">{err}</div>}
      {res && !res.ok && <div className="form-error">{ruleErrorText(res.error)}</div>}
      {res && res.ok && (
        <>
          <div className="try-summary">
            <b>{num(res.alerts_total)}</b> алертов из <b>{num(res.events)}</b> событий
            {res.helpers.length > 0 && <span className="muted"> · с правилами-шагами: {res.helpers.join(", ")}</span>}
          </div>
          <ul className="try-lines">
            {res.lines!.map((l) => {
              const raw = inputLines[l.index] ?? "";
              const hit = l.alerts.length > 0;
              return (
                <li key={l.index} className={hit ? "hit" : l.parsed ? "" : "unparsed"}>
                  <button className="try-line" onClick={() => setOpen(open === l.index ? null : l.index)}>
                    <span className="try-icon">{hit ? <Icon name="alert" size={14} /> : l.parsed ? "·" : "?"}</span>
                    <span className="mono msg">{raw}</span>
                  </button>
                  {l.alerts.map((ai) => (
                    <div key={ai} className="try-alert">
                      <SeverityBadge s={res.alerts[ai].severity} /> <b>{res.alerts[ai].rule_id}</b> {res.alerts[ai].message}
                    </div>
                  ))}
                  {!l.parsed && <div className="muted small">строка не распознана как событие — проверьте формат</div>}
                  {open === l.index && l.event && <EventFields e={l.event as unknown as Record<string, unknown>} />}
                </li>
              );
            })}
          </ul>
          <p className="hint">Нажмите на строку, чтобы увидеть поля события, по которым работает правило.</p>
        </>
      )}
    </div>
  );
}

function EventFields({ e }: { e: Record<string, unknown> }) {
  const rows = FIELD_LABELS.filter(([k]) => e[k] !== undefined && e[k] !== "");
  const extra = (e.extra ?? {}) as Record<string, string>;
  return (
    <dl className="kv try-fields">
      {rows.map(([k, label]) => (
        <div key={k} className="kv-row">
          <dt title={label}>{k}</dt>
          <dd className="mono">{String(e[k])}</dd>
        </div>
      ))}
      {Object.entries(extra).map(([k, v]) => (
        <div key={k} className="kv-row">
          <dt>{k}</dt>
          <dd className="mono">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

const PERIODS = [
  [1, "1 час"],
  [24, "сутки"],
  [72, "3 дня"],
  [168, "неделя"],
] as const;

function TryHistory({ text }: { text: string }) {
  const [hours, setHours] = useState(24);
  const [res, setRes] = useState<RuleTry | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      setRes(await api.tryRuleHistory(text, hours));
    } catch (e) {
      setErr(e instanceof ApiError && e.status === 429 ? "Уже идёт другая проверка, повторите через несколько секунд" : (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const span = res?.first_ts && res.last_ts ? (Date.parse(res.last_ts) - Date.parse(res.first_ts)) / 3600000 : 0;
  const perDay = res && span > 0.5 ? Math.round((res.alerts_total / span) * 24) : null;

  return (
    <div className="try">
      <p className="hint">
        Правило пройдёт по событиям, которые уже сохранены, и покажет, сколько алертов оно дало бы. Так видно заранее, не
        будет ли оно «шуметь».
      </p>
      <div className="try-bar">
        <div className="seg">
          {PERIODS.map(([h, l]) => (
            <button key={h} className={hours === h ? "active" : ""} onClick={() => setHours(h)}>
              {l}
            </button>
          ))}
        </div>
        <span className="grow" />
        <button className="btn btn-primary btn-sm" onClick={run} disabled={busy}>
          <Icon name="play" size={13} /> {busy ? "Проверка…" : "Проверить"}
        </button>
      </div>
      {err && <div className="form-error">{err}</div>}
      {res && !res.ok && <div className="form-error">{ruleErrorText(res.error)}</div>}
      {res && res.ok && (
        <>
          <dl className="kv">
            <dt>Проверено событий</dt>
            <dd>
              {num(res.events)}
              {res.truncated && <span className="muted"> (самые свежие)</span>}
            </dd>
            {res.first_ts && (
              <>
                <dt>Период</dt>
                <dd className="mono">
                  {dateTime(res.first_ts)} — {dateTime(res.last_ts!)}
                </dd>
              </>
            )}
            <dt>Алертов</dt>
            <dd>
              <b>{num(res.alerts_total)}</b>
              {perDay !== null && <span className="muted"> · ≈ {num(perDay)} в сутки</span>}
            </dd>
            <dt>Разных адресов</dt>
            <dd>{num(res.distinct_ips)}</dd>
            <dt>Заняло</dt>
            <dd>{num(res.took_ms)} мс</dd>
          </dl>
          {Object.keys(res.alerts_by_rule).length > 1 && (
            <p className="muted small">
              {Object.entries(res.alerts_by_rule)
                .map(([k, v]) => `${k}: ${v}`)
                .join(" · ")}
            </p>
          )}
          {res.events === 0 && <Empty>За этот период событий нет.</Empty>}
          {res.alerts.length > 0 && (
            <ul className="try-sample">
              {res.alerts.map((a, i) => (
                <li key={i}>
                  <span className="mono small nowrap">{dateTime(a.ts)}</span>
                  <SeverityBadge s={a.severity} />
                  <span className="msg">{a.message}</span>
                </li>
              ))}
            </ul>
          )}
          {res.alerts_total > res.alerts.length && (
            <p className="hint">Показаны первые {res.alerts.length} алертов.</p>
          )}
        </>
      )}
    </div>
  );
}

function Versions({ id, refresh, onLoad }: { id: string; refresh: number; onLoad: (text: string) => void }) {
  const [list, setList] = useState<RuleVersion[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const loading = useRef(false);
  useEffect(() => {
    api
      .ruleHistory(id)
      .then((r) => setList(r.versions))
      .catch((e: Error) => setErr(e.message));
  }, [id, refresh]);

  const open = async (v: RuleVersion) => {
    if (loading.current) return;
    loading.current = true;
    try {
      onLoad((await api.ruleVersion(id, v.version)).source);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      loading.current = false;
    }
  };

  if (err) return <div className="form-error">{err}</div>;
  if (!list) return <Spinner />;
  if (list.length === 0) return <Empty>Правило ещё не меняли из панели.</Empty>;
  return (
    <ul className="versions">
      {list.map((v, i) => (
        <li key={v.version}>
          <div>
            <b>{ACTION_LABEL[v.action] ?? v.action}</b>
            {i === 0 && <span className="tag">текущая</span>}
            <div className="muted small">
              {dateTime(v.ts)} · {v.by === "file" ? "файл на диске" : v.by}
            </div>
          </div>
          <button className="btn btn-sm" onClick={() => open(v)}>
            Открыть
          </button>
        </li>
      ))}
    </ul>
  );
}

function Help() {
  return (
    <div className="help">
      <h4>Ключи правила</h4>
      <dl className="kv">
        {KEYS.map(([k, v]) => (
          <div key={k} className="kv-row">
            <dt className="mono">{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
      <h4>Условия в where</h4>
      <dl className="kv">
        {OPERATORS.map(([k, v]) => (
          <div key={k} className="kv-row">
            <dt className="mono">{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
      <h4>Поля события</h4>
      <p className="muted small">
        {FIELD_LABELS.map(([k, l]) => (
          <span key={k} className="field-chip" title={l}>
            {k}
          </span>
        ))}
      </p>
      <h4>Преобразования (transform)</h4>
      <dl className="kv">
        {TRANSFORMS.map(([k, v]) => (
          <div key={k} className="kv-row">
            <dt className="mono">{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
      <p className="hint">
        Регулярные выражения пишите в 'одинарных кавычках'. В примерах для порога <code>{"{n}"}</code> заменяется номером
        повтора. Правило сохраняется, только если все примеры из <code>tests</code> работают как задумано.
      </p>
    </div>
  );
}
