// Подключённые серверы (агенты) и подключение нового сервера в пару кликов.
import { useState, type FormEvent } from "react";
import { api, type EnrollToken, type Me } from "../api";
import { Icon } from "../components/Icons";
import { Card, CopyButton, Empty, ErrorBox, Modal, Spinner, useAsync, useInterval } from "../components/Ui";
import { ago, dateTime, num } from "../format";
import { navigate, useTitle } from "../router";
import { REPO, RELEASES, detectPlatform, enrollInfo, getAgentCommands, type AgentPlatform } from "../agentSetup";

export function AgentsPage({ me }: { me: Me }) {
  useTitle("Серверы");
  const res = useAsync(() => api.agents(), []);
  useInterval(res.reload, 10000);
  const [adding, setAdding] = useState(false);

  const agents = (res.data?.agents ?? []).slice().sort((a, b) => Number(b.online) - Number(a.online) || a.host.localeCompare(b.host));
  const online = agents.filter((a) => a.online).length;

  return (
    <div className="page">
      <div className="page-head">
        <h1>Серверы</h1>
        {res.data && (
          <span className="muted">
            на связи {online} из {agents.length}
          </span>
        )}
        <span className="grow" />
        <button className="btn btn-primary" onClick={() => navigate("/connect")}>
          <Icon name="plus" size={16} /> Подключить сайт
        </button>
        {me.is_admin && (
          <button className="btn" onClick={() => setAdding(true)} title="Только агент: сам найдёт журналы nginx, SSH, системы">
            <Icon name="server" size={16} /> Подключить сервер
          </button>
        )}
      </div>

      {res.error && <ErrorBox error={res.error} onRetry={res.reload} />}
      {res.loading && !res.data ? (
        <Spinner />
      ) : agents.length === 0 ? (
        <Card>
          <Empty>
            Пока ни один сервер не присылал логи.
            {" Нажмите «Подключить сайт» — мастер по шагам покажет, как включить журнал запросов и подключить агента."}
          </Empty>
        </Card>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th />
                <th>Хост</th>
                <th>Ключ</th>
                <th>Агент</th>
                <th>Адрес</th>
                <th>На связи</th>
                <th>Событий</th>
                <th>Блокировки</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => (
                <tr
                  key={a.key_name}
                  className="clickable"
                  onClick={() => a.host && navigate(`/events?host=${encodeURIComponent(a.host)}`)}
                >
                  <td>
                    <span className={`dot ${a.online ? "on" : "off"}`} title={a.online ? "на связи" : "нет связи больше 2 минут"} />
                  </td>
                  <td>
                    <b>{a.host || "—"}</b>
                  </td>
                  <td className="mono">{a.key_name}</td>
                  <td className="mono">{a.agent || "—"}</td>
                  <td className="mono">{a.remote_addr}</td>
                  <td className="nowrap" title={`впервые: ${dateTime(a.first_seen)}`}>
                    {ago(a.last_seen)}
                  </td>
                  <td>{num(a.events)}</td>
                  <td className="nowrap">
                    <FirewallState fw={a.firewall} synced={a.blocks_synced} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="hint">
            «Нет связи» — агент молчит дольше 2 минут. Блокировки применяет агент, у которого в <code>agent.yaml</code>{" "}
            включено <code>firewall: auto</code> (или nftables, iptables, pf, windows, nginx).
          </p>
        </div>
      )}

      {adding && <EnrollModal onClose={() => setAdding(false)} />}
    </div>
  );
}

function EnrollModal({ onClose }: { onClose: () => void }) {
  const [label, setLabel] = useState("");
  const [ttl, setTtl] = useState(24);
  const [uses, setUses] = useState(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [token, setToken] = useState<EnrollToken | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setToken(await api.createEnrollToken(ttl, uses, label.trim()));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const info = token ? enrollInfo(token) : null;
  const guessed = !!info?.guessed;
  const server = info?.server ?? "";
  const enrollCmd = info?.command ?? "";
  const [platform, setPlatform] = useState<AgentPlatform>(detectPlatform);
  const getAgent = getAgentCommands(platform);

  return (
    <Modal title="Подключить сервер" onClose={onClose}>
      {!token ? (
        <form className="form" onSubmit={submit}>
          <p>
            Панель создаст одноразовый токен. На сервере, который нужно защищать, вы выполните одну команду — агент сам
            найдёт логи (nginx, SSH, sudo, системный журнал) и начнёт их присылать.
          </p>
          <label>
            Подпись (для себя)
            <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="например: веб-серверы" maxLength={100} />
          </label>
          <div className="form-row">
            <label>
              Действует, часов
              <input type="number" min={1} max={720} value={ttl} onChange={(e) => setTtl(Number(e.target.value) || 1)} />
            </label>
            <label>
              Сколько серверов
              <input type="number" min={1} max={1000} value={uses} onChange={(e) => setUses(Number(e.target.value) || 1)} />
            </label>
          </div>
          {error && <div className="form-error">{error}</div>}
          <div className="form-actions">
            <button type="button" className="btn" onClick={onClose}>
              Отмена
            </button>
            <button className="btn btn-primary" disabled={busy}>
              {busy ? "Создание…" : "Создать токен"}
            </button>
          </div>
        </form>
      ) : (
        <div className="enroll-result">
          <div className="seg">
            {(["mac", "linux"] as const).map((p) => (
              <button key={p} className={platform === p ? "active" : ""} onClick={() => setPlatform(p)}>
                {p === "mac" ? "Mac" : "Linux"}
              </button>
            ))}
          </div>
          <ol className="steps">
            <li>
              Возьмите агента — маленькую программу, которая будет читать логи на этом сервере и присылать их сюда.
              В Терминале на защищаемом {platform === "mac" ? "Mac" : "сервере"}:
              <pre className="cmd">{getAgent}</pre>
              <CopyButton text={getAgent} label="Копировать" />
              <p className="hint">
                {platform === "mac" ? (
                  <>
                    Агент лежит внутри приложения SentinelCore. Если приложения на этом Mac нет — скачайте архив{" "}
                    <code>sentinel-…-macos-universal.tar.gz</code> со страницы{" "}
                    <a href={RELEASES} target="_blank" rel="noreferrer">
                      Releases
                    </a>
                    .
                  </>
                ) : (
                  <>
                    Агент берётся из Docker-образа (подходит для Ubuntu 24.04+, Debian 13+). Для других систем соберите его
                    из исходников — см. README на{" "}
                    <a href={REPO} target="_blank" rel="noreferrer">
                      GitHub
                    </a>
                    .
                  </>
                )}
              </p>
            </li>
            <li>
              Подключите его к SIEM (в той же папке):
              <pre className="cmd">{enrollCmd}</pre>
              <CopyButton text={enrollCmd} label="Копировать команду" />
            </li>
            <li>
              Запустите в фоне (окно можно закрыть, после перезагрузки агент стартует сам):
              <pre className="cmd">{platform === "linux" ? "sudo " : ""}./sentinel-agent service install</pre>
              Сервер появится в этом списке через несколько секунд. Журнал своего сайта добавьте командой{" "}
              <code>./sentinel-agent add /путь/к/access.log</code> или через мастер «Подключить сайт».
            </li>
          </ol>
          <dl className="kv">
            <dt>Токен действует до</dt>
            <dd className="mono">{dateTime(token.expires)}</dd>
            <dt>Подключений</dt>
            <dd>{token.uses}</dd>
          </dl>
          {!token.pin && (
            <div className="warn-box">
              <Icon name="alert" size={16} />
              <span>
                Сервер работает без шифрования (TLS): ключ агента пойдёт по сети открыто. Включите HTTPS:{" "}
                <code>sentinel-server gen-cert</code>.
              </span>
            </div>
          )}
          {server.includes("127.0.0.1") || server.includes("localhost") ? (
            <div className="warn-box">
              <Icon name="alert" size={16} />
              <span>
                В команде адрес <code>{server}</code> — он работает только на этой же машине. Для других серверов
                укажите <code>public_url</code> в конфиге SIEM.
              </span>
            </div>
          ) : guessed ? (
            <div className="warn-box">
              <Icon name="alert" size={16} />
              <span>
                Адрес <code>{server}</code> взят из адресной строки браузера. Проверьте, что защищаемый сервер видит SIEM
                по этому адресу, или укажите <code>public_url</code> в конфиге.
              </span>
            </div>
          ) : null}
          <p className="hint">Токен показывается один раз. Агент получит свой личный ключ, который умеет только отправлять логи.</p>
          <div className="form-actions">
            <button className="btn btn-primary" onClick={onClose}>
              Готово
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}

// "nftables; applied=12; skipped=1" | "nginx; error=..." | "none" -> понятный текст
function FirewallState({ fw, synced }: { fw?: string; synced?: string }) {
  if (!fw || fw === "none") return <span className="muted">выключены</span>;
  const parts = fw.split(";").map((p) => p.trim());
  const name = parts[0];
  const kv: Record<string, string> = {};
  for (const p of parts.slice(1)) {
    const i = p.indexOf("=");
    if (i > 0) kv[p.slice(0, i)] = p.slice(i + 1);
    else kv[p] = "";
  }
  const title = synced ? `${fw}\nсинхронизация: ${dateTime(synced)}` : fw;
  if (kv.error !== undefined)
    return (
      <span className="fw-err" title={title}>
        {name}: ошибка
        <small>{kv.error}</small>
      </span>
    );
  if (kv.applied !== undefined)
    return (
      <span className="fw-ok" title={title}>
        {name}: {num(Number(kv.applied))} адр.
      </span>
    );
  return (
    <span className="muted" title={title}>
      {name}: {"cleared" in kv ? "очищено" : "ожидание"}
    </span>
  );
}
