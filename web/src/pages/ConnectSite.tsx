// Мастер «Подключить сайт»: 4 шага без знания безопасности и командной строки.
// 1) на чём сделан сайт  2) включить журнал запросов  3) агент (готовые команды)  4) проверка — ждём первую строку.
import { useEffect, useMemo, useState } from "react";
import { api, type EnrollToken, type Me, type SiemEvent } from "../api";
import {
  RELEASES,
  cleanLabel,
  detectPlatform,
  enrollInfo,
  getAgentCommands,
  guessSiteName,
  shellPath,
  type AgentPlatform,
} from "../agentSetup";
import { Icon } from "../components/Icons";
import { Card, CopyButton } from "../components/Ui";
import { timeOnly } from "../format";
import { Link, navigate, useTitle } from "../router";
import { GUIDES, guideById, type SiteGuide } from "../siteGuides";

const STEPS = ["Сайт", "Журнал", "Агент", "Проверка"];

// Папки, которые macOS не даёт читать фоновым программам без разрешения
const PROTECTED_MAC = /(^~?\/?(Users\/[^/]+\/)?(Documents|Desktop|Downloads)(\/|$))|(\/(Documents|Desktop|Downloads|Library\/Mobile Documents)\/)/;

export function ConnectSitePage({ me }: { me: Me }) {
  useTitle("Подключить сайт");
  const [step, setStep] = useState(0);
  const [platform, setPlatform] = useState<AgentPlatform>(detectPlatform);
  const [guideId, setGuideId] = useState<string>("");
  const [docker, setDocker] = useState(false);
  const [project, setProject] = useState("");
  const [customPath, setCustomPath] = useState("");
  const [name, setName] = useState("");
  const [nameEdited, setNameEdited] = useState(false);
  const [haveAgent, setHaveAgent] = useState<boolean | null>(null);
  const [token, setToken] = useState<EnrollToken | null>(null);
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [tokenBusy, setTokenBusy] = useState(false);

  const guide = guideById(guideId);

  // путь к журналу
  const logPath = useMemo(() => {
    if (!guide) return "";
    if (guide.kind === "code") {
      const dir = project.trim().replace(/[\\/]+$/, "");
      return dir ? `${dir}/${guide.logInProject}` : "";
    }
    return customPath.trim();
  }, [guide, project, customPath]);

  // имя сайта угадываем по пути, пока его не поменяли руками
  useEffect(() => {
    if (!nameEdited) setName(logPath ? guessSiteName(guide?.kind === "code" ? project.trim() + "/access.log" : logPath) : "");
  }, [logPath, nameEdited, guide, project]);

  // при выборе nginx/Apache — подставить обычный путь
  useEffect(() => {
    if (guide?.kind === "ready" && guide.paths) setCustomPath(guide.paths[platform][0]);
    else if (guide?.kind === "custom") setCustomPath("");
  }, [guideId, platform]);

  const label = cleanLabel(name) || "site";
  const needSudo = platform === "linux" && guide?.kind === "ready";
  const sudo = needSudo ? "sudo " : "";
  const macProtected = platform === "mac" && PROTECTED_MAC.test(logPath);

  const createToken = async () => {
    setTokenBusy(true);
    setTokenError(null);
    try {
      setToken(await api.createEnrollToken(24, 1, `сайт ${label}`));
    } catch (e) {
      setTokenError((e as Error).message);
    } finally {
      setTokenBusy(false);
    }
  };

  const enroll = token ? enrollInfo(token) : null;
  const commands = useMemo(() => {
    const lines: string[] = [];
    if (haveAgent === false) {
      lines.push("# 1. скачать агента", getAgentCommands(platform));
      lines.push("", "# 2. подключить его к SIEM", enroll ? enroll.command : "(сначала нажмите «Получить команду подключения» выше)");
      lines.push("", "# 3. читать журнал сайта");
    } else {
      lines.push("cd ~/sentinel-agent", "", "# читать журнал сайта");
    }
    lines.push(`${sudo}./sentinel-agent add ${shellPath(logPath || "/путь/к/access.log")} --name ${label}`);
    lines.push("", haveAgent === false ? "# 4. работать в фоне и запускаться самому" : "# работать в фоне и запускаться самому");
    lines.push(`${platform === "linux" ? "sudo " : ""}./sentinel-agent service install`);
    return lines.join("\n");
  }, [haveAgent, platform, enroll, sudo, logPath, label]);

  const canNext = [!!guide, !!logPath && !!label, haveAgent !== null && (haveAgent || !!token), true][step];

  return (
    <div className="page connect">
      <div className="page-head">
        <h1>Подключить сайт</h1>
        <span className="grow" />
        <Link to="/agents" className="btn btn-sm">
          <Icon name="server" size={14} /> Серверы
        </Link>
      </div>
      <p className="muted connect-lead">
        SIEM узнаёт об атаках из журнала запросов сайта: каждая строка — кто, когда и какую страницу открыл. Агент на компьютере с
        сайтом читает этот журнал и присылает новые строки сюда. Мастер проведёт по шагам — нужно будет только скопировать команды.
      </p>

      <ol className="stepper">
        {STEPS.map((s, i) => (
          <li key={s} className={i === step ? "active" : i < step ? "done" : ""}>
            <button disabled={i > step} onClick={() => setStep(i)}>
              <span className="num">{i < step ? <Icon name="check" size={14} /> : i + 1}</span>
              {s}
            </button>
          </li>
        ))}
      </ol>

      {step === 0 && (
        <Card title="На чём работает сайт?">
          <div className="form-row connect-row">
            <span className="muted">Компьютер с сайтом:</span>
            <div className="seg">
              {(["mac", "linux"] as const).map((p) => (
                <button key={p} className={platform === p ? "active" : ""} onClick={() => setPlatform(p)}>
                  {p === "mac" ? "Mac" : "Linux-сервер"}
                </button>
              ))}
            </div>
          </div>
          <div className="guide-grid">
            {GUIDES.map((g) => (
              <button key={g.id} className={`guide-card ${guideId === g.id ? "active" : ""}`} onClick={() => setGuideId(g.id)}>
                <b>{g.title}</b>
                <small>{g.subtitle}</small>
              </button>
            ))}
          </div>
          <label className="check">
            <input type="checkbox" checked={docker} onChange={(e) => setDocker(e.target.checked)} /> Сайт запущен в Docker
          </label>
          <p className="hint">
            Не уверены? Если вы писали сайт сами на JavaScript — это скорее всего Node.js; на Python — Flask или Django. Сайт на
            хостинге с nginx — выберите nginx.
          </p>
        </Card>
      )}

      {step === 1 && guide && (
        <Card title={`Журнал запросов: ${guide.title}`}>
          <GuideSteps guide={guide} />
          {guide.kind === "code" ? (
            <label className="field">
              Папка проекта — откуда вы запускаете сайт
              <input
                value={project}
                onChange={(e) => setProject(e.target.value)}
                placeholder={platform === "mac" ? "например: ~/SupSearch/server" : "например: /var/www/shop"}
                autoFocus
              />
            </label>
          ) : (
            <label className="field">
              Путь к журналу
              <input
                value={customPath}
                onChange={(e) => setCustomPath(e.target.value)}
                placeholder="/путь/к/access.log"
                list="known-log-paths"
                autoFocus={guide.kind === "custom"}
              />
              {guide.paths && (
                <datalist id="known-log-paths">
                  {[...guide.paths.mac, ...guide.paths.linux].map((p) => (
                    <option key={p} value={p} />
                  ))}
                </datalist>
              )}
            </label>
          )}
          {guide.paths && (
            <p className="hint">
              Обычно здесь:{" "}
              {guide.paths[platform].map((p, i) => (
                <span key={p}>
                  {i > 0 && ", "}
                  <button className="link" onClick={() => setCustomPath(p)}>
                    {p}
                  </button>
                </span>
              ))}
              . Не уверены — в Терминале: <code>ls -la {guide.paths[platform][0].replace(/\/[^/]*$/, "")}</code>
            </p>
          )}
          {logPath && (
            <p>
              Журнал будет здесь: <code>{logPath}</code>
            </p>
          )}
          <label className="field">
            Название сайта в SIEM
            <input
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                setNameEdited(true);
              }}
              placeholder="например: shop"
              maxLength={60}
            />
          </label>
          {name && cleanLabel(name) !== name && (
            <p className="hint">
              Будет записано как <code>{label}</code> (латиница, цифры, точка, дефис).
            </p>
          )}
          {docker && (
            <div className="warn-box">
              <Icon name="alert" size={16} />
              <span>
                Сайт в Docker пишет журнал внутрь контейнера. Подключите папку журнала к компьютеру в docker-compose.yml, например{" "}
                <code>volumes: - ./logs:/app/logs</code>, и укажите здесь путь к этой папке на компьютере.
              </span>
            </div>
          )}
          {macProtected && <MacPrivacyNote />}
        </Card>
      )}

      {step === 2 && (
        <Card title="Агент: программа, которая читает журнал и присылает его сюда">
          <div className="form-row connect-row">
            <span>Агент уже установлен на {platform === "mac" ? "этом Mac" : "этом сервере"}?</span>
            <div className="seg">
              <button className={haveAgent === true ? "active" : ""} onClick={() => setHaveAgent(true)}>
                Да, в ~/sentinel-agent
              </button>
              <button className={haveAgent === false ? "active" : ""} onClick={() => setHaveAgent(false)}>
                Нет
              </button>
            </div>
          </div>

          {haveAgent === false && !token && (
            <div className="connect-token">
              {me.is_admin ? (
                <>
                  <p>Панель выдаст одноразовую команду подключения (действует 24 часа).</p>
                  <button className="btn btn-primary" onClick={createToken} disabled={tokenBusy}>
                    <Icon name="key" size={16} /> {tokenBusy ? "Создание…" : "Получить команду подключения"}
                  </button>
                  {tokenError && <div className="form-error">{tokenError}</div>}
                </>
              ) : (
                <div className="warn-box">
                  <Icon name="alert" size={16} />
                  <span>Подключать новых агентов может только администратор. Попросите его открыть этот мастер.</span>
                </div>
              )}
            </div>
          )}

          {haveAgent !== null && (haveAgent || token) && (
            <>
              <p>
                Откройте Терминал на {platform === "mac" ? "Mac" : "сервере"}, где работает сайт, и выполните (можно всё сразу):
              </p>
              <pre className="cmd">{commands}</pre>
              <CopyButton text={commands} label="Копировать команды" />
              <ul className="connect-notes">
                <li>
                  <code>add</code> покажет, понял ли агент формат журнала, и добавит файл в настройки.
                </li>
                <li>
                  <code>service install</code> запускает агента в фоне: окно Терминала можно закрыть, после перезагрузки он
                  стартует сам.
                  {haveAgent && (
                    <>
                      {" "}
                      Если агент уже работает в открытом окне (<code>./sentinel-agent run</code>) — сначала остановите его там
                      клавишами <kbd>Ctrl</kbd>+<kbd>C</kbd>.
                    </>
                  )}
                </li>
                {platform === "mac" && haveAgent === false && (
                  <li>
                    Агент берётся из приложения SentinelCore. Если его нет на этом Mac — скачайте{" "}
                    <code>sentinel-…-macos-universal.tar.gz</code> со страницы{" "}
                    <a href={RELEASES} target="_blank" rel="noreferrer">
                      Releases
                    </a>
                    .
                  </li>
                )}
              </ul>
              {enroll?.local && platform === "linux" && (
                <div className="warn-box">
                  <Icon name="alert" size={16} />
                  <span>
                    В команде адрес <code>{enroll.server}</code> — он работает, только если сайт на этом же компьютере, что и
                    SIEM. Для другого сервера укажите <code>public_url</code> в настройках SIEM.
                  </span>
                </div>
              )}
              {macProtected && <MacPrivacyNote />}
            </>
          )}
        </Card>
      )}

      {step === 3 && <Verify label={label} logPath={logPath} platform={platform} />}

      <div className="connect-nav">
        {step > 0 && (
          <button className="btn" onClick={() => setStep(step - 1)}>
            <Icon name="back" size={16} /> Назад
          </button>
        )}
        <span className="grow" />
        {step < 3 ? (
          <button className="btn btn-primary" disabled={!canNext} onClick={() => setStep(step + 1)}>
            {step === 2 ? "Я выполнил команды" : "Дальше"} <Icon name="chevron" size={16} />
          </button>
        ) : (
          <button className="btn btn-primary" onClick={() => navigate("/")}>
            На главную
          </button>
        )}
      </div>
    </div>
  );
}

function GuideSteps({ guide }: { guide: SiteGuide }) {
  return (
    <>
      <ol className="steps">
        {guide.steps.map((s, i) => (
          <li key={i}>
            {s.text}
            {s.code && (
              <div className="code-block">
                {s.file && <div className="code-file">{s.file}</div>}
                <pre className="cmd">{s.code}</pre>
                <CopyButton text={s.code} />
              </div>
            )}
          </li>
        ))}
      </ol>
      {guide.note && <p className="hint">{guide.note}</p>}
    </>
  );
}

function MacPrivacyNote() {
  return (
    <div className="warn-box">
      <Icon name="alert" size={16} />
      <span>
        Сайт лежит в папке «Документы», «Рабочий стол» или «Загрузки» — macOS не даёт фоновым программам читать её без
        разрешения. Откройте «Системные настройки» → «Конфиденциальность и безопасность» → «Доступ к диску» (Full Disk
        Access), нажмите «+», затем <kbd>Cmd</kbd>+<kbd>Shift</kbd>+<kbd>G</kbd>, введите <code>~/sentinel-agent</code> и выберите
        файл <code>sentinel-agent</code>. Или перенесите проект в другую папку, например <code>~/Projects</code>.
      </span>
    </div>
  );
}

// Ждём первую строку с меткой сайта.
function Verify({ label, logPath, platform }: { label: string; logPath: string; platform: AgentPlatform }) {
  const [found, setFound] = useState<SiemEvent | null>(null);
  const [count, setCount] = useState(0);
  const [since] = useState(() => Date.now());
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    let stop = false;
    const check = async () => {
      try {
        const p = await api.events({ limit: 1, fields: { source: label } });
        if (stop) return;
        if (p.items.length) setFound(p.items[0]);
      } catch {
        // сеть — попробуем ещё раз
      }
      if (!stop) setCount((c) => c + 1);
    };
    void check();
    const t = window.setInterval(() => {
      setNow(Date.now());
      void check();
    }, 2000);
    return () => {
      stop = true;
      window.clearInterval(t);
    };
  }, [label]);

  const waited = Math.round((now - since) / 1000);
  if (found)
    return (
      <Card title="Готово — сайт подключён">
        <div className="connect-ok">
          <Icon name="check" size={28} />
          <div>
            <p>
              Первая строка от <b>{label}</b> пришла в {timeOnly(found.ts)}:
            </p>
            <p className="mono">{found.message}</p>
          </div>
        </div>
        <p>
          Теперь каждое открытие страницы видно в «Живой ленте» на главной. Если кто-то начнёт подбирать пароли, сканировать
          сайт или пробовать SQL-инъекции, появится алерт на странице «Алерты» (а если настроены уведомления — придёт сообщение).
        </p>
        <p>
          <Link to={`/events?source=${encodeURIComponent(label)}`}>Все события сайта</Link> ·{" "}
          <Link to="/alerts">Алерты</Link>
        </p>
      </Card>
    );
  return (
    <Card title="Проверка: ждём первую строку">
      <div className="connect-wait">
        <span className="spinner-dot" />
        <div>
          <p>
            Откройте свой сайт в браузере и пощёлкайте по страницам. Как только агент пришлёт строку с меткой <b>{label}</b>, здесь
            появится «Готово».
          </p>
          <p className="muted">
            Ждём {waited} с{count > 0 ? "" : "…"}
          </p>
        </div>
      </div>
      {waited >= 30 && (
        <div className="connect-help">
          <b>Долго нет строк? Проверьте по порядку:</b>
          <ol>
            <li>
              Сайт пишет журнал: в Терминале <code>tail -n 3 {shellPath(logPath || "/путь/к/access.log")}</code> — после
              открытия страницы должны появляться новые строки. Нет файла — перезапустите сайт после изменений из шага 2.
            </li>
            <li>
              Агент работает: <code>cd ~/sentinel-agent && {platform === "linux" ? "sudo " : ""}./sentinel-agent service status</code>{" "}
              — должно быть «running».
            </li>
            <li>
              Агент читает этот файл: <code>./sentinel-agent sources</code> — в списке есть <code>[{label}]</code>.
            </li>
            <li>
              Журнал агента:{" "}
              <code>
                {platform === "mac" ? "tail -n 20 ~/Library/Logs/SentinelCore/agent.log" : "sudo journalctl -u sentinel-agent -n 20"}
              </code>{" "}
              — там видно, если нет доступа к файлу или к SIEM.
            </li>
          </ol>
        </div>
      )}
    </Card>
  );
}
