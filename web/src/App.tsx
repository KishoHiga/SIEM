// Каркас панели: проверка входа, боковое меню, страницы.
import { useCallback, useEffect, useState } from "react";
import { api, setUnauthorizedHandler, type Me } from "./api";
import { Icon, type IconName } from "./components/Icons";
import { Spinner } from "./components/Ui";
import { roleLabel } from "./format";
import { LiveProvider, useLive } from "./live";
import { AgentsPage } from "./pages/Agents";
import { ConnectSitePage } from "./pages/ConnectSite";
import { AlertDetailPage } from "./pages/AlertDetail";
import { AlertsPage } from "./pages/Alerts";
import { DashboardPage } from "./pages/Dashboard";
import { EventsPage } from "./pages/Events";
import { IncidentDetailPage, IncidentsPage } from "./pages/Incidents";
import { IpPage } from "./pages/IpPage";
import { LoginPage } from "./pages/Login";
import { ReportPage } from "./pages/Report";
import { ResponsePage } from "./pages/Response";
import { RuleEditorPage } from "./pages/RuleEditor";
import { RulesPage } from "./pages/Rules";
import { Link, match, navigate, useLocation } from "./router";

export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [checking, setChecking] = useState(true);

  const loadMe = useCallback(async () => {
    try {
      setMe(await api.me());
    } catch {
      setMe(null);
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => setMe(null));
    // Вход по ссылке из приложения для Mac: http://127.0.0.1:8080/#key=snt_…
    // Ключ сразу убирается из адресной строки и истории (часть после # на сервер не отправляется).
    const m = window.location.hash.match(/^#key=([A-Za-z0-9_.\-]{20,200})$/);
    if (m) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
      api
        .login(m[1])
        .catch(() => undefined)
        .finally(() => void loadMe());
      return;
    }
    void loadMe();
  }, [loadMe]);

  if (checking) return <Spinner label="Подключение…" />;
  if (!me) return <LoginPage onLogin={loadMe} />;
  return (
    <LiveProvider>
      <Shell
        me={me}
        onLogout={async () => {
          try {
            await api.logout();
          } finally {
            setMe(null);
            navigate("/", true);
          }
        }}
      />
    </LiveProvider>
  );
}

const NAV: { to: string; label: string; icon: IconName }[] = [
  { to: "/", label: "Обзор", icon: "dashboard" },
  { to: "/incidents", label: "Инциденты", icon: "layers" },
  { to: "/alerts", label: "Алерты", icon: "alert" },
  { to: "/events", label: "События", icon: "search" },
  { to: "/response", label: "Реагирование", icon: "ban" },
  { to: "/report", label: "Отчёт", icon: "report" },
  { to: "/rules", label: "Правила", icon: "rules" },
  { to: "/agents", label: "Серверы", icon: "server" },
];

function Shell({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const { path } = useLocation();
  const live = useLive();
  // счётчик новых алертов в меню: сбрасывается, когда открыли раздел алертов
  const [seen, setSeen] = useState(0);
  const onAlerts = path.startsWith("/alerts");
  useEffect(() => {
    if (onAlerts) setSeen(live.alertCount);
  }, [onAlerts, live.alertCount]);
  const newAlerts = live.alertCount - seen;

  let page;
  let m: Record<string, string> | null;
  if (path === "/") page = <DashboardPage />;
  else if (path === "/alerts") page = <AlertsPage me={me} />;
  else if ((m = match("/alerts/:id", path))) page = <AlertDetailPage id={Number(m.id)} me={me} />;
  else if (path === "/incidents") page = <IncidentsPage me={me} />;
  else if ((m = match("/incidents/:id", path))) page = <IncidentDetailPage key={m.id} id={Number(m.id)} me={me} />;
  else if (path === "/events") page = <EventsPage />;
  else if (path === "/rules") page = <RulesPage me={me} />;
  else if (path === "/rules/new") page = <RuleEditorPage key="new" id={null} me={me} />;
  else if ((m = match("/rules/:id", path))) page = <RuleEditorPage key={m.id} id={m.id} me={me} />;
  else if (path === "/report") page = <ReportPage me={me} />;
  else if (path === "/response") page = <ResponsePage me={me} />;
  else if ((m = match("/ip/:addr", path))) page = <IpPage key={m.addr} addr={m.addr} me={me} />;
  else if (path === "/agents") page = <AgentsPage me={me} />;
  else if (path === "/connect") page = <ConnectSitePage me={me} />;
  else
    page = (
      <div className="page">
        <h1>Страница не найдена</h1>
        <Link to="/">На главную</Link>
      </div>
    );

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Icon name="shield" size={22} />
          <span>Sentinel</span>
        </div>
        <nav>
          {NAV.map((n) => {
            const active = n.to === "/" ? path === "/" : path.startsWith(n.to);
            return (
              <Link key={n.to} to={n.to} className={active ? "active" : ""}>
                <Icon name={n.icon} />
                <span>{n.label}</span>
                {n.to === "/alerts" && newAlerts > 0 && <span className="nav-count">{newAlerts > 99 ? "99+" : newAlerts}</span>}
              </Link>
            );
          })}
        </nav>
        <div className="sidebar-foot">
          <div className={`live-dot ${live.state}`} title="Живая лента">
            <span />
            {live.state === "online" ? "На связи" : live.state === "connecting" ? "Подключение…" : "Нет связи"}
          </div>
          <div className="whoami">
            <b>{me.name}</b>
            <small>{roleLabel[me.role] ?? me.role}</small>
          </div>
          <button className="btn btn-ghost" onClick={onLogout}>
            <Icon name="logout" size={16} />
            Выйти
          </button>
        </div>
      </aside>
      <main className="main">{page}</main>
    </div>
  );
}
