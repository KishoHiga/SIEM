// Вход в панель по ключу доступа (роль read / analyst / admin).
import { useState, type FormEvent } from "react";
import { api, ApiError } from "../api";
import { Icon } from "../components/Icons";
import { useTitle } from "../router";

export function LoginPage({ onLogin }: { onLogin: () => void }) {
  useTitle("Вход");
  const [key, setKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!key.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.login(key.trim());
      setKey("");
      onLogin();
    } catch (err) {
      const e2 = err as ApiError;
      if (e2.status === 401) setError("Неверный ключ.");
      else if (e2.status === 403) setError("Этот ключ только для отправки логов (агент). Нужен ключ с ролью read, analyst или admin.");
      else if (e2.status === 429) setError("Слишком много неудачных попыток. Подождите 5 минут.");
      else setError(e2.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <Icon name="shield" size={36} />
          <h1>Sentinel SIEM</h1>
          <p>Вход в панель мониторинга</p>
        </div>
        <label htmlFor="key">Ключ доступа</label>
        <input
          id="key"
          type="password"
          autoComplete="current-password"
          autoFocus
          placeholder="snt_…"
          value={key}
          onChange={(e) => setKey(e.target.value)}
        />
        {error && <div className="form-error">{error}</div>}
        <button className="btn btn-primary btn-block" disabled={busy || !key.trim()}>
          {busy ? "Проверка…" : "Войти"}
        </button>
        <p className="login-hint">
          Ключ администратора сервер печатает при первом запуске. Новый ключ:
          <code>sentinel-server keygen --name ivan --role analyst</code>
        </p>
      </form>
    </div>
  );
}
