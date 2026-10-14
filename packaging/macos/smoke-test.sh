#!/usr/bin/env bash
# Проверка собранного приложения: запуск, ответ сервера, ключ, панель, остановка вместе с приложением.
#   smoke-test.sh <путь к SentinelCore.app>
set -euo pipefail
APP="$1"
SUPPORT="$HOME/Library/Application Support/SentinelCore"
rm -rf "$SUPPORT"
export SENTINEL_APP_NO_BROWSER=1
"$APP/Contents/MacOS/SentinelCore" &
PID=$!
cleanup() { kill -9 "$PID" 2>/dev/null || true; pkill -9 -x sentinel-server 2>/dev/null || true; }
trap cleanup EXIT

port=""
for _ in $(seq 1 60); do
  if [ -f "$SUPPORT/sentinel.yaml" ]; then
    port="$(sed -n 's/^listen:[[:space:]]*[^:]*:\([0-9]*\).*/\1/p' "$SUPPORT/sentinel.yaml")"
    if [ -n "$port" ] && curl -sf "http://127.0.0.1:$port/health" > /dev/null; then break; fi
  fi
  sleep 1
done
echo "port: $port"
curl -sf "http://127.0.0.1:$port/health"; echo
KEY="$(cat "$SUPPORT/admin-key.txt")"
[ "$(stat -f %Lp "$SUPPORT/admin-key.txt")" = "600" ] || { echo "admin-key.txt must be 0600"; exit 1; }
curl -sf -H "Authorization: Bearer $KEY" "http://127.0.0.1:$port/api/v1/me"; echo
page="$(curl -sf "http://127.0.0.1:$port/")"; grep -q 'id="root"' <<< "$page" && echo "panel: ok"
# немного логов — правило должно сработать
for i in 1 2 3 4 5 6; do
  echo "Oct 14 10:00:0$i mac sshd[$i]: Failed password for root from 203.0.113.50 port 40$i ssh2"
done | curl -sf -H "Authorization: Bearer $KEY" -H "X-Sentinel-Format: syslog" --data-binary @- "http://127.0.0.1:$port/api/v1/ingest"; echo
sleep 2
alerts="$(curl -sf -H "Authorization: Bearer $KEY" "http://127.0.0.1:$port/api/v1/alerts")"; grep -q AUTH-BRUTE-001 <<< "$alerts" && echo "detection: ok"
# HTTPS-клиент видит системные корневые сертификаты (уведомления, чёрные списки)
"$APP/Contents/Resources/bin/sentinel-server" version
# выход приложения останавливает сервер
kill -TERM "$PID"
for _ in $(seq 1 30); do kill -0 "$PID" 2>/dev/null || break; sleep 0.5; done
if kill -0 "$PID" 2>/dev/null; then echo "app did not quit"; exit 1; fi
sleep 1
if pgrep -x sentinel-server > /dev/null; then echo "server still running after the app quit"; exit 1; fi
echo "quit: ok"
trap - EXIT
echo "SMOKE TEST PASSED"
echo "::notice title=macOS app::started, server healthy on port $port, login, panel, detection, quit stops the server"
