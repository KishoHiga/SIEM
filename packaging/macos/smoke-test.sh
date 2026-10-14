#!/usr/bin/env bash
# Проверка собранного приложения на чистой учётной записи:
#  1) порт 8080 занят «чужим сайтом» — приложение берёт другой и чужой сайт не трогает;
#  2) сервер отвечает, ключ, панель, обнаружение атаки;
#  3) выход приложения останавливает сервер;
#  4) в настройках снова 8080 (занят) — при запуске приложение само переезжает на свободный порт.
#   smoke-test.sh <путь к SentinelCore.app>
set -euo pipefail
APP="$1"
SUPPORT="$HOME/Library/Application Support/SentinelCore"
CONFIG="$SUPPORT/sentinel.yaml"
rm -rf "$SUPPORT"
export SENTINEL_APP_NO_BROWSER=1

# «чужой сайт» на всех адресах порта 8080
SITE_DIR="$(mktemp -d)"
echo "other site" > "$SITE_DIR/index.html"
python3 -m http.server 8080 --bind 0.0.0.0 --directory "$SITE_DIR" > /dev/null 2>&1 &
SITE=$!
APP_PID=""
cleanup() {
  [ -n "$APP_PID" ] && kill -9 "$APP_PID" 2>/dev/null || true
  pkill -9 -x sentinel-server 2>/dev/null || true
  kill "$SITE" 2>/dev/null || true
}
trap cleanup EXIT
for _ in $(seq 1 20); do curl -sf http://127.0.0.1:8080/ > /dev/null && break; sleep 0.5; done

start_app() {
  "$APP/Contents/MacOS/SentinelCore" &
  APP_PID=$!
  port=""
  for _ in $(seq 1 60); do
    if [ -f "$CONFIG" ]; then
      port="$(sed -n 's/^listen:[[:space:]]*[^:]*:\([0-9]*\).*/\1/p' "$CONFIG")"
      if [ -n "$port" ] && curl -sf "http://127.0.0.1:$port/health" > /dev/null; then return 0; fi
    fi
    sleep 1
  done
  echo "server did not start"; return 1
}

stop_app() {
  kill -TERM "$APP_PID"
  for _ in $(seq 1 30); do kill -0 "$APP_PID" 2>/dev/null || break; sleep 0.5; done
  if kill -0 "$APP_PID" 2>/dev/null; then echo "app did not quit"; exit 1; fi
  APP_PID=""
  sleep 1
  if pgrep -x sentinel-server > /dev/null; then echo "server still running after the app quit"; exit 1; fi
}

start_app
echo "port: $port"
[ "$port" != "8080" ] || { echo "took a busy port"; exit 1; }
[ "$(curl -sf http://127.0.0.1:8080/)" = "other site" ] || { echo "the other site on 8080 is shadowed"; exit 1; }
curl -sf "http://127.0.0.1:$port/health"; echo
KEY="$(cat "$SUPPORT/admin-key.txt")"
[ "$(stat -f %Lp "$SUPPORT/admin-key.txt")" = "600" ] || { echo "admin-key.txt must be 0600"; exit 1; }
curl -sf -H "Authorization: Bearer $KEY" "http://127.0.0.1:$port/api/v1/me"; echo
page="$(curl -sf "http://127.0.0.1:$port/")"; grep -q 'id="root"' <<< "$page" && echo "panel: ok"
for i in 1 2 3 4 5 6; do
  echo "Oct 14 10:00:0$i mac sshd[$i]: Failed password for root from 203.0.113.50 port 40$i ssh2"
done | curl -sf -H "Authorization: Bearer $KEY" -H "X-Sentinel-Format: syslog" --data-binary @- "http://127.0.0.1:$port/api/v1/ingest"; echo
sleep 2
alerts="$(curl -sf -H "Authorization: Bearer $KEY" "http://127.0.0.1:$port/api/v1/alerts")"; grep -q AUTH-BRUTE-001 <<< "$alerts" && echo "detection: ok"
"$APP/Contents/Resources/bin/sentinel-server" version
stop_app
echo "quit: ok"

# в настройках занятый порт — приложение должно само переехать
sed -i '' 's/^listen:.*/listen: 127.0.0.1:8080/' "$CONFIG"
start_app
echo "moved to port: $port"
[ "$port" != "8080" ] || { echo "did not move off the busy port"; exit 1; }
[ "$(curl -sf http://127.0.0.1:8080/)" = "other site" ] || { echo "the other site on 8080 is shadowed"; exit 1; }
curl -sf -H "Authorization: Bearer $KEY" "http://127.0.0.1:$port/api/v1/me" > /dev/null && echo "same data after move: ok"
stop_app

# сервер сам тоже не займёт порт, на котором уже кто-то отвечает
TMPD="$(mktemp -d)"
printf 'listen: 127.0.0.1:8080\ndata_dir: %s/data\n' "$TMPD" > "$TMPD/s.yaml"
"$APP/Contents/Resources/bin/sentinel-server" run -c "$TMPD/s.yaml" > "$TMPD/srv.log" 2>&1 &
SRV=$!
sleep 3
if kill -0 "$SRV" 2>/dev/null; then kill "$SRV"; echo "server started on a busy port"; exit 1; fi
cat "$TMPD/srv.log"
grep -q "already used by another program" "$TMPD/srv.log" && echo "server refuses busy port: ok"

trap - EXIT
cleanup
echo "SMOKE TEST PASSED"
echo "::notice title=macOS app::starts next to another site on 8080 without touching it, moves off a busy port, server healthy, login, panel, detection, quit stops the server"
