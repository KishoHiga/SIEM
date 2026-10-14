#!/bin/sh
# Запуск SentinelCore в контейнере: готовит том /data и запускает сервер от непривилегированного пользователя.
set -e
CONFIG="${SENTINEL_CONFIG:-/etc/sentinel/sentinel.yaml}"

case "$1" in
  run|keygen|gen-cert|enroll-token|test-rules|geo-import|geo-lookup|healthcheck|version|help) ;;
  *) exec "$@" ;;  # своя команда (например, sh)
esac

if [ "$(id -u)" = "0" ]; then
  mkdir -p /data
  # том мог прийти от хоста с другим владельцем
  if [ "$(stat -c %u /data)" != "10001" ]; then chown -R 10001:10001 /data; fi
  if [ ! -d /data/rules ]; then
    cp -r /usr/share/sentinel/rules /data/rules
    chown -R 10001:10001 /data/rules
  fi
  exec setpriv --reuid=10001 --regid=10001 --init-groups sentinel-server "$@" -c "$CONFIG"
fi

[ -d /data/rules ] || cp -r /usr/share/sentinel/rules /data/rules
exec sentinel-server "$@" -c "$CONFIG"
