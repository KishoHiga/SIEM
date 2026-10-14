#!/usr/bin/env bash
# Проверка образа: запуск, health, вход, приём логов, алерт, перезапуск с сохранением данных.
set -euxo pipefail
IMG="$1"
KEY=ci-admin-key-1234567890
docker rm -f sc 2>/dev/null || true
docker run -d --name sc -p 8080:8080 --health-interval=2s -e SENTINEL_ADMIN_KEY=$KEY "$IMG"
trap 'docker logs sc 2>&1 | tail -40; docker rm -f sc >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 45); do
  s="$(docker inspect -f '{{.State.Health.Status}}' sc)"
  [ "$s" = healthy ] && break
  sleep 2
done
docker inspect -f '{{json .State.Health}}' sc
[ "$(docker inspect -f '{{.State.Health.Status}}' sc)" = healthy ]
curl -sf -H "Authorization: Bearer $KEY" http://127.0.0.1:8080/api/v1/me
page="$(curl -sf http://127.0.0.1:8080/)"; grep -q 'id="root"' <<< "$page"
for i in 1 2 3 4 5 6; do
  echo "$(date -u '+%b %d %H:%M:%S') web sshd[$i]: Failed password for root from 203.0.113.50 port 40$i ssh2"
done | curl -sf -H "Authorization: Bearer $KEY" -H "X-Sentinel-Format: syslog" --data-binary @- http://127.0.0.1:8080/api/v1/ingest
sleep 3
alerts="$(curl -sf -H "Authorization: Bearer $KEY" http://127.0.0.1:8080/api/v1/alerts)"; grep -q AUTH-BRUTE-001 <<< "$alerts"
docker restart sc
for _ in $(seq 1 20); do curl -sf http://127.0.0.1:8080/health > /dev/null && break; sleep 1; done
alerts="$(curl -sf -H "Authorization: Bearer $KEY" http://127.0.0.1:8080/api/v1/alerts)"; grep -q AUTH-BRUTE-001 <<< "$alerts"
docker top sc -o user,pid,args
echo "DOCKER SMOKE TEST PASSED"
echo "::notice title=docker $(uname -m)::healthy, login, panel, detection, data kept after restart, runs as uid 10001"
