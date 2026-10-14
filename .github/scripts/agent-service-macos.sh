#!/bin/bash
# Агент как фоновая служба на macOS: add -> service install -> работает -> uninstall.
set -euo pipefail
src="$1"
d="$RUNNER_TEMP/agent service test"   # пробел в пути — нарочно
mkdir -p "$d"
rm -f "$d/sentinel-agent"
cp "$src" "$d/sentinel-agent"
cat > "$d/agent.yaml" <<YAML
server: 'http://127.0.0.1:9'
key: 'snt_ci_dummy_key_0000000000000000'
autodiscover: false
firewall: none
YAML
log="$HOME/Library/Logs/SentinelCore/agent.log"
printf '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 5 "-" "curl"\n' > "$d/site.log"
cd "$d"
./sentinel-agent add "$d/site.log" --name ci
grep -q "source: 'ci'" agent.yaml
./sentinel-agent service install
ok=""
for _ in $(seq 1 20); do
  if ./sentinel-agent service status | grep -q "^Background service: running"; then ok=1; break; fi
  sleep 1
done
./sentinel-agent service status || true
if [ -z "$ok" ]; then
  echo "::error title=agent service::launchd did not start the agent"
  cat "$log" 2>/dev/null || true
  launchctl print "gui/$(id -u)/com.sentinelcore.agent" || true
  exit 1
fi
for _ in $(seq 1 10); do grep -q "watching .*site.log" "$log" 2>/dev/null && break; sleep 1; done
grep -q "watching .*site.log" "$log" || { echo "::error title=agent service::agent does not read the added file"; cat "$log"; exit 1; }
# новый файл подхватывается без перезапуска
printf '{"msg":"x"}\n' > "$d/second.log"
./sentinel-agent add "$d/second.log" --name ci2
for _ in $(seq 1 10); do grep -q "new source \[ci2\]" "$log" && break; sleep 1; done
grep -q "new source \[ci2\]" "$log" || { echo "::error title=agent service::running agent did not pick up 'add'"; cat "$log"; exit 1; }
./sentinel-agent service uninstall
if launchctl print "gui/$(id -u)/com.sentinelcore.agent" >/dev/null 2>&1; then
  echo "::error title=agent service::still loaded after uninstall"; exit 1
fi
test ! -e "$HOME/Library/LaunchAgents/com.sentinelcore.agent.plist"
echo "::notice title=agent service::launchd install, hot add and uninstall work"
