#!/usr/bin/env bash
# Выполнить команду; при ошибке — последние строки вывода в аннотацию (видна через API и в списке проверок).
set -u
out="$(mktemp)"
"$@" 2>&1 | tee "$out"
status=${PIPESTATUS[0]}
if [ "$status" -ne 0 ]; then
  msg="$( { echo "exit code $status: $*"; grep -iE "error|fail|not found|denied" "$out" | tail -n 25; echo '--- last lines ---'; tail -n 40 "$out"; } \
          | sed -e 's/%/%25/g' | awk 'BEGIN{ORS="%0A"} {print}')"
  echo "::error title=step failed::${msg}"
fi
exit "$status"
