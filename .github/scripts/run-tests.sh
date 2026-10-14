#!/usr/bin/env bash
# Прогон тестов. При ошибке — сводка в аннотации (видна в списке проверок и через API).
set -u
bin="$1"; shift
out="$(mktemp)"
"$bin" "$@" > "$out" 2>&1
status=$?
tail -n 3 "$out"
if [ "$status" -eq 0 ]; then
  echo "::notice title=tests ($*)::$(grep -E 'tests,' "$out" | tail -n 1)"
fi
if [ "$status" -ne 0 ]; then
  {
    echo "exit code $status"
    grep -E "FAIL|mismatch|Sanitizer|terminate|Abort|Assertion|Segmentation|error:" "$out" | head -n 60
    echo "--- last lines ---"
    tail -n 40 "$out"
  } > "$out.sum"
  msg="$(sed -e 's/%/%25/g' "$out.sum" | awk 'BEGIN{ORS="%0A"} {print}')"
  echo "::error title=tests failed::${msg}"
  cat "$out"
fi
exit "$status"
