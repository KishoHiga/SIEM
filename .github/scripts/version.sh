#!/usr/bin/env bash
# Версия сборки: из метки v*, из поля «Выпустить версию» или из CMakeLists.txt.
# При выпуске версия обязана совпадать с CMakeLists.txt — чтобы программа и релиз не расходились.
set -euo pipefail
cmake_v="$(sed -n 's/^project(SentinelCore VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)"
v=""
if [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then v="${GITHUB_REF#refs/tags/v}"; fi
if [ -n "${RELEASE_INPUT:-}" ]; then v="${RELEASE_INPUT#v}"; fi
if [ -z "$v" ]; then echo "$cmake_v"; exit 0; fi
if [ "$v" != "$cmake_v" ]; then
  echo "::error title=version::release $v does not match CMakeLists.txt ($cmake_v)" >&2
  exit 1
fi
echo "$v"
