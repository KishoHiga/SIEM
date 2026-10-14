#!/usr/bin/env bash
# OpenSSL для приложения: статические библиотеки сразу для Apple Silicon и Intel (universal).
# В macOS нет общедоступной системной OpenSSL, поэтому она вшивается в программу.
#   build-openssl.sh <куда установить>
set -euo pipefail
VER="${OPENSSL_VERSION:-3.5.9}"
OUT="$1"
MINOS="${MACOSX_DEPLOYMENT_TARGET:-12.0}"
work="$(mktemp -d)"
cd "$work"
base="https://github.com/openssl/openssl/releases/download/openssl-$VER"
curl -fsSLO "$base/openssl-$VER.tar.gz"
curl -fsSLO "$base/openssl-$VER.tar.gz.sha256"
echo "$(awk '{print $1}' "openssl-$VER.tar.gz.sha256")  openssl-$VER.tar.gz" | shasum -a 256 -c -
for arch in arm64 x86_64; do
  mkdir -p "src-$arch"
  tar -xzf "openssl-$VER.tar.gz" -C "src-$arch" --strip-components=1
  (
    cd "src-$arch"
    # openssldir=/private/etc/ssl — корневые сертификаты macOS (/etc/ssl/cert.pem)
    ./Configure "darwin64-$arch-cc" no-shared no-tests no-docs \
      --prefix="$work/inst-$arch" --openssldir=/private/etc/ssl "-mmacosx-version-min=$MINOS"
    make -j"$(sysctl -n hw.ncpu)" build_libs > /dev/null
    make install_dev > /dev/null
  )
done
mkdir -p "$OUT/lib"
rm -rf "$OUT/include"
cp -R "inst-arm64/include" "$OUT/include"
for lib in libssl.a libcrypto.a; do
  lipo -create "inst-arm64/lib/$lib" "inst-x86_64/lib/$lib" -output "$OUT/lib/$lib"
done
lipo -info "$OUT/lib/libssl.a"
rm -rf "$work"
