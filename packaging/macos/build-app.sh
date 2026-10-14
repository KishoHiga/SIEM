#!/usr/bin/env bash
# Сборка SentinelCore.app и SentinelCore-<версия>-macOS.dmg (universal: Apple Silicon + Intel).
#   build-app.sh <версия> <папка OpenSSL из build-openssl.sh> <папка результата>
set -euo pipefail
VERSION="$1"
OPENSSL="$2"
OUT="$3"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/packaging/macos"
MINOS="${MACOSX_DEPLOYMENT_TARGET:-12.0}"
export MACOSX_DEPLOYMENT_TARGET="$MINOS"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
BUILD="$ROOT/build-macos"

echo "== сервер и агент (arm64 + x86_64)"
cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" -DCMAKE_OSX_DEPLOYMENT_TARGET="$MINOS" \
  -DOPENSSL_ROOT_DIR="$OPENSSL" -DOPENSSL_USE_STATIC_LIBS=TRUE
cmake --build "$BUILD" -j "$(sysctl -n hw.ncpu)"
lipo -info "$BUILD/sentinel-server"
if otool -L "$BUILD/sentinel-server" | grep -qi ssl; then
  echo "ошибка: OpenSSL подключён как внешняя библиотека, а должен быть внутри программы" >&2
  exit 1
fi

echo "== панель"
(cd "$ROOT/web" && npm ci --no-audit --no-fund && npm run build)

echo "== программа строки меню"
for arch in arm64 x86_64; do
  swiftc -O -target "$arch-apple-macos$MINOS" -o "$BUILD/SentinelCore-$arch" "$HERE/SentinelCore.swift" -framework AppKit
done
lipo -create "$BUILD/SentinelCore-arm64" "$BUILD/SentinelCore-x86_64" -output "$BUILD/SentinelCore"

echo "== значок"
ICONSET="$BUILD/AppIcon.iconset"
rm -rf "$ICONSET" && mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s "$HERE/AppIcon.png" --out "$ICONSET/icon_${s}x${s}.png" > /dev/null
  sips -z $((s * 2)) $((s * 2)) "$HERE/AppIcon.png" --out "$ICONSET/icon_${s}x${s}@2x.png" > /dev/null
done
iconutil -c icns "$ICONSET" -o "$BUILD/AppIcon.icns"

echo "== SentinelCore.app"
APP="$OUT/SentinelCore.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/bin"
sed "s/@VERSION@/$VERSION/g" "$HERE/Info.plist" > "$APP/Contents/Info.plist"
cp "$BUILD/SentinelCore" "$APP/Contents/MacOS/SentinelCore"
cp "$BUILD/sentinel-server" "$BUILD/sentinel-agent" "$APP/Contents/Resources/bin/"
cp -R "$ROOT/web/dist" "$APP/Contents/Resources/web"
cp -R "$ROOT/rules" "$APP/Contents/Resources/rules"
cp "$ROOT/sentinel.example.yaml" "$APP/Contents/Resources/"
cp "$BUILD/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
# подпись без сертификата разработчика (ad-hoc): без неё macOS на Apple Silicon не запустит программу
codesign --force --sign - "$APP/Contents/Resources/bin/sentinel-server"
codesign --force --sign - "$APP/Contents/Resources/bin/sentinel-agent"
codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP"

echo "== DMG"
STAGE="$BUILD/dmg"
rm -rf "$STAGE" && mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
cp "$HERE/README-dmg.txt" "$STAGE/Как открыть в первый раз.txt"
DMG="$OUT/SentinelCore-$VERSION-macOS.dmg"
rm -f "$DMG"
hdiutil create -volname "SentinelCore $VERSION" -srcfolder "$STAGE" -ov -format UDZO "$DMG" > /dev/null

echo "== архив с программами для командной строки"
CLI="$BUILD/sentinel-$VERSION-macos"
rm -rf "$CLI" && mkdir -p "$CLI"
cp "$APP/Contents/Resources/bin/sentinel-server" "$APP/Contents/Resources/bin/sentinel-agent" "$CLI/"
cp -R "$ROOT/rules" "$CLI/rules"
cp -R "$ROOT/web/dist" "$CLI/web"
cp "$ROOT/sentinel.example.yaml" "$ROOT/README.md" "$CLI/"
tar -czf "$OUT/sentinel-$VERSION-macos-universal.tar.gz" -C "$BUILD" "sentinel-$VERSION-macos"

ls -la "$OUT"
