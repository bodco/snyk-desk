#!/bin/bash
# Builds "Snyk Desk.app" and a zip in dist/. Usage: scripts/make-app.sh [version]
set -euo pipefail

VERSION="${1:-0.0.0-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

swift build -c release --arch arm64
BIN="$(swift build -c release --arch arm64 --show-bin-path)"

APP="dist/Snyk Desk.app"
rm -rf dist
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/SnykDesk" "$APP/Contents/MacOS/SnykDesk"
sed "s/__VERSION__/$VERSION/g" Resources/Info.plist > "$APP/Contents/Info.plist"

# App icon: Resources/AppIcon.png (1024 px) becomes AppIcon.icns.
ICONSET="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
  sips -z $size $size Resources/AppIcon.png --out "$ICONSET/icon_${size}x${size}.png" > /dev/null
  sips -z $((size * 2)) $((size * 2)) Resources/AppIcon.png --out "$ICONSET/icon_${size}x${size}@2x.png" > /dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"

# Ad-hoc signature: enough to run locally, not notarized.
codesign --force --deep --sign - "$APP"

(cd dist && ditto -c -k --keepParent "Snyk Desk.app" "SnykDesk-$VERSION.zip")
echo "Built dist/SnykDesk-$VERSION.zip"
