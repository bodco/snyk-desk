#!/bin/bash
# Installs or updates Snyk Desk from the latest GitHub release.
# Files downloaded by curl are not quarantined, so macOS does not show
# "Apple could not verify ... is free of malware".
# Usage: curl -fsSL https://raw.githubusercontent.com/bodco/snyk-desk/main/scripts/install.sh | bash
set -euo pipefail

API="https://api.github.com/repos/bodco/snyk-desk/releases/latest"
DEST="/Applications/Snyk Desk.app"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

URL="$(curl -fsSL "$API" | /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(a["browser_download_url"] for a in d["assets"] if a["name"].endswith(".zip")))')"
echo "Downloading $URL"
curl -fsSL -o "$TMP/app.zip" "$URL"
/usr/bin/ditto -x -k "$TMP/app.zip" "$TMP/out"

if pgrep -x SnykDesk > /dev/null; then
  echo "Closing Snyk Desk"
  osascript -e 'tell application "Snyk Desk" to quit' > /dev/null 2>&1 || true
  sleep 2
fi
rm -rf "$DEST"
/usr/bin/ditto "$TMP/out/Snyk Desk.app" "$DEST"
/usr/bin/xattr -dr com.apple.quarantine "$DEST" 2>/dev/null || true
echo "Installed $DEST"
open "$DEST"
