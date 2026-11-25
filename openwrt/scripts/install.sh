#!/bin/sh
set -eu

REPO_BASE="${NORT_REPO_BASE:-https://github.com/nurbsn/nOpenWrtRemote/releases/latest/download}"
VERSION="1.0.0-1"

ARCH=""
if command -v opkg >/dev/null 2>&1; then
	ARCH="$(opkg print-architecture | awk '{print $2}' | grep -v '^all$' | grep -v '^noarch$' | tail -n1)"
elif command -v apk >/dev/null 2>&1; then
	ARCH="$(apk --print-arch)"
fi

if [ -z "$ARCH" ]; then
	echo "Nie udało się wykryć architektury OpenWrt." >&2
	exit 1
fi

echo "Wykryta architektura: $ARCH"
TMP_DIR="/tmp/nort-install"
mkdir -p "$TMP_DIR"

AGENT_IPK="nopenwrtremote_${VERSION}_${ARCH}.ipk"
LUCI_IPK="luci-app-nopenwrtremote_${VERSION}_all.ipk"

curl -fsSL "${REPO_BASE}/${AGENT_IPK}" -o "${TMP_DIR}/${AGENT_IPK}"
curl -fsSL "${REPO_BASE}/${LUCI_IPK}" -o "${TMP_DIR}/${LUCI_IPK}"

if command -v opkg >/dev/null 2>&1; then
	opkg update
	opkg install libmbedtls libjson-c ca-bundle curl
	opkg install "${TMP_DIR}/${AGENT_IPK}" "${TMP_DIR}/${LUCI_IPK}"
else
	echo "Zainstaluj pobrane pakiety z ${TMP_DIR} zgodnie z menedżerem apk."
	exit 1
fi

/etc/init.d/nopenwrtremote enable
/etc/init.d/nopenwrtremote restart
rm -rf "$TMP_DIR"
echo "Gotowe! Otwórz w LuCI: Services -> nOpenWrtRemote i zeskanuj kod QR."
