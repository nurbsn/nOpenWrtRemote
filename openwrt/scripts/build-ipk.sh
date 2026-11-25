#!/usr/bin/env bash
set -euo pipefail

# Buduje pakiety .ipk (agent w C11 + LuCI JS) za pomocą oficjalnych obrazów OpenWrt 24.10 SDK (Docker).
# Przykładowe użycie: ./scripts/build-ipk.sh x86-64-24.10.8 mediatek-filogic-24.10.8 ramips-mt7621-24.10.8

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
DIST_DIR="$ROOT_DIR/openwrt/dist"
mkdir -p "$DIST_DIR"

TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
  TARGETS=(
    "x86-64-24.10.8"
    "mediatek-filogic-24.10.8"
    "ramips-mt7621-24.10.8"
    "ath79-generic-24.10.8"
    "ipq40xx-generic-24.10.8"
  )
fi

SECP_CACHE="$ROOT_DIR/openwrt/.cache"
mkdir -p "$SECP_CACHE"
if [ ! -f "$SECP_CACHE/secp256k1-0.6.0.tar.gz" ]; then
  curl -fsSL "https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.6.0.tar.gz" \
    -o "$SECP_CACHE/secp256k1-0.6.0.tar.gz"
fi

for sdk_tag in "${TARGETS[@]}"; do
  echo "=== Building OpenWrt .ipk packages for SDK: $sdk_tag ==="
  out_sub="$DIST_DIR/$sdk_tag"
  mkdir -p "$out_sub"
  chmod 777 "$out_sub"

  docker run --rm \
    -v "$ROOT_DIR:/src:ro" \
    -v "$SECP_CACHE:/dl_cache:ro" \
    -v "$out_sub:/out" \
    "openwrt/sdk:$sdk_tag" \
    bash -lc '
      set -euo pipefail
      if [ -x ./setup.sh ]; then ./setup.sh; fi
      ./scripts/feeds update base packages luci
      ./scripts/feeds install libmbedtls json-c ca-bundle luci-base
      mkdir -p dl package/custom/nopenwrtremote/src package/custom/luci-app-nopenwrtremote
      cp /dl_cache/secp256k1-0.6.0.tar.gz dl/
      cp /src/openwrt/package/nopenwrtremote/Makefile package/custom/nopenwrtremote/
      cp -a /src/openwrt/agent/. package/custom/nopenwrtremote/src/
      cp -a /src/openwrt/luci-app-nopenwrtremote/. package/custom/luci-app-nopenwrtremote/
      make defconfig
      make package/custom/nopenwrtremote/compile V=s
      make package/custom/luci-app-nopenwrtremote/compile V=s
      find bin -name "*nopenwrtremote*.ipk" -exec cp {} /out/ \;
      ls -lh /out/
    '
done
