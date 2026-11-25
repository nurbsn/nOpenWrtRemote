# nOpenWrtRemote

Bezpieczne, zdalne zarządzanie routerem **OpenWrt (LuCI + ubus)** z poziomu aplikacji **Android (.NET 10 MAUI)** bez otwierania żadnych portów na WAN, bez publicznego IP (działa za CGNAT) i bez `VpnService`.

## Architektura bezpieczeństwa (Protokół NORT-1)

```text
[nOpenWrtRemote (.NET 10 MAUI)]                [Router OpenWrt (za NAT/CGNAT)]
  Klucz secp256k1 w SecureStorage                LuCI (uhttpd) TYLKO 127.0.0.1/LAN
  + Biometria (AndroidX.Biometric)               Porty WAN: 100% ZAMKNIĘTE
  LocalLuciProxyServer (127.0.0.1)                       ▲
          │                                              │
          │  1. Sygnalizacja: Nostr NIP-01 + NIP-44 v2   │  2. Połączenie wychodzące WSS
          │     (kind 24135/24136, BIP-340 Schnorr)      │     (TLS 1.3)
          ▼                                              │
  ┌──────────────────────────────────────────────────────┴──────────────────┐
  │       Cloudflare Workers + Durable Objects (relay.gfmm.eu)              │
  │  • NostrRelayDO: ślepy router efemerycznych zdarzeń (zero bazy na dysku)│
  │  • TunnelRoomDO: ślepy przekażnik ramek binarnych (WebSocket Hibernation)│
  └─────────────────────────────────────────────────────────────────────────┘
          ▲                                              │
          └══ Tunel E2EE: Ephemeral secp256k1 ECDH ══════┘
              + HKDF-SHA256 + AES-256-GCM (PFS)
              Przekazuje żądania HTTP (LuCI) i /ubus JSON-RPC
```

### Kluczowe gwarancje bezpieczeństwa
1. **Zero wystawiania LuCI na internet** — agent OpenWrt (`nopenwrtremote-agent`) wykonuje wyłącznie połączenia wychodzące (`wss://relay.gfmm.eu`) i przekazuje ruch lokalnie do `http://127.0.0.1:80`.
2. **Zero-Knowledge Cloudflare Relay** — zarówno warstwa sygnalizacji (Nostr NIP-44 v2), jak i tunel danych (efemeryczny ECDH `secp256k1` + HKDF-SHA256 + kierunkowe klucze **AES-256-GCM** z monotonicznymi licznikami `uint64`) są szyfrowane End-to-End. Cloudflare przekazuje wyłącznie zaszyfrowane ramki i nie przechowuje żadnych logów ani kluczy.
3. **Pełne LuCI na zdalnym routerze + Natywny Dashboard** — aplikacja Android udostępnia natywny pulpit telemetryczny (`ubus`) oraz pełny interfejs **LuCI** serwowany bezpiecznie przez lokalny serwer proxy `127.0.0.1:<port>` z tokenem sesji `HttpOnly; SameSite=Strict` i lokalnym cache zasobów `/luci-static/*`.
4. **Gotowość pod Google Play (`eu.gfmm.nopenwrtremote`)** — bez `VpnService`, z polityką prywatności pod `https://gfmm.eu/nopenwrtremote/privacy` i `allowBackup="false"`.

---

## Struktura repozytorium

- `docs/PROTOCOL.md` — specyfikacja kryptograficzna i binarna protokołu **NORT-1**
- `docs/PLAY_STORE_CHECKLIST.md` — instrukcja publikacji w Google Play Console (`eu.gfmm.nopenwrtremote`)
- `cloudflare-relay/` — Cloudflare Worker + Durable Objects (`NostrRelayDO`, `TunnelRoomDO`) + strony `gfmm.eu/nopenwrtremote` i `/privacy`
- `openwrt/agent/` — ultra-lekki daemon w **czystym C11** (`nopenwrtremote-agent`, **~120 KB `.ipk`**, `libmbedtls` + `libjson-c` + `secp256k1`, działa także na routerach 16 MB flash!)
- `openwrt/luci-app-nopenwrtremote/` — natywny interfejs **LuCI JS** (parowanie kodem QR SVG offline, lista urządzeń, ustawienia UCI, skrypt `rpcd` + `procd`)
- `openwrt/scripts/` — skrypty budowania paczek `.ipk` przez OpenWrt 24.10 SDK (`build-ipk.sh`) oraz instalacji (`install.sh`)
- Repozytorium GitHub: `https://github.com/nurbsn/nOpenWrtRemote`
- `android-maui/` — solucja **.NET 10**:
  - `src/nOpenWrtRemote.Core` — kryptografia (`NBitcoin.Secp256k1`, NIP-44 v2, BIP-340 Schnorr, `TunnelCrypto` AES-256-GCM), klient Nostr, sesja tunelu, `LocalLuciProxyServer`, klient `ubus`
  - `src/nOpenWrtRemote.App` — aplikacja Android **.NET 10 MAUI**
  - `src/nOpenWrtRemote.MockRouter` — symulator routera OpenWrt (mock LuCI + `/ubus` + pełny protokół NORT-1) do testów bez fizycznego routera
  - `tests/nOpenWrtRemote.Core.Tests` — testy kryptografii (wektory RFC 8439, NIP-44 v2, BIP-340, PFS) i pełny test End-to-End tunelu + proxy LuCI

---

## Szybki start

### 1. Wdrożenie Cloudflare Relay (`relay.gfmm.eu` i `gfmm.eu`)
```bash
cd cloudflare-relay
npm install
npm run typecheck
npm test
# Lokalny test (ws://127.0.0.1:8787):
npx wrangler dev
# Wdrożenie produkcyjne (odkomentuj routes w wrangler.jsonc dla gfmm.eu):
npx wrangler deploy
```

### 2. Instalacja na routerze OpenWrt (C11, ~120 KB)
Zbudowanie paczek `.ipk` przez oficjalne obrazy Dockera OpenWrt 24.10 SDK:
```bash
cd openwrt
./scripts/build-ipk.sh
```
Lokalna kompilacja testów C11 na Linuksie:
```bash
cd openwrt/agent
cmake -B build -DCMAKE_BUILD_TYPE=MinSizeRel && cmake --build build && ctest --test-dir build --output-on-failure
```
Po instalacji na routerze otwórz w LuCI: **Services → nOpenWrtRemote** i kliknij **Paruj urządzenie Android (Kod QR)**.

### 3. Test lokalny z `MockRouter` (bez fizycznego routera)
Terminal 1 (lokalny relay Cloudflare):
```bash
cd cloudflare-relay && npx wrangler dev --port 8787
```
Terminal 2 (symulator routera OpenWrt):
```bash
cd android-maui
dotnet run --project src/nOpenWrtRemote.MockRouter -- --relay ws://127.0.0.1:8787
```
Terminal 3 (testy jednostkowe i E2E):
```bash
cd android-maui
dotnet test tests/nOpenWrtRemote.Core.Tests/nOpenWrtRemote.Core.Tests.csproj
```
Skopiuj wygenerowany link `nopenwrt://pair?...` z `MockRouter` i wklej go w ekranie parowania w aplikacji Android (`nOpenWrtRemote.App`).

### 4. Budowa aplikacji Android (.NET 10 MAUI)
```bash
cd android-maui
dotnet build src/nOpenWrtRemote.App/nOpenWrtRemote.App.csproj -f net10.0-android
```
Publikacja paczki `.aab` do Google Play została opisana w [PLAY_STORE_CHECKLIST.md](docs/PLAY_STORE_CHECKLIST.md).
