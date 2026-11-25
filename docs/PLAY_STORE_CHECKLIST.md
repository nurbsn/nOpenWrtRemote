# Checklista publikacji w Google Play — nOpenWrtRemote

Identyfikator aplikacji (`ApplicationId`): `eu.gfmm.nopenwrtremote`  
Domena i polityka prywatności: `https://gfmm.eu/nopenwrtremote/privacy`

---

## 1. Przygotowanie infrastruktury `gfmm.eu` (przed zgłoszeniem w Play Console)

1. Zbuduj i wdróż projekt `cloudflare-relay/`:
   - Skonfiguruj strefę DNS dla `gfmm.eu` w Cloudflare oraz subdomenę `relay.gfmm.eu` (rekord `A`/`AAAA` proxied, np. `192.0.2.1` obsługiwany przez Worker Route).
   - Odkomentuj sekcję `routes` w `cloudflare-relay/wrangler.jsonc`:
     - `relay.gfmm.eu/*`
     - `gfmm.eu/nopenwrtremote*`
   - Wykonaj `npx wrangler deploy`.
2. Zweryfikuj działające adresy HTTPS:
   - `https://gfmm.eu/nopenwrtremote/privacy` — zwraca kod `200 OK` z pełną polityką prywatności.
   - `https://relay.gfmm.eu/health` — zwraca `{ "ok": true }`.
   - `curl -H "Accept: application/nostr+json" https://relay.gfmm.eu/` — zwraca dokument NIP-11.

---

## 2. Klucz podpisujący (Upload Keystore) i budowanie paczki AAB

1. Wygeneruj klucz uploadowy (przechowuj go bezpiecznie poza repozytorium Git!):
   ```powershell
   keytool -genkeypair -v -keystore nopenwrtremote-upload.keystore -alias upload -keyalg RSA -keysize 2048 -validity 10000
   ```
2. Włącz **Play App Signing** w Google Play Console (Google zarządza głównym kluczem dystrybucyjnym).
3. Zbuduj podpisany plik `.aab` w trybie `Release`:
   ```powershell
   cd android-maui
   dotnet publish src/nOpenWrtRemote.App/nOpenWrtRemote.App.csproj `
     -f net10.0-android `
     -c Release `
     -p:AndroidKeyStore=true `
     -p:AndroidSigningKeyStore=C:\sciezka\do\nopenwrtremote-upload.keystore `
     -p:AndroidSigningKeyAlias=upload `
     -p:AndroidSigningStorePass=<HASLO> `
     -p:AndroidSigningKeyPass=<HASLO>
   ```
4. Wynikowy pakiet `.aab` znajdziesz w:
   `android-maui/src/nOpenWrtRemote.App/bin/Release/net10.0-android/publish/eu.gfmm.nopenwrtremote-Signed.aab`.

---

## 3. Ustawienia w Google Play Console

### 3.1 Szczegóły aplikacji (Store Listing)
- **Nazwa aplikacji**: `nOpenWrtRemote`
- **Krótki opis (do 80 znaków)**: `Bezpieczne zdalne zarządzanie routerem OpenWrt i LuCI z szyfrowaniem E2EE`
- **Kategoria**: Narzędzia (`Tools`)
- **E-mail kontaktowy**: np. `support@gfmm.eu` / `privacy@gfmm.eu`
- **Strona www**: `https://gfmm.eu/nopenwrtremote`

### 3.2 Deklaracje bezpieczeństwa danych (Data Safety)
Ponieważ `relay.gfmm.eu` jest ślepym przekaźnikiem zero-knowledge i nie zbiera danych osobowych ani telemetrii:
- **Czy aplikacja gromadzi lub udostępnia dane użytkowników?**: **Nie** (klucze kryptograficzne i lista routerów pozostają wyłącznie lokalnie na urządzeniu w `SecureStorage` z wyłączonym `allowBackup`).
- **Szyfrowanie w tranzycie**: **Tak** (TLS 1.3 + E2EE NIP-44 v2 / AES-256-GCM).
- **Brak reklam i SDK analitycznych**: brak AdMob, Firebase Analytics itp.

### 3.3 Uprawnienia i deklaracje techniczne
- `CAMERA`: wykorzystywane **wyłącznie** na żądanie użytkownika w ekranie skanowania kodu QR parowania routera. W `AndroidManifest.xml` ustawiono `android:required="false"`, dzięki czemu aplikacja jest dostępna również na tabletach/urządzeniach bez aparatu (możliwe ręczne wklejenie URI `nopenwrt://pair?...`).
- `USE_BIOMETRIC`: lokalne odblokowanie aplikacji przez systemowy `BiometricPrompt`.
- `INTERNET` + `ACCESS_NETWORK_STATE`: połączenie wychodzące z relayem Nostr/tunelu (`wss://`).
- **Brak `VpnService`**: nie wymaga składania specjalnej deklaracji VPN w Play Console.
- **Cleartext HTTP**: `network_security_config.xml` blokuje nieszyfrowany ruch HTTP dla całego internetu (`cleartextTrafficPermitted="false"`) z jedynym wyjątkiem pętli zwrotnej `127.0.0.1` dla wewnętrznego proxy LuCI WebView.

### 3.4 Konto testowe / instrukcje dla recenzenta Google Play
W sekcji *Dostęp do aplikacji* w Play Console zaznacz, że aplikacja wymaga własnego urządzenia OpenWrt lub sparowania z routerem testowym i podaj w instrukcji:
- Użytkownik może przetestować aplikację bez fizycznego routera korzystając z dołączonego w repozytorium narzędzia `MockRouter` lub skanując własny kod QR z LuCI (`Services → nOpenWrtRemote`).
- Opcjonalnie na czas recenzji uruchom jedną instancję `nOpenWrtRemote.MockRouter` z testowym URI `nopenwrt://pair?...` w polu uwag dla recenzenta.
