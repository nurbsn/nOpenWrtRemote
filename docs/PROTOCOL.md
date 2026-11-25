# Specyfikacja protokołu NORT-1 (nOpenWrtRemote Transport v1)

Wersja dokumentu: `1.0`  
Domyślny relay produkcyjny: `wss://relay.gfmm.eu`

---

## 1. Przegląd dwuwarstwowy

Protokół **NORT-1** rozdziela warstwę odkrywania/sygnalizacji od warstwy strumieniowania binarnego HTTP/ubus:

1. **Warstwa sygnalizacji (Control Plane)** — oparta na **Nostr** (**NIP-01** + **NIP-44 v2** + **NIP-19**):
   - Urządzenie Android (klient) i agent na routerze OpenWrt posiadają trwałe pary kluczy `secp256k1` (`npub` / `nsec`).
   - Wszystkie komunikaty kontrolne są przesyłane jako zdarzenia **efemeryczne** (`kind: 24135` dla żądań klienta, `kind: 24136` dla odpowiedzi routera), podpisane schematem **BIP-340 Schnorr** i zaszyfrowane w treści metodą **NIP-44 v2** (ECDH + HKDF-SHA256 + padding + ChaCha20 + HMAC-SHA256).
   - Relay Nostr (`NostrRelayDO` na Cloudflare) weryfikuje jedynie poprawność schematu, podpis BIP-340, okno czasowe (`±300 s`) i zakres efemeryczny (`20000..29999`), po czym przekazuje zdarzenie w pamięci RAM bez zapisywania go na dysku.

2. **Warstwa danych (Data Plane)** — efemeryczny tunel WebSocket z **Perfect Forward Secrecy (PFS)**:
   - Klient inicjuje sesję wysyłając zaszyfrowane zdarzenie `tunnel_open` z nowym, efemerycznym kluczem publicznym `client_eph_pub`, losowym `session_id` (16–32 bajty hex), adresem `relay_tunnel_url` oraz `router_token`.
   - Router weryfikuje tożsamość klienta (lista sparowanych kluczy), sprawdza adres `relay_tunnel_url` przeciwko białej liście (ochrona SSRF), generuje własny klucz efemeryczny `router_eph_pub`, odsyła `tunnel_ack` po Nostr i łączy się wychodząco z `TunnelRoomDO`.
   - Obie strony wyliczają niezależne klucze sesyjne **AES-256-GCM** powiązane z transkryptem handshake'u. Cloudflare `TunnelRoomDO` widzi wyłącznie nieprzejrzyste ramki binarne.

---

## 2. Format kodu QR parowania (`nopenwrt://pair`)

Generowany lokalnie w LuCI JS (SVG offline, bez zapytań zewnętrznych):

```text
nopenwrt://pair?v=1&npub=<bech32_router_npub>&relay=<url_encoded_wss_relay>&secret=<32_hex>&name=<url_encoded_router_name>&lan=<optional_lan_ip>
```

| Parametr | Wymagany | Opis |
| :--- | :---: | :--- |
| `v` | Tak | Wersja formatu parowania (`1`) |
| `npub` | Tak | Klucz publiczny routera w formacie NIP-19 Bech32 (`npub1...`) |
| `relay` | Tak | URL relaya Nostr (`wss://relay.gfmm.eu` lub `ws://127.0.0.1:...` w trybie dev) |
| `secret` | Tak | Jednorazowy 128-bitowy sekret parowania (32 znaki hex), ważny 300 sekund w pamięci RAM agenta |
| `name` | Nie | Nazwa routera (domyślnie hostname z UCI) |
| `lan` | Nie | Opcjonalny adres LAN routera (np. `192.168.1.1`) do podpowiedzi trybu lokalnego |

---

## 3. Komunikaty sygnalizacji Nostr (NIP-44 v2 JSON)

Zdarzenie Nostr:
- `kind: 24135` (klient → router), tag `["p", "<router_pubkey_hex>"]`
- `kind: 24136` (router → klient), tag `["p", "<client_pubkey_hex>"]` i `["e", "<request_event_id>"]`
- `created_at`: bieżący czas Unix UTC. Agent odrzuca komunikaty starsze/nowsze o ponad **60 sekund** oraz duplikaty `req_id` (okno anty-replay).

### 3.1 `pair_request` (`kind: 24135`)
```json
{
  "type": "pair_request",
  "v": 1,
  "req_id": "a1b2c3d4e5f6...",
  "ts": 1764090000,
  "secret": "9f8e7d6c...",
  "device_name": "Pixel 9 Pro"
}
```

### 3.2 `pair_ack` (`kind: 24136`)
```json
{
  "type": "pair_ack",
  "v": 1,
  "req_id": "a1b2c3d4e5f6...",
  "ok": true,
  "router_name": "Domowy-AX6000",
  "error": null
}
```
Po udanym parowaniu agent zużywa sekret natychmiast (one-time use) i zapisuje `npub` telefonu w `/etc/config/nopenwrtremote`.

### 3.3 `tunnel_open` (`kind: 24135`)
```json
{
  "type": "tunnel_open",
  "v": 1,
  "req_id": "f0e1d2c3...",
  "ts": 1764090120,
  "session_id": "64_char_lowercase_hex_or_32_char_hex",
  "relay_tunnel_url": "wss://relay.gfmm.eu/tunnel/<session_id>",
  "router_token": "<64_char_hex_secret_for_router_ws_auth>",
  "client_eph_pub": "<64_char_hex_x_only_secp256k1>"
}
```

### 3.4 `tunnel_ack` (`kind: 24136`)
```json
{
  "type": "tunnel_ack",
  "v": 1,
  "req_id": "f0e1d2c3...",
  "ok": true,
  "session_id": "<session_id>",
  "router_eph_pub": "<64_char_hex_x_only_secp256k1>",
  "error": null
}
```

---

## 4. Harmonogram kluczy tunelu (PFS + AES-256-GCM)

1. Obie strony używają kluczy `x-only` (`0x02 || x_pub` przy odtwarzaniu punktu na krzywej `secp256k1`).
2. Obie strony obliczają wspólny punkt ECDH i biorą jego nieshashowaną współrzędną `x` (32 bajty): `shared_eph_x`.
3. Obliczany jest skrót transkryptu sesji:
   ```text
   transcript_hash = SHA256(
       "NORT-1" ||
       client_identity_pub_32B ||
       router_identity_pub_32B ||
       utf8(session_id) ||
       client_eph_pub_32B ||
       router_eph_pub_32B
   )
   ```
4. Klucz główny sesji (`PRK`):
   ```text
   prk = HKDF-Extract(salt = transcript_hash, ikm = shared_eph_x)
   ```
5. Kierunkowe klucze szyfrowania (32 bajty każdy):
   ```text
   key_c2r = HKDF-Expand(prk, info = "nort-c2r-aes256gcm", len = 32)
   key_r2c = HKDF-Expand(prk, info = "nort-r2c-aes256gcm", len = 32)
   ```

### 4.1 Zewnętrzna koperta binarna na WebSocket (`TunnelRoomDO`)
Każda wiadomość WebSocket Binary ma format:

```text
+----------+------------------+--------------------+--------------------+
| dir (1B) |   seq (8B BE)    | ciphertext (N B)   |  GCM tag (16 B)    |
+----------+------------------+--------------------+--------------------+
```

- `dir`: `0x01` (client → router, klucz `key_c2r`) lub `0x02` (router → client, klucz `key_r2c`).
- `seq`: ściśle rosnący licznik `uint64` zaczynający się od `1` dla danego kierunku. Odbiorca **musi** odrzucić każdą ramkę, dla której `seq <= last_received_seq` (ochrona przed replay i duplikacją).
- `nonce` (12 B): `0x00000000` (4 bajty) || `seq` (8 bajtów Big-Endian).
- `AAD`: `utf8(session_id) || dir (1B) || seq (8B BE)`.

---

## 5. Wewnętrzne ramki multipleksowania (Plaintext po deszyfrowaniu)

```text
+---------------+------------------+--------------------+-------------------+
| frame_type 1B | stream_id (4B BE)| payload_len (4B BE)|   payload (N B)   |
+---------------+------------------+--------------------+-------------------+
```

| Kod | Nazwa | Kierunek | Znaczenie |
| :--- | :--- | :---: | :--- |
| `0x01` | `HTTP_REQ_META` | C → R | JSON: `{ method, path, headers }` |
| `0x02` | `HTTP_REQ_BODY` | C → R | Fragment ciała żądania HTTP |
| `0x03` | `HTTP_REQ_END` | C → R | Koniec żądania HTTP dla `stream_id` |
| `0x11` | `HTTP_RES_META` | R → C | JSON: `{ status, headers }` |
| `0x12` | `HTTP_RES_BODY` | R → C | Fragment odpowiedzi HTTP |
| `0x13` | `HTTP_RES_END` | R → C | Koniec odpowiedzi HTTP dla `stream_id` |
| `0x14` | `HTTP_RST` | C ↔ R | Przerwanie strumienia z komunikatem błędu UTF-8 |
| `0x20` | `UBUS_REQ` | C → R | Bezpośrednie wywołanie JSON-RPC `/ubus` |
| `0x21` | `UBUS_RES` | R → C | Odpowiedź JSON-RPC `/ubus` |
| `0x30` | `PING` | C ↔ R | 8-bajtowy znacznik czasu/nonce dla pomiaru RTT |
| `0x31` | `PONG` | C ↔ R | Echo 8-bajtowego payloadu z `PING` |

---

## 6. Reguły bezpieczeństwa brzegowego (SSRF & Loopback)

1. **Ochrona SSRF na routerze**: przed nawiązaniem połączenia do `relay_tunnel_url`, agent OpenWrt weryfikuje:
   - schemat to `wss://` (lub `ws://127.0.0.1` wyłącznie przy jawnej fladze dev),
   - host znajduje się na liście `allowed_tunnel_hosts` w UCI (domyślnie `relay.gfmm.eu`),
   - ścieżka pasuje dokładnie do `/tunnel/[a-f0-9]{32,64}`.
2. **Ochrona serwera lokalnego proxy w Androidzie (`LocalLuciProxyServer`)**:
   - nasłuchuje wyłącznie na `127.0.0.1:<port_efemeryczny>`,
   - wymaga wejścia przez `/__nort_auth?token=<256-bit>` w celu wystawienia ciasteczka `__nort_local_session` (`HttpOnly; SameSite=Strict`),
   - odrzuca każde żądanie bez ważnego `__nort_local_session` kodem `403 Forbidden`,
   - usuwa `__nort_local_session` z nagłówka `Cookie` przed przesłaniem do routera,
   - własny `WebViewClient` blokuje nawigację poza origin `http://127.0.0.1:<port>`.
