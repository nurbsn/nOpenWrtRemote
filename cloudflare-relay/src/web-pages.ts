export function renderLandingPage(): string {
  return `<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>nOpenWrtRemote — Bezpieczne zdalne zarządzanie OpenWrt i LuCI</title>
  <style>
    :root { color-scheme: dark; --bg: #0b1120; --card: #111a2e; --accent: #38bdf8; --ok: #22c55e; --text: #e2e8f0; --muted: #94a3b8; }
    body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
    .wrap { max-width: 860px; margin: 0 auto; padding: 36px 20px 64px; }
    .badge { display: inline-block; padding: 4px 12px; border-radius: 999px; background: rgba(56,189,248,.15); color: var(--accent); font-size: 13px; font-weight: 600; }
    h1 { font-size: 2.1rem; margin: 14px 0 8px; }
    .lead { color: var(--muted); font-size: 1.08rem; margin-bottom: 28px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin: 24px 0; }
    .card { background: var(--card); border: 1px solid rgba(148,163,184,.16); border-radius: 14px; padding: 18px; }
    .card h3 { margin: 0 0 8px; font-size: 1.05rem; color: #fff; }
    .card p { margin: 0; color: var(--muted); font-size: 0.94rem; }
    pre { background: #070b14; border: 1px solid rgba(148,163,184,.2); border-radius: 10px; padding: 14px; overflow-x: auto; color: #cbd5e1; font-size: 0.88rem; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid rgba(148,163,184,.16); color: var(--muted); font-size: 0.9rem; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 12px; }
  </style>
</head>
<body>
  <main class="wrap">
    <span class="badge">Zero-Knowledge E2EE • Protokół NORT-1 (Nostr + AES-256-GCM)</span>
    <h1>nOpenWrtRemote</h1>
    <p class="lead">
      Zdalne zarządzanie routerem OpenWrt i pełnym panelem <strong>LuCI</strong> na Androidzie bez otwierania portów na WAN, bez publicznego IP (działa za CGNAT) oraz bez wbudowanego <code>VpnService</code>.
    </p>

    <div class="grid">
      <div class="card">
        <h3>1. Zero ekspozycji LuCI</h3>
        <p>Agent na OpenWrt nawiązuje wyłącznie połączenie wychodzące TLS 1.3 (<code>wss://relay.gfmm.eu</code>) i komunikuje się lokalnie z <code>127.0.0.1:80</code>.</p>
      </div>
      <div class="card">
        <h3>2. Szyfrowanie End-to-End (PFS)</h3>
        <p>Sygnalizacja przez Nostr NIP-44 v2 + efemeryczny tunel <code>secp256k1</code> ECDH / HKDF-SHA256 / AES-256-GCM. Serwer przekaźnika jest całkowicie ślepy.</p>
      </div>
      <div class="card">
        <h3>3. Pełne LuCI + Pulpit ubus</h3>
        <p>Natywny pulpit telemetryczny oraz pełne LuCI w aplikacji Android (<code>eu.gfmm.nopenwrtremote</code>) poprzez bezpieczny lokalny serwer proxy <code>127.0.0.1</code>.</p>
      </div>
    </div>

    <h2>Instalacja na routerze OpenWrt</h2>
    <pre><code>opkg update
opkg install nopenwrtremote luci-app-nopenwrtremote
# Następnie otwórz w LuCI: Services -&gt; nOpenWrtRemote i zeskanuj kod QR w aplikacji Android.</code></pre>

    <h2>Endpointy przekaźnika</h2>
    <ul>
      <li><strong>Nostr Relay WSS:</strong> <code>wss://relay.gfmm.eu</code> (NIP-01, NIP-11, NIP-44 v2, wyłącznie zdarzenia efemeryczne)</li>
      <li><strong>Kod źródłowy i pakiety OpenWrt (.ipk w C):</strong> <a href="https://github.com/nurbsn/nOpenWrtRemote">github.com/nurbsn/nOpenWrtRemote</a></li>
      <li><strong>Healthcheck:</strong> <a href="/health">/health</a></li>
      <li><strong>Polityka prywatności (Google Play):</strong> <a href="/nopenwrtremote/privacy">/nopenwrtremote/privacy</a></li>
    </ul>

    <footer class="footer">
      <span>gfmm.eu • nOpenWrtRemote</span>
      <span><a href="/nopenwrtremote/privacy">Polityka prywatności / Privacy Policy</a></span>
    </footer>
  </main>
</body>
</html>`;
}

export function renderPrivacyPolicyPage(): string {
  return `<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Polityka prywatności — nOpenWrtRemote</title>
  <style>
    :root { color-scheme: dark; --bg: #0b1120; --card: #111a2e; --accent: #38bdf8; --text: #e2e8f0; --muted: #94a3b8; }
    body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.7; }
    .wrap { max-width: 820px; margin: 0 auto; padding: 36px 20px 64px; }
    h1, h2 { color: #fff; }
    .box { background: var(--card); border: 1px solid rgba(148,163,184,.16); border-radius: 12px; padding: 20px; margin: 18px 0; }
    a { color: var(--accent); }
    code { background: rgba(148,163,184,.15); padding: 2px 6px; border-radius: 4px; }
  </style>
</head>
<body>
  <main class="wrap">
    <h1>Polityka prywatności / Privacy Policy — nOpenWrtRemote</h1>
    <p><strong>Ostatnia aktualizacja:</strong> 2026-11-25 • <strong>Identyfikator aplikacji:</strong> <code>eu.gfmm.nopenwrtremote</code> • <strong>Domena:</strong> <code>gfmm.eu</code></p>

    <div class="box">
      <h2>1. Zasada Zero-Knowledge i brak gromadzenia danych</h2>
      <p>
        Aplikacja <strong>nOpenWrtRemote</strong> została zaprojektowana w architekturze <em>zero-knowledge</em>.
        Wszystkie klucze kryptograficzne (para kluczy <code>secp256k1</code> / Nostr <code>nsec</code>, lista sparowanych routerów oraz opcjonalne dane logowania) są generowane i przechowywane <strong>wyłącznie lokalnie na urządzeniu użytkownika</strong> w zaszyfrowanym magazynie Android (<code>SecureStorage</code>) z wyłączoną kopią zapasową w chmurze (<code>android:allowBackup="false"</code>).
      </p>
      <p>
        Domyślny serwer przekaźnika <code>wss://relay.gfmm.eu</code> pełni wyłącznie rolę ślepego routera zaszyfrowanych ramek End-to-End (NIP-44 v2 oraz AES-256-GCM z Perfect Forward Secrecy). Operator serwera nie ma technicznej możliwości odszyfrowania przesyłanych poleceń, haseł, konfiguracji ani ruchu interfejsu LuCI i nie zapisuje żadnych zdarzeń na dysku.
      </p>
    </div>

    <div class="box">
      <h2>2. Uprawnienia aplikacji Android</h2>
      <ul>
        <li><strong>Aparat (<code>CAMERA</code>):</strong> używany wyłącznie na wyraźne żądanie użytkownika do zeskanowania kodu QR parowania routera (<code>nopenwrt://pair</code>). Obrazy z kamery są przetwarzane lokalnie w pamięci i nigdy nie są zapisywane ani wysyłane.</li>
        <li><strong>Biometria (<code>USE_BIOMETRIC</code>):</strong> opcjonalna lokalna blokada dostępu do aplikacji przy użyciu systemowego mechanizmu Android.</li>
        <li><strong>Internet (<code>INTERNET</code>, <code>ACCESS_NETWORK_STATE</code>):</strong> nawiązywanie szyfrowanego połączenia TLS 1.3 WebSocket z przekaźnikiem Nostr/tunelem (<code>wss://relay.gfmm.eu</code> lub serwerem własnym użytkownika).</li>
      </ul>
    </div>

    <div class="box">
      <h2>3. Brak reklam, śledzenia i analityki</h2>
      <p>Aplikacja nie zawiera żadnych reklam, SDK analitycznych, trackerów ani profilowania użytkowników. Dane nie są sprzedawane ani udostępniane podmiotom trzecim.</p>
    </div>

    <div class="box">
      <h2>4. Kontakt i usuwanie danych</h2>
      <p>
        Ponieważ serwer nie przechowuje kont ani danych osobowych, odinstalowanie aplikacji lub użycie funkcji unieważnienia urządzenia w panelu LuCI usuwa wszystkie lokalne dane.
        Pytania dotyczące prywatności można kierować na adres: <a href="mailto:privacy@gfmm.eu">privacy@gfmm.eu</a>.
      </p>
    </div>

    <p><a href="/nopenwrtremote">← Powrót do strony głównej nOpenWrtRemote</a></p>
  </main>
</body>
</html>`;
}
