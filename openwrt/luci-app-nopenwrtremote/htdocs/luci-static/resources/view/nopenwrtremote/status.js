'use strict';
'require view';
'require rpc';
'require ui';
'require dom';
'require poll';

var callStatus = rpc.declare({
	object: 'luci.nopenwrtremote',
	method: 'status',
	expect: {}
});

var callStartPairing = rpc.declare({
	object: 'luci.nopenwrtremote',
	method: 'start_pairing',
	expect: {}
});

var callListPeers = rpc.declare({
	object: 'luci.nopenwrtremote',
	method: 'list_peers',
	expect: {}
});

var callRevokePeer = rpc.declare({
	object: 'luci.nopenwrtremote',
	method: 'revoke_peer',
	params: ['npub'],
	expect: {}
});

function loadQrScript() {
	if (window.NortQrCode) return Promise.resolve();
	return new Promise(function (resolve, reject) {
		var s = document.createElement('script');
		s.src = L.resource('nopenwrtremote/qrcode.js');
		s.onload = resolve;
		s.onerror = function () { reject(new Error('Nie udało się załadować qrcode.js')); };
		document.head.appendChild(s);
	});
}

return view.extend({
	load: function () {
		return Promise.all([
			callStatus(),
			callListPeers(),
			loadQrScript().catch(function () { return null; })
		]);
	},

	handleStartPairing: function (qrBox) {
		return callStartPairing().then(function (res) {
			if (!res || !res.pair_uri) {
				ui.addNotification(null, E('p', _('Agent nOpenWrtRemote nie odpowiada. Sprawdź czy usługa jest uruchomiona.')), 'error');
				return;
			}
			dom.content(qrBox, '');
			var svgContainer = E('div', { 'style': 'margin:12px 0;padding:12px;background:#fff;display:inline-block;border-radius:8px;border:1px solid #cbd5e1;' });
			if (window.NortQrCode) {
				svgContainer.innerHTML = window.NortQrCode.renderSvg(res.pair_uri, 240);
			}
			var countdown = E('strong', { 'style': 'color:#0284c7;' }, '300 s');
			var expiresAt = res.expires_at ? (res.expires_at * 1000) : (Date.now() + 300000);
			var timer = window.setInterval(function () {
				var left = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
				countdown.textContent = left + ' s';
				if (left <= 0) {
					window.clearInterval(timer);
					countdown.textContent = _('Wygasł — wygeneruj ponownie');
				}
			}, 1000);

			qrBox.appendChild(E('div', { 'class': 'alert-message info' }, [
				E('p', {}, [
					_('Zeskanuj poniższy kod QR w aplikacji '),
					E('strong', {}, 'nOpenWrtRemote'),
					_(' na Androidzie. Kod ważny przez: '),
					countdown
				]),
				svgContainer,
				E('p', { 'style': 'word-break:break-all;font-family:monospace;font-size:12px;' }, res.pair_uri)
			]));
		}).catch(function (err) {
			ui.addNotification(null, E('p', _('Błąd parowania: ') + err.message), 'error');
		});
	},

	renderPeersTable: function (peers, tableEl) {
		var rows = [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, _('Urządzenie')),
				E('th', { 'class': 'th' }, _('Klucz publiczny (npub)')),
				E('th', { 'class': 'th' }, _('Dodano')),
				E('th', { 'class': 'th right' }, _('Akcja'))
			])
		];

		if (!peers || peers.length === 0) {
			rows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td', 'colspan': '4' }, _('Brak sparowanych urządzeń Android.'))
			]));
		} else {
			peers.forEach(function (peer) {
				var addedStr = peer.added_at ? new Date(peer.added_at * 1000).toLocaleString() : '-';
				rows.push(E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td' }, peer.name || 'Android'),
					E('td', { 'class': 'td', 'style': 'font-family:monospace;font-size:12px;' }, peer.npub),
					E('td', { 'class': 'td' }, addedStr),
					E('td', { 'class': 'td right' }, [
						E('button', {
							'class': 'btn cbi-button cbi-button-negative',
							'click': function () {
								callRevokePeer(peer.npub).then(function () {
									return callListPeers();
								}).then(function (r) {
									this.renderPeersTable(r.peers || [], tableEl);
								}.bind(this));
							}.bind(this)
						}, _('Odłącz / Unieważnij'))
					])
				]));
			}, this);
		}
		dom.content(tableEl, rows);
	},

	render: function (data) {
		var status = data[0] || {};
		var peersData = data[1] || {};
		var qrBox = E('div', {});
		var peersTable = E('table', { 'class': 'table' });

		var relayList = (status.relays || []).map(function (r) {
			return E('div', {}, [
				E('span', {
					'class': 'label ' + (r.connected ? 'success' : 'warning'),
					'style': 'margin-right:8px;'
				}, r.connected ? _('Połączono') : _('Łączenie...')),
				E('code', {}, r.url)
			]);
		});

		this.renderPeersTable(peersData.peers || [], peersTable);

		var statusEl = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Status agenta nOpenWrtRemote (NORT-1)')),
			E('table', { 'class': 'table' }, [
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td left', 'width': '33%' }, _('Stan usługi')),
					E('td', { 'class': 'td left' }, status.running
						? E('span', { 'class': 'label success' }, _('Aktywna (E2EE Zero-Knowledge)'))
						: E('span', { 'class': 'label important' }, _('Zatrzymana')))
				]),
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td left' }, _('Tożsamość routera (npub)')),
					E('td', { 'class': 'td left', 'style': 'font-family:monospace;word-break:break-all;' }, status.npub || '-')
				]),
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td left' }, _('Przekaźniki Nostr')),
					E('td', { 'class': 'td left' }, relayList.length ? relayList : '-')
				]),
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td left' }, _('Aktywne tunele E2EE')),
					E('td', { 'class': 'td left' }, String(status.active_tunnels || 0))
				])
			])
		]);

		var pairSection = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Parowanie urządzenia Android')),
			E('p', {}, _('LuCI nie jest wystawiane do internetu. Połączenie przechodzi wyłącznie przez szyfrowany End-to-End tunel po weryfikacji klucza telefonu.')),
			E('button', {
				'class': 'btn cbi-button cbi-button-action',
				'click': ui.createHandlerFn(this, 'handleStartPairing', qrBox)
			}, _('Paruj urządzenie Android (Kod QR)')),
			qrBox
		]);

		var peersSection = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Sparowane urządzenia')),
			peersTable
		]);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('nOpenWrtRemote')),
			statusEl,
			pairSection,
			peersSection
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
