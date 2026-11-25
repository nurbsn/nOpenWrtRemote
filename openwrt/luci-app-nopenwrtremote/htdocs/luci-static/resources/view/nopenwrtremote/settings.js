'use strict';
'require view';
'require form';
'require uci';

return view.extend({
	load: function () {
		return uci.load('nopenwrtremote');
	},

	render: function () {
		var m, s, o;

		m = new form.Map('nopenwrtremote', _('nOpenWrtRemote — Ustawienia'),
			_('Konfiguracja bezpiecznego agenta zdalnego dostępu NORT-1 (Nostr + AES-256-GCM).'));

		s = m.section(form.NamedSection, 'main', 'agent', _('Konfiguracja główna'));

		o = s.option(form.Flag, 'enabled', _('Włącz usługę'));
		o.rmempty = false;

		o = s.option(form.Value, 'router_name', _('Nazwa routera'));
		o.datatype = 'string';
		o.placeholder = 'OpenWrt';

		o = s.option(form.Value, 'lan_ip', _('Adres LAN routera (podpowiedź lokalna)'));
		o.datatype = 'ip4addr';
		o.default = '192.168.1.1';

		o = s.option(form.DynamicList, 'relay', _('Przekaźniki Nostr (WSS)'),
			_('Adresy serwerów sygnalizacyjnych. Domyślny ślepy przekaźnik: wss://relay.gfmm.eu'));
		o.default = 'wss://relay.gfmm.eu';

		o = s.option(form.Value, 'local_target', _('Lokalny adres LuCI/ubus'),
			_('Docelowy lokalny serwer uhttpd. Zawsze pozostaw adres pętli zwrotnej!'));
		o.default = 'http://127.0.0.1:80';

		o = s.option(form.Flag, 'allow_full_luci', _('Zezwól na pełne proxy LuCI'),
			_('Wyłączenie ogranicza zdalny tunel wyłącznie do wywołań /ubus JSON-RPC.'));
		o.default = o.enabled;

		o = s.option(form.DynamicList, 'allowed_tunnel_host', _('Dozwolone hosty tunelu (ochrona SSRF)'),
			_('Agent nawiąże wychodzący tunel WebSocket wyłącznie z hostami z tej listy.'));
		o.default = 'relay.gfmm.eu';

		return m.render();
	}
});
