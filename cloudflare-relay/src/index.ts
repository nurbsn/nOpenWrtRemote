import { NostrRelayDO } from "./nostr-relay-do";
import { TunnelRoomDO } from "./tunnel-room-do";
import { renderLandingPage, renderPrivacyPolicyPage } from "./web-pages";

export { NostrRelayDO, TunnelRoomDO };

export interface Env {
  NOSTR_RELAY: DurableObjectNamespace;
  TUNNEL_ROOM: DurableObjectNamespace;
}

const SESSION_ID_RE = /^[a-f0-9]{32,64}$/;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const isWebSocket = request.headers.get("Upgrade")?.toLowerCase() === "websocket";

    if (path === "/health") {
      return Response.json({
        ok: true,
        service: "nopenwrtremote-relay",
        protocol: "NORT-1",
      });
    }

    if (path === "/nopenwrtremote/privacy") {
      return new Response(renderPrivacyPolicyPage(), {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    if (path === "/nopenwrtremote" || path === "/nopenwrtremote/") {
      return new Response(renderLandingPage(), {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    if (path.startsWith("/tunnel/")) {
      const sessionId = path.slice("/tunnel/".length);
      if (!SESSION_ID_RE.test(sessionId)) {
        return new Response("Invalid tunnel session id", { status: 400 });
      }
      if (!isWebSocket) {
        return new Response("Expected Upgrade: websocket", { status: 426 });
      }
      const id = env.TUNNEL_ROOM.idFromName(sessionId);
      return env.TUNNEL_ROOM.get(id).fetch(request);
    }

    if (path === "/" || path === "/nostr") {
      if (isWebSocket) {
        const id = env.NOSTR_RELAY.idFromName("relay-v1");
        return env.NOSTR_RELAY.get(id).fetch(request);
      }

      if (request.headers.get("Accept")?.includes("application/nostr+json")) {
        return new Response(
          JSON.stringify({
            name: "nOpenWrtRemote Blind Nostr Relay",
            description: "Zero-knowledge ephemeral signaling relay for nOpenWrtRemote (NORT-1).",
            pubkey: "",
            contact: "privacy@gfmm.eu",
            supported_nips: [1, 11, 44],
            software: "nopenwrtremote-relay",
            version: "1.0.0",
            limitation: {
              max_message_length: 65536,
              max_subscriptions: 10,
              auth_required: false,
              payment_required: false,
              restricted_writes: true,
            },
          }),
          {
            headers: {
              "content-type": "application/nostr+json; charset=utf-8",
              "access-control-allow-origin": "*",
            },
          }
        );
      }

      return new Response(renderLandingPage(), {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    return new Response("Not Found", { status: 404 });
  },
};
