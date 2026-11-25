import { DurableObject } from "cloudflare:workers";
import { Env } from "./index";
import { matchesFilters, NostrEvent, NostrFilter, verifyNostrEvent } from "./nostr-verify";

interface SocketAttachment {
  subs: Record<string, NostrFilter[]>;
}

const MAX_SUBS_PER_SOCKET = 10;
const MAX_FILTERS_PER_SUB = 8;

export class NostrRelayDO extends DurableObject {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Expected Upgrade: websocket", { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    this.ctx.acceptWebSocket(server);
    const initial: SocketAttachment = { subs: {} };
    server.serializeAttachment(initial);

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== "string") {
      ws.send(JSON.stringify(["NOTICE", "Binary frames are not supported on Nostr relay"]));
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(message);
    } catch {
      ws.send(JSON.stringify(["NOTICE", "Invalid JSON message"]));
      return;
    }

    if (!Array.isArray(parsed) || parsed.length < 2 || typeof parsed[0] !== "string") {
      ws.send(JSON.stringify(["NOTICE", "Invalid NIP-01 envelope"]));
      return;
    }

    const msgType = parsed[0];
    const attachment = (ws.deserializeAttachment() as SocketAttachment | null) ?? { subs: {} };

    if (msgType === "REQ") {
      const subId = parsed[1];
      if (typeof subId !== "string" || subId.length === 0 || subId.length > 64) {
        ws.send(JSON.stringify(["NOTICE", "Invalid subscription id"]));
        return;
      }

      if (!attachment.subs[subId] && Object.keys(attachment.subs).length >= MAX_SUBS_PER_SOCKET) {
        ws.send(JSON.stringify(["CLOSED", subId, "restricted: max subscriptions reached"]));
        return;
      }

      const rawFilters = parsed.slice(2, 2 + MAX_FILTERS_PER_SUB);
      const filters: NostrFilter[] = rawFilters.filter(
        (f): f is NostrFilter => typeof f === "object" && f !== null
      );

      attachment.subs[subId] = filters;
      ws.serializeAttachment(attachment);

      // Ephemeral relay: no historical storage, immediately signal EOSE
      ws.send(JSON.stringify(["EOSE", subId]));
      return;
    }

    if (msgType === "CLOSE") {
      const subId = parsed[1];
      if (typeof subId === "string" && attachment.subs[subId]) {
        delete attachment.subs[subId];
        ws.serializeAttachment(attachment);
      }
      return;
    }

    if (msgType === "EVENT") {
      const evt = parsed[1] as NostrEvent;
      const result = await verifyNostrEvent(evt);
      if (!result.ok) {
        const eventId = typeof evt?.id === "string" ? evt.id : "";
        ws.send(JSON.stringify(["OK", eventId, false, result.reason]));
        return;
      }

      // Broadcast ephemeral event strictly in memory across active WebSockets
      for (const peer of this.ctx.getWebSockets()) {
        const peerAttachment = (peer.deserializeAttachment() as SocketAttachment | null) ?? { subs: {} };
        for (const [subId, filters] of Object.entries(peerAttachment.subs)) {
          if (matchesFilters(evt, filters)) {
            try {
              peer.send(JSON.stringify(["EVENT", subId, evt]));
            } catch {
              // Ignore dead sockets; runtime cleans them up via webSocketClose/Error
            }
          }
        }
      }

      ws.send(JSON.stringify(["OK", evt.id, true, ""]));
      return;
    }

    ws.send(JSON.stringify(["NOTICE", `Unsupported message type: ${msgType}`]));
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    try {
      ws.close(code, reason);
    } catch {
      // Already closed
    }
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    try {
      ws.close(1011, "WebSocket error");
    } catch {
      // Already closed
    }
  }
}
