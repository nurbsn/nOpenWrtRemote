import { DurableObject } from "cloudflare:workers";
import { Env } from "./index";
import { constantTimeEqualHex, sha256Hex } from "./nostr-verify";

type PeerRole = "client" | "router";

interface TunnelAttachment {
  role: PeerRole;
}

const TOKEN_RE = /^[a-f0-9]{32,128}$/;
const SHA256_HEX_RE = /^[a-f0-9]{64}$/;
const IDLE_TIMEOUT_MS = 15 * 60 * 1000;

export class TunnelRoomDO extends DurableObject {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Expected Upgrade: websocket", { status: 426 });
    }

    const url = new URL(request.url);
    const role = url.searchParams.get("role");
    const token = url.searchParams.get("token") ?? "";
    const peerHash = url.searchParams.get("peer_hash") ?? "";

    if (role !== "client" && role !== "router") {
      return new Response("Invalid role", { status: 400 });
    }
    if (!TOKEN_RE.test(token)) {
      return new Response("Invalid token format", { status: 400 });
    }

    const existing = this.ctx.getWebSockets();
    if (existing.length >= 2) {
      return new Response("Tunnel room full", { status: 409 });
    }
    if (existing.some((s) => (s.deserializeAttachment() as TunnelAttachment | null)?.role === role)) {
      return new Response("Role already connected", { status: 409 });
    }

    if (role === "client") {
      if (!SHA256_HEX_RE.test(peerHash)) {
        return new Response("Client must provide valid peer_hash", { status: 400 });
      }
      await this.ctx.storage.put("peerHash", peerHash);
    } else {
      const expectedPeerHash = await this.ctx.storage.get<string>("peerHash");
      if (!expectedPeerHash) {
        return new Response("Tunnel session not initialized by client", { status: 403 });
      }
      const actualHash = await sha256Hex(token);
      if (!constantTimeEqualHex(actualHash, expectedPeerHash)) {
        return new Response("Unauthorized router token", { status: 403 });
      }
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    this.ctx.acceptWebSocket(server);
    const attachment: TunnelAttachment = { role };
    server.serializeAttachment(attachment);

    await this.ctx.storage.setAlarm(Date.now() + IDLE_TIMEOUT_MS);

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const sender = ws.deserializeAttachment() as TunnelAttachment | null;
    if (!sender) return;

    await this.ctx.storage.setAlarm(Date.now() + IDLE_TIMEOUT_MS);

    for (const peer of this.ctx.getWebSockets()) {
      const peerAttachment = peer.deserializeAttachment() as TunnelAttachment | null;
      if (peerAttachment && peerAttachment.role !== sender.role) {
        try {
          peer.send(message);
        } catch {
          // Peer closing
        }
      }
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    const sender = ws.deserializeAttachment() as TunnelAttachment | null;
    for (const peer of this.ctx.getWebSockets()) {
      if (peer !== ws) {
        try {
          peer.close(1000, sender ? `Peer ${sender.role} disconnected` : "Peer disconnected");
        } catch {
          // Already closed
        }
      }
    }
    await this.ctx.storage.deleteAll();
    try {
      ws.close(code, reason);
    } catch {
      // Already closed
    }
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    await this.webSocketClose(ws, 1011, "Tunnel socket error");
  }

  async alarm(): Promise<void> {
    for (const ws of this.ctx.getWebSockets()) {
      try {
        ws.close(1000, "Tunnel idle timeout");
      } catch {
        // Already closed
      }
    }
    await this.ctx.storage.deleteAll();
  }
}
