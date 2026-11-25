/**
 * Browser-only simulated backend for the public live demo.
 *
 * Loaded only when the app is built with `--mode demo` (VITE_DEMO=1); the
 * regular Tauri build never imports this module. It replaces the Tauri IPC
 * bridge with an in-memory fake so the UI can run on a static web host.
 * Nothing leaves the browser: there is no network, no storage and no crypto.
 */
import { mockIPC } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";
import pkg from "../../package.json";
import type {
  ChatMessage, PrivateMessage, Friend, SavedGroup, FullConfig, PeerSettings, RoomSettings,
} from "../types";

type Args = Record<string, any> | undefined;

const GLOBAL_ROOM = "alterchat-global";
const RELEASES_URL = "https://github.com/onurbaydas/AlterChat/releases/latest";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function fakePeerId(seed: number): string {
  let s = seed * 2654435761 >>> 0;
  let out = "12D3KooW";
  for (let i = 0; i < 44; i++) {
    s = (s * 1103515245 + 12345) >>> 0;
    out += B58[(s >>> 16) % B58.length];
  }
  return out;
}
function fakeHex(seed: number, len = 64): string {
  let s = seed >>> 0;
  let out = "";
  for (let i = 0; i < len; i++) {
    s = (s * 1664525 + 1013904223) >>> 0;
    out += ((s >>> 24) & 15).toString(16);
  }
  return out;
}
const pick = <T,>(xs: T[]): T => xs[Math.floor(Math.random() * xs.length)];
const later = (ms: number, fn: () => void) => window.setTimeout(fn, ms);
const send = (event: string, payload: unknown) => { emit(event, payload).catch(() => {}); };

// ─── Demo world ─────────────────────────────────────────────────────────────

const MY_PEER_ID = fakePeerId(7);
const MY_PUBKEY = fakeHex(77);

interface DemoPeer { id: string; nick: string; pubkey: string; friend: boolean; trust: number }
const PEERS: DemoPeer[] = [
  { id: fakePeerId(101), nick: "LağımFaresi", pubkey: fakeHex(1001), friend: true, trust: 30 },
  { id: fakePeerId(202), nick: "Sığınak-7", pubkey: fakeHex(2002), friend: true, trust: 20 },
  { id: fakePeerId(303), nick: "KörKöstebek", pubkey: fakeHex(3003), friend: false, trust: 10 },
  { id: fakePeerId(404), nick: "PaslıKapak", pubkey: fakeHex(4004), friend: false, trust: 0 },
];
const peerById = (id: string) => PEERS.find(p => p.id === id);

let config: FullConfig = {
  nick: "",
  offline_pubkey: MY_PUBKEY,
  bootstrap_ip: "/dns4/bootstrap.demo.invalid/tcp/4001",
  bootstrap_addrs: [],
  tor_enabled: false,
  proxy_mode: "direct",
  proxy_addr: "",
  mdns_enabled: true,
  dht_server_mode: false,
  relay_enabled: true,
  transport_preference: "tcp",
  relay_fallback_enabled: true,
  publish_capabilities: true,
  cover_traffic: false,
  msg_delay: true,
  local_notifications: true,
  unknown_peer_policy: "allow",
  min_trust_dm: 0,
  min_trust_file: 0,
  min_trust_invite: 0,
  default_ttl: null,
  persistence_enabled: true,
  invite_only_default: false,
  proof_of_work_enabled: false,
  rate_limit_per_minute: 30,
  storage_node_enabled: false,
  storage_quota_mb: 512,
  storage_retention_days: 7,
  sfu_threshold: 6,
  preferred_sfu_peer: "",
  accept_relay: false,
  experimental_media_e2ee: false,
};
let fileSettings = { max_file_size_mb: 100, max_concurrent_transfers: 3 };

const friends: (Friend & { offline_pubkey?: string })[] = PEERS.filter(p => p.friend).map(p => ({
  peer_id: p.id, nickname: p.nick, trust_level: p.trust, blocked: false, muted: false,
  notes: "demo", offline_pubkey: p.pubkey,
}));
const groups: SavedGroup[] = [{ channel_name: GLOBAL_ROOM, persistence_enabled: true, notifications_enabled: true }];
const peerSettings: Record<string, PeerSettings> = {};
const roomSettings: Record<string, RoomSettings> = {};
const trustEdges: { from_peer_id: string; to_peer_id: string; score: number; reason: string }[] = [
  { from_peer_id: PEERS[0].id, to_peer_id: PEERS[1].id, score: 10, reason: "aynı tünel" },
  { from_peer_id: PEERS[1].id, to_peer_id: PEERS[2].id, score: 10, reason: "eski dost" },
  { from_peer_id: PEERS[2].id, to_peer_id: PEERS[3].id, score: -10, reason: "peynir çaldı" },
];

const now = Date.now();
const roomLog: ChatMessage[] = [
  { peer_id: PEERS[0].id, sender: PEERS[0].nick, text: "Sığınağa hoş geldin. Burada her şey uçtan uca şifreli.", timestamp: now - 1000 * 60 * 42, verified: true },
  { peer_id: PEERS[2].id, sender: PEERS[2].nick, text: "Yukarıda kimse var mı? Benim relay üzerinden geliyorum.", timestamp: now - 1000 * 60 * 30, verified: true },
  { peer_id: PEERS[1].id, sender: PEERS[1].nick, text: "Buradayım. Bootstrap düğümü sağlam, DHT yayılıyor.", timestamp: now - 1000 * 60 * 29, verified: true },
  { peer_id: PEERS[3].id, sender: PEERS[3].nick, text: "Kapak yine paslanmış, hole punching ancak ikinci denemede tuttu.", timestamp: now - 1000 * 60 * 12, verified: true },
];
const dmLog: Record<string, PrivateMessage[]> = {
  [PEERS[0].id]: [
    { peer_id: PEERS[0].id, sender_is_me: false, text: "Güvenlik numaralarını doğruladın mı?", timestamp: now - 1000 * 60 * 60 * 3 },
    { peer_id: PEERS[0].id, sender_is_me: true, text: "Henüz değil, akşam yüz yüze bakarız.", timestamp: now - 1000 * 60 * 60 * 3 + 40000 },
  ],
  [PEERS[1].id]: [
    { peer_id: PEERS[1].id, sender_is_me: false, text: "Erzak listesi hazır. Peynir stoğu kritik seviyede.", timestamp: now - 1000 * 60 * 95 },
  ],
};

const ROOM_REPLIES = [
  "Mesajın sığınağa ulaştı. Gossipsub üç hopta yaydı.",
  "Duyuldu. Bu arada kimse tünelde peynir bırakmasın.",
  "İmza geçerli, kimliğin doğrulandı. Hoş geldin.",
  "Relay üzerinden okuyorum, gecikme biraz yüksek ama sorun yok.",
  "Bunu not aldım. Panik düğmesine sakın yanlışlıkla basma.",
  "Burada merkez yok, sunucu yok. Sadece biz farelerimiz var.",
  "Tamam. Bir sonraki nöbet bende.",
];
const DM_REPLIES = [
  "Aldım. Bu kanal sadece ikimiz arasında.",
  "Tamam, güvenlik numaramız eşleşiyor gibi.",
  "Şu an tünelin öbür ucundayım, birazdan dönerim.",
  "Peyniri getirdin mi?",
  "Anlaşıldı. Mesaj kendini imha etsin istersen zamanlayıcıyı kur.",
];
const AMBIENT = [
  "Yeni bir eş keşfedildi, mDNS çalışıyor.",
  "Biri kapıyı mı çaldı? Yok, sadece cover traffic.",
  "Tünelde ışıklar titredi, bağlantı relay'e düştü sonra geri geldi.",
  "Sığınak hâlâ ayakta. Herkese iyi nöbetler.",
];

function replyFor(text: string, pool: string[]): string {
  const t = text.toLocaleLowerCase("tr");
  if (/(merhaba|selam|hello|hi\b|hey)/.test(t)) return pick(["Selam yolcu! Sığınağa hoş geldin.", "Merhaba! Tünel temiz, rahat konuşabilirsin."]);
  if (/(peynir|cheese)/.test(t)) return "Peynir lafını duyunca bütün fareler toplandı.";
  if (/\?\s*$/.test(t)) return pick(["Güzel soru. Cevap merkezi bir sunucuda değil, ağın kendisinde.", "Bilmiyorum, ama kimse de izlemiyor, o kesin."]);
  return pick(pool);
}

// ─── Simulated network ──────────────────────────────────────────────────────

let started = false;
let currentChannel = "";
function startNetwork() {
  if (started) return;
  started = true;
  later(500, () => send("network-status", "connecting"));
  later(900, () => send("network-reachability", "relayed"));
  PEERS.forEach((p, i) => later(1300 + i * 700, () => {
    send("peer-discovered", p.id);
    send("peer-connected", p.id);
  }));
  later(1500, () => send("network-status", "online"));
  later(5000, () => send("network-reachability", "direct"));

  let ambient = 0;
  const tick = () => {
    if (ambient >= AMBIENT.length) return;
    const p = PEERS[(ambient + 2) % PEERS.length];
    pushRoom({ peer_id: p.id, sender: p.nick, text: AMBIENT[ambient++], timestamp: Date.now(), verified: true });
    later(35000 + Math.random() * 25000, tick);
  };
  later(25000, tick);
}

function pushRoom(msg: ChatMessage) {
  roomLog.push(msg);
  // The UI only renders the global room live, so only that room is simulated.
  if (currentChannel === GLOBAL_ROOM) send("new-message", msg);
}

function snake(k: string) { return k.replace(/[A-Z]/g, c => "_" + c.toLowerCase()); }

let transferSeq = 0;

// ─── Command handlers ───────────────────────────────────────────────────────

function handle(cmd: string, args: Args): unknown {
  const a = args ?? {};
  switch (cmd) {
    // plugins
    case "plugin:app|version": return pkg.version;
    case "plugin:updater|check": return null;
    case "plugin:opener|open_url": window.open(String(a.url), "_blank", "noopener"); return null;
    case "plugin:process|restart": window.location.reload(); return null;
    case "plugin:process|exit": return null;

    // identity
    case "login_profile": return "demo-profile";
    case "get_peer_id": return MY_PEER_ID;
    case "get_peer_uri": return `alterchat://connect?peer=${MY_PEER_ID}&pk=${MY_PUBKEY}`;
    case "get_settings":
    case "get_full_config":
      return { ...config, nick: config.nick || "Misafir" };
    case "save_full_config": config = { ...config, ...(a.config ?? {}) }; return null;
    case "save_settings": {
      for (const [k, v] of Object.entries(a)) (config as any)[snake(k)] = v;
      return null;
    }
    case "get_file_transfer_settings": return fileSettings;
    case "save_file_transfer_settings": fileSettings = { ...fileSettings, ...(a.settings ?? {}) }; return fileSettings;
    case "export_profile_config": return JSON.stringify(config, null, 2);
    case "import_profile_config": return null;
    case "get_capacity_score": return 37;

    // contacts and rooms
    case "get_friends": startNetwork(); return friends.map(f => ({ ...f }));
    case "add_friend": {
      const f = { peer_id: String(a.peerId), nickname: String(a.nickname), trust_level: 0, offline_pubkey: a.offlinePubkey ?? undefined };
      const i = friends.findIndex(x => x.peer_id === f.peer_id);
      if (i >= 0) friends[i] = { ...friends[i], ...f }; else friends.push(f);
      return null;
    }
    case "get_saved_groups": return groups.map(g => ({ ...g }));
    case "save_group": {
      const name = String(a.channelName);
      if (!groups.some(g => g.channel_name === name)) groups.push({ channel_name: name, password: a.password ?? undefined });
      return null;
    }
    case "join_channel": {
      currentChannel = String(a.name);
      if (currentChannel === GLOBAL_ROOM) later(150, () => send("chat-history", roomLog.slice()));
      return null;
    }
    case "join_anonymous_channel": later(200, () => send("anonymous-channel-joined", String(a.displayName))); return null;
    case "get_peer_settings": {
      const id = String(a.peerId);
      return peerSettings[id] ?? {
        peer_id: id, trust_level: peerById(id)?.trust ?? 0, blocked: false, muted: false,
        rate_limit_per_minute: 30, proof_of_work_required: false,
      };
    }
    case "save_peer_settings": { const s = a.settings as PeerSettings; peerSettings[s.peer_id] = s; return null; }
    case "get_room_settings": {
      const name = String(a.channelName);
      return roomSettings[name] ?? {
        channel_name: name, default_ttl: null, retention_days: null,
        persistence_enabled: true, invite_only: false, notifications_enabled: true,
      };
    }
    case "save_room_settings": { const s = a.settings as RoomSettings; roomSettings[s.channel_name] = s; return null; }
    case "create_invite":
      return JSON.stringify({
        room_id: a.roomId, room_password: a.roomPassword ?? null, issuer: MY_PEER_ID,
        expires_at: Math.floor(Date.now() / 1000) + Number(a.expiresInSeconds ?? 0),
        max_uses: a.maxUses ?? null, signature: fakeHex(Date.now() & 0xffff, 128),
      });
    case "accept_invite": {
      let tok: any;
      try { tok = JSON.parse(String(a.tokenJson)); } catch { throw "Geçersiz davet / invalid invite token"; }
      if (!tok?.room_id) throw "Geçersiz davet / invalid invite token";
      if (!groups.some(g => g.channel_name === tok.room_id)) groups.push({ channel_name: tok.room_id, password: tok.room_password ?? undefined });
      return [tok.room_id, tok.room_password ?? null];
    }

    // messaging
    case "send_message": {
      const text = String(a.text ?? "");
      if (text.startsWith("BENCHMARK_SCORE:")) return null;
      const mine: ChatMessage = {
        peer_id: MY_PEER_ID, sender: String(a.nick || "Misafir"), text, timestamp: Date.now(),
        ttl: a.ttl ?? undefined, verified: true,
      };
      later(80, () => pushRoom(mine));
      if (currentChannel === GLOBAL_ROOM) {
        const p = pick(PEERS);
        later(1200 + Math.random() * 1800, () => pushRoom({
          peer_id: p.id, sender: p.nick, text: replyFor(text, ROOM_REPLIES), timestamp: Date.now(), verified: true,
        }));
      }
      return null;
    }
    case "send_private_message": {
      const id = String(a.peerId);
      const text = String(a.text ?? "");
      (dmLog[id] ??= []).push({ peer_id: id, sender_is_me: true, text, timestamp: Date.now() });
      const p = peerById(id);
      if (p) {
        later(1500 + Math.random() * 2000, () => {
          const reply = replyFor(text, DM_REPLIES);
          dmLog[id].push({ peer_id: id, sender_is_me: false, text: reply, timestamp: Date.now() });
          send("new-private-message", { peer_id: id, sender_nick: p.nick, text: reply, timestamp: Date.now() });
        });
      }
      return null;
    }
    case "get_private_messages": return (dmLog[String(a.peerId)] ?? []).slice();
    case "search_messages": {
      const q = String(a.query ?? "").toLocaleLowerCase("tr");
      const limit = Number(a.limit ?? 20);
      const out: [string, string, string, number][] = [];
      for (const m of roomLog) if (m.text.toLocaleLowerCase("tr").includes(q)) out.push([`# ${GLOBAL_ROOM}`, m.sender, m.text, m.timestamp]);
      for (const [id, msgs] of Object.entries(dmLog)) for (const m of msgs) {
        if (m.text.toLocaleLowerCase("tr").includes(q)) out.push([`@ ${peerById(id)?.nick ?? id.slice(0, 8)}`, m.sender_is_me ? "You" : (peerById(id)?.nick ?? id.slice(0, 8)), m.text, m.timestamp]);
      }
      return out.slice(0, limit);
    }

    // trust
    case "endorse_peer":
      trustEdges.push({ from_peer_id: MY_PEER_ID, to_peer_id: String(a.peerId), score: Number(a.score), reason: "manual" });
      return null;
    case "list_trust_edges": return trustEdges.map(e => ({ ...e }));
    case "get_safety_number": {
      const hex = fakeHex(String(a.peerPubkeyHex ?? "").length * 31 + 5, 60);
      const digits = hex.replace(/[a-f]/g, c => String(c.charCodeAt(0) % 10));
      return digits.match(/.{5}/g)!.join(" ");
    }

    // system / destructive: harmless in the demo
    case "panic_wipe":
      alert("Demo: panik silme simüle edildi, hiçbir şey silinmedi. Demo yeniden başlıyor.\nDemo: panic wipe simulated, nothing was deleted. Restarting the demo.");
      window.location.reload();
      return null;
    case "export_vault_encrypted": return fakeHex(Date.now() & 0xffff, 256);
    case "import_vault_encrypted": return null;
    case "send_file": {
      const id = `demo-${++transferSeq}`;
      const total = 8;
      for (let i = 1; i <= total; i++) later(300 * i, () => send("file-progress", { transfer_id: id, done_chunks: i, total_chunks: total }));
      later(300 * total + 200, () => send("file-sent", { transfer_id: id }));
      return id;
    }
    case "accept_file_offer":
    case "reject_file_offer":
    case "send_webrtc_signal":
      return null;
    case "open_received_file":
      throw "Demo modunda dosya sistemi yok / no file system in the demo";
    default:
      return null;
  }
}

// ─── Banner ─────────────────────────────────────────────────────────────────

function mountBanner() {
  const bar = document.createElement("div");
  bar.setAttribute("role", "note");
  bar.style.cssText = [
    "position:fixed", "top:0", "left:0", "right:0", "z-index:100000",
    "display:flex", "align-items:center", "justify-content:center", "gap:10px", "flex-wrap:wrap",
    "padding:4px 36px 4px 12px", "font:12px/1.4 'IBM Plex Mono',monospace",
    "background:#ffb000", "color:#111", "text-align:center", "box-shadow:0 2px 8px rgba(0,0,0,.5)",
  ].join(";");
  const text = document.createElement("span");
  text.textContent = "Canlı demo — tarayıcıda sahte ağ ile çalışır, gerçek mesaj gönderilmez / Live demo — simulated network, no real messages";
  const link = document.createElement("a");
  link.href = RELEASES_URL;
  link.target = "_blank";
  link.rel = "noopener";
  link.textContent = "İndir / Download";
  link.style.cssText = "color:#111;font-weight:600;text-decoration:underline";
  const close = document.createElement("button");
  close.type = "button";
  close.textContent = "×";
  close.title = "Kapat / Close";
  close.style.cssText = "position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:0;color:#111;font-size:16px;cursor:pointer;padding:0 4px";
  close.onclick = () => bar.remove();
  bar.append(text, link, close);
  document.body.appendChild(bar);
}

export function installDemoBackend() {
  mockIPC((cmd, args) => handle(cmd, args as Args), { shouldMockEvents: true });
  mountBanner();
}
