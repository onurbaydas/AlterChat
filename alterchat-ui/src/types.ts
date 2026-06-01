export interface ChatMessage {
  peer_id: string;
  sender: string;
  text: string;
  timestamp: number;
  ttl?: number;
}
export interface PrivateMessage {
  id?: number;
  peer_id: string;
  sender_is_me: boolean;
  text: string;
  timestamp: number;
  ttl?: number | null;
}
export interface Friend {
  peer_id: string;
  nickname: string;
  trust_level?: number;
  blocked?: boolean;
  muted?: boolean;
  notes?: string | null;
}
export interface SavedGroup {
  channel_name: string;
  password?: string;
  default_ttl?: number | null;
  persistence_enabled?: boolean;
  invite_only?: boolean;
  notifications_enabled?: boolean;
  retention_days?: number | null;
}
export type ProxyMode = 'direct' | 'tor' | 'i2p' | 'socks5';
export type TransportPreference = 'tcp' | 'quic' | 'websocket';
export type UnknownPeerPolicy = 'allow' | 'block' | 'pow_required';

export interface FullConfig {
  nick: string;
  offline_pubkey?: string;
  bootstrap_ip: string;
  bootstrap_addrs: string[];
  tor_enabled: boolean;
  proxy_mode: ProxyMode;
  proxy_addr: string;
  mdns_enabled: boolean;
  dht_server_mode: boolean;
  relay_enabled: boolean;
  transport_preference: TransportPreference;
  relay_fallback_enabled: boolean;
  publish_capabilities: boolean;
  cover_traffic: boolean;
  msg_delay: boolean;
  local_notifications: boolean;
  unknown_peer_policy: UnknownPeerPolicy;
  min_trust_dm: number;
  min_trust_file: number;
  min_trust_invite: number;
  default_ttl?: number | null;
  persistence_enabled: boolean;
  invite_only_default: boolean;
  proof_of_work_enabled: boolean;
  rate_limit_per_minute: number;
  storage_node_enabled: boolean;
  storage_quota_mb: number;
  storage_retention_days: number;
  sfu_threshold: number;
  preferred_sfu_peer: string;
  accept_relay: boolean;
  experimental_media_e2ee: boolean;
}
export interface PeerSettings {
  peer_id: string;
  trust_level: number;
  blocked: boolean;
  muted: boolean;
  rate_limit_per_minute: number;
  proof_of_work_required: boolean;
}
export interface RoomSettings {
  channel_name: string;
  default_ttl?: number | null;
  retention_days?: number | null;
  persistence_enabled: boolean;
  invite_only: boolean;
  notifications_enabled: boolean;
}
export interface WebRtcStream {
  peerId: string;
  stream: MediaStream;
  type: 'video' | 'screen' | 'audio';
}
