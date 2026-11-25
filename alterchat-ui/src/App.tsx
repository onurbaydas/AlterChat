import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { OnboardingWizard } from "./components/OnboardingWizard";
import { PanicModal } from "./components/PanicModal";
import { SafetyNumbers } from "./components/SafetyNumbers";
import { TrustGraph } from "./components/TrustGraph";
import { VaultExport } from "./components/VaultExport";
import { NetworkStatusBadge } from "./components/NetworkStatusBadge";
import type { NetworkStatus, Reachability } from "./components/NetworkStatusBadge";
import { UpdateChecker } from "./components/UpdateChecker";
import { detectLang, saveLang, strings, type Lang } from "./i18n";
import "./index.css";

import { deriveMediaKey, makeE2EESenderTransform, makeE2EEReceiverTransform } from "./webrtc";
import type { 
  ChatMessage, PrivateMessage, Friend, SavedGroup, FullConfig,
  PeerSettings, RoomSettings, WebRtcStream 
} from "./types";

type FileTransferItem = {
  transferId: string;
  peerId: string;
  filename: string;
  size: number;
  direction: 'send' | 'receive';
  status: 'offer' | 'active' | 'done' | 'failed';
  done: number;
  total: number;
  path?: string;
  reason?: string;
};

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // UI language. Event listeners below are registered once per login, so they
  // read the strings through a ref to follow later language switches.
  const [lang, setLang] = useState<Lang>(detectLang());
  const t = strings(lang);
  const tRef = useRef(t);
  tRef.current = t;
  const changeLang = (next: Lang) => {
    setLang(next);
    saveLang(next);
  };

  const [myNick, setMyNick] = useState<string>("");
  const [myOfflinePubkey, setMyOfflinePubkey] = useState<string>("");
  const [peerId, setPeerId] = useState<string>("Loading...");
  const [peers, setPeers] = useState<string[]>([]);

  // Data State
  const [friends, setFriends] = useState<Friend[]>([]);
  const [savedGroups, setSavedGroups] = useState<SavedGroup[]>([]);

  // Layout state
  const [activeContext, setActiveContext] = useState<{type: 'global'|'group'|'friend', id: string}>({type: 'global', id: 'alterchat-global'});
  // The backend has one joined room at a time; room events belong to the most
  // recently opened group. Kept in a ref so the event listeners (registered
  // once at login) see the current value instead of the one from login time.
  const currentRoomRef = useRef<string>('alterchat-global');
  useEffect(() => {
    if (activeContext.type === 'group') currentRoomRef.current = activeContext.id;
  }, [activeContext]);

  // SFU Election State
  const [myCapacity, setMyCapacity] = useState(0);
  const [peerCapacities, setPeerCapacities] = useState<Record<string, number>>({});
  const [sfuHost, setSfuHost] = useState<string | null>(null);

  // Chat State
  const [channelMessages, setChannelMessages] = useState<Record<string, ChatMessage[]>>({});
  const [privateMessages, setPrivateMessages] = useState<Record<string, PrivateMessage[]>>({});
  const [useOnion, setUseOnion] = useState(false);
  const [peerTrust, setPeerTrust] = useState<Record<string, number>>({});
  const [inputText, setInputText] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const [selectedTtl, setSelectedTtl] = useState<number | null>(null);

  // Modals
  const [showSettings, setShowSettings] = useState(false);
  const [showJoin, setShowJoin] = useState(false);
  const [showAddFriend, setShowAddFriend] = useState(false);
  const [showContextSettings, setShowContextSettings] = useState(false);

  // Modal Inputs
  const [joinName, setJoinName] = useState("");
  const [joinPassword, setJoinPassword] = useState("");
  const [settingsNick, setSettingsNick] = useState("");
  const [settingsBootstrap, setSettingsBootstrap] = useState("");
  const [settingsBootstrapList, setSettingsBootstrapList] = useState("");
  const [torEnabled, setTorEnabled] = useState(false);
  const [proxyMode, setProxyMode] = useState('none');
  const [proxyAddr, setProxyAddr] = useState('');
  const [mdnsEnabled, setMdnsEnabled] = useState(true);
  const [dhtServerMode, setDhtServerMode] = useState(false);
  const [relayEnabled, setRelayEnabled] = useState(false);
  const [transportPreference, setTransportPreference] = useState("tcp");
  const [relayFallbackEnabled, setRelayFallbackEnabled] = useState(false);
  const [publishCapabilities, setPublishCapabilities] = useState(true);
  const [coverTraffic, setCoverTraffic] = useState(false);
  const [msgDelay, setMsgDelay] = useState(true);
  const [localNotifications, setLocalNotifications] = useState(true);
  const [unknownPeerPolicy, setUnknownPeerPolicy] = useState("request-only");
  const [minTrustDm, setMinTrustDm] = useState(0);
  const [minTrustFile, setMinTrustFile] = useState(0);
  const [minTrustInvite, setMinTrustInvite] = useState(0);
  const [defaultTtl, setDefaultTtl] = useState("");
  const [persistenceEnabled, setPersistenceEnabled] = useState(true);
  const [inviteOnlyDefault, setInviteOnlyDefault] = useState(false);
  const [proofOfWorkEnabled, setProofOfWorkEnabled] = useState(false);
  const [rateLimitPerMinute, setRateLimitPerMinute] = useState(30);
  const [storageNodeEnabled, setStorageNodeEnabled] = useState(false);
  const [storageQuotaMb, setStorageQuotaMb] = useState(512);
  const [storageRetentionDays, setStorageRetentionDays] = useState(7);
  const [sfuThreshold, setSfuThreshold] = useState(6);
  const [preferredSfuPeer, setPreferredSfuPeer] = useState("");
  const [acceptRelay, setAcceptRelay] = useState(false);
  const [experimentalMediaE2ee, setExperimentalMediaE2ee] = useState(false);
  const [settingsTab, setSettingsTab] = useState<'identity'|'network'|'privacy'|'rooms'|'storage'|'media'|'advanced'|'about'>('identity');
  const [appVersion, setAppVersion] = useState<string>("0.1.0");
  const [friendIdInput, setFriendIdInput] = useState("");
  const [friendNickInput, setFriendNickInput] = useState("");
  const [friendPubkeyInput, setFriendPubkeyInput] = useState("");
  const [peerSettings, setPeerSettings] = useState<PeerSettings | null>(null);
  const [roomSettings, setRoomSettings] = useState<RoomSettings | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<[string, string, string, number][]>([]);
  const [panicScope, setPanicScope] = useState("active_profile");

  // File Transfer State
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedPeerFile, setSelectedPeerFile] = useState<string>("");
  const [fileTransfers, setFileTransfers] = useState<Record<string, FileTransferItem>>({});
  const [fileMaxMb, setFileMaxMb] = useState(100);
  const [fileMaxConcurrent, setFileMaxConcurrent] = useState(3);

  // WebRTC Full Mesh State
  const pcsRef = useRef<Map<string, RTCPeerConnection>>(new Map());
  const localStreamRef = useRef<MediaStream | null>(null);
  const [remoteStreams, setRemoteStreams] = useState<WebRtcStream[]>([]);
  const [incomingCalls, setIncomingCalls] = useState<{ sender: string, offer: any, callType: string }[]>([]);
  const [inCall, setInCall] = useState(false);
  const [callType, setCallType] = useState<string | null>(null);

  const localVideoRef = useRef<HTMLVideoElement>(null);

  const [showPanicModal, setShowPanicModal] = useState(false);
  // #5 Safety Numbers
  const [safetyNumberPeer, setSafetyNumberPeer] = useState<{pubkey: string, nick: string} | null>(null);
  // #18 Trust Graph
  const [showTrustGraph, setShowTrustGraph] = useState(false);
  // #9/#14 Vault Export
  const [showVaultExport, setShowVaultExport] = useState(false);
  // #11 Anonim kanal
  const [anonChannelName, setAnonChannelName] = useState("");
  // #16 Ağ ban bildirimi
  const [bannedPeers, setBannedPeers] = useState<string[]>([]);

  // Network status indicator
  const [networkStatus, setNetworkStatus] = useState<NetworkStatus>("connecting");
  const [reachability, setReachability] = useState<Reachability>(null);

  useEffect(() => {
    invoke<string>("plugin:app|version")
      .then((v: string) => setAppVersion(v))
      .catch(() => setAppVersion("0.1.0"));
  }, []);

  const handlePanicWipe = async () => {
    setShowPanicModal(true);
  };

  const executePanicWipe = async () => {
    await invoke("panic_wipe", { scope: panicScope, confirm: "WIPE" });
  };

  // --- Initialization & Listeners ---
  useEffect(() => {
    if (!isAuthenticated) return;
    // Load Settings
    invoke<FullConfig>("get_settings").then((settings) => {
      const nick = settings.nick || "Anon" + Math.floor(Math.random() * 1000);
      setMyNick(nick);
      setMyOfflinePubkey(settings.offline_pubkey || "");
      // #1 WebRTC E2EE: pubkey'i global'a yaz (key derivation için)
      (window as any).__alterchat_pubkey = settings.offline_pubkey || "";
      (window as any).__alterchat_peer_pubkeys = {};
      setSettingsNick(nick);
      setSettingsBootstrap(settings.bootstrap_ip);
      setSettingsBootstrapList((settings.bootstrap_addrs || []).join("\n"));
      setTorEnabled(settings.tor_enabled);
      setProxyMode(settings.proxy_mode || 'none');
      setProxyAddr(settings.proxy_addr || '');
      setMdnsEnabled(settings.mdns_enabled !== false);
      setDhtServerMode(settings.dht_server_mode || false);
      setRelayEnabled(settings.relay_enabled || false);
      setTransportPreference(settings.transport_preference || "tcp");
      setRelayFallbackEnabled(settings.relay_fallback_enabled || false);
      setPublishCapabilities(settings.publish_capabilities !== false);
      setCoverTraffic(settings.cover_traffic || false);
      setMsgDelay(settings.msg_delay !== false);
      setLocalNotifications(settings.local_notifications !== false);
      setUnknownPeerPolicy(settings.unknown_peer_policy || "request-only");
      setMinTrustDm(settings.min_trust_dm || 0);
      setMinTrustFile(settings.min_trust_file || 0);
      setMinTrustInvite(settings.min_trust_invite || 0);
      setDefaultTtl(settings.default_ttl ? String(settings.default_ttl) : "");
      setPersistenceEnabled(settings.persistence_enabled !== false);
      setInviteOnlyDefault(settings.invite_only_default || false);
      setProofOfWorkEnabled(settings.proof_of_work_enabled || false);
      setRateLimitPerMinute(settings.rate_limit_per_minute || 30);
      setStorageNodeEnabled(settings.storage_node_enabled || false);
      setStorageQuotaMb(settings.storage_quota_mb || 512);
      setStorageRetentionDays(settings.storage_retention_days || 7);
      setSfuThreshold(settings.sfu_threshold || 6);
      setPreferredSfuPeer(settings.preferred_sfu_peer || "");
      setAcceptRelay(settings.accept_relay || false);
      setExperimentalMediaE2ee(settings.experimental_media_e2ee || false);
    }).catch(() => {
        invoke("get_peer_id").then((id) => {
          const defaultNick = (id as string).substring(0, 6);
          setPeerId(id as string);
          setMyNick(defaultNick);
          setSettingsNick(defaultNick);
        });
    });

    // Load Peer ID
    invoke("get_peer_id").then(id => setPeerId(id as string)).catch(console.error);
    invoke<{ max_file_size_mb: number; max_concurrent_transfers: number }>("get_file_transfer_settings")
      .then(s => { setFileMaxMb(s.max_file_size_mb); setFileMaxConcurrent(s.max_concurrent_transfers); })
      .catch(console.error);

    // Load Data
    const loadData = async () => {
      try {
        const fr = await invoke<Friend[]>("get_friends");
        setFriends(fr);
        // #1 WebRTC E2EE: peer pubkey'leri global'a yaz
        const peerPks: Record<string, string> = {};
        fr.forEach((f: any) => { if (f.offline_pubkey) peerPks[f.peer_id] = f.offline_pubkey; });
        (window as any).__alterchat_peer_pubkeys = peerPks;
        invoke("get_saved_groups").then(groups => setSavedGroups(groups as SavedGroup[])).catch(console.error);
        invoke("get_capacity_score").then(score => setMyCapacity(score as number)).catch(console.error);
      } catch (err) { console.error(err); }
    };
    loadData();

    // Event Listeners
    const unlistenMessage = listen<ChatMessage>("new-message", (e) => {
      // Benchmark messages interception
      if (e.payload.text.startsWith("BENCHMARK_SCORE:")) {
        const score = parseInt(e.payload.text.split(":")[1]);
        setPeerCapacities(prev => ({ ...prev, [e.payload.sender]: score }));
        return; // Don't show in chat
      }

      setChannelMessages(prev => {
        const chan = currentRoomRef.current;
        const msgs = prev[chan] || [];
        return { ...prev, [chan]: [...msgs, e.payload] };
      });
      // Try to fetch their trust if we don't have it
      if (e.payload.peer_id && peerTrust[e.payload.peer_id] === undefined) {
        invoke<any>("get_peer_settings", { peerId: e.payload.peer_id })
          .then(settings => setPeerTrust(prev => ({...prev, [e.payload.peer_id]: settings.trust_level})))
          .catch(() => {});
      }
    });

    const unlistenHistory = listen<ChatMessage[]>("chat-history", (event) => {
        const currentTopic = currentRoomRef.current;
        setChannelMessages(prev => {
        return { ...prev, [currentTopic]: event.payload };
      });
      // Fetch trust for all unique peers
      const uniquePeers = Array.from(new Set(event.payload.map(m => m.peer_id).filter(Boolean)));
      uniquePeers.forEach(pid => {
        if (peerTrust[pid] === undefined) {
          invoke<any>("get_peer_settings", { peerId: pid })
            .then(settings => setPeerTrust(prev => ({...prev, [pid]: settings.trust_level})))
            .catch(() => {});
        }
      });
    });

    const unlistenPm = listen<any>("new-private-message", (event) => {
      const { peer_id, sender_nick, text, timestamp } = event.payload;
      const pm: PrivateMessage = { peer_id, sender_is_me: false, text: `[${sender_nick}] ${text}`, timestamp };
      setPrivateMessages(prev => {
        const msgs = prev[peer_id] || [];
        return { ...prev, [peer_id]: [...msgs, pm] };
      });
    });

    const unlistenPeerDiscovered = listen<string>("peer-discovered", (event) => {
      setPeers((prev) => {
        if (!prev.includes(event.payload)) return [...prev, event.payload];
        return prev;
      });
      setNetworkStatus("online");
    });

    const unlistenPeerExpired = listen<string>("peer-expired", (event) => {
      setPeers((prev: string[]) => {
        const next = prev.filter((p: string) => p !== event.payload);
        setNetworkStatus(next.length > 0 ? "online" : "connecting");
        return next;
      });
      // Cleanup WebRTC if they left
      if (pcsRef.current.has(event.payload)) {
        pcsRef.current.get(event.payload)?.close();
        pcsRef.current.delete(event.payload);
        setRemoteStreams(prev => prev.filter(s => s.peerId !== event.payload));
      }
    });

    const unlistenReachability = listen<string>("network-reachability", (e) => {
      const r = e.payload;
      if (r === "direct" || r === "relayed" || r === "unreachable") setReachability(r);
    });
    const unlistenNetworkStatus = listen<string>("network-status", (event: { payload: string }) => {
      const s = event.payload as NetworkStatus;
      if (s === "online" || s === "connecting" || s === "offline") {
        setNetworkStatus(s);
      }
    });

    const unlistenPeerConnected = listen<string>("peer-connected", () => {
      setNetworkStatus("online");
    });

    const unlistenPeerDisconnected = listen<string>("peer-disconnected", () => {
      setPeers((prev: string[]) => {
        setNetworkStatus(prev.length > 0 ? "online" : "connecting");
        return prev;
      });
    });

    const unlistenSignal = listen<any>("webrtc-signal", async (event) => {
      const { sender, signal } = event.payload;
      const sigObj = JSON.parse(signal);

      if (sigObj.type === "offer") {
        setIncomingCalls(prev => [...prev, { sender, offer: sigObj, callType: sigObj.callType || 'audio' }]);
      } else if (sigObj.type === "answer") {
        const pc = pcsRef.current.get(sender);
        if (pc) await pc.setRemoteDescription(new RTCSessionDescription(sigObj));
      } else if (sigObj.candidate) {
        const pc = pcsRef.current.get(sender);
        if (pc) await pc.addIceCandidate(new RTCIceCandidate(sigObj));
      }
    });

    // Cleanup expired messages
    const cleanupInterval = setInterval(() => {
      const now = Date.now();

      setChannelMessages(prev => {
        let changed = false;
        const next: typeof prev = {};
        for (const [k, v] of Object.entries(prev)) {
          const filtered = v.filter(m => !m.ttl || (m.timestamp + m.ttl * 1000 > now));
          if (filtered.length !== v.length) changed = true;
          next[k] = filtered;
        }
        return changed ? next : prev;
      });

      setPrivateMessages(prev => {
        let changed = false;
        const next: typeof prev = {};
        for (const [k, v] of Object.entries(prev)) {
          const filtered = v.filter(m => !m.ttl || (m.timestamp + m.ttl * 1000 > now));
          if (filtered.length !== v.length) changed = true;
          next[k] = filtered;
        }
        return changed ? next : prev;
      });
    }, 1000);

    // #16 Ağ seviyesi PoW ban bildirimi
    const unlistenNetBan = listen<string>("peer-network-banned", (e) => {
      setBannedPeers(prev => [...new Set([...prev, e.payload])]);
    });
    // #4 Dağıtık revokasyon
    const unlistenRevoke = listen<string>("invite-revoked-global", (e) => {
      console.log("[AlterChat] Invite globally revoked:", e.payload);
    });
    // #11 Anonim kanal
    const unlistenAnon = listen<string>("anonymous-channel-joined", (e) => {
      console.log("[AlterChat] Anonymous channel joined:", e.payload);
    });

    // Backend errors that previously failed silently
    const unlistenSessionError = listen<string>("session-error", (e) => {
      setNetworkStatus("offline");
      alert(tRef.current.sessionError(e.payload));
    });
    const unlistenRoomJoinFailed = listen<string>("room-join-failed", (e) => {
      alert(tRef.current.roomJoinFailed(e.payload));
    });
    const unlistenDmNeedsKey = listen<string>("dm-requires-pubkey", (e) => {
      alert(tRef.current.dmNeedsKey(e.payload.substring(0, 8)));
    });
    const unlistenDmFailed = listen<{ peer_id: string; reason: string }>("dm-delivery-failed", (e) => {
      alert(tRef.current.dmFailed(e.payload.peer_id.substring(0, 8), e.payload.reason));
    });
    const updateTransfer = (id: string, patch: Partial<FileTransferItem>) =>
      setFileTransfers(prev => prev[id] ? { ...prev, [id]: { ...prev[id], ...patch } } : prev);
    const unlistenFileOffer = listen<{ transfer_id: string; peer_id: string; filename: string; size: number }>("file-offer", (e) => {
      const o = e.payload;
      setFileTransfers(prev => ({ ...prev, [o.transfer_id]: {
        transferId: o.transfer_id, peerId: o.peer_id, filename: o.filename, size: o.size,
        direction: 'receive', status: 'offer', done: 0, total: 0,
      } }));
    });
    const unlistenFileProgress = listen<{ transfer_id: string; done_chunks: number; total_chunks: number }>("file-progress", (e) => {
      updateTransfer(e.payload.transfer_id, { status: 'active', done: e.payload.done_chunks, total: e.payload.total_chunks });
    });
    const unlistenFileReceived = listen<{ transfer_id: string; path: string; filename: string }>("file-received", (e) => {
      updateTransfer(e.payload.transfer_id, { status: 'done', path: e.payload.path });
    });
    const unlistenFileSent = listen<{ transfer_id: string }>("file-sent", (e) => {
      updateTransfer(e.payload.transfer_id, { status: 'done' });
    });
    const unlistenFileFailed = listen<{ transfer_id: string; reason: string }>("file-transfer-failed", (e) => {
      updateTransfer(e.payload.transfer_id, { status: 'failed', reason: e.payload.reason });
    });
    const unlistenDmBlocked = listen<string>("private-message-blocked", (e) => {
      alert(tRef.current.dmBlocked(e.payload.substring(0, 8)));
    });

    return () => {
      unlistenSessionError.then(f => f());
      unlistenRoomJoinFailed.then(f => f());
      unlistenDmNeedsKey.then(f => f());
      unlistenDmFailed.then(f => f());
      unlistenDmBlocked.then(f => f());
      unlistenFileOffer.then(f => f());
      unlistenFileProgress.then(f => f());
      unlistenFileReceived.then(f => f());
      unlistenFileSent.then(f => f());
      unlistenFileFailed.then(f => f());
      unlistenMessage.then(f => f());
      unlistenHistory.then(f => f());
      unlistenPm.then(f => f());
      unlistenPeerDiscovered.then(f => f());
      unlistenPeerExpired.then(f => f());
      unlistenNetworkStatus.then(f => f());
      unlistenReachability.then(f => f());
      unlistenPeerConnected.then(f => f());
      unlistenPeerDisconnected.then(f => f());
      unlistenSignal.then(f => f());
      unlistenNetBan.then(f => f());
      unlistenRevoke.then(f => f());
      unlistenAnon.then(f => f());
      clearInterval(cleanupInterval);
    };
  }, [isAuthenticated]);

  // Fetch PMs when opening a friend chat
  useEffect(() => {
    if (activeContext.type === 'friend' && !privateMessages[activeContext.id]) {
      invoke<PrivateMessage[]>("get_private_messages", { peerId: activeContext.id })
        .then(msgs => setPrivateMessages(prev => ({...prev, [activeContext.id]: msgs})))
        .catch(console.error);
    }
  }, [activeContext]);

  // --- SFU Election Logic ---
  useEffect(() => {
    const activePeers = Object.keys(peerCapacities);
    if (activePeers.length + 1 > sfuThreshold) {
      let maxScore = myCapacity;
      let hostId = preferredSfuPeer.trim() || peerId;
      for (const peer of activePeers) {
        if (peerCapacities[peer] > maxScore) {
          maxScore = peerCapacities[peer];
          hostId = peer;
        } else if (peerCapacities[peer] === maxScore && peer > hostId) {
          hostId = peer; // Tie-breaker using string comparison
        }
      }
      setSfuHost(hostId);
    } else {
      setSfuHost(null); // Full Mesh
    }
  }, [peerCapacities, myCapacity, peerId, sfuThreshold, preferredSfuPeer]);

  // TTL Effect for Channel Messages
  useEffect(() => {
    const interval = setInterval(() => {
      // Periodically broadcast our benchmark if we're in a group
      if (activeContext.type === 'group' && myCapacity > 0) {
         invoke("send_message", { text: `BENCHMARK_SCORE:${myCapacity}`, nick: myNick, ttl: 0 }).catch(console.error);
      }

      setChannelMessages(prev => {
        let changed = false;
        const newObj = { ...prev };
        for (const [chan, msgs] of Object.entries(prev)) {
          const newMsgs = msgs.map(m => {
            if (m.ttl && m.text !== "[MESSAGE EXPIRED]" && (Date.now() - m.timestamp > m.ttl * 1000)) {
              changed = true;
              return { ...m, text: "[MESSAGE EXPIRED]" };
            }
            return m;
          });
          newObj[chan] = newMsgs;
        }
        return changed ? newObj : prev;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [channelMessages, privateMessages, activeContext]);

  // --- WebRTC Full Mesh / SFU Logic ---
  const getOrCreatePeerConnection = (targetPeer: string, incomingType: string | null = null) => {
    if (pcsRef.current.has(targetPeer)) {
      return pcsRef.current.get(targetPeer)!;
    }
    // No default STUN server: avoids a third-party (e.g. Google) dependency.
    // Direct P2P is attempted; NAT traversal should go through libp2p relay.
    // @ts-ignore - encodedInsertableStreams is not in standard TS types yet
    const pc = new RTCPeerConnection({ iceServers: [], encodedInsertableStreams: true });

    pc.onicecandidate = (event) => {
      if (event.candidate) {
        invoke("send_webrtc_signal", { peerId: targetPeer, signal: JSON.stringify(event.candidate) });
      }
    };

    pc.ontrack = (event) => {
      const type = (callType || incomingType) as 'video'|'screen'|'audio';

      if (experimentalMediaE2ee) {
        // #1 WebRTC E2EE: AES-256-GCM ile gerçek medya şifre çözme
        // @ts-ignore - Insertable Streams API
        const receiverStreams = event.receiver.createEncodedStreams?.();
        if (receiverStreams) {
          const myPk = (window as any).__alterchat_pubkey || "";
          const peerPk = (window as any).__alterchat_peer_pubkeys?.[targetPeer] || "";
          if (myPk && peerPk) {
            deriveMediaKey(myPk, peerPk).then(key => {
              const decryptTransform = makeE2EEReceiverTransform(key);
              receiverStreams.readable.pipeThrough(decryptTransform).pipeTo(receiverStreams.writable);
            });
          } else {
            // Anahtar henüz mevcut değil — şifresiz geç (degraded mode)
            const passthrough = new TransformStream({ transform(chunk, controller) { controller.enqueue(chunk); } });
            receiverStreams.readable.pipeThrough(passthrough).pipeTo(receiverStreams.writable);
          }
        }
      }

      setRemoteStreams(prev => {
        const filtered = prev.filter(s => s.peerId !== targetPeer);
        return [...filtered, { peerId: targetPeer, stream: event.streams[0], type }];
      });

      // If we are the SFU host, forward this track to all other peers
      if (sfuHost === peerId) {
        pcsRef.current.forEach((otherPc, otherPeerId) => {
          if (otherPeerId !== targetPeer) {
            // Forward track
            event.streams[0].getTracks().forEach(track => {
              otherPc.addTrack(track, event.streams[0]);
            });
          }
        });
      }
    };

    pc.oniceconnectionstatechange = () => {
      if (pc.iceConnectionState === 'disconnected' || pc.iceConnectionState === 'failed') {
        pc.close();
        pcsRef.current.delete(targetPeer);
        setRemoteStreams(prev => prev.filter(s => s.peerId !== targetPeer));
        if (pcsRef.current.size === 0) setInCall(false);
      }
    };

    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach(track => pc.addTrack(track, localStreamRef.current!));
    }

    pcsRef.current.set(targetPeer, pc);
    return pc;
  };

  const handleStartCall = async (type: 'video'|'screen'|'audio') => {
    setCallType(type);
    let stream: MediaStream | null = null;
    try {
      if (type === 'video') stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      if (type === 'screen') stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: true });
      if (type === 'audio') stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch(err) { console.error(err); return; }

    if (stream) {
      localStreamRef.current = stream;
      if (localVideoRef.current && (type === 'video' || type === 'screen')) {
         localVideoRef.current.srcObject = stream;
      }
    }

    setInCall(true);

    // If Star topology and we are not host
    if (sfuHost && sfuHost !== peerId) {
      const targetPeer = sfuHost;
      const pc = getOrCreatePeerConnection(targetPeer);
      if (stream) stream.getTracks().forEach(track => pc.addTrack(track, stream));
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      const offerWithMeta = { type: offer.type, sdp: offer.sdp, callType: type };
      await invoke("send_webrtc_signal", { peerId: targetPeer, signal: JSON.stringify(offerWithMeta) });
      return;
    }

    // Full Mesh or We are Host
    let targetPeers: string[] = [];
    if (activeContext.type === 'friend') {
      targetPeers = [activeContext.id];
    } else {
      // In a group, call active peers who broadcasted recently
      targetPeers = Object.keys(peerCapacities).filter(id => id !== peerId);
    }

    for (const targetPeer of targetPeers) {
      const pc = getOrCreatePeerConnection(targetPeer);
      if (stream) {
        stream.getTracks().forEach(track => {
          const sender = pc.addTrack(track, stream);

          if (experimentalMediaE2ee) {
            // #1 WebRTC E2EE: AES-256-GCM medya şifreleme (Insertable Streams)
            // @ts-ignore
            const senderStreams = sender.createEncodedStreams?.();
            if (senderStreams) {
              const myPk = (window as any).__alterchat_pubkey || "";
              const peerPk = (window as any).__alterchat_peer_pubkeys?.[targetPeer] || "";
              if (myPk && peerPk) {
                deriveMediaKey(myPk, peerPk).then(key => {
                  const encryptTransform = makeE2EESenderTransform(key);
                  senderStreams.readable.pipeThrough(encryptTransform).pipeTo(senderStreams.writable);
                });
              } else {
                const passthrough = new TransformStream({ transform(chunk: any, controller) { controller.enqueue(chunk); } });
                senderStreams.readable.pipeThrough(passthrough).pipeTo(senderStreams.writable);
              }
            }
          }
        });
      }

      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      const offerWithMeta = { type: offer.type, sdp: offer.sdp, callType: type };
      await invoke("send_webrtc_signal", { peerId: targetPeer, signal: JSON.stringify(offerWithMeta) });
    }
  };

  const handleAcceptCall = async (callData: { sender: string, offer: any, callType: string }) => {
    setCallType(callData.callType);
    try {
      if (!localStreamRef.current) {
         localStreamRef.current = await navigator.mediaDevices.getUserMedia({
          audio: true,
          video: callData.callType === 'video'
        });
        if (localVideoRef.current && callData.callType === 'video') {
           localVideoRef.current.srcObject = localStreamRef.current;
        }
      }

      const pc = getOrCreatePeerConnection(callData.sender, callData.callType);
      await pc.setRemoteDescription(new RTCSessionDescription(callData.offer));
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await invoke("send_webrtc_signal", { peerId: callData.sender, signal: JSON.stringify(answer) });

      setInCall(true);
      setIncomingCalls(prev => prev.filter(c => c.sender !== callData.sender));
    } catch (err) {
      console.error(err);
    }
  };

  const handleEndCall = () => {
    pcsRef.current.forEach(pc => pc.close());
    pcsRef.current.clear();

    if (localStreamRef.current) localStreamRef.current.getTracks().forEach(t => t.stop());
    localStreamRef.current = null;
    if (localVideoRef.current) localVideoRef.current.srcObject = null;

    setRemoteStreams([]);
    setInCall(false);
    setCallType(null);
    setIncomingCalls([]);
  };

  // --- Actions ---
  const endorsePeer = (peerId: string, score: number) => {
    if (!peerId) return;
    invoke("endorse_peer", { peerId, score })
      .then(() => {
        setPeerTrust(prev => ({...prev, [peerId]: (prev[peerId] || 0) + score}));
      })
      .catch(console.error);
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) return;
    const input = inputText.trim();
    setInputText("");
    const roomDefaultTtl = activeContext.type === 'group'
      ? savedGroups.find(g => g.channel_name === activeContext.id)?.default_ttl
      : null;
    const effectiveTtl = selectedTtl ?? roomDefaultTtl ?? null;

    if (activeContext.type === 'group') {
      await invoke("send_message", { text: input, nick: myNick || peerId.substring(0,6), ttl: effectiveTtl });
    }
    if (activeContext.type === 'friend') {
      const targetPeer = activeContext.id;
      const timestamp = Date.now();
        invoke("send_private_message", {
          peerId: activeContext.id,
          text: inputText,
          senderNick: myNick,
          ttl: selectedTtl,
          useOnion: useOnion
        }).then(() => {
          const pm: PrivateMessage = { peer_id: targetPeer, sender_is_me: true, text: input, timestamp, ttl: effectiveTtl };
          setPrivateMessages(prev => {
            const msgs = prev[targetPeer] || [];
            return { ...prev, [targetPeer]: [...msgs, pm] };
          });
        });
    }
  };

  const handleJoinGroup = async () => {
    if (!joinName.trim()) return;
    try {
      await invoke("join_channel", { name: joinName, password: joinPassword || null });
      await invoke("save_group", { channelName: joinName, password: joinPassword || null });

      setSavedGroups(prev => [...prev.filter(g => g.channel_name !== joinName), { channel_name: joinName, password: joinPassword || undefined }]);
      setActiveContext({ type: 'group', id: joinName });
      setShowJoin(false);
      setJoinName(""); setJoinPassword("");
    } catch (err) { console.error("Join group error", err); }
  };

  const handleAddFriend = async () => {
    if (!friendIdInput.trim() || !friendNickInput.trim()) return;
    try {
      const pubkey = friendPubkeyInput.trim() || null;
      await invoke("add_friend", { peerId: friendIdInput, nickname: friendNickInput, offlinePubkey: pubkey });
      setFriends(prev => [...prev.filter(f => f.peer_id !== friendIdInput), { peer_id: friendIdInput, nickname: friendNickInput }]);
      setShowAddFriend(false);
      setFriendIdInput(""); setFriendNickInput(""); setFriendPubkeyInput("");
    } catch (err) { console.error("Add friend error", err); }
  };

  const handleSaveSettings = async () => {
    try {
        const bootstrapAddrs = settingsBootstrapList
          .split(/\r?\n/)
          .map(s => s.trim())
          .filter(Boolean);
        await invoke('save_settings', {
          nick: settingsNick,
          bootstrapIp: settingsBootstrap,
          bootstrapAddrs,
          torEnabled,
          proxyMode,
          proxyAddr,
          mdnsEnabled,
          dhtServerMode,
          relayEnabled,
          transportPreference,
          relayFallbackEnabled,
          publishCapabilities,
          coverTraffic,
          msgDelay,
          localNotifications,
          unknownPeerPolicy,
          minTrustDm,
          minTrustFile,
          minTrustInvite,
          defaultTtl: defaultTtl ? parseInt(defaultTtl) : null,
          persistenceEnabled,
          inviteOnlyDefault,
          proofOfWorkEnabled,
          rateLimitPerMinute,
          storageNodeEnabled,
          storageQuotaMb,
          storageRetentionDays,
          sfuThreshold,
          preferredSfuPeer,
          acceptRelay,
          experimentalMediaE2ee,
        });
        const fileSettings = await invoke<{ max_file_size_mb: number; max_concurrent_transfers: number }>(
          "save_file_transfer_settings",
          { settings: { max_file_size_mb: fileMaxMb, max_concurrent_transfers: fileMaxConcurrent } },
        );
        setFileMaxMb(fileSettings.max_file_size_mb);
        setFileMaxConcurrent(fileSettings.max_concurrent_transfers);
        setMyNick(settingsNick);
        alert(t.settingsSaved);
        setShowSettings(false);
    } catch (err) { console.error(err); }
  };

  const handleExportConfig = async () => {
    try {
      const json = await invoke<string>("export_profile_config");
      await navigator.clipboard.writeText(json);
      alert(t.configCopied);
    } catch (err) {
      console.error(err);
      alert(t.configExportFailed);
    }
  };

  const handleImportConfig = async () => {
    const json = window.prompt(t.configPastePrompt);
    if (!json) return;
    try {
      await invoke("import_profile_config", { json });
      alert(t.configImported);
    } catch (err) {
      console.error(err);
      alert(t.configImportFailed);
    }
  };

  const openContextSettings = async () => {
    try {
      if (activeContext.type === 'friend') {
        const settings = await invoke<PeerSettings>("get_peer_settings", { peerId: activeContext.id });
        setPeerSettings(settings);
        setRoomSettings(null);
      } else {
        const settings = await invoke<RoomSettings>("get_room_settings", { channelName: activeContext.id });
        setRoomSettings(settings);
        setPeerSettings(null);
      }
      setShowContextSettings(true);
    } catch (err) {
      console.error(err);
    }
  };

  const saveContextSettings = async () => {
    try {
      if (peerSettings) {
        await invoke("save_peer_settings", { settings: peerSettings });
        setFriends(prev => prev.map(friend => friend.peer_id === peerSettings.peer_id
          ? { ...friend, trust_level: peerSettings.trust_level, blocked: peerSettings.blocked, muted: peerSettings.muted }
          : friend));
      }
      if (roomSettings) {
        await invoke("save_room_settings", { settings: roomSettings });
        setSavedGroups(prev => prev.map(group => group.channel_name === roomSettings.channel_name
          ? {
              ...group,
              default_ttl: roomSettings.default_ttl,
              retention_days: roomSettings.retention_days,
              persistence_enabled: roomSettings.persistence_enabled,
              invite_only: roomSettings.invite_only,
              notifications_enabled: roomSettings.notifications_enabled,
            }
          : group));
      }
      setShowContextSettings(false);
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreateInvite = async () => {
    if (activeContext.type !== 'group') return;
    const group = savedGroups.find(g => g.channel_name === activeContext.id);
    try {
      const token = await invoke<string>("create_invite", {
        roomId: activeContext.id,
        roomPassword: group?.password || null,
        expiresInSeconds: 7 * 24 * 60 * 60,
        maxUses: 25,
      });
      await navigator.clipboard.writeText(token);
      alert(t.inviteCopied);
    } catch (err) {
      console.error(err);
      alert(t.inviteCreateFailed);
    }
  };

  const handleAcceptInvite = async () => {
    const tokenJson = window.prompt(t.invitePastePrompt);
    if (!tokenJson) return;
    try {
      const [roomId, roomPassword] = await invoke<[string, string | null]>("accept_invite", { tokenJson });
      await invoke("join_channel", { name: roomId, password: roomPassword });
      const groups = await invoke<SavedGroup[]>("get_saved_groups");
      setSavedGroups(groups);
      setActiveContext({ type: 'group', id: roomId });
    } catch (err) {
      console.error(err);
      alert(t.inviteAcceptFailed);
    }
  };

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) {
      setSearchResults([]);
      return;
    }
    try {
      const results = await invoke<[string, string, string, number][]>("search_messages", {
        query: searchQuery.trim(),
        limit: 20,
      });
      setSearchResults(results);
    } catch (err) {
      console.error(err);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    const peer = selectedPeerFile;
    e.target.value = '';
    if (!file || !peer) return;
    if (file.size > fileMaxMb * 1024 * 1024) {
      alert(t.fileTooLarge(file.name, fileMaxMb));
      return;
    }
    try {
      const buffer = await file.arrayBuffer();
      const nameHex = Array.from(new TextEncoder().encode(file.name))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      // Raw IPC body: avoids serialising the file as a JSON number array.
      const transferId = await invoke<string>("send_file", new Uint8Array(buffer), {
        headers: { "x-peer-id": peer, "x-file-name": nameHex, "x-file-mime": file.type || "" },
      });
      setFileTransfers(prev => ({ ...prev, [transferId]: {
        transferId, peerId: peer, filename: file.name, size: file.size,
        direction: 'send', status: 'offer', done: 0, total: 0,
      } }));
    } catch (err) {
      console.error("File send error", err);
      alert(t.fileSendFailed(file.name, String(err)));
    }
  };

  const respondToFileOffer = async (transferId: string, accept: boolean) => {
    try {
      await invoke(accept ? "accept_file_offer" : "reject_file_offer", { transferId });
      if (accept) {
        setFileTransfers(prev => prev[transferId] ? { ...prev, [transferId]: { ...prev[transferId], status: 'active' } } : prev);
      }
    } catch (err) { console.error(err); }
  };

  const openReceivedFile = async (transferId: string, reveal: boolean) => {
    try {
      await invoke<string>("open_received_file", { transferId, reveal });
    } catch (err) { alert(t.fileOpenFailed(String(err))); }
  };

  const dismissTransfer = (transferId: string) =>
    setFileTransfers(prev => { const next = { ...prev }; delete next[transferId]; return next; });

  const formatBytes = (n: number) =>
    n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MiB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${n} B`;

  const formatTime = (ts: number) => {
    const d = new Date(ts);
    return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
  };

  // --- Render Helpers ---
  const currentMessages = activeContext.type === 'group'
    ? (channelMessages[activeContext.id] || [])
    : (privateMessages[activeContext.id] || []).map(m => ({
        sender: m.sender_is_me ? "You" : (friends.find(f => f.peer_id === m.peer_id)?.nickname || m.peer_id.substring(0,6)),
        text: m.text,
        timestamp: m.timestamp
      }));

  const activeTitle = activeContext.type === 'group'
    ? `# ${activeContext.id}`
    : `@ ${friends.find(f => f.peer_id === activeContext.id)?.nickname || activeContext.id.substring(0,6)}`;

  const settingsTabLabels: Record<typeof settingsTab, string> = {
    identity: t.tabIdentity,
    network: t.tabNetwork,
    privacy: t.tabPrivacy,
    rooms: t.tabRooms,
    storage: t.tabStorage,
    media: t.tabMedia,
    advanced: t.tabAdvanced,
    about: t.tabAbout,
  };

  if (!isAuthenticated) {
    return (
      <OnboardingWizard
        onComplete={() => setIsAuthenticated(true)}
        lang={lang}
        onLangChange={changeLang}
      />
    );
  }

  return (
    <div className="app-container">
      <UpdateChecker lang={lang} />
      {/* Hidden file input */}
      <input type="file" ref={fileInputRef} style={{display: 'none'}} onChange={handleFileChange} />

      {/* File transfers: incoming offers (ask before accept), progress, results */}
      {Object.values(fileTransfers).length > 0 && (
        <div className="file-transfers">
          {Object.values(fileTransfers).map(ft => {
            const who = friends.find(f => f.peer_id === ft.peerId)?.nickname || ft.peerId.substring(0, 8);
            const pct = ft.total > 0 ? Math.round((ft.done / ft.total) * 100) : 0;
            return (
              <div key={ft.transferId} className={`file-transfer file-transfer-${ft.status}`}>
                <div className="file-transfer-title" title={ft.filename}>
                  {ft.direction === 'receive' ? '⬇' : '⬆'} {ft.filename} <span className="file-transfer-meta">{ft.direction === 'receive' ? t.fileMetaFrom(formatBytes(ft.size), who) : t.fileMetaTo(formatBytes(ft.size), who)}</span>
                </div>
                {ft.status === 'offer' && ft.direction === 'receive' && (
                  <div className="file-transfer-actions">
                    <button className="peer-btn" onClick={() => respondToFileOffer(ft.transferId, false)}>{t.reject}</button>
                    <button className="peer-btn" onClick={() => respondToFileOffer(ft.transferId, true)}>{t.accept}</button>
                  </div>
                )}
                {ft.status === 'offer' && ft.direction === 'send' && (
                  <div className="file-transfer-meta">{t.fileWaiting}</div>
                )}
                {ft.status === 'active' && (
                  <>
                    <progress max={100} value={pct} />
                    <div className="file-transfer-actions">
                      <span className="file-transfer-meta">{pct}%</span>
                      <button className="peer-btn" onClick={() => respondToFileOffer(ft.transferId, false)}>{t.cancel}</button>
                    </div>
                  </>
                )}
                {ft.status === 'done' && (
                  <div className="file-transfer-actions">
                    {ft.direction === 'receive' && ft.path ? (
                      <>
                        <span className="file-transfer-meta" title={ft.path}>{t.fileSaved}</span>
                        <button className="peer-btn" onClick={() => openReceivedFile(ft.transferId, false)}>{t.fileOpen}</button>
                        <button className="peer-btn" onClick={() => openReceivedFile(ft.transferId, true)}>{t.fileShowInFolder}</button>
                      </>
                    ) : <span className="file-transfer-meta">{t.fileDelivered}</span>}
                    <button className="peer-btn" title={t.dismiss} onClick={() => dismissTransfer(ft.transferId)}>✕</button>
                  </div>
                )}
                {ft.status === 'failed' && (
                  <div className="file-transfer-actions">
                    <span className="file-transfer-meta">{t.fileFailed(ft.reason ?? "")}</span>
                    <button className="peer-btn" title={t.dismiss} onClick={() => dismissTransfer(ft.transferId)}>✕</button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
      
      {/* Panic Wipe Modal */}
      <PanicModal 
        showPanicModal={showPanicModal}
        setShowPanicModal={setShowPanicModal}
        panicScope={panicScope}
        setPanicScope={setPanicScope}
        executePanicWipe={executePanicWipe}
        lang={lang}
      />

      {/* Remote Audio Elements for Voice Calls */}
      {remoteStreams.filter(s => s.type === 'audio').map(s => (
        <audio key={s.peerId} autoPlay ref={el => { if(el) el.srcObject = s.stream; }} />
      ))}

      {/* Incoming Call Modals */}
      {incomingCalls.map(c => (
        <div key={c.sender} className="modal-overlay">
          <div className="modal-content">
            <h3>{t.incomingCall} 📞</h3>
            <p>{t.isCalling(friends.find(f => f.peer_id === c.sender)?.nickname || c.sender.substring(0, 8), c.callType === 'video' ? t.callVideo : c.callType === 'screen' ? t.callScreen : c.callType === 'audio' ? t.callAudio : c.callType)}</p>
            <div className="modal-actions">
              <button className="peer-btn" onClick={() => setIncomingCalls(p => p.filter(x => x.sender !== c.sender))} style={{color: '#ff4444', borderColor: '#ff4444'}}>{t.reject}</button>
              <button className="peer-btn" onClick={() => handleAcceptCall(c)} style={{color: '#44ff44', borderColor: '#44ff44'}}>{t.accept}</button>
            </div>
          </div>
        </div>
      ))}

      {/* Settings Modal */}
      {showSettings && (
        <div className="modal-overlay">
          <div className="modal-content settings-modal">
            <h3>{t.settingsTitle}</h3>
            <div className="settings-tabs">
              {(['identity','network','privacy','rooms','storage','media','advanced','about'] as const).map(tab => (
                <button key={tab} className={`settings-tab ${settingsTab === tab ? 'active' : ''}`} onClick={() => setSettingsTab(tab)}>{settingsTabLabels[tab]}</button>
              ))}
            </div>

            <div className="settings-pane">
              {settingsTab === 'identity' && (
                <>
                  <label>{t.nickAlias}</label>
                  <input placeholder={t.nickAliasPh} value={settingsNick} onChange={e => setSettingsNick(e.target.value)} />
                  <div className="settings-note">{t.aliasNote(peerId.substring(0, 16))}</div>
                  <label>{t.language}</label>
                  <select value={lang} onChange={e => changeLang(e.target.value as Lang)}>
                    <option value="tr">Türkçe</option>
                    <option value="en">English</option>
                  </select>
                </>
              )}

              {settingsTab === 'network' && (
                <>
                  <label>{t.primaryBootstrap}</label>
                  <input placeholder="/ip4/x.x.x.x/tcp/XXXX/p2p/12D3..." value={settingsBootstrap} onChange={e => setSettingsBootstrap(e.target.value)} />
                  <label>{t.bootstrapList}</label>
                  <textarea value={settingsBootstrapList} onChange={e => setSettingsBootstrapList(e.target.value)} placeholder={t.bootstrapListPh} />
                  <label>{t.networkMode}</label>
                  <select value={proxyMode} onChange={e => setProxyMode(e.target.value)}>
                    <option value="none">{t.modeDirect}</option>
                    <option value="tor">{t.modeTor}</option>
                    <option value="socks5">{t.modeSocks}</option>
                    <option value="i2p">{t.modeI2p}</option>
                  </select>
                  <label>{t.transportPref}</label>
                  <select value={transportPreference} onChange={e => setTransportPreference(e.target.value)}>
                    <option value="tcp">TCP</option>
                    <option value="quic">{t.quicPreferred}</option>
                    <option value="tor">{t.torPreferred}</option>
                  </select>
                  {(proxyMode === 'socks5' || proxyMode === 'i2p') && (
                    <>
                      <input placeholder={proxyMode === 'socks5' ? t.socksPh : t.i2pPh} value={proxyAddr} onChange={e => setProxyAddr(e.target.value)} />
                      <div className="settings-note">
                        {proxyMode === 'socks5'
                          ? t.socksNote
                          : t.i2pNote}
                      </div>
                    </>
                  )}
                  <label><input type="checkbox" checked={torEnabled} onChange={e => setTorEnabled(e.target.checked)} /> {t.torNextSession}</label>
                  <label><input type="checkbox" checked={mdnsEnabled} onChange={e => setMdnsEnabled(e.target.checked)} /> {t.mdnsDiscovery}</label>
                  <label><input type="checkbox" checked={dhtServerMode} onChange={e => setDhtServerMode(e.target.checked)} /> {t.dhtServe}</label>
                  <label><input type="checkbox" checked={relayEnabled} onChange={e => setRelayEnabled(e.target.checked)} /> {t.volunteerRelay}</label>
                  <label><input type="checkbox" checked={relayFallbackEnabled} onChange={e => setRelayFallbackEnabled(e.target.checked)} /> {t.relayFallback}</label>
                  <label><input type="checkbox" checked={publishCapabilities} onChange={e => setPublishCapabilities(e.target.checked)} /> {t.publishCaps}</label>
                </>
              )}

              {settingsTab === 'privacy' && (
                <>
                  <label><input type="checkbox" checked={coverTraffic} onChange={e => setCoverTraffic(e.target.checked)} /> {t.coverTraffic}</label>
                  <label><input type="checkbox" checked={msgDelay} onChange={e => setMsgDelay(e.target.checked)} /> {t.randomDelay}</label>
                  <label><input type="checkbox" checked={localNotifications} onChange={e => setLocalNotifications(e.target.checked)} /> {t.localNotifications}</label>
                  <label><input type="checkbox" checked={proofOfWorkEnabled} onChange={e => setProofOfWorkEnabled(e.target.checked)} /> {t.requirePow}</label>
                  <label>{t.unknownPeerPolicy}</label>
                  <select value={unknownPeerPolicy} onChange={e => setUnknownPeerPolicy(e.target.value)}>
                    <option value="request-only">{t.policyRequestOnly}</option>
                    <option value="allow">{t.policyAllow}</option>
                    <option value="block">{t.policyBlock}</option>
                  </select>
                  <label>{t.rateLimitIdentity}</label>
                  <input type="number" min={1} value={rateLimitPerMinute} onChange={e => setRateLimitPerMinute(parseInt(e.target.value) || 1)} />
                  <label>{t.minTrustDm}</label>
                  <input type="number" min={0} max={10} value={minTrustDm} onChange={e => setMinTrustDm(parseInt(e.target.value) || 0)} />
                  <label>{t.minTrustFile}</label>
                  <input type="number" min={0} max={10} value={minTrustFile} onChange={e => setMinTrustFile(parseInt(e.target.value) || 0)} />
                  <label>{t.minTrustInvite}</label>
                  <input type="number" min={0} max={10} value={minTrustInvite} onChange={e => setMinTrustInvite(parseInt(e.target.value) || 0)} />
                  <div className="settings-note">{t.privacyNote}</div>
                </>
              )}

              {settingsTab === 'rooms' && (
                <>
                  <label>{t.defaultTtl}</label>
                  <input type="number" min={0} placeholder={t.defaultTtlPh} value={defaultTtl} onChange={e => setDefaultTtl(e.target.value)} />
                  <label><input type="checkbox" checked={persistenceEnabled} onChange={e => setPersistenceEnabled(e.target.checked)} /> {t.persistRoomState}</label>
                  <label><input type="checkbox" checked={inviteOnlyDefault} onChange={e => setInviteOnlyDefault(e.target.checked)} /> {t.inviteOnlyDefault}</label>
                </>
              )}

              {settingsTab === 'storage' && (
                <>
                  <label><input type="checkbox" checked={storageNodeEnabled} onChange={e => setStorageNodeEnabled(e.target.checked)} /> {t.storageNode}</label>
                  <label>{t.storageQuota}</label>
                  <input type="number" min={1} value={storageQuotaMb} onChange={e => setStorageQuotaMb(parseInt(e.target.value) || 1)} />
                  <label>{t.storageRetention}</label>
                  <input type="number" min={1} value={storageRetentionDays} onChange={e => setStorageRetentionDays(parseInt(e.target.value) || 1)} />
                  <label>{t.maxFileSize}</label>
                  <input type="number" min={1} max={4096} value={fileMaxMb} onChange={e => setFileMaxMb(parseInt(e.target.value) || 1)} />
                  <label>{t.maxConcurrent}</label>
                  <input type="number" min={1} max={16} value={fileMaxConcurrent} onChange={e => setFileMaxConcurrent(parseInt(e.target.value) || 1)} />
                  <div className="settings-note">{t.storageNote}</div>
                </>
              )}

              {settingsTab === 'media' && (
                <>
                  <label>{t.sfuThreshold}</label>
                  <input type="number" min={2} value={sfuThreshold} onChange={e => setSfuThreshold(parseInt(e.target.value) || 2)} />
                  <label>{t.preferredSfu}</label>
                  <input value={preferredSfuPeer} onChange={e => setPreferredSfuPeer(e.target.value)} placeholder={t.preferredSfuPh} />
                  <label><input type="checkbox" checked={acceptRelay} onChange={e => setAcceptRelay(e.target.checked)} /> {t.acceptMediaRelay}</label>
                  <label><input type="checkbox" checked={experimentalMediaE2ee} onChange={e => setExperimentalMediaE2ee(e.target.checked)} /> 🔐 {t.mediaE2ee}</label>
                  <div className="settings-note">{t.mediaNote}</div>
                </>
              )}

              {settingsTab === 'advanced' && (
                <>
                  <button className="cyber-btn" onClick={handleExportConfig}>{t.exportConfig}</button>
                  <button className="cyber-btn" onClick={handleImportConfig}>{t.importConfig}</button>
                  <div className="settings-note">{t.configNote}</div>
                  <label>{t.panicScopeLabel}</label>
                  <select value={panicScope} onChange={e => setPanicScope(e.target.value)}>
                    <option value="active_profile">{t.scopeActive}</option>
                    <option value="message_db_only">{t.scopeMsgDb}</option>
                    <option value="all_profiles">{t.scopeAll}</option>
                  </select>
                </>
              )}

              {settingsTab === 'about' && (
                <div className="about-pane">
                  <div className="about-version">AlterChat v{appVersion}</div>
                  <div className="about-desc">
                    {t.aboutDesc}
                  </div>
                  <div>
                    <a
                      href="#"
                      className="about-changelog-link"
                      onClick={(e) => {
                        e.preventDefault();
                        invoke("plugin:opener|open_url", { url: "https://github.com/onurbaydas/AlterChat/blob/main/CHANGELOG.md" }).catch(console.error);
                      }}
                    >
                      {t.changelog}
                    </a>
                  </div>
                  <div className="settings-note">
                    {t.license}
                  </div>
                </div>
              )}
            </div>

            <div className="modal-actions">
              <button className="cyber-btn" onClick={() => setShowSettings(false)}>{t.cancel}</button>
              <button className="cyber-btn primary" onClick={handleSaveSettings}>💾 {t.save}</button>
            </div>
          </div>
        </div>
      )}

      {/* Join Group Modal */}
      {showJoin && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3>{t.joinTitle}</h3>
            <input placeholder={t.groupNamePh} value={joinName} onChange={e => setJoinName(e.target.value)} />
            <input type="password" placeholder={t.groupPwPh} value={joinPassword} onChange={e => setJoinPassword(e.target.value)} />
            <div className="modal-actions">
              <button className="cyber-btn" onClick={() => setShowJoin(false)}>{t.cancel}</button>
              <button className="cyber-btn primary" onClick={handleJoinGroup}>{t.join}</button>
            </div>
          </div>
        </div>
      )}

      {/* Add Friend Modal */}
      {showAddFriend && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3>{t.addFriendTitle}</h3>
            <div className="modal-form">
              <label>{t.peerIdLabel}</label>
              <input type="text" value={friendIdInput} onChange={e => setFriendIdInput(e.target.value)} placeholder="12D3KooW..." />
              <label>{t.friendNick}</label>
              <input type="text" value={friendNickInput} onChange={e => setFriendNickInput(e.target.value)} placeholder="Cypher..." />
              <label>{t.offlinePubkey}</label>
              <input type="text" value={friendPubkeyInput} onChange={e => setFriendPubkeyInput(e.target.value)} placeholder={t.offlinePubkeyPh} />
            </div>
            <div className="modal-actions">
              <button className="cyber-btn" onClick={() => setShowAddFriend(false)}>{t.cancel}</button>
              <button className="cyber-btn primary" onClick={handleAddFriend}>{t.add}</button>
            </div>
          </div>
        </div>
      )}

      {showContextSettings && (
        <div className="modal-overlay">
          <div className="modal-content settings-modal">
            <h3>{activeContext.type === 'friend' ? t.peerControls : t.roomControls}</h3>
            <div className="settings-pane">
              {peerSettings && (
                <>
                  <label>{t.trustLevel}</label>
                  <input type="number" min={0} max={10} value={peerSettings.trust_level} onChange={e => setPeerSettings({ ...peerSettings, trust_level: parseInt(e.target.value) || 0 })} />
                  <label><input type="checkbox" checked={peerSettings.blocked} onChange={e => setPeerSettings({ ...peerSettings, blocked: e.target.checked })} /> {t.blockLocal}</label>
                  <label><input type="checkbox" checked={peerSettings.muted} onChange={e => setPeerSettings({ ...peerSettings, muted: e.target.checked })} /> {t.muteLocal}</label>
                  <label>{t.rateLimitMinute}</label>
                  <input type="number" min={1} value={peerSettings.rate_limit_per_minute} onChange={e => setPeerSettings({ ...peerSettings, rate_limit_per_minute: parseInt(e.target.value) || 1 })} />
                  <label><input type="checkbox" checked={peerSettings.proof_of_work_required} onChange={e => setPeerSettings({ ...peerSettings, proof_of_work_required: e.target.checked })} /> {t.requirePowPeer}</label>
                </>
              )}

              {roomSettings && (
                <>
                  <label>{t.defaultTtl}</label>
                  <input type="number" min={0} value={roomSettings.default_ttl || ""} onChange={e => setRoomSettings({ ...roomSettings, default_ttl: e.target.value ? parseInt(e.target.value) : null })} />
                  <label>{t.retentionDays}</label>
                  <input type="number" min={0} value={roomSettings.retention_days || ""} onChange={e => setRoomSettings({ ...roomSettings, retention_days: e.target.value ? parseInt(e.target.value) : null })} />
                  <label><input type="checkbox" checked={roomSettings.persistence_enabled} onChange={e => setRoomSettings({ ...roomSettings, persistence_enabled: e.target.checked })} /> {t.persistRoom}</label>
                  <label><input type="checkbox" checked={roomSettings.invite_only} onChange={e => setRoomSettings({ ...roomSettings, invite_only: e.target.checked })} /> {t.inviteOnlyLocal}</label>
                  <label><input type="checkbox" checked={roomSettings.notifications_enabled} onChange={e => setRoomSettings({ ...roomSettings, notifications_enabled: e.target.checked })} /> {t.localNotifications}</label>
                </>
              )}
            </div>
            <div className="modal-actions">
              <button className="cyber-btn" onClick={() => setShowContextSettings(false)}>{t.cancel}</button>
              <button className="cyber-btn primary" onClick={saveContextSettings}>{t.save}</button>
            </div>
          </div>
        </div>
      )}

      {/* Left Column: Navigation / Swarms */}
      <div className="nav-panel glass-panel">
        <div className="nav-header">
          <span className="nav-icon">⬢</span> <span>ALTERCHAT</span>
          <span style={{ marginLeft: 'auto' }}><NetworkStatusBadge status={networkStatus} reachability={reachability} lang={lang} /></span>
        </div>
        
        <div className="nav-section">
          <div className="nav-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>{t.encryptedSwarms}</span>
            <button className="icon-btn" style={{ padding: 0, fontSize: '1rem', color: 'var(--accent-primary)' }} title={t.acceptInvite} onClick={handleAcceptInvite}>🎟️</button>
          </div>
          <div className={`nav-item ${activeContext.type === 'global' ? 'active' : ''}`} onClick={() => setActiveContext({type: 'global', id: ''})}>
            <div className="nav-icon">🌐</div>
            <span>{t.globalMesh}</span>
          </div>
          {savedGroups.map(g => (
            <div key={g.channel_name} 
                 className={`nav-item ${activeContext.type === 'group' && activeContext.id === g.channel_name ? 'active' : ''}`}
                 onClick={() => {
                    invoke("join_channel", { name: g.channel_name, password: g.password || null }).catch(console.error);
                    setActiveContext({type: 'group', id: g.channel_name});
                 }}>
              <div className="nav-icon">⬡</div>
              <span>{g.channel_name}</span>
            </div>
          ))}
          <div className="nav-item" onClick={() => setShowJoin(true)}>
            <div className="nav-icon" style={{color: 'var(--accent-green)'}}>+</div>
            <span>{t.joinSwarm}</span>
          </div>

          <div className="nav-label" style={{marginTop: '24px'}}>{t.directNodes}</div>
          {friends.map(f => (
            <div key={f.peer_id} 
                 className={`nav-item ${activeContext.type === 'friend' && activeContext.id === f.peer_id ? 'active' : ''}`}
                 onClick={() => setActiveContext({type: 'friend', id: f.peer_id})}>
              <div className="nav-icon" style={{color: peers.includes(f.peer_id) ? 'var(--accent-green)' : 'var(--text-mono)', fontSize: '0.9rem'}}>●</div>
              <span>{f.nickname}</span>
            </div>
          ))}
          <div className="nav-item" onClick={() => setShowAddFriend(true)}>
            <div className="nav-icon" style={{color: 'var(--accent-cyan)'}}>+</div>
            <span>{t.addNode}</span>
          </div>
        </div>

        <div className="user-profile-bar">
          <div className="avatar-hex">{myNick.substring(0,2).toUpperCase()}</div>
          <div className="user-meta">
            <div className="nick">{myNick}</div>
            <div className="status" title={peerId}>ID: {peerId.substring(0, 8)}...</div>
            {myOfflinePubkey && <div className="status" title={myOfflinePubkey} style={{color: 'var(--accent-primary)', fontSize: '0.65rem'}}>{t.keyLabel}: {myOfflinePubkey.substring(0, 8)}...</div>}
          </div>
          <button className="icon-btn" onClick={() => { setSettingsNick(myNick); setShowSettings(true); }} title={t.settings}>⚙️</button>
          <button className="icon-btn" onClick={() => changeLang(lang === 'tr' ? 'en' : 'tr')} title={t.langTitle} style={{fontSize: '0.7rem', fontWeight: 700}}>{lang === 'tr' ? 'EN' : 'TR'}</button>
          <button className="icon-btn" onClick={handlePanicWipe} title={t.panicWipeTitle} style={{color: 'var(--accent-red)'}}>🚨</button>
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="chat-panel glass-panel">
        <div className="chat-header">
          <div className="chat-title">
            <span className="chat-badge">{activeContext.type === 'group' ? 'PROT-X' : 'PROT-D'}</span>
            <span>{activeTitle.replace(/^# |^@ /, '')}</span>
          </div>
          <div className="header-actions">
            <form onSubmit={handleSearch}>
              <input 
                style={{background: '#1e1f22', border: 'none', color: '#dbdee1', padding: '4px 8px', borderRadius: 4, outline: 'none', fontSize: 13}}
                value={searchQuery} onChange={e => setSearchQuery(e.target.value)} placeholder={t.searchPh} 
              />
            </form>
            {activeContext.type === 'group' && (
              <>
                <button className="icon-btn" title={t.createInvite} onClick={handleCreateInvite}>✉️</button>
                <button className="icon-btn" title={t.groupAudioCall} onClick={() => handleStartCall('audio')} disabled={inCall}>📞</button>
                <button className="icon-btn" title={t.groupVideoCall} onClick={() => handleStartCall('video')} disabled={inCall}>📹</button>
              </>
            )}
            {activeContext.type === 'friend' && peers.includes(activeContext.id) && (
              <>
                <button className="icon-btn" title={t.audioCall} onClick={() => handleStartCall('audio')} disabled={inCall}>📞</button>
                <button className="icon-btn" title={t.videoCall} onClick={() => handleStartCall('video')} disabled={inCall}>📹</button>
                <button className="icon-btn" title={t.sendFile} onClick={() => { setSelectedPeerFile(activeContext.id); fileInputRef.current?.click(); }}>📎</button>
              </>
            )}
            {inCall && <button className="icon-btn" title={t.endCall} onClick={handleEndCall} style={{color: 'var(--danger)'}}>🛑</button>}
            <button className="icon-btn" title={t.contextSettings} onClick={openContextSettings}>⚙️</button>
          </div>
        </div>

        <div className="messages">
          {searchResults.length > 0 && (
            <div style={{padding: '0 16px', marginBottom: 16}}>
              <div style={{background: '#2b2d31', padding: 8, borderRadius: 8}}>
                {searchResults.map((result, i) => (
                  <div key={i} style={{padding: 8, borderBottom: '1px solid #1e1f22', cursor: 'pointer'}} onClick={() => setSearchResults([])}>
                    <div style={{fontSize: 12, color: 'var(--text-muted)'}}>{result[0]}</div>
                    <div style={{fontWeight: 600, color: 'var(--text-normal)'}}>{result[1]}</div>
                    <div style={{color: '#dbdee1', fontSize: 14}}>{result[2]}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {currentMessages.map((msg, i) => (
            <div key={i} className="message">
              <div className="msg-avatar">
                {msg.sender === "You" ? myNick.substring(0,2).toUpperCase() : msg.sender.substring(0,2).toUpperCase()}
              </div>
              <div className="msg-content">
                <div className="msg-header">
                  <span className="msg-author">[{msg.sender === "You" ? "sys" : "usr"}] {msg.sender === "You" ? t.you : msg.sender}</span>
                  {(msg as any).verified === false && (
                    <span className="msg-unverified" style={{ color: '#ff4081', fontSize: 11, marginLeft: 6 }} title={t.unverifiedTitle}>
                      ⚠ {t.unverified}
                    </span>
                  )}
                  {(msg as any).peer_id && msg.sender !== "You" && (
                    <span className="msg-trust" style={{ 
                      color: (peerTrust[(msg as any).peer_id] || 0) >= 10 ? '#00f0ff' : 
                             (peerTrust[(msg as any).peer_id] || 0) < 0 ? '#ff4081' : '#888' 
                    }}>
                      {t.trustLabel}: {peerTrust[(msg as any).peer_id] || 0}
                      <button className="icon-btn" style={{marginLeft: 4, padding: 0, fontSize: 10}} onClick={() => endorsePeer((msg as any).peer_id, 10)} title={t.endorse}>▲</button>
                      <button className="icon-btn" style={{padding: 0, fontSize: 10}} onClick={() => endorsePeer((msg as any).peer_id, -10)} title={t.distrust}>▼</button>
                    </span>
                  )}
                  <span className="msg-time">{formatTime(msg.timestamp)}</span>
                </div>
                <div className="msg-text">{msg.text === "[MESSAGE EXPIRED]" ? t.msgExpired : msg.text}</div>
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        <div className="input-area">
          <form className="input-box" onSubmit={handleSend}>
            <button type="button" className="icon-btn" title={t.uploadFile} onClick={() => { setSelectedPeerFile(activeContext.id); fileInputRef.current?.click(); }}>📎</button>
            <input type="text" value={inputText} onChange={(e) => setInputText(e.target.value)} placeholder={t.transmitTo(activeTitle.replace(/^# |^@ /, ''))} autoFocus />
            <select className="select-cyber" value={selectedTtl || ""} onChange={e => setSelectedTtl(e.target.value ? parseInt(e.target.value) : null)} title={t.ttlTitle}>
              <option value="">{`⏱️ ${t.ttlKeep}`}</option>
              <option value="5">{`🔥 5${t.unitSec}`}</option>
              <option value="15">{`🔥 15${t.unitSec}`}</option>
              <option value="60">{`🔥 1${t.unitMin}`}</option>
              <option value="300">{`🔥 5${t.unitMin}`}</option>
              <option value="3600">{`🔥 1${t.unitHour}`}</option>
              <option value="86400">{`🔥 1${t.unitDay}`}</option>
              <option value="604800">{`🔥 7${t.unitDay}`}</option>
            </select>
            {activeContext.type === 'friend' && (
              <label style={{ display: 'flex', alignItems: 'center', color: 'var(--accent-cyan)', fontSize: 12, marginLeft: 8, cursor: 'pointer' }} title={t.onionTitle}>
                <input type="checkbox" checked={useOnion} onChange={e => setUseOnion(e.target.checked)} style={{ marginRight: 4 }} />
                🧅 ONION
              </label>
            )}
          </form>
        </div>
      </div>

      {/* Rightmost Members Panel */}
      <div className="peers-panel glass-panel">
        <div className="peers-header">{t.activePeers(peers.length)}</div>
        {/* #18 Trust Graph + #9 Vault buttons */}
        <div style={{ display: "flex", gap: 4, padding: "4px 8px", borderBottom: "1px solid #1a2a3a" }}>
          <button
            onClick={() => setShowTrustGraph(true)}
            style={{ flex: 1, fontSize: 10, padding: "4px", background: "transparent",
              border: "1px solid #1a3a2a", borderRadius: 4, color: "#00cc66", cursor: "pointer" }}
            title={t.trustGraphTitle}
          >🕸 {t.trustBtn}</button>
          <button
            onClick={() => setShowVaultExport(true)}
            style={{ flex: 1, fontSize: 10, padding: "4px", background: "transparent",
              border: "1px solid #1a2a3a", borderRadius: 4, color: "#00f0ff", cursor: "pointer" }}
            title={t.vaultBtnTitle}
          >🔑 {t.vaultBtn}</button>
        </div>
        {/* #11 Anonim kanal */}
        <div style={{ padding: "4px 8px", borderBottom: "1px solid #1a2a3a" }}>
          <div style={{ display: "flex", gap: 4 }}>
            <input
              value={anonChannelName}
              onChange={e => setAnonChannelName(e.target.value)}
              placeholder={t.anonChannelPh}
              style={{ flex: 1, fontSize: 10, padding: "4px 6px", background: "#050a0f",
                border: "1px solid #1a2a3a", borderRadius: 4, color: "#aaa" }}
            />
            <button
              onClick={async () => {
                if (anonChannelName.trim()) {
                  await invoke("join_anonymous_channel", { displayName: anonChannelName.trim() });
                  setAnonChannelName("");
                }
              }}
              style={{ fontSize: 10, padding: "4px 8px", background: "#0a1a2a",
                border: "1px solid #00f0ff", borderRadius: 4, color: "#00f0ff", cursor: "pointer" }}
              title={t.anonChannelJoin}
            >🎭</button>
          </div>
        </div>
        {/* #16 Ban uyarısı */}
        {bannedPeers.length > 0 && (
          <div style={{ padding: "4px 8px", fontSize: 10, color: "#cc4444", borderBottom: "1px solid #1a2a3a" }}>
            🚫 {t.bannedPeers(bannedPeers.length)}
          </div>
        )}
        <div className="peers-list">
          {peers.map(p => {
            const isFriend = friends.find(f => f.peer_id === p);
            return (
              <div key={p} className="peer-card">
                <div className={`peer-indicator ${!peers.includes(p) ? 'offline' : ''}`}></div>
                <div className="avatar-hex" style={{width: 32, height: 32, fontSize: '0.8rem'}}>
                  {isFriend ? isFriend.nickname.substring(0,2).toUpperCase() : p.substring(0,2).toUpperCase()}
                </div>
                <div className="peer-details">
                  <span className="peer-name">{isFriend ? isFriend.nickname : p.substring(0,8)}</span>
                  <span className="peer-trust-bar">{t.peerTrustBar}</span>
                  {/* #5 Safety Numbers butonu */}
                  {isFriend?.notes && (
                    <button
                      onClick={() => setSafetyNumberPeer({ pubkey: (isFriend as any).offline_pubkey || "", nick: isFriend.nickname })}
                      style={{ fontSize: 9, padding: "2px 4px", background: "transparent",
                        border: "1px solid #1a2a3a", borderRadius: 3, color: "#888", cursor: "pointer", marginTop: 2 }}
                      title={t.verifySafetyTitle}
                    >🔐 {t.verify}</button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* #5 Safety Numbers Modal */}
      {safetyNumberPeer && (
        <SafetyNumbers
          peerPubkeyHex={safetyNumberPeer.pubkey}
          peerNickname={safetyNumberPeer.nick}
          onClose={() => setSafetyNumberPeer(null)}
          lang={lang}
        />
      )}

      {/* #18 Trust Graph Modal */}
      {showTrustGraph && (
        <TrustGraph
          myPeerId={""}
          friends={friends}
          onClose={() => setShowTrustGraph(false)}
          lang={lang}
        />
      )}

      {/* #9/#14 Vault Export Modal */}
      {showVaultExport && (
        <VaultExport onClose={() => setShowVaultExport(false)} lang={lang} />
      )}

      {/* WebRTC Video Grid Overlay */}
      {inCall && (callType === 'video' || callType === 'screen' || remoteStreams.some(s => s.type !== 'audio')) && (
        <div className="video-container">
          <div className="video-wrapper">
             <div className="video-label">{t.you}</div>
             <video ref={localVideoRef} autoPlay playsInline muted style={{width: '100%'}} />
          </div>
          {remoteStreams.filter(s => s.type === 'video' || s.type === 'screen').map(s => (
            <div key={s.peerId} className="video-wrapper">
               <div className="video-label">{friends.find(f => f.peer_id === s.peerId)?.nickname || s.peerId.substring(0,8)}</div>
               <video autoPlay playsInline ref={el => { if(el) el.srcObject = s.stream; }} style={{width: '100%'}} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default App;
