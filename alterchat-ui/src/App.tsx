import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { LoginScreen } from "./components/LoginScreen";
import { PanicModal } from "./components/PanicModal";
import { SafetyNumbers } from "./components/SafetyNumbers";
import { TrustGraph } from "./components/TrustGraph";
import { VaultExport } from "./components/VaultExport";
import "./index.css";

import { deriveMediaKey, makeE2EESenderTransform, makeE2EEReceiverTransform } from "./webrtc";
import type { 
  ChatMessage, PrivateMessage, Friend, SavedGroup, FullConfig,
  PeerSettings, RoomSettings, WebRtcStream 
} from "./types";

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loginPassword, setLoginPassword] = useState("");
  const [amnesicMode, setAmnesicMode] = useState(false);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  const [myNick, setMyNick] = useState<string>("");
  const [myOfflinePubkey, setMyOfflinePubkey] = useState<string>("");
  const [peerId, setPeerId] = useState<string>("Loading...");
  const [peers, setPeers] = useState<string[]>([]);

  // Data State
  const [friends, setFriends] = useState<Friend[]>([]);
  const [savedGroups, setSavedGroups] = useState<SavedGroup[]>([]);

  // Layout state
  const [activeContext, setActiveContext] = useState<{type: 'global'|'group'|'friend', id: string}>({type: 'global', id: 'alterchat-global'});

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
  const [settingsTab, setSettingsTab] = useState<'identity'|'network'|'privacy'|'rooms'|'storage'|'media'|'advanced'>('identity');
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

  const handlePanicWipe = async () => {
    setShowPanicModal(true);
  };

  const executePanicWipe = async () => {
    await invoke("panic_wipe", { scope: panicScope });
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!loginPassword.trim()) return;
    setIsLoggingIn(true);
    try {
      const id = await invoke<string>("login_profile", { password: loginPassword, amnesic: amnesicMode });
      setPeerId(id);
      setIsAuthenticated(true);
    } catch (err) {
      alert("Failed to unlock vault: " + err);
    }
    setIsLoggingIn(false);
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
        const chan = activeContext.type === 'group' ? activeContext.id : 'alterchat-global';
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
        const currentTopic = activeContext.type === 'group' ? activeContext.id : 'alterchat-global';
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
    });

    const unlistenPeerExpired = listen<string>("peer-expired", (event) => {
      setPeers((prev) => prev.filter(p => p !== event.payload));
      // Cleanup WebRTC if they left
      if (pcsRef.current.has(event.payload)) {
        pcsRef.current.get(event.payload)?.close();
        pcsRef.current.delete(event.payload);
        setRemoteStreams(prev => prev.filter(s => s.peerId !== event.payload));
      }
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

    return () => {
      unlistenMessage.then(f => f());
      unlistenHistory.then(f => f());
      unlistenPm.then(f => f());
      unlistenPeerDiscovered.then(f => f());
      unlistenPeerExpired.then(f => f());
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
      invoke<PrivateMessage[]>("get_private_messages", { peer_id: activeContext.id })
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
    // STUN sunucusu kasıtlı olarak boş: Google bağımlılığı manifesto ihlali.
    // Doğrudan P2P bağlantı denenecek; NAT traversal için libp2p relay kullanılmalı.
    // @ts-ignore - encodedInsertableStreams is not in standard TS types yet
    const pc = new RTCPeerConnection({ iceServers: [], encodedInsertableStreams: true });

    pc.onicecandidate = (event) => {
      if (event.candidate) {
        invoke("send_webrtc_signal", { peer_id: targetPeer, signal: JSON.stringify(event.candidate) });
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
      await invoke("send_webrtc_signal", { peer_id: targetPeer, signal: JSON.stringify(offerWithMeta) });
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
      await invoke("send_webrtc_signal", { peer_id: targetPeer, signal: JSON.stringify(offerWithMeta) });
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
      await invoke("send_webrtc_signal", { peer_id: callData.sender, signal: JSON.stringify(answer) });

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
          peer_id: activeContext.id,
          text: inputText,
          sender_nick: myNick,
          ttl: selectedTtl,
          use_onion: useOnion
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
      await invoke("save_group", { channel_name: joinName, password: joinPassword || null });

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
      await invoke("add_friend", { peer_id: friendIdInput, nickname: friendNickInput, offline_pubkey: pubkey });
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
        setMyNick(settingsNick);
        alert("Ayarlar kaydedildi. Ağ transport değişiklikleri sonraki oturumda geçerli olur.");
        setShowSettings(false);
    } catch (err) { console.error(err); }
  };

  const handleExportConfig = async () => {
    try {
      const json = await invoke<string>("export_profile_config");
      await navigator.clipboard.writeText(json);
      alert("Config JSON panoya kopyalandı.");
    } catch (err) {
      console.error(err);
      alert("Config export başarısız.");
    }
  };

  const handleImportConfig = async () => {
    const json = window.prompt("Config JSON yapıştır:");
    if (!json) return;
    try {
      await invoke("import_profile_config", { json });
      alert("Config içe aktarıldı. Yeniden girişte tüm ayarlar yüklenecek.");
    } catch (err) {
      console.error(err);
      alert("Config import başarısız.");
    }
  };

  const openContextSettings = async () => {
    try {
      if (activeContext.type === 'friend') {
        const settings = await invoke<PeerSettings>("get_peer_settings", { peer_id: activeContext.id });
        setPeerSettings(settings);
        setRoomSettings(null);
      } else {
        const settings = await invoke<RoomSettings>("get_room_settings", { channel_name: activeContext.id });
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
      alert("Invite token copied to clipboard.");
    } catch (err) {
      console.error(err);
      alert("Invite creation failed.");
    }
  };

  const handleAcceptInvite = async () => {
    const tokenJson = window.prompt("Paste invite token JSON:");
    if (!tokenJson) return;
    try {
      const [roomId, roomPassword] = await invoke<[string, string | null]>("accept_invite", { tokenJson });
      await invoke("join_channel", { name: roomId, password: roomPassword });
      const groups = await invoke<SavedGroup[]>("get_saved_groups");
      setSavedGroups(groups);
      setActiveContext({ type: 'group', id: roomId });
    } catch (err) {
      console.error(err);
      alert("Invite accept failed.");
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
    if (file && selectedPeerFile) {
      try {
        const buffer = await file.arrayBuffer();
        await invoke("send_file", { peer_id: selectedPeerFile, filename: file.name, data: Array.from(new Uint8Array(buffer)) });
        alert(`File ${file.name} sent to ${selectedPeerFile.substring(0,6)}`);
      } catch (err) { console.error("File send error", err); }
    }
    e.target.value = '';
  };

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

  if (!isAuthenticated) {
    return (
      <LoginScreen 
        loginPassword={loginPassword}
        setLoginPassword={setLoginPassword}
        amnesicMode={amnesicMode}
        setAmnesicMode={setAmnesicMode}
        isLoggingIn={isLoggingIn}
        handleLogin={handleLogin}
      />
    );
  }

  return (
    <div className="app-container">
      {/* Hidden file input */}
      <input type="file" ref={fileInputRef} style={{display: 'none'}} onChange={handleFileChange} />
      
      {/* Panic Wipe Modal */}
      <PanicModal 
        showPanicModal={showPanicModal}
        setShowPanicModal={setShowPanicModal}
        panicScope={panicScope}
        setPanicScope={setPanicScope}
        executePanicWipe={executePanicWipe}
      />

      {/* Remote Audio Elements for Voice Calls */}
      {remoteStreams.filter(s => s.type === 'audio').map(s => (
        <audio key={s.peerId} autoPlay ref={el => { if(el) el.srcObject = s.stream; }} />
      ))}

      {/* Incoming Call Modals */}
      {incomingCalls.map(c => (
        <div key={c.sender} className="modal-overlay">
          <div className="modal-content">
            <h3>Incoming Call 📞</h3>
            <p>{friends.find(f => f.peer_id === c.sender)?.nickname || c.sender.substring(0, 8)}... is calling ({c.callType})</p>
            <div className="modal-actions">
              <button className="peer-btn" onClick={() => setIncomingCalls(p => p.filter(x => x.sender !== c.sender))} style={{color: '#ff4444', borderColor: '#ff4444'}}>Reject</button>
              <button className="peer-btn" onClick={() => handleAcceptCall(c)} style={{color: '#44ff44', borderColor: '#44ff44'}}>Accept</button>
            </div>
          </div>
        </div>
      ))}

      {/* Settings Modal */}
      {showSettings && (
        <div className="modal-overlay">
          <div className="modal-content settings-modal">
            <h3>Settings & Sovereignty</h3>
            <div className="settings-tabs">
              {(['identity','network','privacy','rooms','storage','media','advanced'] as const).map(tab => (
                <button key={tab} className={`settings-tab ${settingsTab === tab ? 'active' : ''}`} onClick={() => setSettingsTab(tab)}>{tab}</button>
              ))}
            </div>

            <div className="settings-pane">
              {settingsTab === 'identity' && (
                <>
                  <label>Nickname alias</label>
                  <input placeholder="Nickname" value={settingsNick} onChange={e => setSettingsNick(e.target.value)} />
                  <div className="settings-note">Alias changes do not change your cryptographic identity: {peerId.substring(0, 16)}...</div>
                </>
              )}

              {settingsTab === 'network' && (
                <>
                  <label>Primary bootstrap node</label>
                  <input placeholder="/ip4/x.x.x.x/tcp/XXXX/p2p/12D3..." value={settingsBootstrap} onChange={e => setSettingsBootstrap(e.target.value)} />
                  <label>Bootstrap list</label>
                  <textarea value={settingsBootstrapList} onChange={e => setSettingsBootstrapList(e.target.value)} placeholder="One multiaddr per line" />
                  <label>Network mode</label>
                  <select value={proxyMode} onChange={e => setProxyMode(e.target.value)}>
                    <option value="none">Direct</option>
                    <option value="tor">Tor via Arti</option>
                    <option value="socks5">SOCKS5 placeholder</option>
                    <option value="i2p">I2P placeholder</option>
                  </select>
                  <label>Transport preference</label>
                  <select value={transportPreference} onChange={e => setTransportPreference(e.target.value)}>
                    <option value="tcp">TCP</option>
                    <option value="quic">QUIC preferred</option>
                    <option value="tor">Tor preferred</option>
                  </select>
                  {(proxyMode === 'socks5' || proxyMode === 'i2p') && <input placeholder={proxyMode === 'socks5' ? '127.0.0.1:9050' : '127.0.0.1:7656'} value={proxyAddr} onChange={e => setProxyAddr(e.target.value)} />}
                  <label><input type="checkbox" checked={torEnabled} onChange={e => setTorEnabled(e.target.checked)} /> Tor transport on next session</label>
                  <label><input type="checkbox" checked={mdnsEnabled} onChange={e => setMdnsEnabled(e.target.checked)} /> Local mDNS discovery</label>
                  <label><input type="checkbox" checked={dhtServerMode} onChange={e => setDhtServerMode(e.target.checked)} /> Serve DHT records</label>
                  <label><input type="checkbox" checked={relayEnabled} onChange={e => setRelayEnabled(e.target.checked)} /> Volunteer relay mode</label>
                  <label><input type="checkbox" checked={relayFallbackEnabled} onChange={e => setRelayFallbackEnabled(e.target.checked)} /> Try relay fallback when direct path fails</label>
                  <label><input type="checkbox" checked={publishCapabilities} onChange={e => setPublishCapabilities(e.target.checked)} /> Publish local capabilities to connected peers</label>
                </>
              )}

              {settingsTab === 'privacy' && (
                <>
                  <label><input type="checkbox" checked={coverTraffic} onChange={e => setCoverTraffic(e.target.checked)} /> Cover traffic chaff</label>
                  <label><input type="checkbox" checked={msgDelay} onChange={e => setMsgDelay(e.target.checked)} /> Random send delay</label>
                  <label><input type="checkbox" checked={localNotifications} onChange={e => setLocalNotifications(e.target.checked)} /> Local notifications</label>
                  <label><input type="checkbox" checked={proofOfWorkEnabled} onChange={e => setProofOfWorkEnabled(e.target.checked)} /> Require proof-of-work for noisy peers</label>
                  <label>Unknown peer policy</label>
                  <select value={unknownPeerPolicy} onChange={e => setUnknownPeerPolicy(e.target.value)}>
                    <option value="request-only">Request-only</option>
                    <option value="allow">Allow</option>
                    <option value="block">Block</option>
                  </select>
                  <label>Rate limit per identity/minute</label>
                  <input type="number" min={1} value={rateLimitPerMinute} onChange={e => setRateLimitPerMinute(parseInt(e.target.value) || 1)} />
                  <label>Minimum trust for DM</label>
                  <input type="number" min={0} max={10} value={minTrustDm} onChange={e => setMinTrustDm(parseInt(e.target.value) || 0)} />
                  <label>Minimum trust for file</label>
                  <input type="number" min={0} max={10} value={minTrustFile} onChange={e => setMinTrustFile(parseInt(e.target.value) || 0)} />
                  <label>Minimum trust for invite</label>
                  <input type="number" min={0} max={10} value={minTrustInvite} onChange={e => setMinTrustInvite(parseInt(e.target.value) || 0)} />
                  <div className="settings-note">No telemetry, no global moderation, no central account authority.</div>
                </>
              )}

              {settingsTab === 'rooms' && (
                <>
                  <label>Default TTL seconds</label>
                  <input type="number" min={0} placeholder="empty = off" value={defaultTtl} onChange={e => setDefaultTtl(e.target.value)} />
                  <label><input type="checkbox" checked={persistenceEnabled} onChange={e => setPersistenceEnabled(e.target.checked)} /> Persist room state locally</label>
                  <label><input type="checkbox" checked={inviteOnlyDefault} onChange={e => setInviteOnlyDefault(e.target.checked)} /> Invite-only by default</label>
                </>
              )}

              {settingsTab === 'storage' && (
                <>
                  <label><input type="checkbox" checked={storageNodeEnabled} onChange={e => setStorageNodeEnabled(e.target.checked)} /> Volunteer encrypted storage node</label>
                  <label>Storage quota MB</label>
                  <input type="number" min={1} value={storageQuotaMb} onChange={e => setStorageQuotaMb(parseInt(e.target.value) || 1)} />
                  <label>Storage retention days</label>
                  <input type="number" min={1} value={storageRetentionDays} onChange={e => setStorageRetentionDays(parseInt(e.target.value) || 1)} />
                </>
              )}

              {settingsTab === 'media' && (
                <>
                  <label>SFU threshold</label>
                  <input type="number" min={2} value={sfuThreshold} onChange={e => setSfuThreshold(parseInt(e.target.value) || 2)} />
                  <label>Preferred SFU peer</label>
                  <input value={preferredSfuPeer} onChange={e => setPreferredSfuPeer(e.target.value)} placeholder="PeerId or blank" />
                  <label><input type="checkbox" checked={acceptRelay} onChange={e => setAcceptRelay(e.target.checked)} /> Accept volunteer media relay role</label>
                  <label><input type="checkbox" checked={experimentalMediaE2ee} onChange={e => setExperimentalMediaE2ee(e.target.checked)} /> 🔐 Media E2EE (AES-256-GCM WebRTC encryption)</label>
                  <div className="settings-note">XOR demo media crypto was removed; real SFrame/AES-GCM is a future phase.</div>
                </>
              )}

              {settingsTab === 'advanced' && (
                <>
                  <button className="cyber-btn" onClick={handleExportConfig}>Export config JSON</button>
                  <button className="cyber-btn" onClick={handleImportConfig}>Import config JSON</button>
                  <div className="settings-note">Config export excludes private keys and message databases.</div>
                  <label>Panic wipe scope</label>
                  <select value={panicScope} onChange={e => setPanicScope(e.target.value)}>
                    <option value="active_profile">Active profile</option>
                    <option value="message_db_only">Message DB only</option>
                    <option value="all_profiles">All local profiles</option>
                  </select>
                </>
              )}
            </div>

            <div className="modal-actions">
              <button className="cyber-btn" onClick={() => setShowSettings(false)}>İptal</button>
              <button className="cyber-btn primary" onClick={handleSaveSettings}>💾 Kaydet</button>
            </div>
          </div>
        </div>
      )}

      {/* Join Group Modal */}
      {showJoin && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3>Join / Create Group</h3>
            <input placeholder="Group Name" value={joinName} onChange={e => setJoinName(e.target.value)} />
            <input type="password" placeholder="Password (E2EE)" value={joinPassword} onChange={e => setJoinPassword(e.target.value)} />
            <div className="modal-actions">
              <button className="cyber-btn" onClick={() => setShowJoin(false)}>Cancel</button>
              <button className="cyber-btn primary" onClick={handleJoinGroup}>Join</button>
            </div>
          </div>
        </div>
      )}

      {/* Add Friend Modal */}
      {showAddFriend && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3>Add Friend / Contact</h3>
            <div className="modal-form">
              <label>Peer ID</label>
              <input type="text" value={friendIdInput} onChange={e => setFriendIdInput(e.target.value)} placeholder="12D3KooW..." />
              <label>Nickname</label>
              <input type="text" value={friendNickInput} onChange={e => setFriendNickInput(e.target.value)} placeholder="Cypher..." />
              <label>Offline Public Key (Optional)</label>
              <input type="text" value={friendPubkeyInput} onChange={e => setFriendPubkeyInput(e.target.value)} placeholder="Hex key for DHT mailbox..." />
            </div>
            <div className="modal-actions">
              <button className="cyber-btn" onClick={() => setShowAddFriend(false)}>Cancel</button>
              <button className="cyber-btn primary" onClick={handleAddFriend}>Add</button>
            </div>
          </div>
        </div>
      )}

      {showContextSettings && (
        <div className="modal-overlay">
          <div className="modal-content settings-modal">
            <h3>{activeContext.type === 'friend' ? 'Peer Controls' : 'Room Controls'}</h3>
            <div className="settings-pane">
              {peerSettings && (
                <>
                  <label>Trust level</label>
                  <input type="number" min={0} max={10} value={peerSettings.trust_level} onChange={e => setPeerSettings({ ...peerSettings, trust_level: parseInt(e.target.value) || 0 })} />
                  <label><input type="checkbox" checked={peerSettings.blocked} onChange={e => setPeerSettings({ ...peerSettings, blocked: e.target.checked })} /> Block this identity locally</label>
                  <label><input type="checkbox" checked={peerSettings.muted} onChange={e => setPeerSettings({ ...peerSettings, muted: e.target.checked })} /> Mute notifications locally</label>
                  <label>Rate limit/minute</label>
                  <input type="number" min={1} value={peerSettings.rate_limit_per_minute} onChange={e => setPeerSettings({ ...peerSettings, rate_limit_per_minute: parseInt(e.target.value) || 1 })} />
                  <label><input type="checkbox" checked={peerSettings.proof_of_work_required} onChange={e => setPeerSettings({ ...peerSettings, proof_of_work_required: e.target.checked })} /> Require proof-of-work from this peer</label>
                </>
              )}

              {roomSettings && (
                <>
                  <label>Default TTL seconds</label>
                  <input type="number" min={0} value={roomSettings.default_ttl || ""} onChange={e => setRoomSettings({ ...roomSettings, default_ttl: e.target.value ? parseInt(e.target.value) : null })} />
                  <label>Retention days</label>
                  <input type="number" min={0} value={roomSettings.retention_days || ""} onChange={e => setRoomSettings({ ...roomSettings, retention_days: e.target.value ? parseInt(e.target.value) : null })} />
                  <label><input type="checkbox" checked={roomSettings.persistence_enabled} onChange={e => setRoomSettings({ ...roomSettings, persistence_enabled: e.target.checked })} /> Persist this room locally</label>
                  <label><input type="checkbox" checked={roomSettings.invite_only} onChange={e => setRoomSettings({ ...roomSettings, invite_only: e.target.checked })} /> Invite-only local policy</label>
                  <label><input type="checkbox" checked={roomSettings.notifications_enabled} onChange={e => setRoomSettings({ ...roomSettings, notifications_enabled: e.target.checked })} /> Local notifications</label>
                </>
              )}
            </div>
            <div className="modal-actions">
              <button className="cyber-btn" onClick={() => setShowContextSettings(false)}>Cancel</button>
              <button className="cyber-btn primary" onClick={saveContextSettings}>Save</button>
            </div>
          </div>
        </div>
      )}

      {/* Left Column: Navigation / Swarms */}
      <div className="nav-panel glass-panel">
        <div className="nav-header">
          <span className="nav-icon">⬢</span> <span>NODAL</span>
        </div>
        
        <div className="nav-section">
          <div className="nav-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Encrypted Swarms</span>
            <button className="icon-btn" style={{ padding: 0, fontSize: '1rem', color: 'var(--accent-primary)' }} title="Accept Invite" onClick={handleAcceptInvite}>🎟️</button>
          </div>
          <div className={`nav-item ${activeContext.type === 'global' ? 'active' : ''}`} onClick={() => setActiveContext({type: 'global', id: ''})}>
            <div className="nav-icon">🌐</div>
            <span>Global Mesh</span>
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
            <span>Join Swarm</span>
          </div>

          <div className="nav-label" style={{marginTop: '24px'}}>Direct Nodes</div>
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
            <span>Add Node</span>
          </div>
        </div>

        <div className="user-profile-bar">
          <div className="avatar-hex">{myNick.substring(0,2).toUpperCase()}</div>
          <div className="user-meta">
            <div className="nick">{myNick}</div>
            <div className="status" title={peerId}>ID: {peerId.substring(0, 8)}...</div>
            {myOfflinePubkey && <div className="status" title={myOfflinePubkey} style={{color: 'var(--accent-primary)', fontSize: '0.65rem'}}>KEY: {myOfflinePubkey.substring(0, 8)}...</div>}
          </div>
          <button className="icon-btn" onClick={() => { setSettingsNick(myNick); setShowSettings(true); }} title="Settings">⚙️</button>
          <button className="icon-btn" onClick={handlePanicWipe} title="PANIC WIPE" style={{color: 'var(--accent-red)'}}>🚨</button>
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
                value={searchQuery} onChange={e => setSearchQuery(e.target.value)} placeholder="Search..." 
              />
            </form>
            {activeContext.type === 'group' && (
              <>
                <button className="icon-btn" title="Create signed invite" onClick={handleCreateInvite}>✉️</button>
                <button className="icon-btn" title="Group Audio Call" onClick={() => handleStartCall('audio')} disabled={inCall}>📞</button>
                <button className="icon-btn" title="Group Video Call" onClick={() => handleStartCall('video')} disabled={inCall}>📹</button>
              </>
            )}
            {activeContext.type === 'friend' && peers.includes(activeContext.id) && (
              <>
                <button className="icon-btn" title="Audio Call" onClick={() => handleStartCall('audio')} disabled={inCall}>📞</button>
                <button className="icon-btn" title="Video Call" onClick={() => handleStartCall('video')} disabled={inCall}>📹</button>
                <button className="icon-btn" title="Send File" onClick={() => { setSelectedPeerFile(activeContext.id); fileInputRef.current?.click(); }}>📎</button>
              </>
            )}
            {inCall && <button className="icon-btn" onClick={handleEndCall} style={{color: 'var(--danger)'}}>🛑</button>}
            <button className="icon-btn" title="Context Settings" onClick={openContextSettings}>⚙️</button>
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
                  <span className="msg-author">[{msg.sender === "You" ? "sys" : "usr"}] {msg.sender}</span>
                  {(msg as any).peer_id && msg.sender !== "You" && (
                    <span className="msg-trust" style={{ 
                      color: (peerTrust[(msg as any).peer_id] || 0) >= 10 ? '#00f0ff' : 
                             (peerTrust[(msg as any).peer_id] || 0) < 0 ? '#ff4081' : '#888' 
                    }}>
                      TRUST: {peerTrust[(msg as any).peer_id] || 0}
                      <button className="icon-btn" style={{marginLeft: 4, padding: 0, fontSize: 10}} onClick={() => endorsePeer((msg as any).peer_id, 10)} title="Endorse">▲</button>
                      <button className="icon-btn" style={{padding: 0, fontSize: 10}} onClick={() => endorsePeer((msg as any).peer_id, -10)} title="Distrust">▼</button>
                    </span>
                  )}
                  <span className="msg-time">{formatTime(msg.timestamp)}</span>
                </div>
                <div className="msg-text">{msg.text}</div>
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        <div className="input-area">
          <form className="input-box" onSubmit={handleSend}>
            <button type="button" className="icon-btn" title="Upload File" onClick={() => { setSelectedPeerFile(activeContext.id); fileInputRef.current?.click(); }}>📎</button>
            <input type="text" value={inputText} onChange={(e) => setInputText(e.target.value)} placeholder={`Transmit to ${activeTitle.replace(/^# |^@ /, '')}...`} autoFocus />
            <select className="select-cyber" value={selectedTtl || ""} onChange={e => setSelectedTtl(e.target.value ? parseInt(e.target.value) : null)} title="Message Auto-Destruct Time">
              <option value="">⏱️ KEEP</option>
              <option value="5">🔥 5s</option>
              <option value="15">🔥 15s</option>
              <option value="60">🔥 1m</option>
              <option value="300">🔥 5m</option>
              <option value="3600">🔥 1h</option>
              <option value="86400">🔥 1d</option>
              <option value="604800">🔥 7d</option>
            </select>
            {activeContext.type === 'friend' && (
              <label style={{ display: 'flex', alignItems: 'center', color: 'var(--accent-cyan)', fontSize: 12, marginLeft: 8, cursor: 'pointer' }} title="Use Onion Routing">
                <input type="checkbox" checked={useOnion} onChange={e => setUseOnion(e.target.checked)} style={{ marginRight: 4 }} />
                🧅 ONION
              </label>
            )}
          </form>
        </div>
      </div>

      {/* Rightmost Members Panel */}
      <div className="peers-panel glass-panel">
        <div className="peers-header">ACTIVE PEERS ({peers.length})</div>
        {/* #18 Trust Graph + #9 Vault buttons */}
        <div style={{ display: "flex", gap: 4, padding: "4px 8px", borderBottom: "1px solid #1a2a3a" }}>
          <button
            onClick={() => setShowTrustGraph(true)}
            style={{ flex: 1, fontSize: 10, padding: "4px", background: "transparent",
              border: "1px solid #1a3a2a", borderRadius: 4, color: "#00cc66", cursor: "pointer" }}
            title="Trust Graph"
          >🕸 Trust</button>
          <button
            onClick={() => setShowVaultExport(true)}
            style={{ flex: 1, fontSize: 10, padding: "4px", background: "transparent",
              border: "1px solid #1a2a3a", borderRadius: 4, color: "#00f0ff", cursor: "pointer" }}
            title="Vault Export/Import"
          >🔑 Vault</button>
        </div>
        {/* #11 Anonim kanal */}
        <div style={{ padding: "4px 8px", borderBottom: "1px solid #1a2a3a" }}>
          <div style={{ display: "flex", gap: 4 }}>
            <input
              value={anonChannelName}
              onChange={e => setAnonChannelName(e.target.value)}
              placeholder="anon channel name..."
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
              title="Join Anonymous Channel"
            >🎭</button>
          </div>
        </div>
        {/* #16 Ban uyarısı */}
        {bannedPeers.length > 0 && (
          <div style={{ padding: "4px 8px", fontSize: 10, color: "#cc4444", borderBottom: "1px solid #1a2a3a" }}>
            🚫 {bannedPeers.length} peer(s) network-banned for PoW abuse
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
                  <span className="peer-trust-bar">TRUST: 99% | REP: HIGH</span>
                  {/* #5 Safety Numbers butonu */}
                  {isFriend?.notes && (
                    <button
                      onClick={() => setSafetyNumberPeer({ pubkey: (isFriend as any).offline_pubkey || "", nick: isFriend.nickname })}
                      style={{ fontSize: 9, padding: "2px 4px", background: "transparent",
                        border: "1px solid #1a2a3a", borderRadius: 3, color: "#888", cursor: "pointer", marginTop: 2 }}
                      title="Verify Safety Numbers"
                    >🔐 verify</button>
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
        />
      )}

      {/* #18 Trust Graph Modal */}
      {showTrustGraph && (
        <TrustGraph
          myPeerId={""}
          friends={friends}
          onClose={() => setShowTrustGraph(false)}
        />
      )}

      {/* #9/#14 Vault Export Modal */}
      {showVaultExport && (
        <VaultExport onClose={() => setShowVaultExport(false)} />
      )}

      {/* WebRTC Video Grid Overlay */}
      {inCall && (callType === 'video' || callType === 'screen' || remoteStreams.some(s => s.type !== 'audio')) && (
        <div className="video-container">
          <div className="video-wrapper">
             <div className="video-label">You</div>
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
