import React, { useEffect, useState } from "react";
import { WebRtcStream, Friend } from "../types";

interface CallManagerProps {
  inCall: boolean;
  callType: 'audio' | 'video' | 'screen' | null;
  remoteStreams: WebRtcStream[];
  friends: Friend[];
  localVideoRef: React.RefObject<HTMLVideoElement>;
  peerCapacityScores: Record<string, number>;
}

export function CallManager({ inCall, callType, remoteStreams, friends, localVideoRef, peerCapacityScores }: CallManagerProps) {
  const [sfuHost, setSfuHost] = useState<string | null>(null);

  // Decentralized SFU Election Logic (Manifesto II & WebRTC Phase)
  useEffect(() => {
    if (inCall && remoteStreams.length > 2) {
      // Find peer with highest capacity/PoW score
      let bestPeer = null;
      let maxScore = -1;
      
      for (const stream of remoteStreams) {
        const score = peerCapacityScores[stream.peerId] || 0;
        if (score > maxScore) {
          maxScore = score;
          bestPeer = stream.peerId;
        }
      }
      
      // If a remote peer has a much better connection/capacity, nominate them as SFU
      if (bestPeer && maxScore > 1000) {
        setSfuHost(bestPeer);
      }
    } else {
      setSfuHost(null);
    }
  }, [inCall, remoteStreams, peerCapacityScores]);

  if (!inCall) return null;

  return (
    <div className="video-container">
      {sfuHost && <div className="sfu-indicator">Relaying via {sfuHost.substring(0, 8)} (Highest Capacity)</div>}
      <div className="video-wrapper">
         <div className="video-label">You</div>
         <video ref={localVideoRef as any} autoPlay playsInline muted style={{width: '100%'}} />
      </div>
      {remoteStreams.filter(s => s.type === 'video' || s.type === 'screen').map(s => (
        <div key={s.peerId} className="video-wrapper">
           <div className="video-label">{friends.find(f => f.peer_id === s.peerId)?.nickname || s.peerId.substring(0,8)}</div>
           <video autoPlay playsInline ref={el => { if(el) el.srcObject = s.stream; }} style={{width: '100%'}} />
        </div>
      ))}
    </div>
  );
}
