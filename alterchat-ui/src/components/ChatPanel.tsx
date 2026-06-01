import React, { useRef, useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ChatMessage, PrivateMessage } from "../types";

interface ChatPanelProps {
  activeContext: { type: string; id: string };
  activeTitle: string;
  currentMessages: (ChatMessage | PrivateMessage)[];
  myNick: string;
  peerTrust: Record<string, number>;
  endorsePeer: (peerId: string, delta: number) => void;
  handleSearch: (e: React.FormEvent) => void;
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  searchResults: string[][];
  setSearchResults: (r: string[][]) => void;
}

export function ChatPanel(props: ChatPanelProps) {
  const [inputText, setInputText] = useState("");
  const [selectedTtl, setSelectedTtl] = useState<number | null>(null);
  const [useOnion, setUseOnion] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [props.currentMessages]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) return;
    try {
      if (props.activeContext.type === 'group') {
        await invoke("send_message", { 
          channel: props.activeContext.id, 
          text: inputText, 
          ttl: selectedTtl 
        });
      } else if (props.activeContext.type === 'friend') {
        await invoke("send_private_message", { 
          peerId: props.activeContext.id, 
          text: inputText, 
          ttl: selectedTtl,
          onion: useOnion
        });
      } else {
        await invoke("send_global_message", { 
          text: inputText, 
          ttl: selectedTtl 
        });
      }
      setInputText("");
    } catch (err) {
      console.error("Failed to send:", err);
    }
  };

  return (
    <div className="chat-panel glass-panel">
      {/* Messages rendering logic here */}
      <div className="messages">
        {props.currentMessages.map((msg, i) => (
          <div key={i} className="message">
             <div className="msg-text">{msg.text}</div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>
      <div className="input-area">
        <form className="input-box" onSubmit={handleSend}>
          <input type="text" value={inputText} onChange={(e) => setInputText(e.target.value)} placeholder={`Transmit to ${props.activeTitle}...`} autoFocus />
        </form>
      </div>
    </div>
  );
}
