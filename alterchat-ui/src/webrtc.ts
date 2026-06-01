export async function deriveMediaKey(myPubkeyHex: string, peerPubkeyHex: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  // Sıra bağımsız: her iki taraf aynı ham materyali üretir
  const [a, b] = [myPubkeyHex, peerPubkeyHex].sort();
  const material = encoder.encode(`AlterChat_WebRTC_E2EE_v1|${a}|${b}`);
  const baseKey = await crypto.subtle.importKey("raw", material, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: encoder.encode("media-e2ee"), info: encoder.encode("aes-gcm-256") },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export function makeE2EESenderTransform(key: CryptoKey): TransformStream {
  let frameCounter = 0;
  return new TransformStream({
    async transform(chunk: any, controller) {
      const iv = new Uint8Array(12);
      new DataView(iv.buffer).setUint32(0, frameCounter++ & 0xFFFFFFFF);
      const data = chunk.data instanceof ArrayBuffer ? chunk.data : new ArrayBuffer(0);
      try {
        const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
        chunk.data = encrypted;
        controller.enqueue(chunk);
      } catch {
        controller.enqueue(chunk); // fallback: şifreleme başarısız olursa geç
      }
    }
  });
}

export function makeE2EEReceiverTransform(key: CryptoKey): TransformStream {
  let frameCounter = 0;
  return new TransformStream({
    async transform(chunk: any, controller) {
      const iv = new Uint8Array(12);
      new DataView(iv.buffer).setUint32(0, frameCounter++ & 0xFFFFFFFF);
      const data = chunk.data instanceof ArrayBuffer ? chunk.data : new ArrayBuffer(0);
      try {
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
        chunk.data = decrypted;
        controller.enqueue(chunk);
      } catch {
        controller.enqueue(chunk); // fallback: şifre çözme başarısız olursa ham geç
      }
    }
  });
}
