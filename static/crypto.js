// Client-side end-to-end encryption: AES-256-GCM via Web Crypto API
const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)),
};

// Packet layout: IV(12) || AES-GCM( len(4) || header-json || file-bytes )
// Filename/type are encrypted too, so storage learns nothing about the content.
export async function encryptFile(file) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const header = new TextEncoder().encode(JSON.stringify({ name: file.name, type: file.type }));
  const data = new Uint8Array(await file.arrayBuffer());
  const plain = new Uint8Array(4 + header.length + data.length);
  new DataView(plain.buffer).setUint32(0, header.length);
  plain.set(header, 4);
  plain.set(data, 4 + header.length);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return { blob: out, keyB64: b64u.enc(await crypto.subtle.exportKey("raw", key)) };
}

export async function decryptFile(packet, keyB64) {
  const key = await crypto.subtle.importKey("raw", b64u.dec(keyB64), "AES-GCM", false, ["decrypt"]);
  const iv = packet.slice(0, 12);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, packet.slice(12)));
  const hlen = new DataView(plain.buffer).getUint32(0);
  const meta = JSON.parse(new TextDecoder().decode(plain.slice(4, 4 + hlen)));
  return { meta, data: plain.slice(4 + hlen) };
}
