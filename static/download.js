import { decryptFile } from "/static/crypto.js";
const $ = (id) => document.getElementById(id);
const status = (msg, cls = "") => { $("status").className = cls; $("status").textContent = msg; };

$("go").addEventListener("click", async () => {
  const id = location.pathname.split("/").pop(), key = location.hash.slice(1);
  if (!key) return status("This link is missing its decryption key.", "err");
  $("go").disabled = true;
  try {
    status("Requesting secure download URL…");
    const r = await fetch(`/api/download-url/${id}`, { method: "POST" });
    if (!r.ok) throw new Error((await r.json()).error);
    const { url } = await r.json();

    status("Downloading encrypted file…");
    const enc = new Uint8Array(await (await fetch(url)).arrayBuffer());

    status("Decrypting in your browser…");
    const { meta, data } = await decryptFile(enc, key);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([data], { type: meta.type || "application/octet-stream" }));
    a.download = meta.name; a.click();
    status("✔ Decrypted: " + meta.name, "ok");
  } catch (e) { status("Error: " + (e.message || "decryption failed"), "err"); }
  $("go").disabled = false;
});
