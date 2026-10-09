import { encryptFile } from "/static/crypto.js";
const $ = (id) => document.getElementById(id);
const status = (msg, cls = "") => { $("status").className = cls; $("status").textContent = msg; };

$("go").addEventListener("click", async () => {
  const file = $("file").files[0], token = $("token").value;
  if (!file || !token) return status("Select a file and enter the access token.", "err");
  $("go").disabled = true;
  try {
    status("Encrypting in your browser…");
    const { blob, keyB64 } = await encryptFile(file);
    const auth = { "Content-Type": "application/json", Authorization: "Bearer " + token };

    status("Requesting secure upload URL…");
    let r = await fetch("/api/upload-url", { method: "POST", headers: auth, body: JSON.stringify({
      size: blob.length, expiry_hours: +$("hours").value, max_downloads: +$("maxdl").value }) });
    if (!r.ok) throw new Error((await r.json()).error || "request failed");
    const { id, url, headers } = await r.json();

    status("Uploading encrypted file…");
    const put = await fetch(url, { method: "PUT", headers, body: blob });
    if (!put.ok) throw new Error("storage upload failed (" + put.status + ")");

    r = await fetch(`/api/files/${id}/complete`, { method: "POST", headers: auth });
    if (!r.ok) throw new Error("could not verify upload");

    status("✔ Done. Share this link (the key is inside it and never sent to the server):\n" +
      `${location.origin}/d/${id}#${keyB64}`, "ok");
  } catch (e) { status("Error: " + e.message, "err"); }
  $("go").disabled = false;
});
