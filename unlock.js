/* Classroom Portal, published teacher site: the token page.
   Derives the key from the token (PBKDF2-SHA-256; the salt is made from the token itself, so no salt is
   published), checks it by opening this page, saves the key (not the token) in IndexedDB, starts the
   service worker (sw.js) and reloads. From then on sw.js decrypts every page and file on this device. */
(function () {
  "use strict";
  // never inside another site's frame (a meta CSP cannot set frame-ancestors)
  if (window.top !== window.self) { try { window.top.location = window.self.location.href; } catch (e) { document.documentElement.innerHTML = ""; } return; }
  const ITER = 250000;
  const me = document.currentScript;
  const root = new URL(".", me.src);
  const $ = id => document.getElementById(id);
  const form = $("f"), input = $("t"), msg = $("m");
  const say = (t, bad) => { msg.textContent = t; msg.className = bad ? "bad" : ""; };
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  if (!("serviceWorker" in navigator) || !window.crypto || !crypto.subtle || !window.indexedDB) {
    form.hidden = true;
    say("This browser cannot open this site. Use an up-to-date Chrome, Edge, Firefox or Safari (not a private window).", true);
    return;
  }
  if (document.body.dataset.state === "wrong") say("The passkey saved on this device no longer opens the site (it was changed). Enter the new one.", true);

  function db() {
    return new Promise((res, rej) => { const r = indexedDB.open("classroom-teacher", 1); r.onupgradeneeded = () => r.result.createObjectStore("k"); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
  }
  async function keyStore(mode, fn) { const d = await db(); return new Promise((res, rej) => { const tx = d.transaction("k", mode); const out = fn(tx.objectStore("k")); tx.oncomplete = () => res(out && out.result); tx.onerror = () => rej(tx.error); }); }
  // saved with the time and how long it may live, so sw.js can let it expire: 30 days, or 8 hours on a shared
  // computer (a classroom or projector PC, security audit 2026-10-25). The token itself is never saved.
  const SHARED_TTL = 8 * 60 * 60 * 1000;
  const saveKey = (key, shared) => keyStore("readwrite", s => s.put(shared ? { key, at: Date.now(), ttl: SHARED_TTL } : { key, at: Date.now() }, "key"));
  const loadKey = () => keyStore("readonly", s => s.get("key"));

  async function deriveKey(token) {
    const enc = new TextEncoder();
    const salt = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode("classroom-portal/teacher/v1|" + token))).slice(0, 16);
    const base = await crypto.subtle.importKey("raw", enc.encode(token), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  }
  async function startWorker() {
    await navigator.serviceWorker.register(new URL("sw.js", root).href, { scope: root.pathname });
    await navigator.serviceWorker.ready;
    if (navigator.serviceWorker.controller) location.reload();
    else navigator.serviceWorker.addEventListener("controllerchange", () => location.reload(), { once: true });
  }

  // An expired key is deleted as soon as this page loads, not only when the worker next sees a request
  // (security audit 2026-10-26). A key in date with no worker running (a new tab, or the browser dropped it):
  // start the worker once.
  const MAX_AGE = 30 * 24 * 60 * 60 * 1000;   // must match sw.js
  loadKey().then(k => {
    if (!k) return;
    if (!k.key || typeof k.at !== "number" || Date.now() - k.at >= Math.min(MAX_AGE, k.ttl || MAX_AGE)) { keyStore("readwrite", s => s.delete("key")).catch(() => {}); return; }
    if (document.body.dataset.state !== "wrong" && !navigator.serviceWorker.controller && !sessionStorage.getItem("cl-restart")) { sessionStorage.setItem("cl-restart", "1"); say("Opening…"); startWorker(); }
  }).catch(() => {});

  form.addEventListener("submit", async e => {
    e.preventDefault();
    const token = input.value.trim();
    if (!token) return;
    say("Checking…");
    try {
      const key = await deriveKey(token);
      const ct = b64($("ct").textContent);
      await crypto.subtle.decrypt({ name: "AES-GCM", iv: ct.slice(0, 12) }, key, ct.slice(12));
      await saveKey(key, !!($("shared") && $("shared").checked));
      input.value = "";
      sessionStorage.removeItem("cl-restart");
      say("Opening…");
      await startWorker();
    } catch (err) {
      say("That passkey does not open this site. Check it and try again.", true);
    }
  });
})();
