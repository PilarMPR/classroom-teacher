/* Classroom Portal, published teacher site: the service worker.
   Every file of the teacher site (https://teacher.rojoclassroom.app/, its own origin) is stored encrypted (AES-256-GCM). Pages are small "enter your token" pages
   carrying the encrypted page; every other file is iv + ciphertext. Once a device has the key (saved by
   unlock.js in IndexedDB, never the token), this worker decrypts each request on the fly.
   Without the key it serves the token page, and other files answer 403. */
"use strict";
const SCOPE = new URL("./", self.location).pathname;
const PLAIN = new Set([SCOPE + "sw.js", SCOPE + "unlock.js"]);
const TYPES = {
  html: "text/html; charset=utf-8", js: "text/javascript; charset=utf-8", mjs: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8", json: "application/json; charset=utf-8", md: "text/markdown; charset=utf-8",
  txt: "text/plain; charset=utf-8", svg: "image/svg+xml", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg",
  gif: "image/gif", webp: "image/webp", ico: "image/x-icon", woff2: "font/woff2", woff: "font/woff", pdf: "application/pdf"
};

// The key is kept as { key, at }. After 30 days it expires: it is deleted and the token page asks again.
const MAX_AGE = 30 * 24 * 60 * 60 * 1000;
function getKey() {
  return new Promise(res => {
    const r = indexedDB.open("classroom-teacher", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("k");
    r.onerror = () => res(null);
    r.onsuccess = () => {
      try {
        const g = r.result.transaction("k").objectStore("k").get("key");
        g.onsuccess = () => {
          const v = g.result;
          if (v && v.key && Date.now() - v.at < Math.min(MAX_AGE, v.ttl || MAX_AGE)) return res(v.key);   // ttl: 8 hours on a shared computer
          if (v) { try { r.result.transaction("k", "readwrite").objectStore("k").delete("key"); } catch (e) {} }   // expired, or the old format
          res(null);
        };
        g.onerror = () => res(null);
      }
      catch (e) { res(null); }
    };
  });
}
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const dec = (key, bytes) => crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, key, bytes.slice(12));
// every page this worker serves refuses to sit in another site's frame (GitHub Pages sends no such header)
const HTML = { "Content-Type": TYPES.html, "Cache-Control": "no-store", "X-Frame-Options": "SAMEORIGIN", "Content-Security-Policy": "frame-ancestors 'self'" };
const page = (text, status = 200) => new Response(text, { status, headers: HTML });

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", e => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== self.location.origin || !url.pathname.startsWith(SCOPE) || PLAIN.has(url.pathname)) return;
  e.respondWith(serve(url));
});

async function serve(url) {
  let path = url.pathname;
  if (path.endsWith("/")) path += "index.html";
  const res = await fetch(path, { cache: "no-cache" });
  if (!res.ok) return res;
  const key = await getKey();
  const ext = (path.split(".").pop() || "").toLowerCase();
  if (ext === "html") {
    const text = await res.text();
    const m = text.match(/<script type="text\/plain" id="ct">([A-Za-z0-9+/=]+)<\/script>/);
    if (!key || !m) return page(text);
    try { return new Response(await dec(key, b64(m[1])), { headers: HTML }); }
    catch (e) { return page(text.replace('data-state="locked"', 'data-state="wrong"')); }   // the token changed since this device unlocked
  }
  if (!key) return new Response("Locked", { status: 403 });
  try { return new Response(await dec(key, new Uint8Array(await res.arrayBuffer())), { headers: { "Content-Type": TYPES[ext] || "application/octet-stream" } }); }
  catch (e) { return new Response("Locked", { status: 403 }); }
}
