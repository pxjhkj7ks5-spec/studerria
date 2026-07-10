const CACHE = "shieldline-runtime-v4";
const SHELL = ["./", "./index.html", "./offline.html", "./manifest.webmanifest"];

self.addEventListener("install", (event) => event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting())));

self.addEventListener("activate", (event) => event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key.startsWith("shieldline-") && key !== CACHE).map((key) => caches.delete(key)))).then(() => self.clients.claim())));

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET" || new URL(event.request.url).origin !== self.location.origin) return;
  if (new URL(event.request.url).pathname.includes("/api/")) return;
  if (event.request.mode === "navigate") {
    const freshRequest = new Request(event.request, { cache: "no-store" });
    event.respondWith(fetch(freshRequest).then((response) => {
      const copy = response.clone();
      void caches.open(CACHE).then((cache) => cache.put("./index.html", copy));
      return response;
    }).catch(async () => (await caches.match("./index.html")) || caches.match("./offline.html")));
    return;
  }
  event.respondWith(caches.match(event.request).then((cached) => cached || fetch(event.request).then((response) => {
    if (response.ok && (/\/assets\//.test(event.request.url) || /\.(?:js|css|png|webp|svg|woff2?)$/i.test(new URL(event.request.url).pathname))) {
      void caches.open(CACHE).then((cache) => cache.put(event.request, response.clone()));
    }
    return response;
  }).catch(() => caches.match("./"))));
});
