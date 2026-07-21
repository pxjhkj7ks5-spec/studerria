const CACHE = "shieldline-runtime-v8";
const SHELL = [
  "./",
  "./index.html",
  "./offline.html",
  "./manifest.webmanifest?v=4",
  "./favicon.ico?v=4",
  "./favicon-32.png?v=4",
  "./shieldline-mark.svg?v=4",
  "./shieldline-mask.svg?v=4",
  "./apple-touch-icon.png?v=4",
  "./icon-192.png?v=4",
  "./icon-512.png?v=4",
  "./audio/sfx/chime.mp3",
  "./audio/sfx/confirm.mp3",
  "./audio/sfx/gun-burst-1.mp3",
  "./audio/sfx/impact.mp3",
  "./audio/sfx/mechanical.mp3",
  "./audio/sfx/missile-launch.mp3",
  "./audio/sfx/radio-static.mp3",
  "./audio/sfx/siren.mp3",
  "./audio/sfx/timer.mp3",
];

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
    }).catch(async () => {
      const cache = await caches.open(CACHE);
      return (await cache.match("./index.html")) || cache.match("./offline.html");
    }));
    return;
  }
  event.respondWith(caches.open(CACHE).then(async (cache) => {
    const cached = await cache.match(event.request);
    if (cached) return cached;
    return fetch(event.request).then((response) => {
      if (response.ok && (/\/assets\//.test(event.request.url) || /\.(?:js|css|mp3|ogg|png|webp|svg|woff2?)$/i.test(new URL(event.request.url).pathname))) {
        void cache.put(event.request, response.clone());
      }
      return response;
    }).catch(() => cache.match("./"));
  }));
});
