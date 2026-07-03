import { createServer } from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { extname, join, normalize, resolve } from "node:path";

const port = Number(process.env.PORT || 8080);
const basePath = normalizeBasePath(process.env.SHIELDLINE_BASE_PATH || "/shieldline");
const distDir = resolve("dist");
const indexPath = join(distDir, "index.html");

const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".png", "image/png"],
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
  [".webp", "image/webp"],
  [".ico", "image/x-icon"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"],
]);

function normalizeBasePath(value) {
  const raw = String(value || "").trim();
  if (!raw || raw === "/") return "";
  const withLeading = raw.startsWith("/") ? raw : `/${raw}`;
  return withLeading.replace(/\/+$/, "");
}

function sendFile(res, filePath) {
  const ext = extname(filePath).toLowerCase();
  res.writeHead(200, {
    "Content-Type": contentTypes.get(ext) || "application/octet-stream",
    "Cache-Control": ext === ".html" ? "no-store" : "public, max-age=31536000, immutable",
    "X-Content-Type-Options": "nosniff",
  });
  createReadStream(filePath).pipe(res);
}

function resolveAssetPath(pathname) {
  const withoutBase = basePath && pathname.startsWith(basePath)
    ? pathname.slice(basePath.length) || "/"
    : pathname;
  const decoded = decodeURIComponent(withoutBase.split("?")[0]);
  const normalizedPath = normalize(decoded).replace(/^(\.\.[/\\])+/, "");
  const filePath = join(distDir, normalizedPath);
  if (!filePath.startsWith(distDir)) return null;
  if (!existsSync(filePath) || !statSync(filePath).isFile()) return null;
  return filePath;
}

createServer((req, res) => {
  const requestUrl = new URL(req.url || "/", "http://127.0.0.1");
  const pathname = requestUrl.pathname.replace(/\/+$/, "") || "/";

  if (basePath && pathname !== basePath && !pathname.startsWith(`${basePath}/`)) {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }

  const filePath = resolveAssetPath(requestUrl.pathname);
  if (filePath) {
    sendFile(res, filePath);
    return;
  }

  if (!existsSync(indexPath)) {
    res.writeHead(503, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Shieldline build is not available.");
    return;
  }

  sendFile(res, indexPath);
}).listen(port, "0.0.0.0", () => {
  console.log(`Shieldline listening on 0.0.0.0:${port}${basePath || "/"}`);
});
