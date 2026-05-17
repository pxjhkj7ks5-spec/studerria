export function getBasePath() {
  const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "/china-map";
  if (!basePath || basePath === "/") {
    return "";
  }
  return basePath.startsWith("/") ? basePath.replace(/\/+$/, "") : `/${basePath.replace(/\/+$/, "")}`;
}
