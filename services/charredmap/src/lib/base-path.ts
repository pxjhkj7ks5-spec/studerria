const externalUrlPattern = /^(?:[a-z][a-z\d+\-.]*:)?\/\//i;

function normalizeBasePath(basePath?: string) {
  if (!basePath || basePath === "/") {
    return "";
  }

  const trimmed = basePath.trim();

  if (!trimmed) {
    return "";
  }

  const withLeadingSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withLeadingSlash.replace(/\/+$/, "");
}

export function getBasePath() {
  return normalizeBasePath(process.env.NEXT_PUBLIC_BASE_PATH ?? "/charredmap");
}

export function withBasePath(path: string) {
  if (!path) {
    return getBasePath() || "/";
  }

  if (
    !path.startsWith("/") ||
    externalUrlPattern.test(path) ||
    path.startsWith("data:") ||
    path.startsWith("blob:")
  ) {
    return path;
  }

  const basePath = getBasePath();

  if (!basePath || path === basePath || path.startsWith(`${basePath}/`)) {
    return path;
  }

  return path === "/" ? basePath : `${basePath}${path}`;
}
