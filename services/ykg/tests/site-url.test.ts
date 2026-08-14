import assert from "node:assert/strict";
import test from "node:test";
import { resolvePublicSiteLocation } from "../src/lib/site-url";

test("uses the current subdirectory URL by default", () => {
  assert.deepEqual(resolvePublicSiteLocation(), {
    baseUrl: "https://studerria.com",
    path: "/ykg",
    url: "https://studerria.com/ykg",
  });
});

test("supports a hostname-root public URL for the subdomain cutover", () => {
  assert.deepEqual(
    resolvePublicSiteLocation("https://ykg.studerria.com/"),
    {
      baseUrl: "https://ykg.studerria.com",
      path: "",
      url: "https://ykg.studerria.com/",
    },
  );
});

test("removes query and fragment data from a configured public URL", () => {
  assert.deepEqual(
    resolvePublicSiteLocation("https://example.com/store/?draft=1#preview"),
    {
      baseUrl: "https://example.com",
      path: "/store",
      url: "https://example.com/store",
    },
  );
});

test("falls back safely when the public URL is invalid", () => {
  assert.deepEqual(resolvePublicSiteLocation("javascript:alert(1)"), {
    baseUrl: "https://studerria.com",
    path: "/ykg",
    url: "https://studerria.com/ykg",
  });
});
