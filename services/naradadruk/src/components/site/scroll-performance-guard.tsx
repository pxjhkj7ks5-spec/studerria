"use client";

import { useEffect } from "react";

const SCROLLING_CLASS = "nd-scrolling";
const SCROLL_IDLE_MS = 180;

export function ScrollPerformanceGuard() {
  useEffect(() => {
    const root = document.documentElement;
    let clearTimer: number | null = null;

    const markScrolling = () => {
      root.classList.add(SCROLLING_CLASS);
      if (clearTimer !== null) {
        window.clearTimeout(clearTimer);
      }
      clearTimer = window.setTimeout(() => {
        root.classList.remove(SCROLLING_CLASS);
        clearTimer = null;
      }, SCROLL_IDLE_MS);
    };

    const clearScrolling = () => {
      if (clearTimer !== null) {
        window.clearTimeout(clearTimer);
        clearTimer = null;
      }
      root.classList.remove(SCROLLING_CLASS);
    };

    const options: AddEventListenerOptions = { passive: true };

    window.addEventListener("wheel", markScrolling, options);
    window.addEventListener("scroll", markScrolling, options);
    window.addEventListener("touchmove", markScrolling, options);
    window.addEventListener("blur", clearScrolling);
    document.addEventListener("visibilitychange", clearScrolling);

    return () => {
      window.removeEventListener("wheel", markScrolling);
      window.removeEventListener("scroll", markScrolling);
      window.removeEventListener("touchmove", markScrolling);
      window.removeEventListener("blur", clearScrolling);
      document.removeEventListener("visibilitychange", clearScrolling);
      clearScrolling();
    };
  }, []);

  return null;
}
