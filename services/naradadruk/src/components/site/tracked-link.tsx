"use client";

import type { AnchorHTMLAttributes, ReactNode } from "react";
import {
  trackPlausible,
  type PlausibleEventName,
  type PlausibleEventProps,
} from "@/lib/analytics";

type TrackedLinkProps = AnchorHTMLAttributes<HTMLAnchorElement> & {
  children: ReactNode;
  eventName: PlausibleEventName;
  eventProps?: PlausibleEventProps;
};

export function TrackedLink({
  children,
  eventName,
  eventProps,
  onClick,
  ...props
}: TrackedLinkProps) {
  return (
    <a
      {...props}
      onClick={(event) => {
        trackPlausible(eventName, eventProps);
        onClick?.(event);
      }}
    >
      {children}
    </a>
  );
}
