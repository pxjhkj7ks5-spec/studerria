export const CHANNELS = [
  "AerisRimor",
  "kyiv_airdef",
  "kievinform_ua1",
] as const;
export type Channel = (typeof CHANNELS)[number];
export interface ChannelMessage {
  channel: Channel;
  messageId: number;
  publishedAt: string;
  receivedAt: string;
  text: string;
  url: string;
  replyTo?: number;
  forwardedFrom?: string;
  contentHash: string;
}
export interface Bulletin {
  version: "civil-1";
  kind: "warning" | "all_clear_report" | "other";
  areaIds: string[];
  uncertain: boolean;
  reasons: string[];
}
