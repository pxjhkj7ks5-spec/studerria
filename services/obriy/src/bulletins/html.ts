import { load } from "cheerio";
import { hash } from "../security.js";
import { sourceDate } from "../ingestion/http.js";
import type { Channel, ChannelMessage } from "./types.js";

export function parseChannelHtml(
  html: string,
  channel: Channel,
  at = new Date(),
): ChannelMessage[] {
  const $ = load(html);
  const nodes = $(".tgme_widget_message[data-post]");
  if (!nodes.length || !$(".tgme_channel_info").length)
    throw new Error("channel_html_unavailable");
  const result: ChannelMessage[] = [];
  nodes.each((_i, el) => {
    const node = $(el),
      post = node.attr("data-post") ?? "";
    const [handle, rawId] = post.split("/");
    const messageId = Number(rawId);
    const published = sourceDate(
      node.find(".tgme_widget_message_date time").attr("datetime"),
      at.getTime(),
    );
    if (
      handle?.toLowerCase() !== channel.toLowerCase() ||
      !Number.isSafeInteger(messageId) ||
      messageId <= 0 ||
      !published
    )
      throw new Error("channel_message_invalid");
    const textNode = node.find(".tgme_widget_message_text").first().clone();
    textNode.find("br").replaceWith("\n");
    textNode.find("script,style").remove();
    const text = textNode.text().trim();
    if (text.length > 16384) throw new Error("channel_message_too_large");
    const reply = node.find("a.tgme_widget_message_reply").attr("href") ?? "";
    const replyMatch = reply.match(
      new RegExp(`^https://t\\.me/${channel}/(\\d+)$`, "i"),
    );
    const forward = node
      .find(".tgme_widget_message_forwarded_from a")
      .attr("href");
    const forwardedFrom =
      forward && /^https:\/\/t\.me\/[a-zA-Z0-9_]+(?:\/\d+)?$/.test(forward)
        ? forward
        : undefined;
    const replyTo = replyMatch ? Number(replyMatch[1]) : undefined;
    result.push({
      channel,
      messageId,
      publishedAt: published.toISOString(),
      receivedAt: at.toISOString(),
      text,
      url: `https://t.me/${channel}/${messageId}`,
      replyTo,
      forwardedFrom,
      contentHash: hash(
        JSON.stringify([text, published.toISOString(), replyTo, forwardedFrom]),
      ),
    });
  });
  return [...new Map(result.map((m) => [m.messageId, m])).values()].sort(
    (a, b) => a.messageId - b.messageId,
  );
}
