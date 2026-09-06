import { CHANNELS } from "../src/bulletins/types.js";
import { fetchChannelPage } from "../src/bulletins/collector.js";
import { parseBulletin } from "../src/bulletins/parser.js";
// Read-only public-web contract check. No texts, positions or private data in output.
let failed = false;
for (const channel of CHANNELS) {
  try {
    const messages = await fetchChannelPage(
      channel,
      undefined,
      new AbortController().signal,
    );
    const counts = { warning: 0, all_clear_report: 0, other: 0 };
    for (const m of messages) counts[parseBulletin(m.text).kind]++;
    console.log(
      JSON.stringify({
        channel,
        available: true,
        messages: messages.length,
        classifications: counts,
      }),
    );
  } catch {
    failed = true;
    console.log(JSON.stringify({ channel, available: false }));
  }
}
process.exitCode = failed ? 1 : 0;
