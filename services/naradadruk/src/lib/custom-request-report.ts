type Event = { name: string; sessionId: string; createdAt: Date };
export function buildCustomRequestReport(events: Event[], now = new Date()) {
  const day = 86_400_000;
  const currentStart = now.getTime() - 14 * day;
  const previousStart = currentStart - 14 * day;
  const summarize = (from: number, to: number) => {
    const period = events.filter((event) => event.createdAt.getTime() >= from && event.createdAt.getTime() < to);
    const count = (name: string) => new Set(period.filter((event) => event.name === name).map((event,index) => event.sessionId || `anonymous-${index}`)).size;
    const opens = count("Custom Request Open"), starts = count("Custom Request Start"), submissions = count("Custom Request Submitted");
    const startSessions = new Map<string, number>();
    for (const event of period) {
      if (event.name === "Custom Request Start" && event.sessionId) {
        startSessions.set(event.sessionId, Math.min(startSessions.get(event.sessionId) ?? Infinity, event.createdAt.getTime()));
      }
    }
    const completedSessions = new Set(period.filter((event) => event.name === "Custom Request Submitted" && startSessions.has(event.sessionId) && event.createdAt.getTime() >= startSessions.get(event.sessionId)!).map((event) => event.sessionId));
    return { opens, starts, submissions, completionRate: startSessions.size ? Math.round(completedSessions.size / startSessions.size * 1000) / 10 : null };
  };
  return { current:summarize(currentStart,now.getTime() + 1),previous:summarize(previousStart,currentStart) };
}
