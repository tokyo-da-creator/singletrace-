export type LimitDecision = { ok: true } | { ok: false; retryAfter: number };

export function createLimiter(limit: number, windowMs: number) {
  const hits = new Map<string, number[]>();
  return function check(key: string, now = Date.now()): LimitDecision {
    const recent = (hits.get(key) ?? []).filter((stamp) => now - stamp < windowMs);
    if (recent.length >= limit) {
      const retryAfter = Math.max(1, Math.ceil((windowMs - (now - recent[0])) / 1000));
      hits.set(key, recent);
      return { ok: false, retryAfter };
    }
    recent.push(now);
    hits.set(key, recent);
    return { ok: true };
  };
}

export const apiLimiter = createLimiter(120, 60_000);
export const investigateLimiter = createLimiter(30, 60_000);
