export class HttpError extends Error {
  readonly name = "HttpError";

  constructor(
    readonly status: number,
    message: string,
    readonly retryable: boolean,
    readonly retryAfterSeconds: number | null = null,
  ) {
    super(message);
  }
}

export type RequestOptions = {
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  retries?: number;
  now?: () => number;
};

const USER_AGENT = "SignalTrace/0.1 (student threat-intelligence portfolio; non-commercial)";

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function retryDelay(attempt: number, retryAfterSeconds: number | null): number {
  if (retryAfterSeconds != null && retryAfterSeconds >= 0 && retryAfterSeconds <= 60) {
    return retryAfterSeconds * 1000;
  }
  const base = Math.min(15000, 500 * 2 ** attempt);
  const jitter = Math.floor(Math.random() * base * 0.25);
  return base + jitter;
}

export async function requestText(url: string, options: RequestOptions = {}): Promise<string> {
  const fetchImpl = options.fetch ?? fetch;
  const sleep = options.sleep ?? defaultSleep;
  const retries = options.retries ?? 3;
  const timeoutMs = options.timeoutMs ?? 60000;
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const response = await fetchImpl(url, {
        method: options.method ?? "GET",
        headers: {
          "User-Agent": USER_AGENT,
          Accept: "text/plain, text/csv, application/json",
          ...options.headers,
        },
        body: options.body,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (response.ok) return await response.text();
      const retryAfter = response.headers.get("retry-after");
      const retryAfterSeconds = retryAfter && /^\d+$/.test(retryAfter) ? Number(retryAfter) : null;
      const retryable = response.status === 429 || response.status >= 500;
      const error = new HttpError(
        response.status,
        `Upstream responded ${response.status} for ${new URL(url).host}${new URL(url).pathname}`,
        retryable,
        retryAfterSeconds,
      );
      if (!retryable || attempt === retries) throw error;
      lastError = error;
      await sleep(retryDelay(attempt, retryAfterSeconds));
    } catch (error) {
      if (error instanceof HttpError && !error.retryable) throw error;
      lastError = error instanceof Error ? error : new Error("Request failed");
      if (attempt === retries) break;
      await sleep(retryDelay(attempt, error instanceof HttpError ? error.retryAfterSeconds : null));
    }
  }

  throw lastError ?? new Error("Request failed");
}

export async function requestJson<T>(url: string, options: RequestOptions = {}): Promise<T> {
  const text = await requestText(url, {
    ...options,
    headers: { Accept: "application/json", ...options.headers },
  });
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(`Upstream returned malformed JSON from ${new URL(url).host}`);
  }
}
