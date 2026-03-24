const DEFAULT_TIMEOUT_MS = parseInt(process.env.HTTP_TIMEOUT_MS ?? "10000", 10);
const DEFAULT_MAX_RETRIES = parseInt(process.env.HTTP_MAX_RETRIES ?? "3", 10);

interface FetchOptions {
  timeoutMs?: number;
  maxRetries?: number;
  headers?: Record<string, string>;
  method?: string;
  body?: string;
}

export class HttpError extends Error {
  constructor(
    message: string,
    public status: number,
    public url: string
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export class OfflineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OfflineError";
  }
}

export async function resilientFetch(
  url: string,
  options: FetchOptions = {}
): Promise<Response> {
  const {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxRetries = DEFAULT_MAX_RETRIES,
    headers = {},
    method = "GET",
    body,
  } = options;

  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      const response = await fetch(url, {
        method,
        headers: { ...headers },
        body,
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        throw new HttpError(
          `HTTP ${response.status}: ${response.statusText}`,
          response.status,
          url
        );
      }

      return response;
    } catch (error) {
      lastError = error as Error;

      if (error instanceof HttpError && error.status >= 400 && error.status < 500) {
        throw error;
      }

      if (attempt < maxRetries) {
        const delay = Math.min(1000 * Math.pow(2, attempt), 8000);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }

  if (
    lastError &&
    (lastError.name === "AbortError" ||
      lastError.message.includes("fetch failed") ||
      lastError.message.includes("ENOTFOUND") ||
      lastError.message.includes("ECONNREFUSED"))
  ) {
    throw new OfflineError(
      `Unable to reach ${url} after ${maxRetries + 1} attempts. Network may be unavailable.`
    );
  }

  throw lastError ?? new Error(`Failed to fetch ${url}`);
}

export function isOffline(): boolean {
  return process.env.OFFLINE_MODE === "true";
}
