export interface RetryWithBackoffOptions<T> {
  idempotent: boolean;
  attempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  jitterRatio?: number;
  shouldRetryResult?: (result: T) => boolean;
  shouldRetryError?: (error: unknown) => boolean;
  sleep?: (delayMs: number) => Promise<void>;
}

const DEFAULT_ATTEMPTS = 3;
const DEFAULT_BASE_DELAY_MS = 100;
const DEFAULT_MAX_DELAY_MS = 2_000;
const DEFAULT_JITTER_RATIO = 0.2;

function defaultSleep(delayMs: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, Math.max(0, delayMs));
  });
}

function jitterDelay(delayMs: number, jitterRatio: number): number {
  if (delayMs <= 0 || jitterRatio <= 0) {
    return Math.max(0, delayMs);
  }
  const window = Math.floor(delayMs * jitterRatio);
  if (window <= 0) {
    return Math.max(0, delayMs);
  }
  const delta = Math.floor(Math.random() * ((window * 2) + 1)) - window;
  return Math.max(0, delayMs + delta);
}

export function shouldRetryHttpStatus(status: number): boolean {
  return status === 429 || status === 502 || status === 503 || status === 504;
}

export async function retryWithBackoff<T>(
  operation: () => Promise<T>,
  options: RetryWithBackoffOptions<T>,
): Promise<T> {
  const attempts = Math.max(1, options.attempts ?? DEFAULT_ATTEMPTS);
  if (!options.idempotent && attempts > 1) {
    throw new Error("retryWithBackoff requires idempotent=true when attempts > 1");
  }

  const baseDelayMs = Math.max(0, options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS);
  const maxDelayMs = Math.max(baseDelayMs, options.maxDelayMs ?? DEFAULT_MAX_DELAY_MS);
  const jitterRatio = Math.max(0, options.jitterRatio ?? DEFAULT_JITTER_RATIO);
  const shouldRetryResult = options.shouldRetryResult;
  const shouldRetryError = options.shouldRetryError ?? (() => false);
  const sleep = options.sleep ?? defaultSleep;

  let delayMs = baseDelayMs;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const result = await operation();
      if (attempt < attempts && shouldRetryResult?.(result) === true) {
        await sleep(jitterDelay(delayMs, jitterRatio));
        delayMs = Math.min(maxDelayMs, delayMs * 2);
        continue;
      }
      return result;
    } catch (error) {
      if (attempt >= attempts || !shouldRetryError(error)) {
        throw error;
      }
      await sleep(jitterDelay(delayMs, jitterRatio));
      delayMs = Math.min(maxDelayMs, delayMs * 2);
    }
  }

  throw new Error("retryWithBackoff exhausted attempts without a terminal result");
}
