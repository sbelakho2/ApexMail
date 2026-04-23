export type HttpResponseData = {
  status: number;
  headers: Headers;
  bodyText: string;
  json: unknown | undefined;
};

export async function requestWithTimeout(
  input: string,
  init: RequestInit,
  timeoutMs = 15_000,
): Promise<HttpResponseData> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(input, {
      ...init,
      signal: controller.signal,
    });

    const bodyText = await response.text();
    let json: unknown | undefined;

    if (bodyText.length > 0) {
      try {
        json = JSON.parse(bodyText);
      } catch {
        json = undefined;
      }
    }

    return {
      status: response.status,
      headers: response.headers,
      bodyText,
      json,
    };
  } finally {
    clearTimeout(timeout);
  }
}

export function buildRequestInit(method: string, withMalformedBody = false): RequestInit {
  const upper = method.toUpperCase();
  if (upper === 'GET' || upper === 'DELETE') {
    return { method: upper };
  }

  if (withMalformedBody) {
    return {
      method: upper,
      headers: {
        'content-type': 'application/json',
      },
      body: '{"malformed":',
    };
  }

  return {
    method: upper,
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      e2e: true,
      sentAt: new Date().toISOString(),
    }),
  };
}
