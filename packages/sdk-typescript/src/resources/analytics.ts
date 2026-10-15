/**
 * Analytics resource.
 *
 * The analytics API exposes typed subpaths only (there is no GET
 * /v1/analytics): /dashboard, /volume, /engagement, /deliverability,
 * /subject-line (POST) and /export. Every GET subpath accepts exactly the
 * query parameters {from, to, interval} (interval: hour | day | week |
 * month).
 */
import { ValidationError } from "../errors.js";
import type { ApexMail } from "../client.js";

const VALID_INTERVALS = ["hour", "day", "week", "month"] as const;

export interface AnalyticsQuery {
  from?: string;
  to?: string;
  interval?: string;
  signal?: AbortSignal;
}

export interface AnalyticsExportOptions {
  from?: string;
  to?: string;
  /** Export format (default "json"). */
  format?: string;
  signal?: AbortSignal;
}

function analyticsQuery(options: AnalyticsQuery): Record<string, string | number | boolean> {
  if (options.interval !== undefined && !(VALID_INTERVALS as readonly string[]).includes(options.interval)) {
    throw new ValidationError(
      `interval must be one of ${VALID_INTERVALS.join(", ")} (got ${JSON.stringify(options.interval)})`,
    );
  }
  const params: Record<string, string | number | boolean> = {};
  if (options.from) {
    params.from = options.from;
  }
  if (options.to) {
    params.to = options.to;
  }
  if (options.interval) {
    params.interval = options.interval;
  }
  return params;
}

export class AnalyticsResource {
  readonly #client: ApexMail;

  constructor(client: ApexMail) {
    this.#client = client;
  }

  /** Dashboard counters: {total_sent, total_delivered, ..., click_rate}. */
  async dashboard(options: AnalyticsQuery = {}): Promise<Record<string, unknown>> {
    return this.#client.request<Record<string, unknown>>("GET", "/v1/analytics/dashboard", {
      params: analyticsQuery(options),
      signal: options.signal,
    });
  }

  /** Volume timeseries: [{date, sent, delivered, bounced}, ...]. */
  async volume(options: AnalyticsQuery = {}): Promise<Record<string, unknown>> {
    return this.#client.request<Record<string, unknown>>("GET", "/v1/analytics/volume", {
      params: analyticsQuery(options),
      signal: options.signal,
    });
  }

  /** Engagement rates + timeseries: {open_rate, click_rate, timeseries, ...}. */
  async engagement(options: AnalyticsQuery = {}): Promise<Record<string, unknown>> {
    return this.#client.request<Record<string, unknown>>("GET", "/v1/analytics/engagement", {
      params: analyticsQuery(options),
      signal: options.signal,
    });
  }

  /** Deliverability rates: {delivery_rate, bounce_rate, ...}. */
  async deliverability(options: AnalyticsQuery = {}): Promise<Record<string, unknown>> {
    return this.#client.request<Record<string, unknown>>("GET", "/v1/analytics/deliverability", {
      params: analyticsQuery(options),
      signal: options.signal,
    });
  }

  /** Analyze a subject line (POST /subject-line with body {subject}). */
  async analyzeSubjectLine(subject: string, options: { signal?: AbortSignal } = {}): Promise<Record<string, unknown>> {
    return this.#client.request<Record<string, unknown>>("POST", "/v1/analytics/subject-line", {
      json: { subject },
      signal: options.signal,
    });
  }

  /** Start an analytics export job ({job_id?, download_url?, status}). */
  async export(options: AnalyticsExportOptions = {}): Promise<Record<string, unknown>> {
    const params: Record<string, string | number | boolean> = { format: options.format ?? "json" };
    if (options.from) {
      params.from = options.from;
    }
    if (options.to) {
      params.to = options.to;
    }
    return this.#client.request<Record<string, unknown>>("GET", "/v1/analytics/export", {
      params,
      signal: options.signal,
    });
  }

  /**
   * @deprecated GET /v1/analytics does not exist on the API. Kept as an
   * alias of dashboard() for backwards compatibility; `groupBy` is mapped
   * to the API's `interval` parameter, while `tag`/`domain` are ignored
   * (the API has no such filters).
   */
  async get(options: {
    from: string;
    to: string;
    groupBy?: string;
    tag?: string;
    domain?: string;
  }): Promise<Record<string, unknown>> {
    console.warn(
      "analytics.get() is deprecated: the API exposes typed subpaths. " +
        "Use dashboard()/volume()/engagement()/deliverability().",
    );
    return this.dashboard({ from: options.from, to: options.to, interval: options.groupBy });
  }
}
