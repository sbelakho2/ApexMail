/**
 * Events resource — delivery event queries, stats and timeseries.
 *
 * ListEventsQuery accepts {limit, offset, event_type, message_id} only
 * (deny_unknown_fields): a `cursor` parameter is rejected by the server
 * with HTTP 400 and is therefore refused client-side.
 */
import type { Event, EventStats, EventTimeseriesPoint } from "../models.js";
import { rejectCursor, validateId } from "../payload.js";
import type { ApexMail } from "../client.js";

export interface ListEventsOptions {
  limit?: number;
  offset?: number;
  /** Not supported: the server rejects `cursor` with HTTP 400. */
  cursor?: string;
  eventType?: string;
  messageId?: string;
}

export interface EventRangeOptions {
  from?: string;
  to?: string;
}

function extractList(data: unknown, key: string): Record<string, unknown>[] {
  if (Array.isArray(data)) {
    return data as Record<string, unknown>[];
  }
  if (data && typeof data === "object") {
    const record = data as Record<string, unknown>;
    for (const candidate of [key, "data", "items"]) {
      const value = record[candidate];
      if (Array.isArray(value)) {
        return value as Record<string, unknown>[];
      }
    }
  }
  return [];
}

export class EventsResource {
  readonly #client: ApexMail;

  constructor(client: ApexMail) {
    this.#client = client;
  }

  async list(options: ListEventsOptions = {}): Promise<Event[]> {
    rejectCursor("/v1/events", options.cursor);
    const params: Record<string, string | number | boolean> = {};
    if (options.limit !== undefined) {
      params.limit = options.limit;
    }
    if (options.offset !== undefined) {
      params.offset = options.offset;
    }
    if (options.eventType) {
      params.event_type = options.eventType;
    }
    if (options.messageId) {
      params.message_id = options.messageId;
    }
    const data = await this.#client.request<unknown>("GET", "/v1/events", { params });
    return extractList(data, "events") as unknown as Event[];
  }

  /** All events for a specific sent message (max 100 results). */
  async getByMessage(messageId: string): Promise<Event[]> {
    const data = await this.#client.request<unknown>("GET", "/v1/events", {
      params: { message_id: messageId, limit: 100 },
    });
    return extractList(data, "events") as unknown as Event[];
  }

  async get(eventId: string, options: { signal?: AbortSignal } = {}): Promise<Event> {
    validateId(eventId, "event");
    const data = await this.#client.request<unknown>("GET", `/v1/events/${eventId}`, {
      signal: options.signal,
    });
    if (data && typeof data === "object" && !Array.isArray(data)) {
      const record = data as Record<string, unknown>;
      if (record.event && typeof record.event === "object") {
        return record.event as Event;
      }
    }
    return data as Event;
  }

  async stats(options: EventRangeOptions = {}): Promise<EventStats> {
    const params: Record<string, string | number | boolean> = {};
    if (options.from) {
      params.from = options.from;
    }
    if (options.to) {
      params.to = options.to;
    }
    return this.#client.request<EventStats>("GET", "/v1/events/stats", { params });
  }

  async timeseries(options: EventRangeOptions = {}): Promise<EventTimeseriesPoint[]> {
    const params: Record<string, string | number | boolean> = {};
    if (options.from) {
      params.from = options.from;
    }
    if (options.to) {
      params.to = options.to;
    }
    const data = await this.#client.request<unknown>("GET", "/v1/events/timeseries", { params });
    return extractList(data, "timeseries") as unknown as EventTimeseriesPoint[];
  }
}
