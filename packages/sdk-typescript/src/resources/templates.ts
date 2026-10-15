/**
 * Templates resource — template management and rendering.
 *
 * Mirrors sdk-python's TemplatesResource (create/list/get/update/duplicate/
 * rollback/delete/render). Create always sends `text_body` (null when
 * absent), exactly like the Python client.
 */
import { ValidationError } from "../errors.js";
import type { Template, TemplateRenderResponse } from "../models.js";
import { rejectCursor, validateId } from "../payload.js";
import type { ApexMail } from "../client.js";

export interface ListTemplatesOptions {
  limit?: number;
  offset?: number;
  /** Not supported: the server rejects `cursor` with HTTP 400. */
  cursor?: string;
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

function extractItem(data: unknown, key: string): Record<string, unknown> {
  if (data && typeof data === "object" && !Array.isArray(data)) {
    const record = data as Record<string, unknown>;
    const value = record[key];
    if (value && typeof value === "object") {
      return value as Record<string, unknown>;
    }
    return record;
  }
  return {};
}

export class TemplatesResource {
  readonly #client: ApexMail;

  constructor(client: ApexMail) {
    this.#client = client;
  }

  async create(
    input: { name: string; subject: string; htmlBody: string; textBody?: string | null; signal?: AbortSignal },
  ): Promise<Template> {
    const data = await this.#client.request<unknown>("POST", "/v1/templates", {
      json: {
        name: input.name,
        subject: input.subject,
        html_body: input.htmlBody,
        text_body: input.textBody ?? null,
      },
      signal: input.signal,
    });
    return extractItem(data, "template") as unknown as Template;
  }

  async list(options: ListTemplatesOptions = {}): Promise<Template[]> {
    rejectCursor("/v1/templates", options.cursor);
    const params: Record<string, string | number | boolean> = {};
    if (options.limit !== undefined) {
      params.limit = options.limit;
    }
    if (options.offset !== undefined) {
      params.offset = options.offset;
    }
    const data = await this.#client.request<unknown>("GET", "/v1/templates", { params });
    return extractList(data, "templates") as unknown as Template[];
  }

  async get(templateId: string, options: { signal?: AbortSignal } = {}): Promise<Template> {
    validateId(templateId, "template");
    const data = await this.#client.request<unknown>("GET", `/v1/templates/${templateId}`, {
      signal: options.signal,
    });
    return extractItem(data, "template") as unknown as Template;
  }

  async update(
    templateId: string,
    input: { name?: string; subject?: string; htmlBody?: string; textBody?: string | null; signal?: AbortSignal },
  ): Promise<Template> {
    validateId(templateId, "template");
    const payload: Record<string, unknown> = {};
    if (input.name !== undefined) {
      payload.name = input.name;
    }
    if (input.subject !== undefined) {
      payload.subject = input.subject;
    }
    if (input.htmlBody !== undefined) {
      payload.html_body = input.htmlBody;
    }
    if (input.textBody !== undefined) {
      payload.text_body = input.textBody;
    }
    if (Object.keys(payload).length === 0) {
      throw new ValidationError("Update payload must include at least one field");
    }
    const data = await this.#client.request<unknown>("PUT", `/v1/templates/${templateId}`, {
      json: payload,
      signal: input.signal,
    });
    return extractItem(data, "template") as unknown as Template;
  }

  async duplicate(templateId: string, options: { signal?: AbortSignal } = {}): Promise<Template> {
    validateId(templateId, "template");
    const data = await this.#client.request<unknown>("POST", `/v1/templates/${templateId}/duplicate`, {
      signal: options.signal,
    });
    return extractItem(data, "template") as unknown as Template;
  }

  async rollback(templateId: string, version: number, options: { signal?: AbortSignal } = {}): Promise<Template> {
    validateId(templateId, "template");
    const data = await this.#client.request<unknown>("POST", `/v1/templates/${templateId}/rollback`, {
      json: { version },
      signal: options.signal,
    });
    return extractItem(data, "template") as unknown as Template;
  }

  async delete(templateId: string, options: { signal?: AbortSignal } = {}): Promise<void> {
    validateId(templateId, "template");
    await this.#client.request<unknown>("DELETE", `/v1/templates/${templateId}`, {
      signal: options.signal,
    });
  }

  /** Render a template with variables without sending (previews). */
  async render(
    templateId: string,
    variables: Record<string, unknown>,
    options: { signal?: AbortSignal } = {},
  ): Promise<TemplateRenderResponse> {
    validateId(templateId, "template");
    return this.#client.request<TemplateRenderResponse>(
      "POST",
      `/v1/templates/${templateId}/render`,
      { json: { variables }, signal: options.signal },
    );
  }
}
