/**
 * Resource surface contract tests: endpoints, wire bodies, query
 * parameters, response extraction and the client-side cursor refusals —
 * asserted on the requests a local node:http stub actually received.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { ApexMail, ValidationError, KNOWN_WEBHOOK_EVENTS } from "../dist/esm/index.js";
import { TEST_API_KEY, captureWarnings, startStub } from "./helpers/stub.mjs";

async function withClient(handler, fn) {
  const stub = await startStub(handler);
  const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
  try {
    return await fn(client, stub);
  } finally {
    client.close();
    await stub.close();
  }
}

const request = (stub) => stub.requests[stub.requests.length - 1];

describe("webhooks resource", () => {
  const webhookBody = (extra = {}) => ({
    id: "wh_1",
    url: "https://example.com/hook",
    events: ["message.delivered"],
    secret: "whsec_generated_server_side",
    status: "active",
    created_at: "2026-08-29T00:00:00Z",
    updated_at: "2026-08-29T00:00:00Z",
    ...extra,
  });

  test("create sends exactly {url, events}", async () => {
    await withClient(
      () => ({ body: { data: webhookBody() } }),
      async (client, stub) => {
        const webhook = await client.webhooks.create({
          name: "legacy name",
          url: "https://example.com/hook",
          events: ["message.delivered", "message.bounced", "*"],
          description: "legacy",
          secret: "whsec_legacy",
          enabled: true,
        });
        const record = request(stub);
        assert.equal(record.method, "POST");
        assert.equal(record.path, "/v1/webhooks");
        assert.deepEqual(record.json, {
          url: "https://example.com/hook",
          events: ["message.delivered", "message.bounced", "*"],
        });
        assert.equal(webhook.id, "wh_1");
        assert.equal(webhook.status, "active");
        assert.equal(webhook.secret, "whsec_generated_server_side");
      },
    );
  });

  test("update maps enabled to status and transmits only {url, events, status}", async () => {
    await withClient(
      () => ({ body: { data: webhookBody({ status: "paused" }) } }),
      async (client, stub) => {
        await client.webhooks.update("wh_1", {
          url: "https://example.com/hook2",
          events: ["message.opened"],
          enabled: false,
        });
        const record = request(stub);
        assert.equal(record.method, "PUT");
        assert.equal(record.path, "/v1/webhooks/wh_1");
        assert.deepEqual(record.json, {
          url: "https://example.com/hook2",
          events: ["message.opened"],
          status: "paused",
        });
      },
    );
  });

  test("update rejects unknown statuses and empty payloads", async () => {
    await withClient(
      () => ({ body: { data: webhookBody() } }),
      async (client) => {
        await assert.rejects(client.webhooks.update("wh_1", { status: "enabled" }), ValidationError);
        await assert.rejects(client.webhooks.update("wh_1", { name: "ignored" }), ValidationError);
      },
    );
  });

  test("create requires a non-localhost HTTPS URL", async () => {
    await withClient(
      () => ({ body: { data: webhookBody() } }),
      async (client) => {
        await assert.rejects(
          client.webhooks.create({ url: "http://example.com/hook", events: ["*"] }),
          ValidationError,
        );
      },
    );
  });

  test("rotateSecret posts to the rotate route and returns the new secret", async () => {
    await withClient(
      () => ({ body: { data: webhookBody({ secret: "whsec_rotated" }) } }),
      async (client, stub) => {
        const webhook = await client.webhooks.rotateSecret("wh_1");
        const record = request(stub);
        assert.equal(record.method, "POST");
        assert.equal(record.path, "/v1/webhooks/wh_1/rotate-secret");
        assert.equal(webhook.secret, "whsec_rotated");
      },
    );
  });

  test("test() posts without a body; delete() hits the item route", async () => {
    await withClient(
      (record) =>
        record.method === "DELETE"
          ? { status: 204 }
          : { body: { data: { success: true, response_time_ms: 12 } } },
      async (client, stub) => {
        const result = await client.webhooks.test("wh_1");
        assert.equal(result.success, true);
        assert.equal(request(stub).path, "/v1/webhooks/wh_1/test");
        assert.equal(request(stub).body, "", "the server takes no body");
        await client.webhooks.delete("wh_1");
        assert.equal(request(stub).method, "DELETE");
        assert.equal(request(stub).path, "/v1/webhooks/wh_1");
      },
    );
  });

  test("list accepts a bare array and an envelope", async () => {
    await withClient(
      () => ({ body: { data: [webhookBody()] } }),
      async (client) => {
        const { webhooks } = await client.webhooks.list({ limit: 10, offset: 5 });
        assert.equal(webhooks.length, 1);
        assert.equal(webhooks[0].id, "wh_1");
      },
    );
  });

  test("known events match the server list, unknown ones warn but pass (SM15 F1)", async () => {
    assert.deepEqual([...KNOWN_WEBHOOK_EVENTS], [
      "message.accepted", "message.queued", "message.attempted",
      "message.deferred", "message.delivered", "message.bounced",
      "message.complained", "message.suppressed", "message.opened",
      "message.clicked", "message.cancelled",
      "recipient.unsubscribed",
      "campaign.started", "campaign.ab_winner_selected", "campaign.completed",
      "placement_test.completed",
      "inbound", "*",
    ]);

    await withClient(
      () => ({ body: { data: webhookBody() } }),
      async (client) => {
        const { warnings } = await captureWarnings(() =>
          client.webhooks.create({ url: "https://example.com/hook", events: ["message.accepted", "delivered"] }),
        );
        assert.equal(warnings.length, 1, "one warning naming the unknown event");
        assert.match(warnings[0], /Unknown webhook event type\(s\): delivered/);
      },
    );
    // Server-valid events pass without any warning.
    await withClient(
      () => ({ body: { data: webhookBody() } }),
      async (client) => {
        const { warnings } = await captureWarnings(() =>
          client.webhooks.create({ url: "https://example.com/hook", events: ["message.accepted", "message.cancelled"] }),
        );
        assert.deepEqual(warnings, []);
      },
    );
  });

  test("update with a server-valid event set talks to the wire", async () => {
    await withClient(
      () => ({ body: { data: webhookBody() } }),
      async (client, stub) => {
        const { warnings } = await captureWarnings(() =>
          client.webhooks.update("wh_1", { events: ["message.accepted", "message.cancelled"] }),
        );
        assert.deepEqual(warnings, []);
        assert.deepEqual(request(stub).json.events, ["message.accepted", "message.cancelled"]);
      },
    );
  });
});

describe("domains resource", () => {
  const domainBody = {
    id: "dom_1",
    name: "example.com",
    status: "pending",
    spf_verified: false,
    created_at: "2026-08-29T00:00:00Z",
  };

  test("create sends exactly {name}", async () => {
    await withClient(
      () => ({ body: { data: domainBody } }),
      async (client, stub) => {
        const domain = await client.domains.create("example.com", { verificationMethod: "dns_txt" });
        assert.deepEqual(request(stub).json, { name: "example.com" });
        assert.equal(domain.id, "dom_1");
      },
    );
  });

  test("get/verify/delete hit the documented routes and validate ids", async () => {
    await withClient(
      (record) =>
        record.method === "DELETE"
          ? { status: 204 }
          : { body: { data: { ...domainBody, status: "verified" } } },
      async (client, stub) => {
        await client.domains.get("dom_1");
        assert.equal(request(stub).path, "/v1/domains/dom_1");
        const verifyResult = await client.domains.verify("dom_1");
        assert.equal(request(stub).method, "POST");
        assert.equal(request(stub).path, "/v1/domains/dom_1/verify");
        assert.equal(verifyResult.status, "verified");
        await client.domains.delete("dom_1");
        assert.equal(request(stub).method, "DELETE");
        assert.equal(request(stub).path, "/v1/domains/dom_1");
        await assert.rejects(client.domains.get("bad id!"), ValidationError);
      },
    );
  });

  test("health aliases get() (the API has no /health route)", async () => {
    await withClient(
      () => ({ body: { data: domainBody } }),
      async (client, stub) => {
        await client.domains.health("dom_1");
        assert.equal(request(stub).path, "/v1/domains/dom_1");
      },
    );
  });

  test("list forwards limit/offset, accepts a bare array, and refuses cursor", async () => {
    await withClient(
      () => ({ body: { data: [domainBody] } }),
      async (client, stub) => {
        const { domains } = await client.domains.list({ limit: 10, offset: 20 });
        assert.equal(request(stub).query.get("limit"), "10");
        assert.equal(request(stub).query.get("offset"), "20");
        assert.equal(domains.length, 1);
        await assert.rejects(client.domains.list({ cursor: "cur_1" }), (error) => {
          assert.ok(error instanceof ValidationError);
          assert.equal(error.code, "UNSUPPORTED_PAGINATION");
          assert.match(error.message, /\/v1\/domains does not support cursor pagination/);
          return true;
        });
      },
    );
  });
});

describe("templates resource", () => {
  const templateBody = {
    id: "tpl_1",
    name: "welcome",
    subject: "Welcome, {{name}}!",
    html_body: "<h1>Hello</h1>",
    text_body: null,
    version: 1,
    status: "active",
    created_at: "2026-08-29T00:00:00Z",
    updated_at: "2026-08-29T00:00:00Z",
  };

  test("create always sends text_body (null when absent), like sdk-python", async () => {
    await withClient(
      () => ({ body: { data: templateBody } }),
      async (client, stub) => {
        await client.templates.create({ name: "welcome", subject: "Welcome", htmlBody: "<h1>Hello</h1>" });
        assert.deepEqual(request(stub).json, {
          name: "welcome",
          subject: "Welcome",
          html_body: "<h1>Hello</h1>",
          text_body: null,
        });
      },
    );
  });

  test("update builds a partial PUT and refuses an empty payload", async () => {
    await withClient(
      () => ({ body: { data: templateBody } }),
      async (client, stub) => {
        await client.templates.update("tpl_1", { subject: "New", textBody: "plain" });
        assert.equal(request(stub).method, "PUT");
        assert.equal(request(stub).path, "/v1/templates/tpl_1");
        assert.deepEqual(request(stub).json, { subject: "New", text_body: "plain" });
        await assert.rejects(client.templates.update("tpl_1", {}), ValidationError);
      },
    );
  });

  test("duplicate and rollback hit their routes", async () => {
    await withClient(
      () => ({ body: { data: templateBody } }),
      async (client, stub) => {
        await client.templates.duplicate("tpl_1");
        assert.equal(request(stub).path, "/v1/templates/tpl_1/duplicate");
        await client.templates.rollback("tpl_1", 3);
        assert.equal(request(stub).path, "/v1/templates/tpl_1/rollback");
        assert.deepEqual(request(stub).json, { version: 3 });
      },
    );
  });

  test("render posts {variables} and returns the rendered fields", async () => {
    await withClient(
      () => ({ body: { data: { subject: "Welcome, Jane!", html: "<h1>Hello, Jane</h1>", text: null } } }),
      async (client, stub) => {
        const rendered = await client.templates.render("tpl_1", { name: "Jane" });
        assert.equal(request(stub).path, "/v1/templates/tpl_1/render");
        assert.deepEqual(request(stub).json, { variables: { name: "Jane" } });
        assert.equal(rendered.subject, "Welcome, Jane!");
      },
    );
  });

  test("list extracts the templates array and refuses cursor", async () => {
    await withClient(
      () => ({ body: { data: [templateBody] } }),
      async (client) => {
        const templates = await client.templates.list({ limit: 5 });
        assert.equal(templates[0].id, "tpl_1");
        await assert.rejects(client.templates.list({ cursor: "cur_1" }), ValidationError);
      },
    );
  });
});

describe("suppressions resource", () => {
  const suppressionBody = {
    id: "sup_1",
    email: "user@example.com",
    reason: "bounce",
    source: null,
    created_at: "2026-08-29T00:00:00Z",
  };

  test("add/create post {email, reason[, source]}", async () => {
    await withClient(
      () => ({ body: { data: suppressionBody } }),
      async (client, stub) => {
        await client.suppressions.add({ email: "user@example.com", reason: "bounce" });
        assert.deepEqual(request(stub).json, { email: "user@example.com", reason: "bounce" });
        await client.suppressions.create({ email: "user@example.com", reason: "manual", source: "api" });
        assert.deepEqual(request(stub).json, { email: "user@example.com", reason: "manual", source: "api" });
      },
    );
  });

  test("check escapes the addr-spec path segment (URL-injection guard)", async () => {
    await withClient(
      () => ({ body: { data: { email: "o'brien+j/s@example.com", suppressed: false } } }),
      async (client, stub) => {
        await client.suppressions.check("o'brien+j/s@example.com");
        assert.equal(request(stub).path, "/v1/suppressions/check/o%27brien%2Bj%2Fs%40example.com");
      },
    );
  });

  test("list forwards reason and refuses cursor", async () => {
    await withClient(
      () => ({ body: { data: [suppressionBody] } }),
      async (client, stub) => {
        const rows = await client.suppressions.list({ reason: "bounce", limit: 5, offset: 1 });
        assert.equal(request(stub).query.get("reason"), "bounce");
        assert.equal(rows[0].id, "sup_1");
        await assert.rejects(client.suppressions.list({ cursor: "cur_1" }), ValidationError);
      },
    );
  });

  test("bulk posts the entries array", async () => {
    await withClient(
      () => ({ body: { data: { created: 1, duplicates: 0, invalid: 0 } } }),
      async (client, stub) => {
        const result = await client.suppressions.bulk([{ email: "a@example.com", reason: "bounce" }]);
        assert.equal(request(stub).path, "/v1/suppressions/bulk");
        assert.deepEqual(request(stub).json.entries, [{ email: "a@example.com", reason: "bounce" }]);
        assert.equal(result.created, 1);
      },
    );
  });
});

describe("events resource", () => {
  const eventBody = {
    id: "evt_1",
    message_id: "msg_1",
    event_type: "delivered",
    recipient: "user@example.com",
    timestamp: "2026-08-29T00:00:00Z",
  };

  test("list forwards filters and refuses cursor", async () => {
    await withClient(
      () => ({ body: { data: [eventBody] } }),
      async (client, stub) => {
        const events = await client.events.list({ eventType: "delivered", messageId: "msg_1", limit: 5 });
        assert.equal(request(stub).query.get("event_type"), "delivered");
        assert.equal(request(stub).query.get("message_id"), "msg_1");
        assert.equal(events[0].id, "evt_1");
        await assert.rejects(client.events.list({ cursor: "cur_1" }), ValidationError);
      },
    );
  });

  test("getByMessage pins message_id and limit=100", async () => {
    await withClient(
      () => ({ body: { data: [eventBody] } }),
      async (client, stub) => {
        await client.events.getByMessage("msg_1");
        assert.equal(request(stub).query.get("message_id"), "msg_1");
        assert.equal(request(stub).query.get("limit"), "100");
      },
    );
  });

  test("stats and timeseries hit their routes with from/to", async () => {
    await withClient(
      (record) =>
        record.path.endsWith("/stats")
          ? { body: { data: { total: 1, delivered: 1, bounced: 0, complained: 0, opened: 0, clicked: 0 } } }
          : { body: { data: [{ timestamp: "2026-08-29T00:00:00Z", count: 1, event_type: "delivered" }] } },
      async (client, stub) => {
        const stats = await client.events.stats({ from: "2026-08-01", to: "2026-08-31" });
        assert.equal(request(stub).path, "/v1/events/stats");
        assert.equal(request(stub).query.get("from"), "2026-08-01");
        assert.equal(stats.total, 1);
        const series = await client.events.timeseries({ from: "2026-08-01" });
        assert.equal(request(stub).path, "/v1/events/timeseries");
        assert.equal(series[0].count, 1);
      },
    );
  });
});

describe("analytics resource", () => {
  test("typed methods hit the real subpaths with {from, to, interval}", async () => {
    await withClient(
      () => ({ body: { data: {} } }),
      async (client, stub) => {
        await client.analytics.dashboard({ from: "2026-01-01", to: "2026-02-01" });
        assert.deepEqual(
          [request(stub).method, request(stub).path, request(stub).query.toString()],
          ["GET", "/v1/analytics/dashboard", "from=2026-01-01&to=2026-02-01"],
        );
        await client.analytics.volume({ interval: "week" });
        assert.equal(request(stub).path, "/v1/analytics/volume");
        assert.equal(request(stub).query.get("interval"), "week");
        await client.analytics.engagement();
        assert.equal(request(stub).path, "/v1/analytics/engagement");
        assert.equal(request(stub).url, "/v1/analytics/engagement");
        await client.analytics.deliverability();
        assert.equal(request(stub).path, "/v1/analytics/deliverability");
      },
    );
  });

  test("analyzeSubjectLine posts {subject}", async () => {
    await withClient(
      () => ({ body: { data: {} } }),
      async (client, stub) => {
        await client.analytics.analyzeSubjectLine("Open me");
        assert.equal(request(stub).method, "POST");
        assert.equal(request(stub).path, "/v1/analytics/subject-line");
        assert.deepEqual(request(stub).json, { subject: "Open me" });
      },
    );
  });

  test("export defaults format=json; interval is validated", async () => {
    await withClient(
      () => ({ body: { data: {} } }),
      async (client, stub) => {
        await client.analytics.export({ from: "2026-01-01" });
        assert.equal(request(stub).path, "/v1/analytics/export");
        assert.equal(request(stub).query.get("format"), "json");
        await assert.rejects(client.analytics.volume({ interval: "fortnight" }), ValidationError);
      },
    );
  });

  test("get() is a deprecated alias of dashboard()", async () => {
    await withClient(
      () => ({ body: { data: {} } }),
      async (client, stub) => {
        const { warnings } = await captureWarnings(() =>
          client.analytics.get({ from: "2026-01-01", to: "2026-02-01", groupBy: "day" }),
        );
        assert.equal(warnings.length, 1);
        assert.match(warnings[0], /analytics\.get\(\) is deprecated/);
        assert.equal(request(stub).path, "/v1/analytics/dashboard");
        assert.equal(request(stub).query.get("interval"), "day");
      },
    );
  });
});

describe("api keys resource", () => {
  test("create sends {name, scopes} and only includes expires_in_days when asked", async () => {
    await withClient(
      () => ({ body: { data: { id: "key_1", key: "am_live_..." } } }),
      async (client, stub) => {
        await client.apiKeys.create({ name: "Production Backend", scopes: ["messages:write"] });
        assert.deepEqual(request(stub).json, { name: "Production Backend", scopes: ["messages:write"] });
        await client.apiKeys.create({
          name: "Temp",
          expiresInDays: 30,
          expiresAt: "2027-02-09T00:00:00Z", // legacy: ignored on the wire
        });
        assert.deepEqual(request(stub).json, { name: "Temp", scopes: [], expires_in_days: 30 });
      },
    );
  });

  test("list forwards limit/offset defaults and refuses cursor", async () => {
    await withClient(
      () => ({ body: { data: [{ id: "key_1" }] } }),
      async (client, stub) => {
        const keys = await client.apiKeys.list();
        assert.equal(request(stub).query.get("limit"), "50");
        assert.equal(request(stub).query.get("offset"), "0");
        assert.equal(keys[0].id, "key_1");
        await assert.rejects(client.apiKeys.list({ cursor: "cur_1" }), ValidationError);
      },
    );
  });

  test("revoke escapes the key id path segment", async () => {
    await withClient(
      () => ({ status: 204 }),
      async (client, stub) => {
        await client.apiKeys.revoke("key/1");
        assert.equal(request(stub).method, "DELETE");
        assert.equal(request(stub).path, "/v1/auth/api-keys/key%2F1");
      },
    );
  });
});

describe("emails resource read paths", () => {
  test("list sends limit/offset defaults and surfaces meta pagination", async () => {
    await withClient(
      () => ({
        body: {
          data: [{ id: "msg_1", from: "a@example.com", to: ["b@example.com"], subject: "s", status: "sent", created_at: "x" }],
          meta: { hasMore: true, nextCursor: "cur_2" },
        },
      }),
      async (client, stub) => {
        const page = await client.emails.list({ status: "sent", sortBy: "created_at" });
        const { query } = request(stub);
        assert.equal(query.get("limit"), "25");
        assert.equal(query.get("offset"), "0");
        assert.equal(query.get("status"), "sent");
        assert.equal(query.get("sort_by"), "created_at");
        assert.equal(page.emails.length, 1);
        assert.equal(page.cursor, "cur_2");
        assert.equal(page.has_more, true);
      },
    );
  });

  test("get tolerates the legacy {email: ...} wrapper and validates ids", async () => {
    await withClient(
      () => ({ body: { data: { email: { id: "msg_1", subject: "s" } } } }),
      async (client, stub) => {
        const email = await client.emails.get("msg_1");
        assert.equal(email.id, "msg_1");
        assert.equal(request(stub).path, "/v1/messages/msg_1");
        await assert.rejects(client.emails.get("bad id!"), ValidationError);
      },
    );
  });

  test("cancel posts to the cancel route", async () => {
    await withClient(
      () => ({ body: { data: { id: "msg_1", status: "cancelled", created_at: "x" } } }),
      async (client, stub) => {
        const result = await client.emails.cancel("msg_1");
        assert.equal(request(stub).method, "POST");
        assert.equal(request(stub).path, "/v1/messages/msg_1/cancel");
        assert.equal(result.status, "cancelled");
      },
    );
  });
});
