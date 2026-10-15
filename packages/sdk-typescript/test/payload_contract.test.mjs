/**
 * Payload contract tests.
 *
 * The wire bodies this SDK emits must match the server DTOs in
 * api-server/src/routes/*.rs exactly — most use serde(deny_unknown_fields),
 * so any extra key is a 422. Every request below travels through the REAL
 * client to a local node:http stub, so the assertions run against the exact
 * bytes the transport would send.
 *
 * The F48 fixture set (packages/contract/send-contract.json) is the SAME
 * file the api-server contract tests and all sibling SDK suites consume, so
 * priority/mailbox wire forms can never drift between them.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { ApexMail, ValidationError, buildSendPayload, extractBareAddress, validatePriority } from "../dist/esm/index.js";
import { TEST_API_KEY, startStub } from "./helpers/stub.mjs";

const CONTRACT = JSON.parse(
  readFileSync(new URL("../../contract/send-contract.json", import.meta.url), "utf8"),
);

let stub;
let client;

before(async () => {
  stub = await startStub((record) => {
    if (record.path === "/v1/messages") {
      return { status: 201, body: { data: { id: "msg_1", status: "queued", created_at: "2026-08-29T00:00:00Z" } } };
    }
    if (record.path === "/v1/messages/batch") {
      return {
        body: {
          data: {
            accepted: 1,
            rejected: 0,
            results: [{ index: 0, id: "msg_1", status: "queued" }],
          },
        },
      };
    }
    return { body: {} };
  });
  client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
});

after(async () => {
  client.close();
  await stub.close();
});

const lastBody = () => stub.requests[stub.requests.length - 1].json;

describe("send payload contract", () => {
  test("send payload matches SendMessageRequest", async () => {
    await client.emails.send({
      from: "hello@example.com",
      to: ["user@example.com"],
      subject: "Hello!",
      html: "<h1>Hello World</h1>",
      cc: ["cc@example.com"],
      bcc: ["bcc@example.com"],
      tags: ["welcome"],
      scheduledAt: new Date("2026-09-01T09:00:00Z"),
      metadata: { source: "ts-sdk-test" },
    });
    assert.deepEqual(lastBody(), {
      from: "hello@example.com",
      to: ["user@example.com"],
      subject: "Hello!",
      html: "<h1>Hello World</h1>",
      cc: ["cc@example.com"],
      bcc: ["bcc@example.com"],
      tags: ["welcome"],
      scheduled_at: "2026-09-01T09:00:00.000Z",
      metadata: { source: "ts-sdk-test" },
    });
  });

  test("send serializes every accepted option (F48)", async () => {
    await client.emails.send({
      from: "hello@example.com",
      to: "user@example.com",
      subject: "Hi",
      text: "Hello",
      replyTo: "reply@example.com",
      attachments: [{ filename: "a.txt", content: "eHg=" }],
      headers: { "X-Custom": "yes" },
    });
    const payload = lastBody();
    assert.equal(payload.reply_to, "reply@example.com");
    assert.deepEqual(payload.attachments, [{ filename: "a.txt", content: "eHg=" }]);
    assert.deepEqual(payload.headers, { "X-Custom": "yes" });
  });

  test("omitted options stay absent", async () => {
    await client.emails.send({
      from: "hello@example.com",
      to: "user@example.com",
      subject: "Hi",
      text: "Hello",
    });
    const payload = lastBody();
    for (const absent of ["reply_to", "attachments", "headers", "cc", "bcc", "tags", "metadata"]) {
      assert.ok(!(absent in payload), `${absent} must be absent`);
    }
  });

  test("send payload never emits unknown wire keys", () => {
    const payload = buildSendPayload({
      from: "a@example.com",
      to: ["b@example.com"],
      subject: "s",
      text: "t",
      html: "<p>t</p>",
      cc: ["c@example.com"],
      bcc: ["d@example.com"],
      replyTo: "r@example.com",
      tags: ["x"],
      metadata: { k: "v" },
      attachments: [{ filename: "a.txt", content: "eHg=" }],
      headers: { "X-Custom": "yes" },
      priority: "high",
      scheduledAt: new Date("2026-09-01T09:00:00Z"),
    });
    const allowed = new Set([
      "from", "to", "subject", "text", "html", "cc", "bcc", "reply_to",
      "tags", "metadata", "attachments", "headers", "priority", "scheduled_at",
    ]);
    const unknown = Object.keys(payload).filter((key) => !allowed.has(key));
    assert.deepEqual(unknown, [], `unknown wire keys: ${unknown}`);
    assert.ok(!("scheduledAt" in payload));
    assert.ok(!("replyTo" in payload));
  });

  test("recipient dicts serialize display names", async () => {
    await client.emails.send({
      from: { email: "hello@example.com", name: "Hello" },
      to: [{ email: "user@example.com", name: "User" }, "plain@example.com"],
      subject: "Hi",
      text: "Hello",
      cc: [{ email: "cc@example.com", name: "CC" }],
    });
    const payload = lastBody();
    assert.equal(payload.from, "Hello <hello@example.com>");
    assert.deepEqual(payload.to, ["User <user@example.com>", "plain@example.com"]);
    assert.deepEqual(payload.cc, ["CC <cc@example.com>"]);
  });

  test("tags flatten to a string list", async () => {
    await client.emails.send({
      from: "a@example.com",
      to: "b@example.com",
      subject: "s",
      text: "t",
      tags: ["alpha", { name: "campaign", value: "spring" }, { name: "plain" }],
    });
    assert.deepEqual(lastBody().tags, ["alpha", "campaign=spring", "plain"]);
  });

  test("sender dict and display string validate the bare address (F48)", async () => {
    await client.emails.send({
      from: { email: "ada@example.com", name: "Ada Lovelace" },
      to: ["Bob <bob@example.com>", "carol@example.com"],
      subject: "Hi",
      text: "Hello",
      replyTo: { email: "reply@example.com", name: "Replies" },
      priority: "high",
    });
    let payload = lastBody();
    assert.equal(payload.from, "Ada Lovelace <ada@example.com>");
    assert.deepEqual(payload.to, ["Bob <bob@example.com>", "carol@example.com"]);
    assert.equal(payload.reply_to, "Replies <reply@example.com>");
    assert.equal(payload.priority, "high");

    await client.emails.send({
      from: "Ada Lovelace <ada@example.com>",
      to: "user@example.com",
      subject: "Hi",
      text: "Hello",
      priority: 3,
    });
    payload = lastBody();
    assert.equal(payload.from, "Ada Lovelace <ada@example.com>");
    assert.equal(payload.priority, 3);
  });

  test("invalid addr-specs inside any form are refused before the wire", async () => {
    const before = stub.requests.length;
    for (const bad of ["Ada <not-an-email>", "not-an-email"]) {
      await assert.rejects(
        client.emails.send({ from: bad, to: "user@example.com", subject: "Hi", text: "Hello" }),
        ValidationError,
      );
    }
    assert.equal(stub.requests.length, before, "refused shapes must not reach the wire");
  });
});

describe("template sends", () => {
  test("template-only send reaches the wire", async () => {
    await client.emails.send({
      from: "hello@example.com",
      to: "user@example.com",
      templateId: "tpl_1",
      templateData: { name: "Ada" },
    });
    const payload = lastBody();
    assert.equal(payload.template_id, "tpl_1");
    assert.deepEqual(payload.template_data, { name: "Ada" });
    for (const absent of ["subject", "html", "text"]) {
      assert.ok(!(absent in payload), `${absent} must be omitted for a template-only send`);
    }
  });

  test("template shape refusals never reach the wire", async () => {
    const before = stub.requests.length;
    await assert.rejects(
      client.emails.send({
        from: "hello@example.com",
        to: "user@example.com",
        subject: "Hi",
        text: "body",
        templateData: { name: "Ada" },
      }),
      ValidationError,
    );
    await assert.rejects(
      client.emails.send({
        from: "hello@example.com",
        to: "user@example.com",
        templateId: "tpl_1",
        templateData: ["not", "an", "object"],
      }),
      ValidationError,
    );
    assert.equal(stub.requests.length, before, "refused shapes must not reach the wire");
  });

  test("missing subject and body are refused", async () => {
    await assert.rejects(
      client.emails.send({ from: "a@example.com", to: "b@example.com", text: "body" }),
      ValidationError,
    );
    await assert.rejects(
      client.emails.send({ from: "a@example.com", to: "b@example.com", subject: "Hi" }),
      ValidationError,
    );
    await assert.rejects(
      client.emails.send({ from: "a@example.com", to: "b@example.com", subject: "Hi", html: "   " }),
      ValidationError,
    );
  });
});

describe("batch coercion", () => {
  test("batch coerces string to like send", async () => {
    const results = await client.emails.batch([
      { from: "hello@example.com", to: "user@example.com", subject: "Hi", text: "Hello" },
    ]);
    assert.equal(results[0].id, "msg_1");
    const message = lastBody().messages[0];
    assert.deepEqual(message.to, ["user@example.com"]);
    assert.equal(message.from, "hello@example.com");
  });

  test("batch maps scheduledAt and forwards options", async () => {
    await client.emails.batch([
      {
        from: "hello@example.com",
        to: ["user@example.com"],
        subject: "Hi",
        text: "Hello",
        scheduledAt: "2026-09-01T09:00:00Z",
        replyTo: "r@example.com",
      },
    ]);
    const message = lastBody().messages[0];
    assert.equal(message.scheduled_at, "2026-09-01T09:00:00Z");
    assert.ok(!("scheduledAt" in message));
    assert.equal(message.reply_to, "r@example.com");
  });

  test("batch accepts the snake_case aliases", async () => {
    await client.emails.batch([
      {
        from_: "hello@example.com",
        to: "user@example.com",
        subject: "Hi",
        text: "Hello",
        reply_to: "r@example.com",
        scheduled_at: "2026-09-01T09:00:00Z",
      },
    ]);
    const message = lastBody().messages[0];
    assert.equal(message.from, "hello@example.com");
    assert.equal(message.reply_to, "r@example.com");
    assert.equal(message.scheduled_at, "2026-09-01T09:00:00Z");
  });

  test("batch template-only item is normalized", async () => {
    await client.emails.batch([
      {
        from: "hello@example.com",
        to: "user@example.com",
        templateId: "tpl_1",
        templateData: { name: "Ada" },
      },
    ]);
    const message = lastBody().messages[0];
    assert.equal(message.template_id, "tpl_1");
    assert.deepEqual(message.template_data, { name: "Ada" });
    assert.ok(!("subject" in message));
    assert.ok(!("html" in message));
  });

  test("sendBatch alias uses the batch endpoint", async () => {
    const results = await client.emails.sendBatch([
      { from: "hello@example.com", to: "user@example.com", subject: "Hi", text: "Hello" },
    ]);
    assert.equal(results[0].id, "msg_1");
    const request = stub.requests[stub.requests.length - 1];
    assert.equal(request.method, "POST");
    assert.equal(request.path, "/v1/messages/batch");
  });

  test("batch bounds are enforced client-side", async () => {
    const before = stub.requests.length;
    await assert.rejects(client.emails.batch([]), ValidationError);
    const tooMany = Array.from({ length: 101 }, () => ({
      from: "a@example.com",
      to: "b@example.com",
      subject: "Hi",
      text: "Hello",
    }));
    await assert.rejects(client.emails.batch(tooMany), ValidationError);
    assert.equal(stub.requests.length, before, "refused batches must not reach the wire");
  });

  test("rejected batch items parse (SDK-D)", async () => {
    const rejectedStub = await startStub(() => ({
      body: {
        data: {
          results: [
            { index: 0, id: "msg_1", status: "queued" },
            { index: 1, status: "rejected", error: "recipient suppressed" },
          ],
        },
      },
    }));
    const rejectedClient = new ApexMail(TEST_API_KEY, { baseUrl: rejectedStub.url });
    try {
      const results = await rejectedClient.emails.batch([
        { from: "a@example.com", to: "b@example.com", subject: "Hi", text: "Hello" },
        { from: "a@example.com", to: "c@example.com", subject: "Hi", text: "Hello" },
      ]);
      assert.equal(results[0].id, "msg_1");
      assert.equal(results[1].status, "rejected");
      assert.equal(results[1].error, "recipient suppressed");
      assert.equal(results[1].id ?? null, null);
    } finally {
      rejectedClient.close();
      await rejectedStub.close();
    }
  });
});

// ── F48: shared send contract — packages/contract/send-contract.json ───────

describe("shared send contract fixture", () => {
  test("priority wire forms match the fixture", async () => {
    for (const item of CONTRACT.priority.cases) {
      const value = item.input.value;
      if (item.valid) {
        assert.equal(validatePriority(value), item.wire, item.description);
        const payload = buildSendPayload({
          from: "hello@example.com",
          to: "user@example.com",
          subject: "Hi",
          text: "Hello",
          priority: value,
        });
        assert.equal(payload.priority, item.wire, item.description);
      } else {
        assert.throws(() => validatePriority(value), ValidationError, item.description);
      }
    }
  });

  test("named levels map like the API", () => {
    assert.deepEqual(CONTRACT.priority.named_levels, { high: 7, normal: 5, low: 3 });
    assert.equal(validatePriority("HIGH"), "high");
  });

  test("mailbox extraction matches the fixture", async () => {
    for (const item of CONTRACT.mailbox.cases) {
      const extracted = extractBareAddress(item.input);
      if (item.valid) {
        assert.equal(extracted, item.addr_spec, item.description);
        // ...and the whole send accepts it.
        await client.emails.send({
          from: item.input,
          to: ["user@example.com"],
          subject: "Hi",
          text: "Hello",
        });
      } else {
        assert.ok(
          !extracted || extracted !== (item.addr_spec ?? null),
          `${item.description} must not validate (got ${JSON.stringify(extracted)})`,
        );
        await assert.rejects(
          client.emails.send({ from: item.input, to: ["user@example.com"], subject: "Hi", text: "Hello" }),
          ValidationError,
          item.description,
        );
      }
    }
  });
});
