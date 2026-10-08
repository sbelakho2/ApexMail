# Console Assistant

The console assistant answers questions about your workspace from the
published ApexMail documentation: pricing, plans, deliverability, domains,
compliance and the API. It lives at `/assistant` in the console's Account
navigation.

## What it can answer

- Plan catalogue questions (prices, included volume, retention, team size).
- Deliverability setup: SPF, DKIM and DMARC, and where your exact DNS
  records are published.
- API and SDK availability, webhook behaviour, and account status facts
  (your current plan, verified domains, sending volume) read at request
  time.

Answers cite the documentation they came from. Citations appear under each
answer and expand in place.

## Grounding and escalation

The assistant is grounded: it is instructed to state only what the canonical
product facts and the published documentation support, and a verifier checks
every factual sentence against those sources before the answer is shown. It
never invents prices, features, dates or commitments.

When a question cannot be answered from the verified sources, the answer is
escalated to a human instead of guessed. Escalated answers carry a notice
with the support address. This is the same escalation path used elsewhere in
the product.

## Conversations and retention

Conversations are stored server-side, per user, and the console shows your
most recent session. Each message posts through a normal form submission, so
the page works without JavaScript.

Conversation history is retained for the retention window configured for the
deployment (90 days by default, `AI_CHAT_RETENTION_DAYS`). Sessions older
than the window are dropped. Account facts shown to the model are read at
request time and are not copied into the conversation.

Conversations are visible only to the user they belong to, within their
workspace. A session cannot be read or continued by another user or another
workspace.

## Availability

When the assistant is switched off for a workspace, the page reports that the
capability is not enabled. When the model runtime is not configured, answers
are escalated to a human instead of generated. When the conversation store
cannot be read, the page says so explicitly, so an outage is never mistaken
for an empty conversation.

Per-user and per-tenant rate limits apply. After a burst of questions the
assistant asks you to retry shortly.

## Privacy

The assistant sends your question, the conversation history for the current
session, and read-only account facts (plan, limits, recent volume, verified
domains) to the model runtime. Answers and citations are stored with the
conversation. No other workspace data is sent, and the assistant cannot
change anything in your workspace.

If your message asks us to contact you and includes an email address, that
address and the message are passed to our sales team as a contact request.
The request is recorded for a human follow-up only: no email is sent to you
by that path, and nothing is added to your contacts.

The assistant is AI-powered. Answers are informational and do not constitute
legal, tax or compliance advice.
