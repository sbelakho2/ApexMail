# AI draft review

This page is the operator runbook for the AI draft queue: what lands there,
how to review it, and what each decision does.

## What lands in the queue

The mailbot drafts a reply when an inbound message needs one. A draft appears
here when:

- an inbound message was answered by the assistant and needs human approval,
- a lead arrived through the contact form and a first response was drafted,
- the assistant could not verify an answer and left a human-review note
  instead.

The queue lives at AI Drafts in the control plane. Nothing in it has been
sent: drafts are held until a person decides.

## Reviewing a draft

Each row shows the subject, the sender, the workspace, the classification and
an objection class when the classifier recorded one. First-response drafts
carry a marker so the SLA-relevant ones are recognisable.

Open the draft reply to read the full text. The draft quotes the original
message, so tone and context are visible in one place.

## Deciding

Approve queues the reply through the platform sender and closes the draft.
The transaction also closes the first-response request and records the
enqueue instant, which feeds the latency metric.

Reject closes the draft without sending anything and records the reason against
the operator who decided.

A draft that a colleague already handled is reported as already handled. Two
operators cannot both decide the same draft: the claim is transactional.

## When something looks wrong

- Same draft appears twice: it will not. The queue lists pending drafts only,
  and a decision consumes the row.
- The reply claims something you cannot verify: reject it and note why. The
  verifier should have caught it, so the note is evidence for a regression.
- The queue is empty but you expected work: check that the mailbot is enabled
  and that the model runtime is configured. An assistant that cannot generate
  answers declines to human review instead of guessing, and declines are
  visible on the message rather than here.
- The queue itself will not load: the page says the queue is unavailable. That
  is a service problem, not an empty queue.

## Related

- First-response SLO: `docs/operations/first-response-slo.md`
- Assistant behaviour: `docs/user-guide/assistant.md`
