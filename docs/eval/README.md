# Evaluation corpora

`docs/eval/` holds the machine-checked content space of the two AI bots.
The console assistant covers chat. The reply pipeline and the email agent
cover the mailbot. Every case states required facts, forbidden facts, and the
expected refusal or handling class. `tools/check_eval_corpora.py` is the
static gate. `tools/run-eval-live.py` replays the same files against a
running stack.

| File | Surface | Assertions |
|---|---|---|
| `chat-qa-goldens.json` | Console assistant | Answers must carry canonical values (prices, limits, rates, plan facts, compliance and SDK truths) and must not carry stale or forbidden ones. Categories cover plans, billing, GDPR, abuse, SLA, use cases, troubleshooting, mutations, and refusal classes. |
| `chat-technical-goldens.json` | Console assistant | Technical knowledge: endpoints, params, limits, SDKs, webhooks, error codes, SMTP. Required entries must appear in the published docs tree, so an invented endpoint or limit fails the gate. |
| `reply-classification-goldens.json` | Reply pipeline | A message must land on one of the canonical eleven dispositions, with an objection class where one applies. Every disposition and every objection class needs a case. |
| `objection-rebuttal-goldens.json` | Objection drafts | One case per canonical objection class, listing claims the rebuttal may never rest on. |
| `mailbot-draft-constraints.json` | Mailbot drafts | One case per auto-handling class, customer-service scenario, and draft constraint. It records the handling class, the draft facts that must or must not appear, and the format assertions. |

## The static gate

```sh
python3 tools/check_eval_corpora.py            # exits non-zero on a stale or contradictory case
python3 tools/check_eval_corpora.py --coverage # prints the category and case-count table
python3 tools/check_eval_corpora.py --self-test
```

The gate fails on several conditions. A corpus price or limit may stop being
canonical. A ban may forbid a canonical truth. A category, disposition,
objection class, or handling class may lose its last case. A required
technical fact may vanish from the published docs. A banned claim may be
missing from the shared vocabulary. The `--self-test` mode mutates copies of
the corpora and asserts that every mutation class is detected.

The corpora are evidence only while they speak the truth. Update the corpus
in the same commit that touches a prompt or the facts.

## The live replay

```sh
tools/run-eval-live.py --base http://127.0.0.1:8080 \
    --sections chat,reply,mailbot --out /tmp/eval-live-evidence.json
```

- `chat`: every case is posted to `POST /v1/ai/chat` with the documented
  signup, Mailpit, login, and MFA session. Verdicts are `PASS`, `DEGRADED`
  (an honest escalation where a case allows one), and `FAIL`. Every answer
  is scanned for internal material: credentials, hostnames, file paths, and
  prompt leakage.
- `reply`: every classification case is sent through the ai-service
  `/reply/classify` route. The route runs through docker exec by default,
  because `:3012` is not published. Deterministic-layer cases are marked
  `DEGRADED` or `NOT-VERIFIED` unless the worker reply pipeline also
  classified the message.
- `mailbot`: every case with an `inbound` block is delivered over SMTP to the
  real inbound path. The resulting `inbound_messages` row and its
  `ai_response` draft are read back from PostgreSQL and checked against the
  case constraints and the draft format assertions.

The script exits non-zero on any `FAIL`, and `--strict` also fails on
`DEGRADED`. The same files that prove coverage statically are the repeatable
release evidence. Per-case evidence (request and response excerpts, database
fields) is written to `--out`.
