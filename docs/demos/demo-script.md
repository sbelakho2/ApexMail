# Demo script and presenter guide

This guide covers the server-driven demo: what it runs, how to present it, and
what each step proves. The script itself lives in code
(`crates/api-server/src/routes/demos/script.rs`) so the walkthrough cannot drift
from the product; this page is the long-form companion.

## How a demo runs

1. Open the control plane and go to Demos.
2. Choose a script and create a session. The viewer link is shown once: it is
   stored hashed, so copy it before leaving the page.
3. Share the link with the prospect. They can follow along as you work.
4. Press "Run next step" to advance. Each step executes real machinery and its
   result appears on the viewer page within a refresh.
5. When the last step runs, the session completes and the link becomes a
   replay of every step and result.

Links expire after 48 hours. Create a new session for a new call.

## The platform tour, step by step

The tour is deliberate in its order: see the product, do the thing, verify it,
price it, ask it.

| Step | Kind | What it proves |
|---|---|---|
| The console you would use every day | `render_page` | The dashboard is the live product render, not a screenshot |
| Campaigns live in the same console | `render_page` | Campaigns are part of the same workspace |
| Send a real message through the sandbox API | `explorer_exec` | The API accepts a real request and answers with its real status |
| See the message the platform just accepted | `explorer_exec` | The message is visible in the account that sent it |
| Register a sending domain | `explorer_exec` | Domain onboarding is a working API, not a form mock |
| Grade the deliverability of a domain | `grader` | The grader runs the same engine customers use |
| Price a volume on the public plan catalog | `calculator` | Pricing comes from the billing catalog, never a slide |
| Ask the grounded assistant what is included | `chat_narrate` | Answers are verified against published documentation |

## Presenter notes

- Every step executes against the sandbox tenant under `example.com`, so a
  demo can never touch a customer's data or attempt real external delivery.
- The narration step is the product's own verifier-gated answer. If the
  assistant escalates, the page shows the escalation notice: that is the
  honest outcome and worth saying out loud rather than hiding.
- If a lane fails, the step records the failure verbatim. Do not talk past it:
  the platform's own answer is the demo's integrity.
- The pricing step reads the same catalog billing charges. If a number differs
  from a slide deck, the deck is wrong.

## Maintenance

Adding a step means adding it to the script in code, running the demo, and
updating the table above. The script's own tests enforce that every step kind
is executable and that the tour exercises every kind, so a step cannot
silently rot.
