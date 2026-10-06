# Evaluation corpora

Three small corpora that make the AI surfaces testable against the canonical
facts. They are JSON so the same files can be fed to the ai-service evaluation
endpoint (`POST /evaluate` with the AI-admin token) after a model or prompt
change, and asserted in tests.

| File | Surface | What a case asserts |
|---|---|---|
| `chat-qa-goldens.json` | Console assistant | A question whose answer must contain specific canonical values and must not contain stale ones |
| `reply-classification-goldens.json` | Reply classifier | A message that must land on a disposition, with an objection class where one applies |
| `objection-rebuttal-goldens.json` | Objection drafts | An objection class whose rebuttal may only rest on library guidance or canonical facts, plus claims that must never appear |

## How to use them

1. Update the corpus in the same change that changes a prompt or the facts.
2. Run the assistant, the classifier and a draft through the surfaces.
3. Score each case: `must_contain` present, `must_not_contain` absent,
   disposition and objection class matched.
4. Record the results as release evidence.

The corpora are deliberately small and hand-checked. Their value is that a
stale price or an invented claim fails a case, not that they cover every
phrasing.
