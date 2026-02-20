# LLM — AI Chatbot & Inference Runtime Playbook

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** LLM inference engine, model lifecycle, embeddings/RAG, unified assistant, content generation, and all runtime issues tied to the AI subsystem.
> **Intent Class:** `LLM.*` — 11 leaf intents
> **Last Updated:** 2026-02-17

---

## Reference: AI Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  apps/ai/src/                                                   │
│  ├── inference/                                                 │
│  │   ├── engine.ts        llama.cpp sidecar, Qwen 3-8B (GGUF)  │
│  │   ├── lifecycle.ts     State machine, circuit breaker, queue │
│  │   └── embeddings.ts    MiniLM-L6-v2, vector store, chunking │
│  ├── assistant/                                                 │
│  │   └── unified.ts       Conversational agent, 20+ actions    │
│  └── content/                                                   │
│      └── generator.ts     Subject lines, CTAs, email body gen  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Constants Quick Reference

| Constant | Value | Source |
|----------|-------|--------|
| Context length | 8 192 tokens | `engine.ts` |
| Max output tokens | 768 tokens | `engine.ts` |
| Model | Qwen 3-8B (GGUF via llama.cpp sidecar) | `engine.ts` |
| Embedding model | all-MiniLM-L6-v2 | `embeddings.ts` |
| Embedding dimensions | 384 | `embeddings.ts` |
| Max embed input tokens | 512 | `embeddings.ts` |
| Inference queue size | 100 | `lifecycle.ts` |
| Inference request timeout | 30 000 ms | `lifecycle.ts` |
| Max concurrent inference | 5 | `lifecycle.ts` |
| Circuit breaker threshold | 5 failures | `lifecycle.ts` |
| Circuit breaker reset | 30 000 ms | `lifecycle.ts` |
| Model load timeout | 60 000 ms | `lifecycle.ts` |
| Session TTL | 30 min | `unified.ts` |
| Max sessions | 1 000 | `unified.ts` |
| Rate limit | 30 msgs / 60 s | `unified.ts` |
| Confidence threshold (auto mode) | 0.70 | `unified.ts` |

---

## LLM.CONTEXT.TOO_LONG — "Input exceeds the model's context window"

**Symptoms:** User submits a long conversation or document and gets a truncation warning or degraded response quality. May see internal error referencing context length.

**Root cause:** Total prompt + history + system instructions exceed 8 192 tokens (Qwen 3-8B context length).

**Resolution:**

1. **How context is managed:**
   - System prompt consumes ~300–500 tokens.
   - Conversation history is capped at `maxHistoryLength = 20` messages (`unified.ts`).
   - `maxContextTokens = 2 048` reserved for assistant context window.
   - Remaining budget ≈ 8 192 − system − context = ~5 600 tokens for user input + history.

2. **Automatic mitigation built in:**
   - Oldest messages are pruned when history exceeds 20 entries.
   - If the prompt still exceeds the window, the engine truncates from the beginning of the conversation.

3. **Troubleshooting steps:**
   - **Reduce history:** Start a new session (`POST /v1/ai/sessions`) to reset conversation state.
   - **Shorter input:** If pasting large email templates or logs, extract the relevant section.
   - **Chunk large documents:** For RAG ingestion, the `TextChunker` automatically splits at `chunkSize = 500 chars` with `chunkOverlap = 50 chars`.

4. **Configuration tuning (admin):**
   - Increase `contextLength` only if running a quantized model that fits in available RAM.
   - Reduce `maxHistoryLength` to give more room for long single-turn inputs.

5. **Monitoring:**
   ```
   metric: ai_tokens_processed_total
   metric: ai_request_count
   ```
   If `tokens_processed` per request approaches 8 192 consistently, context overflow is likely.

---

## LLM.TOKENS.MAX_OUTPUT_EXCEEDED — "Response is cut off / incomplete output"

**Symptoms:** The AI's response ends abruptly mid-sentence. User sees partial answers.

**Root cause:** Generation hit the `maxTokens = 768` limit before producing a stop sequence (`<|im_end|>` or `<|endoftext|>`).

**Resolution:**

1. **Verify truncation vs. error:**
   - Truncated responses still return HTTP 200 with the partial text.
   - Check if the response ends with a stop sequence — if not, it was truncated.

2. **Workarounds:**
   - Ask the assistant to "continue" — it will generate the next chunk from where it stopped.
   - Ask for a "concise" or "summarized" version to fit within limits.
   - Break complex requests into smaller sub-questions.

3. **Configuration (admin):**
   - `maxTokens` can be increased but will proportionally increase latency.
   - Total `contextLength` (8 192) is shared between input + output. Increasing `maxTokens` reduces available input space.

4. **Content generator**: Uses `temperature = 0.8` (higher for creativity). Subject lines are capped at 60 chars, preheaders at 100 chars — these won't hit token limits.

---

## LLM.STREAM.INTERRUPTED — "Streaming response stops mid-way / connection drops"

**Symptoms:** SSE or streaming response starts, then drops. Client receives partial tokens.

**Root cause possibilities:**
- Network timeout (reverse proxy, load balancer, or client-side)
- Inference request timeout (30 000 ms per request in the queue)
- Circuit breaker opened mid-stream
- Server restart during generation

**Resolution:**

1. **Check inference queue timeout:**
   - Default `timeoutMs = 30 000 ms`. If generation takes longer, request is terminated with `Request timeout`.
   - For complex prompts, 30 s may be insufficient on CPU-only inference.

2. **Check circuit breaker state:**
   ```
   GET /v1/ai/health
   ```
   Response includes `circuitBreaker.state` — should be `closed`. If `open`, the breaker tripped after 5 consecutive failures and will auto-attempt `half-open` after 30 s.

3. **Reverse proxy timeouts:**
   - **Nginx:** `proxy_read_timeout` must be ≥ expected generation time (recommend 120 s for streaming).
   - **Cloudflare:** Free plan has 100 s timeout; Enterprise has configurable.
   - Add `X-Accel-Buffering: no` header for SSE streams.

4. **Client-side:**
   - EventSource API auto-reconnects — ensure client handles reconnection.
   - If using `fetch()` with `ReadableStream`, implement a retry with exponential backoff.

5. **Recovery:**
   - Circuit breaker auto-recovers: after `resetTimeoutMs = 30 000 ms`, it enters `half-open` and allows 1 request through. After 3 consecutive successes (`halfOpenSuccessThreshold = 3`), it closes.
   - Manual reset: call `circuitBreaker.reset()` in admin console.

---

## LLM.HALLUCINATION.RISK_MISSING_EVIDENCE — "AI gave an incorrect / unsupported answer"

**Symptoms:** The assistant provides factually wrong information, cites non-existent features, or gives advice inconsistent with ApexMail's actual capabilities.

**Root cause:** Language models generate plausible-sounding text without grounding in verified facts. Risk increases with:
- High temperature (0.7 default, 0.8 for content generation)
- No RAG context retrieved
- Ambiguous or open-ended questions
- Questions about features that don't exist

**Resolution:**

1. **Built-in mitigations:**
   - **Model output validation** (`isModelOutputUsable`): For `knowledge` intents, requires ≥ 30 chars, > 70% real English words, ≥ 6 real-word tokens. Below threshold → falls back to template responses.
   - **Greeting validation:** ≥ 4 tokens, > 70% real words.
   - **Command/billing/domain intents:** Must contain a structured action block — pure prose is rejected.
   - **Confidence scoring:** If no intent pattern matches, confidence = 0.3 (well below auto-approve threshold of 0.7) → triggers escalation.

2. **Reduce hallucination risk:**
   - **Lower temperature:** `temperature = 0.3–0.5` for factual queries (trade-off: less creative content generation).
   - **Enable RAG:** Ensure the vector store is populated with product documentation, FAQ, and knowledge base articles.
   - **Narrower system prompt:** Explicitly instruct the model to say "I don't know" when uncertain.

3. **Verification flow:**
   - The assistant has an `always-escalate` list for high-risk actions (`cancel_subscription`, `process_refund`, `delete_campaign`, etc.) — these actions always require human confirmation regardless of confidence.
   - Critical/high risk actions require explicit user confirmation before execution.

4. **Reporting hallucinations:**
   - Collect the session ID and message ID.
   - Log as a quality issue — the training/fine-tuning team uses these to improve the system prompt and RAG index.

---

## LLM.ROUTER.CONFIDENCE_LOW — "Intent classification confidence is too low / wrong intent detected"

**Symptoms:** The assistant misunderstands what the user wants, routes to the wrong action, or says "I'm not sure what you're asking."

**Root cause:** Intent detection confidence fell below the action threshold. Confidence scoring:

| Scenario | Confidence |
|----------|-----------|
| Strong pattern match (e.g., "send campaign to list X") | 0.50–0.95 (proportional to match length) |
| Domain expiration concern | 0.85 |
| Quota/limit concern | 0.80 |
| Escalation request ("talk to human") | 0.90 |
| Knowledge question ("how do I…") | 0.65 |
| Negated action ("don't send") | 0.60 |
| No match (fallback) | 0.30 |

**Resolution:**

1. **Autonomous mode threshold:** Default `confidenceThreshold = 0.70`. Below this, the assistant escalates rather than acting autonomously.

2. **Why confidence drops:**
   - Ambiguous phrasing ("handle this for me" — handle what?)
   - Misspellings or abbreviations not in the pattern set
   - Mixed intents in one message ("send the campaign and also refund the last charge")
   - New feature requests not covered by existing patterns

3. **User-facing guidance:**
   - Ask users to be specific: "Send campaign 'Spring Sale' to list 'VIP Customers'" instead of "send it."
   - One intent per message for best results.

4. **Admin tuning:**
   - Add new intent patterns to the pattern map in `unified.ts`.
   - Lower `confidenceThreshold` only if false escalations outnumber misrouted actions.
   - Review escalation logs — `ambiguous_intent` and `confidence_too_low` escalations indicate gaps in the pattern set.

5. **Sentiment-based escalation:** If user sentiment drops below `sentimentEscalationThreshold = -0.5` (e.g., "this is ridiculous, it never works"), auto-escalate to human support regardless of intent confidence.

---

## LLM.TOOLPLAN.INVALID_ARGS — "AI tried to call a tool/action with wrong arguments"

**Symptoms:** The assistant attempts an action but it fails with validation errors. Internal log shows malformed action block.

**Root cause:** The LLM generated a structured action block (` ```action ... ``` `) with incorrect, missing, or extra parameters.

**Resolution:**

1. **Action validation flow:**
   - Assistant output is parsed for structured action blocks.
   - Action type is validated against the known set (20+ action types across 5 risk levels).
   - Parameters are validated against expected schema per action type.
   - If validation fails, the action is NOT executed.

2. **Common failure modes:**
   - **Missing required field:** e.g., `send_campaign` without `campaignId`.
   - **Wrong type:** e.g., passing string where number expected.
   - **Hallucinated action:** e.g., `restart_server` — not in the action set.

3. **Action risk levels and their parameter expectations:**

   | Risk | Actions | Notes |
   |------|---------|-------|
   | safe | `get_billing_status`, `check_api_status`, etc. | Auto-approved, read-only, minimal params |
   | low | `verify_domain`, `check_deliverability` | Auto-approved, requires domain/target param |
   | medium | `create_campaign`, `add_contact`, etc. | Requires confirmation, multiple params |
   | high | `send_campaign`, `import_contacts` | Always escalated to human |
   | critical | `delete_campaign`, `cancel_subscription` | Always escalated to human |

4. **Fix:**
   - Invalid actions are caught before execution — no customer data is affected.
   - The assistant retries by reformulating the action block.
   - If retries fail, escalation is triggered (`repeated_failure`, severity: `medium`).
   - Admin can inspect the raw LLM output in audit logs (all actions logged when `auditAllActions = true`).

---

## LLM.VERIFIER.FAIL_REGENERATE — "AI verifier rejected the response, needs regeneration"

**Symptoms:** The assistant produces a response that fails post-generation validation. User may see a generic fallback message instead of a tailored answer.

**Root cause:** The `isModelOutputUsable()` validator rejected the output. Rules:

| Intent | Must pass |
|--------|-----------|
| `command` / `billing` / `domain` | Contains a structured ` ```action ``` ` block |
| `greeting` | ≥ 4 tokens, > 70% real English words |
| `knowledge` | ≥ 30 chars, > 70% real words, ≥ 6 real-word tokens |
| `unclear` | Always fails → template fallback |

**Resolution:**

1. **Expected behavior:** Failed validation causes the assistant to fall back to pre-written template responses. This is a **safety feature**, not a bug.

2. **When it's a problem:**
   - If the model consistently fails validation for legitimate queries, the real words dictionary may be too restrictive.
   - Mock mode produces random tokens that will always fail validation — confirm you're running with the real GGUF model file.

3. **Diagnostics:**
   - Check log for `⚠️ [AI] MOCK MODE` — if present, no real model is loaded.
   - Check `ai_error_rate` metric — if > 50%, the model may be corrupted or the wrong quantization is loaded.

4. **Tuning:**
   - The 70% real-word threshold is hardcoded. If the model outputs technical jargon or non-English text, this threshold needs adjustment.
   - For multilingual deployments, this validator may need to be language-aware.

---

## LLM.RAG.IRRELEVANT_CHUNKS — "Retrieved context chunks are not relevant to the query"

**Symptoms:** The assistant's answers reference unrelated content, or the RAG pipeline returns documents that don't match the user's question.

**Root cause:** Embedding similarity search returned low-quality matches.

**Resolution:**

1. **How the RAG pipeline works:**
   - User input → `embed()` via MiniLM-L6-v2 → 384-dim vector → cosine similarity search against vector store → top-K chunks returned → injected into LLM prompt.

2. **Search defaults:**
   - `topK = 10` — returns 10 most similar chunks.
   - `threshold = 0.0` — no minimum similarity filter (all results returned).

3. **Root causes of irrelevant chunks:**
   - **Threshold too low:** Default 0.0 means even dissimilar chunks are returned. Increase to 0.3–0.5.
   - **Poor chunking:** Default `chunkSize = 500 chars` / `chunkOverlap = 50 chars`. If documents are highly structured (tables, code), larger chunks or custom separators help.
   - **Stale index:** Vector store hasn't been updated with latest documentation.
   - **Semantic gap:** User phrasing differs significantly from indexed content (e.g., "email not arriving" vs. "delivery failure").

4. **Fix:**
   - Increase similarity `threshold` to 0.3 minimum.
   - Reduce `topK` to 3–5 to avoid diluting context with marginal matches.
   - Re-index documentation with better chunking (increase `chunkOverlap` to 100+).
   - Add synonyms / FAQ-style entries to the index.

5. **Debugging:**
   ```bash
   # Check similarity scores for a query
   POST /v1/ai/embeddings/search
   {
     "query": "how do I verify my domain",
     "topK": 5
   }
   ```
   Inspect the `score` field — scores < 0.3 indicate poor matches.

---

## LLM.RAG.TOO_MANY_CHUNKS — "Too many chunks injected into context, crowding out the prompt"

**Symptoms:** RAG retrieves many chunks but the LLM's response quality drops because too much context is injected, displacing the actual user question and conversation history.

**Root cause:** `topK = 10` chunks × ~500 chars each = ~5 000 chars (~1 250 tokens) consumed by RAG context. Combined with system prompt (~400 tokens) and history, this can push total context past the 8 192-token window.

**Resolution:**

1. **Reduce `topK`:** For most queries, 3–5 chunks provide sufficient context. Setting `topK = 3` saves ~875 tokens.

2. **Increase similarity `threshold`:** Only inject chunks above 0.4 similarity. This naturally reduces count for queries with few strong matches.

3. **Budget-aware injection:**
   - `maxContextTokens = 2 048` in the unified assistant limits how much context is injected.
   - If RAG chunks + conversation history exceed this, oldest history messages are pruned.

4. **Chunk deduplication:** If multiple chunks come from the same document, consider returning only the highest-scoring one per source to avoid redundancy.

5. **Vector store capacity:** LRU eviction kicks in at `MAX_VECTOR_STORE_SIZE = 10 000` entries. If the store is at capacity, older/less-accessed entries are evicted automatically.

---

## LLM.PERF.SLOW_FIRST_TOKEN — "First response token takes too long (high TTFT)"

**Symptoms:** After the user sends a message, there's a long delay (several seconds to minutes) before the first token appears in the response.

**Root cause possibilities:**
- Model not loaded (cold start)
- Model warming up
- Inference queue backed up
- CPU-bound inference (GPU not enabled)

**Resolution:**

1. **Check model state:**
   ```
   GET /v1/ai/health
   ```
   Expected: `status: "ready"`, `warmupComplete: true`.

   | State | Meaning | TTFT Impact |
   |-------|---------|-------------|
   | `unloaded` | Model not in memory | 60+ s (must load first) |
   | `loading` | Actively loading from disk | Wait for completion (up to `loadTimeoutMs = 60 s`) |
   | `warming_up` | Loaded, running warmup iterations | Wait for `warmupIterations = 3` to complete |
   | `ready` | Ready for inference | Normal TTFT |
   | `error` | Load failed, ≥ `maxConsecutiveErrors = 5` | Model needs manual reload |

2. **Cold start optimization:**
   - Set `autoLoad = true` in lifecycle config to load model at service startup.
   - Use the warmup phase (`warmupIterations = 3`) — this primes the llama.cpp sidecar's KV cache.
   - The default model is Q4_K_M quantized (~5 GB). Higher quantizations (Q8, FP16 ~16 GB) trade RAM for quality.

3. **Queue congestion:**
   - `maxQueueSize = 100`. If at capacity, new requests get `Inference queue full` error.
   - `MAX_CONCURRENT = 5` — only 5 inference requests run in parallel.
   - Check queue depth:
     ```
     metric: ai_inference_queue_depth
     ```
   - If queue is consistently > 50, scale horizontally or increase `numThreads = 4`.

4. **CPU vs GPU:**
   - Default: `useGPU = false` (CPU mode, `numThreads = 4`).
   - CPU inference for 8B model: **2–8 tokens/sec** depending on hardware.
   - GPU inference (CUDA): **30–100 tokens/sec** depending on GPU.
   - Enable GPU: set `useGPU = true` and ensure the llama.cpp build includes CUDA support.

5. **Expected TTFT benchmarks:**

   | Config | TTFT (first token) |
   |--------|--------------------|
   | CPU, 4 threads, cold start | 60–120 s |
   | CPU, 4 threads, warm | 3–10 s |
   | GPU (A10G), warm | 0.5–2 s |

---

## LLM.PERF.CONCURRENCY_QUEUE_STARVATION — "High concurrency causes queue starvation / requests timing out"

**Symptoms:** Multiple users/requests hit the AI service simultaneously and some requests timeout with `Request timeout` (30 s) or `Inference queue full` (> 100 queued).

**Root cause:** The inference pipeline is single-model with bounded concurrency:
- `MAX_CONCURRENT = 5` parallel inference runs
- `maxQueueSize = 100` pending requests
- `timeoutMs = 30 000 ms` per queued request
- 8B model on CPU: ~3–5 s per generation → max throughput ≈ 1–1.5 req/s

**Resolution:**

1. **Horizontal scaling:**
   - Deploy multiple AI service replicas behind a load balancer.
   - Each replica loads its own model copy (~8 GB RAM per replica).
   - Use sticky sessions so conversation context stays on one replica.

2. **Queue tuning:**
   - Increase `maxQueueSize` (but this increases tail latency, not throughput).
   - Increase `timeoutMs` to tolerate longer queue waits (but degrades user experience).
   - Increase `MAX_CONCURRENT` only if hardware supports it (RAM, CPU cores, GPU memory).

3. **Rate limiting (per-tenant):**
   - Assistant rate limit: `30 messages / 60 s` per user session.
   - Autonomous mode: `50 autonomousActionsPerHour` per tenant.
   - These prevent single tenants from starving others.

4. **Priority queuing (not yet implemented):**
   - Enterprise / high-tier tenants could get priority queue placement.
   - Escalation and safety-critical requests (e.g., PII detection) could bypass the queue.

5. **Monitoring:**
   ```
   ai_inference_queue_depth        → queue health
   ai_error_rate                   → failure ratio
   ai_avg_latency_ms               → response time trend
   ai_request_count                → throughput
   ai_tokens_processed_total       → utilization
   ```

6. **Circuit breaker interaction:**
   - If queue starvation causes 5+ consecutive timeouts, the circuit breaker opens.
   - All new requests immediately fail with circuit-open error for 30 s.
   - After 30 s, one request is allowed through (half-open). If it succeeds 3 times, the breaker closes.
   - **Emergency reset:** `POST /v1/ai/circuit-breaker/reset` (admin only).

---

## Decision Tree

```
AI / LLM issue
├── Input too long → LLM.CONTEXT.TOO_LONG
│   └── Start new session, reduce history, chunk input
├── Output cut off → LLM.TOKENS.MAX_OUTPUT_EXCEEDED
│   └── Ask "continue", request shorter answer
├── Streaming interruption → LLM.STREAM.INTERRUPTED
│   └── Check circuit breaker, proxy timeouts, client reconnect
├── Wrong/fabricated answer → LLM.HALLUCINATION.RISK_MISSING_EVIDENCE
│   └── Lower temperature, check RAG index, report for training
├── Wrong intent detected → LLM.ROUTER.CONFIDENCE_LOW
│   └── Rephrase query, check confidence scores, add patterns
├── Action call failed → LLM.TOOLPLAN.INVALID_ARGS
│   └── Caught before execution, check audit log, retry
├── Response rejected by verifier → LLM.VERIFIER.FAIL_REGENERATE
│   └── Check mock mode, review validation thresholds
├── Retrieved docs irrelevant → LLM.RAG.IRRELEVANT_CHUNKS
│   └── Increase similarity threshold, reduce topK, re-index
├── Too many docs in context → LLM.RAG.TOO_MANY_CHUNKS
│   └── Reduce topK, increase threshold, enable dedup
├── Slow first token → LLM.PERF.SLOW_FIRST_TOKEN
│   └── Check model state, enable autoLoad, enable GPU
└── Queue starvation → LLM.PERF.CONCURRENCY_QUEUE_STARVATION
    └── Scale replicas, tune queue/timeout, check circuit breaker
```

---

## Appendix: PII & Safety Guardrails

The unified assistant includes automatic detection and escalation for:

| Pattern | Detection | Action |
|---------|-----------|--------|
| SSN (`XXX-XX-XXXX`) | Regex | Escalate as `pii_detected` (severity: high) |
| Credit card (16 digits) | Regex | Escalate as `pii_detected` (severity: high) |
| Legal keywords (lawyer, subpoena, lawsuit, GDPR request, etc.) | Keyword set | Escalate as `legal_request` (severity: urgent) |
| Negative sentiment (< -0.5) | Scoring model | Escalate as `angry_customer` (severity: high) |
| ALL CAPS (>50% of message) | Heuristic | −0.2 sentiment penalty |
| Excessive punctuation (`!!!`, `???`) | Heuristic | −0.15 sentiment penalty |
