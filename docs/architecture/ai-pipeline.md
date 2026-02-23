# ApexMail AI — 3-Model Pipeline Architecture

> **Implementation Note (2026-02):** AI capabilities are implemented in Rust crates at `services/mail-server/crates/ai-service/` and `services/mail-server/crates/ai-embeddings/`. TypeScript interfaces below are design specifications; actual implementation is Rust.

## Overview

The ApexMail assistant uses a three-stage pipeline for every user interaction. This design separates _planning_ from _generation_ from _verification_, enabling each stage to be tested, swapped, and improved independently.

```
User message
    │
    ▼
┌──────────────────────────────────────┐
│  Stage 1 — PLANNER                   │
│  Qwen 2.5-7B-Instruct (fine-tuned)  │
│  Classifies intent, extracts params, │
│  selects knowledge context           │
└──────────────────────────────────────┘
    │  PlanResult { intent, params, context, tool_call? }
    ▼
┌──────────────────────────────────────┐
│  Stage 2 — GENERATOR                 │
│  Qwen 2.5-7B-Instruct (same model)  │
│  Generates the user-facing response  │
│  grounded in the plan's context      │
└──────────────────────────────────────┘
    │  Draft response text
    ▼
┌──────────────────────────────────────┐
│  Stage 3 — VERIFIER                  │
│  Deterministic rules + model check   │
│  Validates facts, blocks halluc.,    │
│  ensures safety & compliance         │
└──────────────────────────────────────┘
    │  Final response (or retry)
    ▼
User
```

## Stage 1: Planner

**Model**: Qwen 2.5-7B-Instruct (fine-tuned QLoRA adapter, ONNX)

The planner receives the user message and chat history, then produces a structured plan:

```typescript
interface PlanResult {
    // What the user wants
    intent: 'question' | 'action' | 'greeting' | 'off_topic' | 'clarification';

    // Extracted parameters (for actions)
    params?: Record<string, unknown>;

    // Which knowledge context to inject into the generator prompt
    context_keys: string[];  // e.g. ['pricing_table', 'payg_rates']

    // If the user wants to perform an action
    tool_call?: {
        name: string;        // e.g. 'SEND_CAMPAIGN'
        args: Record<string, unknown>;
        requires_confirm: boolean;
    };

    // Confidence score (0-1)
    confidence: number;

    // If confidence < threshold, ask clarifying question instead
    clarification_prompt?: string;
}
```

**Training data**: The planner is trained on (user_message → PlanResult JSON) pairs. The fine-tuned model learns to produce valid JSON plans for every input.

**Key responsibilities**:
- Intent classification (question vs action vs greeting vs off-topic)
- Entity extraction (campaign name, list name, plan tier, etc.)
- Context selection (which knowledge articles to inject)
- Confidence estimation
- Action parameter mapping

## Stage 2: Generator

**Model**: Same Qwen 2.5-7B-Instruct model (separate inference call)

The generator receives a prompt constructed from the plan:

```
System: {system_prompt}
Context: {selected_knowledge_articles}
Plan: {plan_summary}
User: {original_user_message}
```

It generates a natural-language response grounded in the provided context. The generator never sees raw product data — it only sees what the planner selected.

**Key responsibilities**:
- Natural language response generation
- Markdown formatting (tables, code blocks, lists)
- Action block formatting (`\`\`\`action {...}\`\`\``)
- Tone & voice consistency

## Stage 3: Verifier

**Implementation**: Deterministic rules (primary) + optional model check (secondary)

The verifier is a fast, rule-based pipeline that validates the generator's output before returning it to the user.

### Rule checks (deterministic)

| Rule | Description |
|------|-------------|
| **Pricing facts** | Regex-check that any dollar amounts match the canonical pricing table |
| **URL validation** | Ensure URLs are `api.apexmail.ee` or `app.apexmail.ee` (no hallucinated domains) |
| **API key format** | Any API key patterns must match `am_live_*` or `am_test_*` format |
| **Action JSON** | Validate action blocks parse as valid JSON with required fields |
| **Forbidden claims** | Block responses containing uptime SLA numbers, competitor bashing, legal advice |
| **Off-topic leak** | If planner said `off_topic`, verify the response declines the request |
| **Response length** | Block very short (<20 chars) or very long (>4000 chars) responses |
| **Repetition** | Detect degenerate repetitive output |
| **PII detection** | Block responses that echo back potential PII from user input |

### Retry logic

If the verifier rejects a response:
1. First retry: Re-generate with the same plan + a correction hint
2. Second retry: Re-run the planner with a forced context expansion
3. Final fallback: Return a safe template-based response from the knowledge base

Maximum 2 retries before fallback.

## Deployment

```
VPS (production)
├── ONNX Runtime (CPU)
│   └── qwen2.5-7b-instruct.onnx  (~8 GB INT8)
├── Planner inference call (~200-500ms)
├── Generator inference call (~500-2000ms)
└── Verifier rules (~1-5ms)
```

Total latency budget: **< 3 seconds** for the full pipeline.

## Knowledge Context Store

The planner selects from a pre-indexed knowledge store:

| Key | Content |
|-----|---------|
| `pricing_table` | Full plan pricing with limits |
| `payg_rates` | PAYG email and API overage rates |
| `api_auth` | Authentication methods and key formats |
| `api_endpoints` | Endpoint reference (messages, campaigns, domains, etc.) |
| `domain_setup` | SPF/DKIM/DMARC verification steps |
| `deliverability` | Best practices, benchmarks, warm-up guidance |
| `webhooks` | Event types, payload format, signatures |
| `templates` | Handlebars syntax, dynamic content |
| `sdks` | Node.js and Python SDK installation and usage |
| `suppression` | Suppression list management |
| `compliance` | GDPR, CAN-SPAM, consent management |
| `troubleshooting` | Common errors (401, 429, spam folder) |
| `automation` | Workflows, drip campaigns, triggers |
| `segmentation` | Audience targeting, segments |
| `sto` | Send-time optimisation |
| `capabilities` | Feature summary |

Each context article is ~200-500 tokens, ensuring the full prompt (system + context + plan + user) stays well within the 8192-token context window.

## Testing & Evaluation

| Test suite | What it checks | Target |
|------------|----------------|--------|
| **Golden QA set** (eval.py) | End-to-end pipeline accuracy | ≥95% A-grade |
| **Planner unit tests** | Intent classification + entity extraction | ≥98% accuracy |
| **Verifier rule tests** | Each rule fires correctly on positive/negative examples | 100% |
| **Hallucination tests** | Model correctly refuses non-existent features | ≥99% |
| **Prompt injection tests** | Model resists jailbreak/injection attempts | 100% |
| **Latency benchmarks** | Full pipeline under 3 seconds on target VPS | P99 < 3s |

## Future Evolution

1. **Planner → dedicated small model**: If latency is critical, train a 1B Qwen model specifically for planning (structured output only)
2. **Generator → larger model**: If quality needs improve, swap to a 14B or 32B model (may need GPU inference)
3. **Verifier → LLM judge**: Add a small model as a secondary judge for subjective quality checks
4. **RAG integration**: Replace static context store with vector search over the full documentation corpus
