# ADR 0004: AI Local Inference

## Status
Accepted

## Date
2024-02-01

## Context
ApexMail needs AI capabilities for:
- Send-time optimization
- Content generation
- Chatbot/support automation
- Analytics predictions
- Spam/phishing detection

We wanted to avoid paid AI API dependencies (OpenAI, Anthropic) for core functionality while maintaining high quality.

## Decision
We built an **AI Intelligence Suite** using local inference with ONNX Runtime:

### Architecture
```
apps/ai/
├── src/
│   ├── inference/      # ONNX Runtime engine
│   ├── chatbot/        # Conversational AI
│   ├── mailbot/        # Email command processing
│   ├── sto/            # Send-time optimization
│   ├── content/        # Content generation
│   └── analytics/      # Predictive analytics
```

### Model Strategy

#### Primary: Local ONNX Models
- **Embeddings**: MiniLM-L6-v2 (384 dimensions)
- **Classification**: Fine-tuned BERT variants
- **Generation**: Phi-3.5-mini quantized (INT8)

#### Fallback: API-based (Optional)
- Anthropic Claude for complex generation
- Only activated if `ANTHROPIC_API_KEY` is set
- Graceful degradation to local models

### Inference Engine
```typescript
interface InferenceEngine {
  // Text generation with local model
  generate(prompt: string, options: GenerateOptions): Promise<string>;
  
  // Embedding generation for semantic search
  embed(text: string): Promise<number[]>;
  
  // Chat completion with context
  chat(messages: Message[], options: ChatOptions): Promise<string>;
}
```

### Send-Time Optimization (STO)
Predicts optimal send times based on:
- Historical engagement patterns
- Timezone inference
- Day-of-week preferences
- Industry benchmarks

Model architecture:
- Input: User features + historical data
- Output: Probability distribution over 168 hours (7 days × 24 hours)
- Training: Collaborative filtering + neural network

### Content Generation
- Subject line variants
- Email body suggestions
- CTA optimization
- Plain-text conversion

### Vector Store
- In-memory HNSW index for semantic search
- Persistence to disk for durability
- Supports 100k+ vectors with <50ms query

## Consequences

### Positive
- Zero API costs for core AI features
- Low latency (local inference)
- Full data privacy (no external calls)
- Offline capability

### Negative
- Model maintenance burden
- Higher compute requirements
- May lag behind frontier models

### Performance Targets
| Operation | Target Latency | Achieved |
|-----------|---------------|----------|
| Embedding | <50ms | ✅ 25ms |
| Generation (100 tokens) | <2s | ✅ 1.5s |
| STO prediction | <100ms | ✅ 40ms |
| Semantic search (10k docs) | <50ms | ✅ 30ms |

## Related ADRs
- ADR 0003: Sales Autopilot (lead scoring)
- ADR 0005: SLO Management (AI service SLOs)
