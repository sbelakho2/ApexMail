# @apexmail/ai

Local-first AI Intelligence Suite for ApexMail.

This service powers:
- **Send Time Optimization (STO)**: Predicting the best time to send emails.
- **Subject Line Analysis**: Scoring and improving subject lines.
- **Generative Reply**: Drafting responses (EXPERIMENTAL).
- **Semantic Search**: Vector embeddings for email content.

## Architecture

ApexMail AI uses a **Sidecar Pattern**. The Node.js application (`src/index.ts`) acts as an orchestrator and API gateway, while the heavy lifting is done by a local `llama-server` instance (from the `llama.cpp` project).

- **API/Orchestrator**: Node.js + Hono (Port 3004)
- **Inference Engine**: `llama-server` (Port 8081)
- **Communication**: HTTP via OpenAI-compatible `/v1/chat/completions`

## Prerequisites

1.  **llama.cpp tools**: You need the `llama-server` binary.
    - Mac (Homebrew): `brew install llama.cpp`
    - Linux/Windows: Build from source or download pre-built binaries.

2.  **Model Files**: Download the GGUF quantized models.
    - Recommended LLM: `Qwen/Qwen2.5-7B-Instruct-GGUF` (q4_k_m or q5_k_m)
    - Recommended Embeddings: `sentence-transformers/all-MiniLM-L6-v2` (ONNX or GGUF if supported)

    Place models in `./models/`:
    ```bash
    mkdir -p models
    # Example download (requires huggingface-cli)
    huggingface-cli download Qwen/Qwen2.5-7B-Instruct-GGUF qwen2.5-7b-instruct-q4_k_m.gguf --local-dir models --local-dir-use-symlinks False
    ```

## Running the Service

1.  **Start the Sidecar (llama-server)**:
    ```bash
    # Run in a separate terminal or service
    llama-server -m models/qwen2.5-7b-instruct-q4_k_m.gguf -c 8192 --port 8081 --host 127.0.0.1 --embedding
    ```
    *Note: The `--embedding` flag is crucial for semantic search features.*

2.  **Start the AI App**:
    ```bash
    # From apps/ai directory
    pnpm dev
    ```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | API Port | `3004` |
| `LLAMA_SERVER_URL` | Llama server address | `http://127.0.0.1:8081` |
| `LLAMA_TIMEOUT_MS` | Inference timeout | `30000` |
| `REDIS_URL` | Redis for caching/STO | (Required for production) |

## Features Implementation Status

- [x] **Inference Engine**: Robust client with retries and health checks.
- [x] **Send Time Optimization**: In-memory + Redis implementation (see `src/sto`).
- [ ] **Subject Line Scorer**: Basic heuristic implementation.
- [ ] **Content Generation**: Experimental.

## Production Notes

- **Do NOT run `llama-server` on the same CPU cores as the API/DB.** Use Docker CPU limits or affinity.
- **Memory Usage**: A 7B model requires ~6GB RAM. Ensure your worker node has at least 8-16GB RAM.
- **GPU**: For higher throughput, compile `llama-server` with CUDA/Metal support and pass `-ngl 99` (offload all layers).
