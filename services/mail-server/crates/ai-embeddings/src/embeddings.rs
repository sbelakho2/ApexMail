//! Embedding generation via HTTP sidecar (llama-server / ONNX Runtime).

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::config::InferenceConfig;
use crate::types::{EmbeddingError, InferenceRequest, InferenceResponse};

/// Service for generating text embeddings via an inference sidecar.
pub struct EmbeddingService {
    client: Client,
    config: InferenceConfig,
    semaphore: Arc<Semaphore>,
}

impl EmbeddingService {
    pub fn new(config: InferenceConfig) -> Result<Self, EmbeddingError> {
        let mut client_builder =
            Client::builder().timeout(Duration::from_millis(config.timeout_ms));

        // Configure TLS for sidecar communication (O-9.1)
        if config.sidecar_tls_enabled {
            // reqwest with `rustls-tls` feature already uses rustls with
            // system certificate verification by default.
            client_builder = client_builder.https_only(true);
            if !config.sidecar_tls_ca_path.is_empty() {
                let pem = std::fs::read(&config.sidecar_tls_ca_path).map_err(|e| {
                    EmbeddingError::ConfigError(format!(
                        "failed to read sidecar TLS CA at {}: {e}",
                        config.sidecar_tls_ca_path
                    ))
                })?;
                let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
                    EmbeddingError::ConfigError(format!(
                        "invalid PEM CA at {}: {e}",
                        config.sidecar_tls_ca_path
                    ))
                })?;
                client_builder = client_builder.add_root_certificate(cert);
                info!(
                    ca_path = %config.sidecar_tls_ca_path,
                    "sidecar TLS enabled with custom CA"
                );
            } else {
                info!("sidecar TLS enabled with system CA certificates");
            }
        } else {
            warn!(
                "sidecar TLS is DISABLED — inference traffic to {} is unencrypted. \
                 This should only be used for internal/testing deployments on trusted networks.",
                config.url
            );
        }

        let client = client_builder.build().map_err(EmbeddingError::Http)?;

        let semaphore = Arc::new(Semaphore::new(config.max_concurrency));

        Ok(Self {
            client,
            config,
            semaphore,
        })
    }

    /// Generate an embedding for a single text input.
    pub async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if text.is_empty() {
            return Err(EmbeddingError::EmptyText);
        }

        let results = self.embed_batch(&[text.to_string()]).await?;
        results.into_iter().next().ok_or_else(|| {
            EmbeddingError::InferenceError("Empty response from inference server".into())
        })
    }

    /// Generate embeddings for a batch of texts with concurrency control.
    pub async fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(vec![]);
        }

        // Acquire semaphore permit
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| EmbeddingError::InferenceError(format!("Semaphore error: {}", e)))?;

        let request = InferenceRequest {
            input: texts.to_vec(),
            model: self.config.model.clone(),
        };

        let url = format!("{}/v1/embeddings", self.config.url);
        let response = self.client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EmbeddingError::InferenceError(format!(
                "Inference server returned {}: {}",
                status, body
            )));
        }

        let inference_resp: InferenceResponse = response.json().await?;

        let vectors = finalize_batch(texts.len(), inference_resp.data, self.config.dimension)?;

        info!(
            count = vectors.len(),
            dimension = self.config.dimension,
            "Generated embeddings"
        );
        Ok(vectors)
    }

    pub fn dimension(&self) -> usize {
        self.config.dimension
    }
}

/// SM9 #4/#5: validate the sidecar response CONTRACT and L2-normalize.
///
/// A sidecar that returns fewer embeddings than inputs, duplicates an index,
/// or drops one would otherwise produce a silently MISALIGNED batch —
/// callers zipping texts with embeddings (or storing chunk i's text with
/// chunk i's vector) would corrupt tenant data with no error anywhere. A
/// NaN/±Inf component makes the L2 norm NaN, so `l2_normalize` returns the
/// vector with its NaNs intact (all comparisons against NaN are false) and
/// downstream cosine/ranking math is poisoned — such a batch is rejected
/// fail-closed. A norm that OVERFLOWS to ±Inf (finite-but-huge components)
/// would instead silently normalize into the zero vector; it is rejected the
/// same way.
fn finalize_batch(
    expected_len: usize,
    data: Vec<crate::types::InferenceEmbedding>,
    dimension: usize,
) -> Result<Vec<Vec<f32>>, EmbeddingError> {
    let mut embeddings: Vec<(usize, Vec<f32>)> =
        data.into_iter().map(|e| (e.index, e.embedding)).collect();

    // Sort by index to maintain order
    embeddings.sort_by_key(|(idx, _)| *idx);

    if embeddings.len() != expected_len {
        return Err(EmbeddingError::InferenceError(format!(
            "inference server returned {} embeddings for {} inputs — \
             refusing the misaligned batch",
            embeddings.len(),
            expected_len
        )));
    }
    for (pos, (idx, _)) in embeddings.iter().enumerate() {
        if *idx != pos {
            return Err(EmbeddingError::InferenceError(format!(
                "inference server returned non-contiguous embedding indices: \
                 expected index {pos}, found {idx} (duplicated or dropped input)"
            )));
        }
    }

    let vectors: Vec<Vec<f32>> = embeddings
        .into_iter()
        .map(|(_, v)| {
            // SM9 #5 (verifier-repair): reject a non-finite NORM, not only
            // non-finite components. Finite-but-huge components (e.g. 1e20 —
            // perfectly valid JSON) square to +Inf, so `l2_normalize` divides
            // every component into 0.0: the embedding is silently replaced by
            // the zero vector and passes every post-hoc finite check. The
            // batch fails closed instead of laundering the overflow.
            let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            if !norm.is_finite() {
                return Err(EmbeddingError::InferenceError(
                    "inference server returned a vector whose L2 norm is \
                     non-finite (component overflow to NaN/Inf) — rejecting \
                     the batch"
                        .into(),
                ));
            }
            Ok(l2_normalize(v))
        })
        .collect::<Result<Vec<_>, EmbeddingError>>()?;

    for v in &vectors {
        if v.len() != dimension {
            return Err(EmbeddingError::DimensionMismatch {
                got: v.len(),
                expected: dimension,
            });
        }
        if let Some(bad) = v.iter().position(|x| !x.is_finite()) {
            return Err(EmbeddingError::InferenceError(format!(
                "inference server returned a non-finite vector component \
                 (NaN/Inf) at position {bad} — rejecting the batch"
            )));
        }
    }

    Ok(vectors)
}

/// L2 normalize a vector to unit length.
pub fn l2_normalize(mut v: Vec<f32>) -> Vec<f32> {
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > f32::EPSILON {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
    v
}

/// Cosine similarity between two vectors (assumes L2-normalized).
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    dot as f64
}

/// Dot product of two vectors.
pub fn dot_product(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() {
        return 0.0;
    }
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (*x as f64) * (*y as f64))
        .sum()
}

/// Euclidean distance between two vectors.
pub fn euclidean_distance(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() {
        return f64::INFINITY;
    }
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| {
            let d = (*x as f64) - (*y as f64);
            d * d
        })
        .sum::<f64>()
        .sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PoolingStrategy;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDCTCCAfGgAwIBAgIUWXOehNlSPl0jLU50A8nVvzXznmowDQYJKoZIhvcNAQEL\n\
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDUwNTE4MDc0M1oXDTI2MDUw\n\
NjE4MDc0M1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\n\
AAOCAQ8AMIIBCgKCAQEA1n/5enp9942WCf2XnBQKjnKMA2aTOAEQlPmziypW8uDf\n\
Ywk/UDwonrgOYzvQA4WGBaFPQGZV/QaM3iJPMFgn2Auav1NzvSE7cgNdmq2OS8tC\n\
ukx5dwOHIC35zyYXRVvbHFVhmCVaNM0SxcukOZy1Q1KkiYR9JplsyYT2eaqFFD9z\n\
MIG16sPivK53u4NM9pl1c9ObC+pgM6L1NNybvW8Q1XUXKRD0M6/ae6JuyLcPn2gl\n\
0C+YT/t7+5F25tW8wO/pVAioCKEdI59el4xJ+DANAGdRo51SVRbn1er7XEEistBW\n\
wCOVYBNzK1LsaSAFb69oDKq+e9y5YZr27fNWiVQ8sQIDAQABo1MwUTAdBgNVHQ4E\n\
FgQUIhh+YoNpEczhCN/L5FmcHp15kR4wHwYDVR0jBBgwFoAUIhh+YoNpEczhCN/L\n\
5FmcHp15kR4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAmuBs\n\
2NvoclXnDcM7sHDffFaoUEc5Wu+TiPsHAIsxh7WJdZd1gMqxa21RxzAEyoxsrGI+\n\
iu6KZyT7qif5dCAzSZ4uHpAi480FhHAYrY81B46Kz6BIMrCWGsxhGqjepCRnyI1z\n\
YQ2srIs7wxsOaeNekq7WJ/k/zhq+g15Xbr+IfN1Hoo44QTzuQznwW7wuE8BR5kZS\n\
CcBJ1PGNP6OQsgLDp37cZfB8Qj1AOixfzINHDaam61pU7GGHWL0NRszaAcTb9kc9\n\
37ukNv8LiR1YsEdKP1abF61LqyAOU5xaluX/SzcUO/Lj/dshL8C3Jo4/irEVeOGi\n\
PmScTyfBMj4Ej4fcpQ==\n\
-----END CERTIFICATE-----\n";

    fn test_config(sidecar_tls_enabled: bool, sidecar_tls_ca_path: String) -> InferenceConfig {
        InferenceConfig {
            url: "https://localhost:8080".to_string(),
            model: "test".to_string(),
            dimension: 384,
            max_concurrency: 4,
            timeout_ms: 5000,
            pooling: PoolingStrategy::Mean,
            sidecar_tls_enabled,
            sidecar_tls_ca_path,
        }
    }

    fn write_temp_ca(contents: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
            .join(format!(
                "apexmail-ai-embeddings-ca-{}-{unique}.pem",
                std::process::id()
            ));
        std::fs::write(&path, contents).expect("write test CA");
        path
    }

    #[test]
    fn test_l2_normalize() {
        let v = vec![3.0, 4.0];
        let n = l2_normalize(v);
        let norm: f32 = n.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
        assert!((n[0] - 0.6).abs() < 1e-5);
        assert!((n[1] - 0.8).abs() < 1e-5);
    }

    #[test]
    fn test_l2_normalize_zero() {
        let v = vec![0.0, 0.0, 0.0];
        let n = l2_normalize(v);
        assert!(n.iter().all(|x| *x == 0.0));
    }

    #[test]
    fn test_cosine_similarity_identical() {
        let a = l2_normalize(vec![1.0, 2.0, 3.0]);
        let sim = cosine_similarity(&a, &a);
        assert!((sim - 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = l2_normalize(vec![1.0, 0.0]);
        let b = l2_normalize(vec![0.0, 1.0]);
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-5);
    }

    #[test]
    fn test_cosine_similarity_opposite() {
        let a = l2_normalize(vec![1.0, 0.0]);
        let b = l2_normalize(vec![-1.0, 0.0]);
        let sim = cosine_similarity(&a, &b);
        assert!((sim + 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_cosine_similarity_different_lengths() {
        let a = vec![1.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        let sim = cosine_similarity(&a, &b);
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn test_dot_product() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![4.0, 5.0, 6.0];
        let dot = dot_product(&a, &b);
        assert!((dot - 32.0).abs() < 1e-5);
    }

    #[test]
    fn test_euclidean_distance_same() {
        let a = vec![1.0, 2.0, 3.0];
        let dist = euclidean_distance(&a, &a);
        assert!(dist.abs() < 1e-5);
    }

    #[test]
    fn test_euclidean_distance() {
        let a = vec![0.0, 0.0];
        let b = vec![3.0, 4.0];
        let dist = euclidean_distance(&a, &b);
        assert!((dist - 5.0).abs() < 1e-5);
    }

    #[test]
    fn test_euclidean_distance_different_lengths() {
        let a = vec![1.0];
        let b = vec![1.0, 2.0];
        let dist = euclidean_distance(&a, &b);
        assert_eq!(dist, f64::INFINITY);
    }

    #[test]
    fn test_embedding_service_dimension() {
        let mut config = test_config(false, String::new());
        config.url = "http://localhost:8080".to_string();
        let svc = EmbeddingService::new(config).unwrap();
        assert_eq!(svc.dimension(), 384);
    }

    #[test]
    fn test_embedding_service_accepts_custom_sidecar_ca() {
        let ca_path = write_temp_ca(TEST_CA_PEM);
        let config = test_config(true, ca_path.display().to_string());

        let svc = EmbeddingService::new(config).expect("custom CA should build HTTPS client");

        assert_eq!(svc.dimension(), 384);
        let _ = std::fs::remove_file(ca_path);
    }

    #[test]
    fn test_embedding_service_rejects_invalid_custom_sidecar_ca() {
        let ca_path = write_temp_ca(
            "-----BEGIN CERTIFICATE-----\nnot-valid-base64\n-----END CERTIFICATE-----\n",
        );
        let config = test_config(true, ca_path.display().to_string());

        let result = EmbeddingService::new(config);

        let _ = std::fs::remove_file(ca_path);
        assert!(result.is_err(), "invalid CA must be rejected");
    }

    // ── SM9 #4/#5: sidecar response-contract validation ─────────────────────
    // A mock sidecar binds 127.0.0.1:0 and serves a CANNED embeddings body,
    // so the tests can mutate the response the way a misbehaving or hostile
    // sidecar would (dropped entries, duplicated indices, NaN vectors).

    /// Serve `body` verbatim from a localhost POST /v1/embeddings endpoint;
    /// returns the base URL. No real network egress.
    async fn spawn_mock_sidecar(body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock sidecar");
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                // Drain the full request (headers + Content-Length body)
                // before answering, so the client never sees an early close.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break 0;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos;
                    }
                };
                let content_length: usize = String::from_utf8_lossy(&buf[..header_end])
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut body_bytes = buf[header_end + 4..].to_vec();
                while body_bytes.len() < content_length {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    body_bytes.extend_from_slice(&chunk[..n]);
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    fn batch_service_config(url: String) -> InferenceConfig {
        InferenceConfig {
            url,
            model: "test".to_string(),
            dimension: 4,
            max_concurrency: 2,
            timeout_ms: 5000,
            pooling: PoolingStrategy::Mean,
            sidecar_tls_enabled: false,
            sidecar_tls_ca_path: String::new(),
        }
    }

    fn unit_vector(index: f32, dim: usize) -> String {
        let mut v: Vec<String> = Vec::with_capacity(dim);
        for i in 0..dim {
            let component = if i as u32 == index as u32 { 1.0 } else { 0.0 };
            v.push(format!("{component}"));
        }
        format!("[{}]", v.join(","))
    }

    /// SM9 #4 (positive control): indices arriving OUT of order are sorted
    /// back into request order, so vectors stay aligned with their texts.
    #[tokio::test]
    async fn embed_batch_restores_request_order_from_indices() {
        // texts [a, b, c] answered with indices [2, 0, 1].
        let body = format!(
            r#"{{"data":[
                {{"index":2,"embedding":{}}},
                {{"index":0,"embedding":{}}},
                {{"index":1,"embedding":{}}}
            ]}}"#,
            unit_vector(2.0, 4),
            unit_vector(0.0, 4),
            unit_vector(1.0, 4),
        );
        let url = spawn_mock_sidecar(Box::leak(body.into_boxed_str())).await;
        let svc = EmbeddingService::new(batch_service_config(url)).unwrap();

        let vectors = svc
            .embed_batch(&["a".into(), "b".into(), "c".into()])
            .await
            .expect("well-formed sidecar response is accepted");
        assert_eq!(vectors.len(), 3);
        assert_eq!(vectors[0], vec![1.0, 0.0, 0.0, 0.0], "text a ↔ index 0");
        assert_eq!(vectors[1], vec![0.0, 1.0, 0.0, 0.0], "text b ↔ index 1");
        assert_eq!(vectors[2], vec![0.0, 0.0, 1.0, 0.0], "text c ↔ index 2");
    }

    /// SM9 #4: a sidecar that answers 2 embeddings for 3 inputs is refused —
    /// the batch would be silently misaligned.
    #[tokio::test]
    async fn embed_batch_rejects_short_sidecar_response() {
        let body = format!(
            r#"{{"data":[
                {{"index":0,"embedding":{}}},
                {{"index":1,"embedding":{}}}
            ]}}"#,
            unit_vector(0.0, 4),
            unit_vector(1.0, 4),
        );
        let url = spawn_mock_sidecar(Box::leak(body.into_boxed_str())).await;
        let svc = EmbeddingService::new(batch_service_config(url)).unwrap();

        let result = svc.embed_batch(&["a".into(), "b".into(), "c".into()]).await;
        let err = result.expect_err("dropped input must fail the batch");
        let msg = err.to_string();
        assert!(msg.contains("2 embeddings for 3 inputs"), "{msg}");
    }

    /// SM9 #4: a duplicated index (same length, one input answered twice,
    /// another dropped) is refused as non-contiguous.
    #[tokio::test]
    async fn embed_batch_rejects_duplicated_index() {
        let body = format!(
            r#"{{"data":[
                {{"index":0,"embedding":{}}},
                {{"index":1,"embedding":{}}},
                {{"index":1,"embedding":{}}}
            ]}}"#,
            unit_vector(0.0, 4),
            unit_vector(1.0, 4),
            unit_vector(3.0, 4),
        );
        let url = spawn_mock_sidecar(Box::leak(body.into_boxed_str())).await;
        let svc = EmbeddingService::new(batch_service_config(url)).unwrap();

        let result = svc.embed_batch(&["a".into(), "b".into(), "c".into()]).await;
        let err = result.expect_err("duplicate index must fail the batch");
        let msg = err.to_string();
        assert!(
            msg.contains("non-contiguous") && msg.contains("expected index 2"),
            "{msg}"
        );
    }

    /// SM9 #4: a single-text request whose sidecar response carries no data
    /// errors instead of returning a fabricated empty vector.
    #[tokio::test]
    async fn embed_errors_when_response_lacks_the_requested_input() {
        let url = spawn_mock_sidecar(r#"{"data":[]}"#).await;
        let svc = EmbeddingService::new(batch_service_config(url)).unwrap();

        let result = svc.embed("hello").await;
        let err = result.expect_err("missing embedding must error");
        assert!(
            err.to_string().contains("0 embeddings for 1 inputs"),
            "{err}"
        );
    }

    /// SM9 #5: ±Inf components are rejected over the wire. (Valid JSON
    /// cannot carry a `NaN` literal, but a float overflow such as 1e40
    /// deserializes to an infinite f32 — the same failure a hostile or
    /// misbehaving sidecar produces.)
    #[tokio::test]
    async fn embed_batch_rejects_non_finite_vectors_over_the_wire() {
        for bad in ["1e40", "-1e40"] {
            let body = format!(r#"{{"data":[{{"index":0,"embedding":[{bad},0.0,0.0,0.0]}}]}}"#);
            let url = spawn_mock_sidecar(Box::leak(body.into_boxed_str())).await;
            let svc = EmbeddingService::new(batch_service_config(url)).unwrap();

            let result = svc.embed_batch(&["a".into()]).await;
            let err = result.expect_err("non-finite components must be rejected");
            assert!(err.to_string().contains("non-finite"), "{bad}: {err}");
        }
    }

    /// SM9 #5: NaN components are rejected by the batch validator —
    /// `l2_normalize` passes NaN through unnormalized (all comparisons
    /// against NaN are false), and a NaN vector poisons every downstream
    /// cosine/ranking computation. (Driven directly: valid JSON cannot
    /// carry a NaN literal.)
    #[test]
    fn finalize_batch_rejects_nan_components() {
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let data = vec![crate::types::InferenceEmbedding {
                index: 0,
                embedding: vec![bad, 0.0, 0.0, 0.0],
            }];
            let err = finalize_batch(1, data, 4).expect_err("NaN/Inf must be rejected");
            assert!(err.to_string().contains("non-finite"), "{bad}: {err}");
        }
        // A finite batch of the right shape is accepted and normalized.
        let data = vec![crate::types::InferenceEmbedding {
            index: 0,
            embedding: vec![3.0, 0.0, 0.0, 0.0],
        }];
        let vectors = finalize_batch(1, data, 4).expect("finite batch accepted");
        assert_eq!(vectors[0], vec![1.0, 0.0, 0.0, 0.0]);
    }

    /// SM9 #5 (verifier-repair): finite-but-huge components OVERFLOW the L2
    /// norm to +Inf, and `l2_normalize` then divides every component into
    /// 0.0 — without the norm gate the batch would be silently accepted as
    /// an all-zero embedding and /embed would answer 200 with corrupt data.
    #[test]
    fn finalize_batch_rejects_a_norm_that_overflows() {
        for hostile in [vec![1e20f32, 1e20, 0.0, 0.0], vec![3e38f32, 1.0, 0.0, 0.0]] {
            let data = vec![crate::types::InferenceEmbedding {
                index: 0,
                embedding: hostile.clone(),
            }];
            let err = finalize_batch(1, data, 4)
                .expect_err("an overflowing L2 norm must fail the batch");
            assert!(
                err.to_string().contains("non-finite"),
                "{hostile:?}: {err}"
            );
        }
    }

    /// SM9 #5 (verifier-repair): the same overflow arriving over the wire
    /// (valid JSON finite numbers) is an error, never a 200 with a zeroed
    /// embedding.
    #[tokio::test]
    async fn embed_batch_rejects_overflowing_norm_over_the_wire() {
        let body = r#"{"data":[{"index":0,"embedding":[1e20,1e20,0.0,0.0]}]}"#;
        let url = spawn_mock_sidecar(body).await;
        let svc = EmbeddingService::new(batch_service_config(url)).unwrap();

        let result = svc.embed_batch(&["a".into()]).await;
        let err = result.expect_err("overflowing norm must be rejected");
        assert!(err.to_string().contains("non-finite"), "{err}");
    }
}
