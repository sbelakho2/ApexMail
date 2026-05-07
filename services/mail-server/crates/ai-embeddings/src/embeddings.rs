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

        let mut embeddings: Vec<(usize, Vec<f32>)> = inference_resp
            .data
            .into_iter()
            .map(|e| (e.index, e.embedding))
            .collect();

        // Sort by index to maintain order
        embeddings.sort_by_key(|(idx, _)| *idx);

        let vectors: Vec<Vec<f32>> = embeddings
            .into_iter()
            .map(|(_, v)| {
                // Apply L2 normalization
                l2_normalize(v)
            })
            .collect();

        // Validate dimensions
        for v in &vectors {
            if v.len() != self.config.dimension {
                return Err(EmbeddingError::DimensionMismatch {
                    got: v.len(),
                    expected: self.config.dimension,
                });
            }
        }

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
        let path = std::env::temp_dir().join(format!(
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
}
