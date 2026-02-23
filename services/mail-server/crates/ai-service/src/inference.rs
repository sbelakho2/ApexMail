//! Inference engine — model registry and prediction dispatch.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::types::{AiError, Model, ModelStatus, Prediction};

/// In-process inference engine backed by a concurrent model registry.
pub struct InferenceEngine {
    models: Arc<DashMap<String, Model>>,
}

impl Default for InferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl InferenceEngine {
    pub fn new() -> Self {
        Self {
            models: Arc::new(DashMap::new()),
        }
    }

    /// Register (or replace) a model in the registry.
    pub fn register_model(&self, model: Model) {
        self.models.insert(model.id.clone(), model);
    }

    /// Run a single prediction against a registered model.
    ///
    /// In this simple implementation the "prediction" is a mock pass-through
    /// that measures latency and produces a placeholder output.
    pub fn run_prediction(
        &self,
        model_id: &str,
        input: serde_json::Value,
    ) -> Result<Prediction, AiError> {
        let model = self
            .models
            .get(model_id)
            .ok_or_else(|| AiError::ModelNotFound(model_id.to_string()))?;

        if model.status != ModelStatus::Ready {
            return Err(AiError::InferenceFailed(format!(
                "model {} is not ready (status: {:?})",
                model_id, model.status
            )));
        }

        let start = Instant::now();

        // Simple mock inference — echo a confidence based on model accuracy
        let confidence = model.accuracy;
        let output = serde_json::json!({
            "model": model.name,
            "version": model.version,
            "result": "predicted",
        });

        let latency_ms = start.elapsed().as_millis() as u64;
        Ok(Prediction::new(model_id, input, output, confidence, latency_ms))
    }

    /// Run predictions for a batch of inputs.
    pub fn batch_predict(
        &self,
        model_id: &str,
        inputs: Vec<serde_json::Value>,
    ) -> Result<Vec<Prediction>, AiError> {
        inputs
            .into_iter()
            .map(|input| self.run_prediction(model_id, input))
            .collect()
    }

    /// Retrieve a model by ID.
    pub fn get_model(&self, id: &str) -> Option<Model> {
        self.models.get(id).map(|entry| entry.value().clone())
    }

    /// List all registered models.
    pub fn list_models(&self) -> Vec<Model> {
        self.models.iter().map(|entry| entry.value().clone()).collect()
    }

    /// Return summary statistics for a model.
    pub fn model_stats(&self, id: &str) -> Result<serde_json::Value, AiError> {
        let model = self
            .models
            .get(id)
            .ok_or_else(|| AiError::ModelNotFound(id.to_string()))?;

        Ok(serde_json::json!({
            "id": model.id,
            "name": model.name,
            "version": model.version,
            "model_type": model.model_type,
            "accuracy": model.accuracy,
            "status": model.status,
            "trained_at": model.trained_at.to_rfc3339(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ModelStatus, ModelType};
    use chrono::Utc;

    fn make_model(id: &str) -> Model {
        Model {
            id: id.to_string(),
            name: format!("test-{id}"),
            version: "1.0".to_string(),
            model_type: ModelType::Classification,
            accuracy: 0.92,
            trained_at: Utc::now(),
            status: ModelStatus::Ready,
        }
    }

    #[test]
    fn test_register_and_predict() {
        let engine = InferenceEngine::new();
        let model = make_model("m1");
        engine.register_model(model);

        let pred = engine
            .run_prediction("m1", serde_json::json!({"feature": 42}))
            .unwrap();
        assert_eq!(pred.model_id, "m1");
        assert!((pred.confidence - 0.92).abs() < f64::EPSILON);
    }

    #[test]
    fn test_predict_unknown_model_errors() {
        let engine = InferenceEngine::new();
        let res = engine.run_prediction("nope", serde_json::json!({}));
        assert!(res.is_err());
    }

    #[test]
    fn test_batch_predict_and_list() {
        let engine = InferenceEngine::new();
        engine.register_model(make_model("b1"));
        engine.register_model(make_model("b2"));

        let preds = engine
            .batch_predict("b1", vec![serde_json::json!(1), serde_json::json!(2)])
            .unwrap();
        assert_eq!(preds.len(), 2);

        let models = engine.list_models();
        assert_eq!(models.len(), 2);
    }
}
