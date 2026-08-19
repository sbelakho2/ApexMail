//! Remote model-runtime client.
//!
//! ApexMail never fabricates a prediction locally. Every generative response
//! comes from the configured OpenAI-compatible model endpoint, and requests
//! fail closed when model serving has not been explicitly enabled.

use reqwest::Client;
use serde::Serialize;
use std::time::{Duration, Instant};

use crate::config::AiConfig;
use crate::types::{AiError, Prediction};

/// Connection details for an OpenAI-compatible chat-completions runtime.
#[derive(Debug, Clone)]
pub struct InferenceConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub model: String,
    pub api_key: Option<String>,
    pub timeout: Duration,
}

impl InferenceConfig {
    pub fn from_ai_config(config: &AiConfig) -> Self {
        Self {
            enabled: config.model_enabled,
            endpoint: config.model_endpoint.trim().trim_end_matches('/').to_string(),
            model: config.model_name.trim().to_string(),
            api_key: (!config.model_api_key.trim().is_empty())
                .then(|| config.model_api_key.clone()),
            timeout: Duration::from_secs(config.model_timeout_secs),
        }
    }

    pub fn from_env() -> Result<Self, String> {
        AiConfig::from_env().map(|config| Self::from_ai_config(&config))
    }

    fn chat_completions_url(&self) -> String {
        if self.endpoint.ends_with("/chat/completions") {
            self.endpoint.clone()
        } else {
            format!("{}/chat/completions", self.endpoint)
        }
    }

    fn validate(&self) -> Result<(), AiError> {
        if !self.enabled {
            return Err(AiError::ModelUnavailable(
                "AI_MODEL_ENABLED is false".into(),
            ));
        }
        if self.model.is_empty() {
            return Err(AiError::ModelUnavailable(
                "AI_MODEL_NAME is not configured".into(),
            ));
        }
        if !(self.endpoint.starts_with("http://") || self.endpoint.starts_with("https://")) {
            return Err(AiError::ModelUnavailable(
                "AI_MODEL_ENDPOINT must use http or https".into(),
            ));
        }
        Ok(())
    }
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self::from_env().unwrap_or_else(|_| Self::from_ai_config(&AiConfig::default()))
    }
}

#[derive(Debug, Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

/// A bounded client for the model provider.
#[derive(Clone)]
pub struct LlmClient {
    config: InferenceConfig,
    http: Client,
}

impl LlmClient {
    pub fn new(config: InferenceConfig) -> Self {
        let http = Client::builder()
            .timeout(config.timeout)
            .build()
            .unwrap_or_else(|_| Client::new());
        Self { config, http }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn configured_model(&self) -> &str {
        &self.config.model
    }

    /// Run a chat request against the configured model. The endpoint must use
    /// the OpenAI `POST /chat/completions` response shape.
    pub async fn generate(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        max_tokens: u32,
    ) -> Result<String, AiError> {
        self.generate_for_model(
            &self.config.model,
            system_prompt,
            user_prompt,
            max_tokens,
            0.0,
        )
        .await
    }

    pub async fn plan(&self, system_prompt: &str, user_prompt: &str) -> Result<String, AiError> {
        self.generate_for_model(
            &self.config.model,
            system_prompt,
            user_prompt,
            768,
            0.0,
        )
        .await
    }

    /// Generate a response and invoke the supplied callback with bounded text
    /// chunks. This preserves the pipeline's progressive response contract for
    /// providers that do not expose server-sent streaming.
    pub async fn generate_streaming<F>(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        _assistant_prefix: &str,
        mut on_chunk: F,
    ) -> Result<String, AiError>
    where
        F: FnMut(&str),
    {
        let response = self.generate(system_prompt, user_prompt, 768).await?;
        let mut start = 0;
        while start < response.len() {
            let mut end = (start + 512).min(response.len());
            while end > start && !response.is_char_boundary(end) {
                end -= 1;
            }
            if end == start {
                end = response.len();
            }
            on_chunk(&response[start..end]);
            start = end;
        }
        Ok(response)
    }

    /// Execute an explicitly requested model against structured input. The
    /// input is serialized to JSON rather than interpreted as configuration.
    pub async fn predict(
        &self,
        model_id: &str,
        input: serde_json::Value,
    ) -> Result<Prediction, AiError> {
        self.config.validate()?;
        if model_id.trim() != self.config.model {
            return Err(AiError::ModelNotFound(model_id.to_string()));
        }

        let started = Instant::now();
        let prompt = serde_json::to_string_pretty(&input)
            .map_err(|error| AiError::InvalidInput(format!("cannot serialize model input: {error}")))?;
        let text = self
            .generate_for_model(
                model_id,
                "You are an ApexMail model runtime. Return only the response to the supplied JSON input.",
                &prompt,
                768,
                0.0,
            )
            .await?;

        Ok(Prediction::new(
            model_id,
            input,
            serde_json::json!({ "text": text }),
            None,
            started.elapsed().as_millis() as u64,
        ))
    }

    pub async fn generate_for_model(
        &self,
        model: &str,
        system_prompt: &str,
        user_prompt: &str,
        max_tokens: u32,
        temperature: f64,
    ) -> Result<String, AiError> {
        self.config.validate()?;
        if model.trim().is_empty() || model != self.config.model {
            return Err(AiError::ModelNotFound(model.to_string()));
        }
        if system_prompt.trim().is_empty() || user_prompt.trim().is_empty() {
            return Err(AiError::InvalidInput(
                "system and user prompts must not be empty".into(),
            ));
        }
        if max_tokens == 0 || max_tokens > 8_192 {
            return Err(AiError::InvalidInput(
                "max_tokens must be between 1 and 8192".into(),
            ));
        }

        let payload = serde_json::json!({
            "model": model,
            "messages": [
                ChatMessage { role: "system", content: system_prompt },
                ChatMessage { role: "user", content: user_prompt },
            ],
            "max_tokens": max_tokens,
            "temperature": temperature.clamp(0.0, 2.0),
            "stream": false,
        });

        let mut request = self.http.post(self.config.chat_completions_url()).json(&payload);
        if let Some(api_key) = &self.config.api_key {
            request = request.bearer_auth(api_key);
        }

        let response = request.send().await.map_err(|error| {
            AiError::ModelUnavailable(format!("model provider request failed: {error}"))
        })?;
        let status = response.status();
        let body = response.text().await.map_err(|error| {
            AiError::ModelUnavailable(format!("could not read model provider response: {error}"))
        })?;

        if !status.is_success() {
            let detail: String = body.chars().take(512).collect();
            return Err(AiError::ModelUnavailable(format!(
                "model provider returned {status}: {detail}"
            )));
        }

        let json: serde_json::Value = serde_json::from_str(&body).map_err(|error| {
            AiError::InferenceFailed(format!("model provider returned invalid JSON: {error}"))
        })?;
        let content = json
            .pointer("/choices/0/message/content")
            .and_then(serde_json::Value::as_str)
            .or_else(|| json.pointer("/choices/0/text").and_then(serde_json::Value::as_str))
            .or_else(|| json.get("response").and_then(serde_json::Value::as_str))
            .ok_or_else(|| {
                AiError::InferenceFailed(
                    "model provider response did not contain choices[0].message.content".into(),
                )
            })?;

        let content = content.trim();
        if content.is_empty() {
            return Err(AiError::InferenceFailed(
                "model provider returned an empty response".into(),
            ));
        }
        Ok(content.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_chat_completion_urls() {
        let mut config = InferenceConfig::default();
        config.endpoint = "http://model.example/v1".into();
        assert_eq!(
            config.chat_completions_url(),
            "http://model.example/v1/chat/completions"
        );

        config.endpoint = "https://model.example/v1/chat/completions".into();
        assert_eq!(
            config.chat_completions_url(),
            "https://model.example/v1/chat/completions"
        );
    }

    #[tokio::test]
    async fn disabled_runtime_fails_closed() {
        let client = LlmClient::new(InferenceConfig::default());
        let result = client.generate("system", "user", 16).await;
        assert!(matches!(result, Err(AiError::ModelUnavailable(_))));
    }

    #[tokio::test]
    async fn rejects_unknown_model_before_network_access() {
        let mut config = InferenceConfig::default();
        config.enabled = true;
        let client = LlmClient::new(config);
        let result = client.predict("unknown", serde_json::json!({})).await;
        assert!(matches!(result, Err(AiError::ModelNotFound(_))));
    }
}