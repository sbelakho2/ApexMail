//! gRPC Service Implementation
//!
//! Implements the OutboundService for email sending.

use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info};
use uuid::Uuid;

use mail_proto::generated::{
    outbound_service_server::OutboundService,
    QueueEmailRequest, QueueEmailResponse,
    SendEmailRequest, SendEmailResponse, RecipientResult,
    GetDeliveryStatusRequest, GetDeliveryStatusResponse,
    CancelEmailRequest, CancelEmailResponse,
    QueueBulkEmailsRequest, QueueBulkEmailsResponse,
    GetQueueStatsRequest, GetQueueStatsResponse,
    DeliveryStatus,
};
use crate::queue::{EmailQueue, QueuedEmail, EmailStatus, CancelResult};

const MAX_BULK_EMAILS: usize = 1_000;

/// Outbound gRPC service
pub struct OutboundServiceImpl {
    queue: Arc<EmailQueue>,
}

impl OutboundServiceImpl {
    pub fn new(queue: Arc<EmailQueue>) -> Self {
        Self { queue }
    }
}

#[tonic::async_trait]
impl OutboundService for OutboundServiceImpl {
/// Queue email for delivery
    async fn queue_email(
        &self,
        request: Request<QueueEmailRequest>,
    ) -> Result<Response<QueueEmailResponse>, Status> {
        let req = request.into_inner();
        
        debug!(
            from = %req.from,
            to = ?req.to,
            subject = %req.subject,
            campaign_id = %req.campaign_id,
            "Queueing email"
        );
        
        let email = QueuedEmail {
            id: Uuid::new_v4(),
            from_address: req.from,
            to_addresses: req.to,
            subject: req.subject,
            text_body: Some(req.text_body), // #118:Preserve empty string as Some("")
            html_body: if req.html_body.is_empty() { None } else { Some(req.html_body) },
            headers: serde_json::Value::Object(
                req.headers.into_iter().map(|(k, v)| (k, serde_json::Value::String(v))).collect()
            ),
            status: EmailStatus::Pending,
            attempts: 0,
            max_attempts: 5,
            last_error: None,
            next_retry_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            sent_at: None,
            campaign_id: if req.campaign_id.is_empty() { None } else { Uuid::parse_str(&req.campaign_id).ok() },
            sequence_id: None,
            contact_id: None,
            priority: 0,
        };
        
        match self.queue.enqueue(email).await {
            Ok(id) => {
                info!(email_id = %id, "Email queued");
                Ok(Response::new(QueueEmailResponse {
                    email_id: id.to_string(),
                    status: "queued".to_string(),
                }))
            }
            Err(e) => {
                error!(error = %e, "Failed to queue email");
                Err(Status::internal(format!("Failed to queue email: {}", e)))
            }
        }
    }
    
/// Send email immediately (bypassing queue)
    async fn send_email_now(
        &self,
        request: Request<SendEmailRequest>,
    ) -> Result<Response<SendEmailResponse>, Status> {
        let req = request.into_inner();
        
        debug!(
            from = %req.from,
            to = ?req.to,
            subject = %req.subject,
            "Sending email immediately"
        );
        
// Create a queued email with high priority
        let email = QueuedEmail {
            id: Uuid::new_v4(),
            from_address: req.from.clone(),
            to_addresses: req.to.clone(),
            subject: req.subject,
            text_body: Some(req.text_body), // #118:Preserve empty string
            html_body: if req.html_body.is_empty() { None } else { Some(req.html_body) },
            headers: serde_json::Value::Object(
                req.headers.into_iter().map(|(k, v)| (k, serde_json::Value::String(v))).collect()
            ),
            status: EmailStatus::Pending,
            attempts: 0,
            max_attempts: 1, // Immediate send - no retries
            last_error: None,
            next_retry_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            sent_at: None,
            campaign_id: None,
            sequence_id: None,
            contact_id: None,
            priority: 100, // High priority for immediate sends
        };
        
        match self.queue.enqueue(email.clone()).await {
            Ok(id) => {
// #116:Report queued status, not accepted:true — delivery hasn't happened yet
                info!(email_id = %id, "Email queued for immediate delivery");
                
                let recipients: Vec<RecipientResult> = req.to.iter().map(|email| {
                    RecipientResult {
                        email: email.clone(),
                        accepted: false, // Not yet delivered
                        error: String::default(),
                    }
                }).collect();
                
                Ok(Response::new(SendEmailResponse {
                    email_id: id.to_string(),
                    message_id: format!("<{}@apexmail.ee>", id),
                    success: true, // Queued successfully
                    error: String::default(),
                    recipients,
                }))
            }
            Err(e) => {
                error!(error = %e, "Failed to queue email");
                Ok(Response::new(SendEmailResponse {
                    email_id: String::new(),
                    message_id: String::new(),
                    success: false,
                    error: e.to_string(),
                    recipients: vec![],
                }))
            }
        }
    }
    
/// Get delivery status
    async fn get_delivery_status(
        &self,
        request: Request<GetDeliveryStatusRequest>,
    ) -> Result<Response<GetDeliveryStatusResponse>, Status> {
        let req = request.into_inner();

        let email_id = Uuid::parse_str(&req.email_id)
            .map_err(|e| Status::invalid_argument(format!("Invalid email ID: {}", e)))?;

        let email = self
            .queue
            .get_email(&email_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get delivery status: {}", e)))?;

        let email = match email {
            Some(email) => email,
            None => return Err(Status::not_found("Email not found")),
        };

        let status = match email.status {
            EmailStatus::Pending | EmailStatus::Deferred => DeliveryStatus::Queued,
            EmailStatus::Processing => DeliveryStatus::Sending,
            EmailStatus::Sent => DeliveryStatus::Sent,
            EmailStatus::Failed => DeliveryStatus::Failed,
        };

        Ok(Response::new(GetDeliveryStatusResponse {
            email_id: req.email_id,
            status: status as i32,
            queued_at: email.created_at.timestamp(),
            sent_at: email.sent_at.map(|ts| ts.timestamp()).unwrap_or(0),
            delivered_at: 0,
            bounced_at: 0,
            attempts: email.attempts,
            last_error: email.last_error.unwrap_or_default(),
            attempts_detail: vec![],
        }))
    }
    
/// Cancel queued email
    async fn cancel_email(
        &self,
        request: Request<CancelEmailRequest>,
    ) -> Result<Response<CancelEmailResponse>, Status> {
        let req = request.into_inner();
        
        let email_id = Uuid::parse_str(&req.email_id)
            .map_err(|e| Status::invalid_argument(format!("Invalid email ID: {}", e)))?;
        
// the TOCTOU race between reading status and writing the cancellation.
        match self.queue.cancel_email_atomic(&email_id).await {
            Ok(CancelResult::Cancelled) => {
                info!(email_id = %email_id, "Email cancelled");
                Ok(Response::new(CancelEmailResponse {
                    success: true,
                    error: String::new(),
                }))
            }
            Ok(CancelResult::NotFound) => {
                Err(Status::not_found("Email not found"))
            }
            Ok(CancelResult::NotCancellable(reason)) => {
                Ok(Response::new(CancelEmailResponse {
                    success: false,
                    error: reason,
                }))
            }
            Err(e) => {
                error!(error = %e, "Failed to cancel email");
                Ok(Response::new(CancelEmailResponse {
                    success: false,
                    error: e.to_string(),
                }))
            }
        }
    }
    
/// Queue bulk emails
    async fn queue_bulk_emails(
        &self,
        request: Request<QueueBulkEmailsRequest>,
    ) -> Result<Response<QueueBulkEmailsResponse>, Status> {
        let req = request.into_inner();
        if req.emails.len() > MAX_BULK_EMAILS {
            return Err(Status::invalid_argument(format!(
                "bulk email request limited to {} entries",
                MAX_BULK_EMAILS
            )));
        }
        let mut results = Vec::with_capacity(req.emails.len());
        let mut queued_count = 0i32;
        let mut failed_count = 0i32;
        
        for email_req in req.emails {
            let email = QueuedEmail {
                id: Uuid::new_v4(),
                from_address: email_req.from,
                to_addresses: email_req.to,
                subject: email_req.subject,
                text_body: Some(email_req.text_body), // #118:Preserve empty string
                html_body: if email_req.html_body.is_empty() { None } else { Some(email_req.html_body) },
                headers: serde_json::Value::Object(
                    email_req.headers.into_iter().map(|(k, v)| (k, serde_json::Value::String(v))).collect()
                ),
                status: EmailStatus::Pending,
                attempts: 0,
                max_attempts: 5,
                last_error: None,
                next_retry_at: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                sent_at: None,
                campaign_id: if email_req.campaign_id.is_empty() { None } else { Uuid::parse_str(&email_req.campaign_id).ok() },
                sequence_id: None,
                contact_id: None,
                priority: 0,
            };
            
            match self.queue.enqueue(email).await {
                Ok(id) => {
                    queued_count += 1;
                    results.push(QueueEmailResponse {
                        email_id: id.to_string(),
                        status: "queued".to_string(),
                    });
                }
                Err(e) => {
                    failed_count += 1;
                    results.push(QueueEmailResponse {
                        email_id: String::new(),
                        status: format!("failed: {}", e),
                    });
                }
            }
        }
        
        info!(queued = queued_count, failed = failed_count, "Bulk emails processed");
        
        Ok(Response::new(QueueBulkEmailsResponse {
            results,
            queued_count,
            failed_count,
        }))
    }
    
/// Get queue statistics
    async fn get_queue_stats(
        &self,
        _request: Request<GetQueueStatsRequest>,
    ) -> Result<Response<GetQueueStatsResponse>, Status> {
        match self.queue.get_stats().await {
            Ok(stats) => {
                Ok(Response::new(GetQueueStatsResponse {
                    pending_count: stats.pending as i64,
                    sending_count: stats.processing as i64,
                    sent_today: stats.sent as i64,
                    failed_today: stats.failed as i64,
                    bounced_today: 0,
                    average_delivery_time_ms: 0.0,
                }))
            }
            Err(e) => {
                error!(error = %e, "Failed to get queue stats");
                Err(Status::internal(e.to_string()))
            }
        }
    }
}
