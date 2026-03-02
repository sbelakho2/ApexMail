pub mod health;
pub mod auth;
pub mod account;
pub mod messages;
pub mod domains;
pub mod templates;
pub mod suppressions;
pub mod events;
pub mod webhooks;
pub mod analytics;
pub mod support;
pub mod scim;
pub mod campaigns;
pub mod contacts;
pub mod automations;
pub mod ai_insights;
pub mod dedicated_ips;
pub mod ses_notifications;

// Migrated from apps/web auth routes
pub mod session;
pub mod forgot_password;
pub mod sso;
pub mod impersonate;
pub mod csrf;
pub mod telemetry;

// Migrated from apps/control-plane
pub mod admin;
