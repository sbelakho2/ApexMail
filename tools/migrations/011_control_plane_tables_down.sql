-- =============================================================================
-- Rollback for 011_control_plane_tables.sql
-- =============================================================================

DROP TABLE IF EXISTS sandbox_stats CASCADE;
DROP TABLE IF EXISTS sandbox_captured_emails CASCADE;
DROP TABLE IF EXISTS autopilot_inbox_messages CASCADE;
DROP TABLE IF EXISTS support_ticket_messages CASCADE;
DROP TABLE IF EXISTS support_tickets CASCADE;
DROP TABLE IF EXISTS availability_slots CASCADE;
DROP TABLE IF EXISTS calendar_events CASCADE;
DROP TABLE IF EXISTS content_items CASCADE;
DROP TABLE IF EXISTS feature_flag_overrides CASCADE;
DROP TABLE IF EXISTS feature_flags CASCADE;
DROP TABLE IF EXISTS secrets CASCADE;
DROP TABLE IF EXISTS messages_archive CASCADE;
