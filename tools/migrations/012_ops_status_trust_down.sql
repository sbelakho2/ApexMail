-- Down migration for 012_ops_status_trust.sql

DROP TABLE IF EXISTS trust_faq;
DROP TABLE IF EXISTS trust_data_practices;
DROP TABLE IF EXISTS trust_sub_processors;
DROP TABLE IF EXISTS trust_security_controls;
DROP TABLE IF EXISTS trust_documents;
DROP TABLE IF EXISTS trust_certifications;
DROP TABLE IF EXISTS status_page_subscribers;
DROP TABLE IF EXISTS status_page_maintenance;
DROP TABLE IF EXISTS status_page_incident_updates;
DROP TABLE IF EXISTS status_page_incidents;
DROP TABLE IF EXISTS status_page_groups;
DROP TABLE IF EXISTS status_page_components;
