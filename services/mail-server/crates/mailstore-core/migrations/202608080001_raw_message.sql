-- Add raw RFC5322 message bytes so IMAP FETCH BODY[] can return the exact
-- message as received/stored (previously only parsed text_body/html_body
-- were persisted, making full-message retrieval impossible).

ALTER TABLE mail_messages ADD COLUMN IF NOT EXISTS raw_message BYTEA;
