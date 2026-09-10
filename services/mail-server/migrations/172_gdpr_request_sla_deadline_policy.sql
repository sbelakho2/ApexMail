-- 172: shared calendar-aware GDPR request SLA deadline policy (audit F78).
--
-- DEFECT: the admin compliance overview queried gdpr_requests.sla_deadline
-- twice, but that column does not exist in the canonical gdpr_requests
-- model (the table does, so the route's existence guard passed and the SQL
-- error propagated instead of the overview).
--
-- POLICY: deadlines are deliberately DERIVED from the recorded request
-- timestamp rather than persisted — the request workflow does not record
-- authorized extensions, so a stored deadline column would only ever hold
-- a recomputable value and could silently drift from the rule. The one
-- authoritative calculation lives in THIS function and every consumer
-- (both overview queries, future reports) must call it:
--
--   gdpr_request_sla_deadline(created_at) = created_at + one calendar month
--
-- GDPR Art. 12(3): the controller responds without undue delay and in any
-- event within ONE MONTH of receipt. Calendar-month arithmetic is used
-- (2026-01-31 -> 2026-02-28), not a fixed 30x24h interval, so counts agree
-- across calendar boundaries (short months, leap Februaries). A request is
-- OVERDUE when it is still open (status not completed/rejected) and the
-- derived deadline is in the past.
--
-- LIMITATION (recorded here on purpose): authorized statutory extensions
-- (up to two further months for complex requests) are not persisted by the
-- current workflow, so they cannot widen a derived deadline. When the
-- workflow starts recording extensions, add the extension column and fold
-- it into this function — consumers keep calling the same policy.

CREATE OR REPLACE FUNCTION gdpr_request_sla_deadline(p_created_at TIMESTAMPTZ)
RETURNS TIMESTAMPTZ
LANGUAGE SQL
IMMUTABLE
RETURNS NULL ON NULL INPUT
AS $$
    SELECT p_created_at + INTERVAL '1 month'
$$;

COMMENT ON FUNCTION gdpr_request_sla_deadline(TIMESTAMPTZ) IS
    'Authoritative GDPR request SLA deadline: one calendar month after the recorded creation timestamp (audit F78).';
