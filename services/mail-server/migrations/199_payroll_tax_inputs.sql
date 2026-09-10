-- 199_payroll_tax_inputs.sql
--
-- =============================================================================
-- F81: canonical payroll model with the per-employee tax inputs the
-- statutory salary computations need. estonia_ou.rs query_employees reads
-- payroll_records (employee_name, personal_code, gross_salary_cents,
-- pay_period) and previously applied ONE permanent constant pension rate
-- (2%) and one income-tax rate to every row — but funded pension (II
-- pillar) is an employee-specific choice (2/4/6%, or 0% when not
-- participating / exempt) and the withheld income-tax rate is
-- date-effective, so the inputs must live on the payment record.
--
-- Shape: same columns query_employees already selects, plus
--   * funded_pension_rate — the employee's II-pillar choice for the period
--     (NULL = participation unknown → the calculation reports the record
--     as incomplete instead of silently assuming a rate),
--   * pension_exemption — employee legally exempt from pension insurance,
--   * unemployment_insurance_exemption — employee exempt from unemployment
--     insurance (e.g. receiving old-age pension).
--
-- Rates are computed per payment period through the versioned, date-
-- effective tax policy module (compliance/src/tax_policy.rs), never stored
-- as constants here.
-- =============================================================================

CREATE TABLE IF NOT EXISTS payroll_records (
    id                                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_name                     TEXT        NOT NULL,
    personal_code                     TEXT,
    gross_salary_cents                BIGINT      NOT NULL
        CHECK (gross_salary_cents >= 0),
    funded_pension_rate               DOUBLE PRECISION
        CHECK (funded_pension_rate IS NULL
               OR funded_pension_rate IN (0.0, 0.02, 0.04, 0.06)),
    pension_exemption                 BOOLEAN     NOT NULL DEFAULT false,
    unemployment_insurance_exemption  BOOLEAN     NOT NULL DEFAULT false,
    pay_period                        TIMESTAMPTZ NOT NULL,
    created_at                        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- query_employees: per-period lookup.
CREATE INDEX IF NOT EXISTS idx_payroll_records_period
    ON payroll_records (pay_period);
CREATE INDEX IF NOT EXISTS idx_payroll_records_employee
    ON payroll_records (employee_name, pay_period DESC);
