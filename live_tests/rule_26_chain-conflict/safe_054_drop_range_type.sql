-- `sm_core.energy_span` is a RANGE type in the baseline. Dropping it must not be
-- reported as a missing object, and its automatically created multirange must
-- not be treated as a dependent requiring CASCADE.
DROP TYPE sm_core.energy_span;
