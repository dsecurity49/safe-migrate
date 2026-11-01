-- A renamed multirange remains the range's implicit companion, so dropping the
-- range must still remove it without requiring CASCADE.
ALTER TYPE sm_core.energy_span_multirange RENAME TO energy_span_multi;
DROP TYPE sm_core.energy_span;
