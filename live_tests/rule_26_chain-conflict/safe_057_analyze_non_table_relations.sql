-- PostgreSQL warns and skips ANALYZE on views, sequences, indexes, and composite types.
CREATE TABLE sm_core.analyze_probe (id integer, label text);
CREATE VIEW sm_core.analyze_probe_view AS SELECT id FROM sm_core.analyze_probe;
CREATE SEQUENCE sm_core.analyze_probe_seq;
CREATE INDEX analyze_probe_idx ON sm_core.analyze_probe (id);
CREATE TYPE sm_core.analyze_probe_comp AS (a integer, b text);
ANALYZE sm_core.analyze_probe_view;
ANALYZE sm_core.analyze_probe_seq;
ANALYZE sm_core.analyze_probe_idx;
ANALYZE sm_core.analyze_probe_comp;
ANALYZE sm_core.analyze_probe (id, label);
