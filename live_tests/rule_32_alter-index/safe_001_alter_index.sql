ALTER INDEX test_table_note_idx SET TABLESPACE pg_default;
ALTER INDEX test_table_note_idx SET (fillfactor = 70);
ALTER INDEX test_table_note_idx RESET (fillfactor);
ALTER INDEX test_table_note_idx DEPENDS ON EXTENSION plpgsql;
ALTER INDEX test_table_note_idx NO DEPENDS ON EXTENSION plpgsql;
ALTER INDEX test_table_note_idx RENAME TO test_table_note_idx_renamed;