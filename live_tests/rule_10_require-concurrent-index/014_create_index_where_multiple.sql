CREATE INDEX idx_msk ON t_large(id, created_at) WHERE id > 0 AND created_at > '2020-01-01';
