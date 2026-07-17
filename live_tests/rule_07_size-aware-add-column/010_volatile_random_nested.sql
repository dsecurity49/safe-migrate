ALTER TABLE test_table ADD COLUMN c INT DEFAULT (random() * 100)::int;
