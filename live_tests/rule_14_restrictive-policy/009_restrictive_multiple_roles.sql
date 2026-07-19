CREATE POLICY p ON test_table AS RESTRICTIVE FOR SELECT TO admin, manager USING (true);
