ALTER TABLE sm_core.batch1_rules DISABLE RULE rule_origin;
ALTER TABLE sm_core.batch1_rules ENABLE RULE rule_origin;
ALTER TABLE sm_core.batch1_rules DISABLE RULE rule_disabled;
ALTER TABLE sm_core.batch1_rules ENABLE REPLICA RULE rule_replica;
ALTER TABLE sm_core.batch1_rules ENABLE ALWAYS RULE rule_always;
