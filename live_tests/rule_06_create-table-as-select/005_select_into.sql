-- The shared differential baseline owns sm_core.t and uses sm_core first in
-- search_path. Keep this target distinct so this case exercises SELECT INTO.
SELECT * INTO select_into_result FROM test_table;
