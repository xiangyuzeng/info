SELECT rule_id, rule_name, status, feature_id, feature_type,
       condition_type, condition_value, rule_express, access_id, operator,
       create_time, update_time
FROM luckyus_iriskcontrolservice.t_rms_engine_rule
ORDER BY update_time DESC
