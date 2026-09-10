-- Full RMS strategy catalogue for the SMS scene, with rule expansion.
-- status: 1=ONLINE, 2=PREONLINE(观察), 0=关闭
SELECT s.strategy_id, s.strategy_name, s.status, s.result_code, s.exec_priority,
       s.scene_id, s.strategy_express, s.rule_operator, s.strategy_type,
       s.operator, s.create_time, s.update_time, s.remarks, s.description
FROM luckyus_iriskcontrolservice.t_rms_engine_strategy s
WHERE s.scene_id = 'LKUS_push'
ORDER BY s.status DESC, s.update_time DESC
