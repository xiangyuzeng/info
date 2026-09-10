-- SOP §3.4 API链路异常: does this requester ever do anything except ask for an OTP?
-- A gateway uid that only ever appears in LKUS_push (never login / order / payment)
-- is a scripted client, not a customer.
SELECT JSON_UNQUOTE(JSON_EXTRACT(CAST(JSON_UNQUOTE(JSON_EXTRACT(request_strategy_engine,'$.para')) AS JSON),'$.uid')) AS uid,
       scene_id, COUNT(*) n
FROM luckyus_iriskcontrolservice.{tbl}
WHERE tenant='LKUS' AND create_time >= '{t0}' AND create_time < '{t1}'
GROUP BY uid, scene_id
