-- =====================================================================
-- LKUS 风控日志 · 近 20 天 · Doris 版（宽表：一行一请求）
-- 生成日期 2026-09-10 · 北美安全 / DBA
-- =====================================================================
-- ⚠️ 未实测：databasecheck 在 Doris 上无账号（1045 Access denied），本文件无法在真实
--    Doris 上验证。仅使用团队既有查询中已跑通过的函数：GET_JSON_STRING / JSON_EXTRACT /
--    DATE_FORMAT / CONCAT / LATERAL VIEW EXPLODE_JSON_ARRAY_JSON / NOW() - INTERVAL。
--    未使用 MAP_AGG / REGEXP_REPLACE / DATE_SUB / JSON_TABLE（后者为 MySQL 8 专有）。
--
-- 【为什么这样写】直接 SELECT featureDetail 原串会拖垮查询：该字段实测均值 20,641 字节/行，
--    20 天约 6.5 万行 ≈ 1.3 GB，瓶颈在结果回传而非扫描。这里把它 EXPLODE 成行、
--    只取需要的值、再透视回一行一请求，每行约 500 字节，小 40 倍。
--
-- ⚠️ 坑 A：GROUP BY 必须带每请求唯一键。
--    实测（源库单分片 912 行）：仅按「时间+号码+IP」聚合只剩 899 个唯一值，
--    13 行（1.4%）会被静默合并。因此这里用 requestId 作为分组主键。
--    残留：requestId 为空的极少数行（实测 5/912）若自然键相同仍会合并。
--
-- ⚠️ 坑 B：LATERAL VIEW 是 inner 语义，featureDetail 为空的请求会被整行丢掉。
--    若必须保留，改用 EXPLODE_JSON_ARRAY_JSON_OUTER（若该版本支持），
--    或先跑不带特征的轻量版，再与本查询结果 LEFT JOIN。
--
-- 验收基准（同窗口源库实测值，跑完请逐项对照）：
--    行数 64,931 · PASS 41,629 / REJECT 23,121 / REVIEW 181
--    country_code top: 1=23,130 · 92=5,359 · 265=5,223 · 375=4,499 · 213=4,465 · 386=4,384
--    recaptcha_score 非空 55,333
-- =====================================================================
SELECT
  GET_JSON_STRING(extend, '$.respDetailStrategyEngine.re.requestId')
    AS request_id,
  access_time                                         AS access_time,
  CONCAT(DATE_FORMAT(access_time, '%Y-%m'))           AS access_time_mn,
  CONCAT(DATE_FORMAT(access_time, '%Y-%m-%d'))        AS access_time_dt,
  CONCAT(DATE_FORMAT(access_time, '%Y-%m-%dT%H'))
    AS access_time_hr,
  cid                                                 AS cid,
  scene_id                                            AS scene_id,
  l1_scene                                            AS l1_scene,
  l2_scene                                            AS l2_scene,
  result                                              AS result,
  version                                             AS version,
  country_code                                        AS country_code,
  phone_no                                            AS phone_no,
  user_no                                             AS user_no,
  ip                                                  AS ip,
  ip_country                                          AS ip_country,
  ip_province                                         AS ip_province,
  ip_city                                             AS ip_city,
  JSON_EXTRACT(resp_detail, '$.code')                 AS risk_resp_code,
  JSON_EXTRACT(resp_detail, '$.detail')               AS risk_resp_detail,
  JSON_EXTRACT(resp_detail, '$.message')              AS risk_resp_message,
  JSON_EXTRACT(resp_detail, '$.result')               AS risk_resp_result,

  -- ---- featureDetail 透视：23 个频次特征各一列（特征名取自实测数据，非手写）----
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '手机号近1天的访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_phone_1d,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '手机号近1分钟的访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_phone_1m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '手机号近5分钟的访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_phone_5m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '手机号近30分钟的访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_phone_30m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '区号近1分钟的访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ac_1m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '区号近5分钟的访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ac_5m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '区号近60分钟的访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ac_60m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '区号近1天内的访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ac_1d,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = 'IP近1分钟的访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ip_1m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '同IP近5分钟的访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ip_5m_same,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = 'IP近1分钟关联的手机号个数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ip_phone_1m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = 'IP近5分钟关联的手机号个数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ip_phone_5m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = 'IP近10分钟关联的手机号个数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ip_phone_10m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = 'IP近60分钟关联的手机号个数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ip_phone_60m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = 'IPC段近1分钟关联的手机号个数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ipc_phone_1m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = 'IPC段近10分钟关联的手机号个数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ipc_phone_10m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = 'IP近60分钟关联的国家区号个数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ip_cc_60m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '同手机号30分钟关联的IP city个数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_phone_ipcity,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '同区号近60分钟非美国IP访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ac_nonus_60m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '同区号近60分钟未携带recaptchaV3token 访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ac_notoken_60m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '一分钟请求量'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_req_1m,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '一小时请求量'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_req_1h,
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') = '同IP近10分钟的访问次数'
           THEN GET_JSON_STRING(feature, '$.comments.apiResp') END)   AS f_ip_10m_same,

  -- 人机识别分：前缀匹配，同时覆盖改名前后的两个特征名（见手册「坑 1」）
  MAX(CASE WHEN GET_JSON_STRING(feature, '$.name') LIKE 'reCAPTCHA V3%'
           THEN GET_JSON_STRING(GET_JSON_STRING(feature, '$.comments.apiResp'), '$.riskAnalysis.score') END)   AS recaptcha_score

FROM t_iriskcontrol_log
LATERAL VIEW EXPLODE_JSON_ARRAY_JSON(
  GET_JSON_STRING(extend, '$.respDetailStrategyEngine.re.featureDetail')) t AS feature

WHERE tenant = 'LKUS'
  AND l1_scene = '1000'
  AND country_code IS NOT NULL
  AND country_code <> ''
  AND access_time >= NOW() - INTERVAL 20 DAY
  -- 特征名白名单：炸开后立刻收敛，约 230 万行 -> 150 万行（第二大性能杠杆）
  AND (
    GET_JSON_STRING(feature, '$.name') IN (
    '手机号近1天的访问次数',
    '手机号近1分钟的访问次数',
    '手机号近5分钟的访问次数',
    '手机号近30分钟的访问次数',
    '区号近1分钟的访问次数',
    '区号近5分钟的访问次数',
    '区号近60分钟的访问次数',
    '区号近1天内的访问次数',
    'IP近1分钟的访问次数',
    '同IP近5分钟的访问次数',
    'IP近1分钟关联的手机号个数',
    'IP近5分钟关联的手机号个数',
    'IP近10分钟关联的手机号个数',
    'IP近60分钟关联的手机号个数',
    'IPC段近1分钟关联的手机号个数',
    'IPC段近10分钟关联的手机号个数',
    'IP近60分钟关联的国家区号个数',
    '同手机号30分钟关联的IP city个数',
    '同区号近60分钟非美国IP访问次数',
    '同区号近60分钟未携带recaptchaV3token 访问次数',
    '一分钟请求量',
    '一小时请求量',
    '同IP近10分钟的访问次数'
    )
    OR GET_JSON_STRING(feature, '$.name') LIKE 'reCAPTCHA V3%'
  )

GROUP BY
  GET_JSON_STRING(extend, '$.respDetailStrategyEngine.re.requestId'),
  access_time,
  CONCAT(DATE_FORMAT(access_time, '%Y-%m')),
  CONCAT(DATE_FORMAT(access_time, '%Y-%m-%d')),
  CONCAT(DATE_FORMAT(access_time, '%Y-%m-%dT%H')),
  cid,
  scene_id,
  l1_scene,
  l2_scene,
  result,
  version,
  country_code,
  phone_no,
  user_no,
  ip,
  ip_country,
  ip_province,
  ip_city,
  JSON_EXTRACT(resp_detail, '$.code'),
  JSON_EXTRACT(resp_detail, '$.detail'),
  JSON_EXTRACT(resp_detail, '$.message'),
  JSON_EXTRACT(resp_detail, '$.result')
ORDER BY access_time
;
