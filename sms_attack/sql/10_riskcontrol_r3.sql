-- Round-3 pull: same shape as 08_riskcontrol_20d.sql plus the token-state field.
--
-- Why a new file: 08 captures recaptcha_score but NOT whether a token was presented at
-- all. Round 3 turns on exactly that distinction -- 段枝宏 2026-09-11: "后续黑产可能不再
-- 带 recaptcher 的 token 了，对应的风险分特征就失效了". A missing score and a missing
-- token are different states (score can be absent because Google did not answer), so
-- recap_token_len is pulled alongside the score and never inferred from it.
--
-- Three constraints carried over unchanged, each paid for in an earlier round:
--   1. reCAPTCHA score is matched by SHAPE, never by feature name (renamed 3x in 30 days;
--      name-matching fails silently and looks exactly like a reCAPTCHA outage).
--   2. Raw featureDetail is never SELECTed (~20.6 KB/row -> ~1.3 GB for 20 days).
--   3. No REPLACE( anywhere -- the gateway rejects such a SELECT as a write operation.
--      Strip the '+' with TRIM(LEADING '+' FROM ...).
--
-- l1_scene='1000' == scene_id='LKUS_push' (verified). l2_scene has no source-side
-- equivalent; left NULL rather than guessed.
-- Placeholders: {tbl} {days}
SELECT
  l.id,
  l.create_time                                            AS access_time,
  DATE_FORMAT(l.create_time,'%Y-%m')                       AS access_time_mn,
  DATE_FORMAT(l.create_time,'%Y-%m-%d')                    AS access_time_dt,
  DATE_FORMAT(l.create_time,'%Y-%m-%dT%H')                 AS access_time_hr,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.cid'))                   AS cid,
  l.scene_id,
  '1000'                                                   AS l1_scene,
  NULL                                                     AS l2_scene,
  l.result,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.version'))               AS version,
  TRIM(LEADING '+' FROM COALESCE(JSON_UNQUOTE(JSON_EXTRACT(pa,'$.countryCode')), l.country_code))
                                                           AS country_code,
  COALESCE(JSON_UNQUOTE(JSON_EXTRACT(pa,'$.phoneNo')), l.phone) AS phone_no,
  l.user_no,
  COALESCE(JSON_UNQUOTE(JSON_EXTRACT(pa,'$.realIp')), l.ip) AS ip,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.realIpCountry'))         AS ip_country,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.realIpProvince'))        AS ip_province,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.realIpCity'))            AS ip_city,
  JSON_UNQUOTE(JSON_EXTRACT(l.response,'$.code'))          AS risk_resp_code,
  JSON_UNQUOTE(JSON_EXTRACT(l.response,'$.detail'))        AS risk_resp_detail,
  JSON_UNQUOTE(JSON_EXTRACT(l.response,'$.message'))       AS risk_resp_message,
  JSON_UNQUOTE(JSON_EXTRACT(l.response,'$.result'))        AS risk_resp_result,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.uid'))                   AS gateway_uid,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.userAgent'))             AS user_agent,
  -- token STATE, not the token: length only. 0/NULL vs >0 separates absent/empty from
  -- present. The token itself is a credential and never leaves the database.
  CHAR_LENGTH(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(pa,'$.recaptchaV3Token')),''))
                                                           AS recap_token_len,
  -- distinguishes "key absent from para" from "key present but empty string"
  CASE WHEN JSON_EXTRACT(pa,'$.recaptchaV3Token') IS NULL THEN 'absent'
       WHEN JSON_UNQUOTE(JSON_EXTRACT(pa,'$.recaptchaV3Token')) = '' THEN 'empty'
       ELSE 'present' END                                  AS token_state,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.recaptchaV3Enabled'))    AS recap_enabled,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.recaptchaV3Action'))     AS recap_action,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.app'))                   AS app,
  (SELECT JSON_OBJECTAGG(x.nm, COALESCE(x.v,''))
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.featureDetail')) AS JSON),
          '$[*]' COLUMNS (nm VARCHAR(200) PATH '$.name', v VARCHAR(60) PATH '$.comments.apiResp')) x
    WHERE x.nm NOT LIKE '%名单%' AND x.nm NOT REGEXP '^reCAPTCHA V3')      AS feats_json,
  (SELECT MAX(CASE WHEN JSON_VALID(x.v)
                   THEN JSON_UNQUOTE(JSON_EXTRACT(CAST(x.v AS JSON),'$.riskAnalysis.score')) END)
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.featureDetail')) AS JSON),
          '$[*]' COLUMNS (nm VARCHAR(200) PATH '$.name', v LONGTEXT PATH '$.comments.apiResp')) x
    WHERE x.nm REGEXP '^reCAPTCHA V3')                                     AS recaptcha_score,
  -- which reCAPTCHA feature name(s) the engine used on this row: the rename audit trail
  (SELECT GROUP_CONCAT(DISTINCT x.nm)
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.featureDetail')) AS JSON),
          '$[*]' COLUMNS (nm VARCHAR(200) PATH '$.name')) x
    WHERE x.nm REGEXP '^reCAPTCHA V3')                                     AS recap_feature_name,
  (SELECT JSON_ARRAYAGG(JSON_UNQUOTE(JSON_EXTRACT(h.e,'$.strategyId')))
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.hitStrategy')) AS JSON),
          '$[*]' COLUMNS (e JSON PATH '$')) h)                             AS hit_online,
  (SELECT JSON_ARRAYAGG(JSON_UNQUOTE(JSON_EXTRACT(h.e,'$.strategyId')))
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.hitPreOnlineStrategy')) AS JSON),
          '$[*]' COLUMNS (e JSON PATH '$')) h)                             AS hit_preonline,
  JSON_UNQUOTE(JSON_EXTRACT(re,'$.bestStrategyId'))        AS best_strategy_id,
  JSON_UNQUOTE(JSON_EXTRACT(re,'$.bestPreOnlineStrategyId')) AS best_pre_strategy_id
FROM (
  SELECT id, create_time, scene_id, result, user_no, ip, phone, country_code, response,
         CAST(JSON_UNQUOTE(JSON_EXTRACT(request_strategy_engine,'$.para')) AS JSON) AS pa,
         JSON_EXTRACT(response_strategy_engine,'$.re') AS re
  FROM luckyus_iriskcontrolservice.{tbl}
  WHERE tenant='LKUS' AND scene_id='LKUS_push'
    AND create_time >= NOW() - INTERVAL {days} DAY
    AND country_code IS NOT NULL AND country_code <> ''
) l
