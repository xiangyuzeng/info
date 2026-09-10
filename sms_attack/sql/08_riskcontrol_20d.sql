-- Doris-equivalent pull of t_iriskcontrol_log, from the MySQL upstream source.
--
-- Replaces:  SELECT ..., GET_JSON_STRING(extend,'$.respDetailStrategyEngine.re.featureDetail')
--            FROM t_iriskcontrol_log WHERE tenant='LKUS' AND l1_scene='1000' ...
-- That column averages ~20.6 KB/row, so selecting it raw moves ~1.2 GB for 20 days.
-- Here featureDetail is flattened SERVER-SIDE and only scalars cross the wire (~500 B/row).
--
-- l1_scene='1000' == scene_id='LKUS_push' (verified: the Doris export shows l1_scene is
-- uniformly 1000 across every LKUS_push row). l2_scene has no source-side equivalent.
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
  NULL                                                     AS l2_scene,   -- 源库无此字段，见 README
  l.result,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.version'))               AS version,
  TRIM(LEADING '+' FROM COALESCE(JSON_UNQUOTE(JSON_EXTRACT(pa,'$.countryCode')), l.country_code))
                                                           AS country_code,
  COALESCE(JSON_UNQUOTE(JSON_EXTRACT(pa,'$.phoneNo')), l.phone) AS phone_no,
  l.user_no,
  COALESCE(JSON_UNQUOTE(JSON_EXTRACT(pa,'$.realIp')), l.ip) AS ip,
  -- base ip_country/province/city columns are NULL for every row; the engine's judgement
  -- value lives in para -- that is also the value the strategies actually evaluate.
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.realIpCountry'))         AS ip_country,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.realIpProvince'))        AS ip_province,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.realIpCity'))            AS ip_city,
  JSON_UNQUOTE(JSON_EXTRACT(l.response,'$.code'))          AS risk_resp_code,
  JSON_UNQUOTE(JSON_EXTRACT(l.response,'$.detail'))        AS risk_resp_detail,
  JSON_UNQUOTE(JSON_EXTRACT(l.response,'$.message'))       AS risk_resp_message,
  JSON_UNQUOTE(JSON_EXTRACT(l.response,'$.result'))        AS risk_resp_result,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.uid'))                   AS gateway_uid,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.userAgent'))             AS user_agent,
  -- every non-list feature as a compact name -> value object (~500 B vs ~20 KB raw)
  (SELECT JSON_OBJECTAGG(x.nm, COALESCE(x.v,''))
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.featureDetail')) AS JSON),
          '$[*]' COLUMNS (nm VARCHAR(200) PATH '$.name', v VARCHAR(60) PATH '$.comments.apiResp')) x
    WHERE x.nm NOT LIKE '%名单%' AND x.nm NOT REGEXP '^reCAPTCHA V3')      AS feats_json,
  -- NAME-AGNOSTIC score: this feature was renamed 'reCAPTCHA V3 token是否有效' <->
  -- 'reCAPTCHA V3风险分' between 08-27 and 09-05. Matching a literal name silently drops
  -- the score for that whole window. Match the shape instead.
  (SELECT MAX(CASE WHEN JSON_VALID(x.v)
                   THEN JSON_UNQUOTE(JSON_EXTRACT(CAST(x.v AS JSON),'$.riskAnalysis.score')) END)
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.featureDetail')) AS JSON),
          '$[*]' COLUMNS (nm VARCHAR(200) PATH '$.name', v LONGTEXT PATH '$.comments.apiResp')) x
    WHERE x.nm REGEXP '^reCAPTCHA V3')                                     AS recaptcha_score,
  (SELECT JSON_ARRAYAGG(JSON_UNQUOTE(JSON_EXTRACT(h.e,'$.strategyId')))
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.hitStrategy')) AS JSON),
          '$[*]' COLUMNS (e JSON PATH '$')) h)                             AS hit_online,
  (SELECT JSON_ARRAYAGG(JSON_UNQUOTE(JSON_EXTRACT(h.e,'$.strategyId')))
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.hitPreOnlineStrategy')) AS JSON),
          '$[*]' COLUMNS (e JSON PATH '$')) h)                             AS hit_preonline,
  JSON_UNQUOTE(JSON_EXTRACT(re,'$.bestStrategyId'))        AS best_strategy_id
FROM (
  SELECT id, create_time, scene_id, result, user_no, ip, phone, country_code, response,
         CAST(JSON_UNQUOTE(JSON_EXTRACT(request_strategy_engine,'$.para')) AS JSON) AS pa,
         JSON_EXTRACT(response_strategy_engine,'$.re') AS re
  FROM luckyus_iriskcontrolservice.{tbl}
  WHERE tenant='LKUS' AND scene_id='LKUS_push'
    AND create_time >= NOW() - INTERVAL {days} DAY
    AND country_code IS NOT NULL AND country_code <> ''
) l
