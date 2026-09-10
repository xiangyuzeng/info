-- Per-shard scalar pull for the LKUS_push scene.
-- One row per risk-control request, with para/re JSON flattened server-side so the
-- 24KB engine blobs never cross the wire. Placeholders: {tbl} {t0} {t1}
SELECT
  l.id, l.create_time, l.result AS risk_result, l.country_code AS cc_raw,
  l.phone, l.ip, l.device_type, l.did, l.device_id, l.tongdun_device_id, l.email, l.user_no,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.uid'))                AS uid,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.realIp'))             AS real_ip,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.realIpCountry'))      AS real_ip_country,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.realIpCity'))         AS real_ip_city,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.realIpProvince'))     AS real_ip_province,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.cid'))                AS cid,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.version'))            AS version,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.countryCode'))        AS country_code,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.userAgent'))          AS user_agent,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.app'))                AS app,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.recaptchaV3Enabled')) AS recap_enabled,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.recaptchaV3Action'))  AS recap_action,
  JSON_UNQUOTE(JSON_EXTRACT(pa,'$.reviewRepeat'))       AS review_repeat,
  CHAR_LENGTH(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(pa,'$.recaptchaV3Token')),'')) AS recap_token_len,
  JSON_UNQUOTE(JSON_EXTRACT(re,'$.resultCode'))         AS result_code,
  JSON_UNQUOTE(JSON_EXTRACT(re,'$.resultName'))         AS result_name,
  JSON_UNQUOTE(JSON_EXTRACT(re,'$.bestStrategyId'))     AS best_strategy_id,
  JSON_UNQUOTE(JSON_EXTRACT(re,'$.bestPreOnlineStrategyId')) AS best_pre_strategy_id,
  (SELECT JSON_ARRAYAGG(JSON_UNQUOTE(JSON_EXTRACT(h.e,'$.strategyId')))
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.hitStrategy')) AS JSON),
          '$[*]' COLUMNS (e JSON PATH '$')) h)                      AS hit_online,
  (SELECT JSON_ARRAYAGG(JSON_UNQUOTE(JSON_EXTRACT(h.e,'$.strategyId')))
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.hitPreOnlineStrategy')) AS JSON),
          '$[*]' COLUMNS (e JSON PATH '$')) h)                      AS hit_preonline,
  (SELECT JSON_ARRAYAGG(JSON_UNQUOTE(JSON_EXTRACT(h.e,'$.strategyId')))
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.hitBreakStrategy')) AS JSON),
          '$[*]' COLUMNS (e JSON PATH '$')) h)                      AS hit_break,
  -- every non-list feature the engine computed, as name -> value
  (SELECT JSON_OBJECTAGG(x.nm, COALESCE(x.v,''))
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.featureDetail')) AS JSON),
          '$[*]' COLUMNS (nm VARCHAR(200) PATH '$.name', v VARCHAR(60) PATH '$.comments.apiResp')) x
    WHERE x.nm NOT LIKE '%名单%' AND x.nm NOT REGEXP '^reCAPTCHA V3')       AS feats,
  -- reCAPTCHA V3 risk score lives inside the token-validity feature's Google assessment
  -- NAME-AGNOSTIC on purpose: this feature was renamed
  -- 'reCAPTCHA V3 token是否有效' -> 'reCAPTCHA V3风险分' between 2026-08-27 and 09-05
  -- (both names coexist 09-06/07). Matching a literal name silently loses the score
  -- for that whole window and looks exactly like a reCAPTCHA outage. Match the shape
  -- (an apiResp that parses to a JSON object carrying riskAnalysis.score) instead.
  (SELECT MAX(CASE WHEN JSON_VALID(x.v)
                   THEN JSON_UNQUOTE(JSON_EXTRACT(CAST(x.v AS JSON),'$.riskAnalysis.score')) END)
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.featureDetail')) AS JSON),
          '$[*]' COLUMNS (nm VARCHAR(200) PATH '$.name', v LONGTEXT PATH '$.comments.apiResp')) x
    WHERE x.nm REGEXP '^reCAPTCHA V3')                              AS recap_score,
  (SELECT MAX(LEFT(x.v,40))
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.featureDetail')) AS JSON),
          '$[*]' COLUMNS (nm VARCHAR(200) PATH '$.name', v LONGTEXT PATH '$.comments.apiResp')) x
    WHERE x.nm REGEXP '^reCAPTCHA V3' AND JSON_VALID(x.v)=0)        AS recap_note,
  (SELECT GROUP_CONCAT(DISTINCT x.nm)
     FROM JSON_TABLE(CAST(JSON_UNQUOTE(JSON_EXTRACT(re,'$.featureDetail')) AS JSON),
          '$[*]' COLUMNS (nm VARCHAR(200) PATH '$.name')) x
    WHERE x.nm REGEXP '^reCAPTCHA V3')                              AS recap_feature_name
FROM (
  SELECT id, create_time, result, country_code, phone, ip, device_type, did, device_id,
         tongdun_device_id, email, user_no,
         CAST(JSON_UNQUOTE(JSON_EXTRACT(request_strategy_engine,'$.para')) AS JSON) AS pa,
         JSON_EXTRACT(response_strategy_engine,'$.re') AS re
  FROM luckyus_iriskcontrolservice.{tbl}
  WHERE tenant='LKUS' AND scene_id='LKUS_push'
    AND create_time >= '{t0}' AND create_time < '{t1}'
) l
