-- Daily OTP SMS actually sent (i.e. passed risk control) with the `filled` label.
-- filled=1 means the recipient actually entered the code => genuine user.
-- A collapsing fill-rate on non-+1 traffic is the ground-truth signature of SMS pumping.
-- sent_time is NULL for every row in this table -- use create_time.
SELECT DATE(create_time) d,
       CASE WHEN area_code IN ('1','+1')   THEN '+1'
            WHEN area_code IN ('86','+86') THEN '+86'
            WHEN area_code IS NULL OR area_code='' THEN 'unknown'
            ELSE 'other' END AS ac_group,
       TRIM(LEADING '+' FROM area_code) AS area_code,
       COUNT(*) sends, SUM(filled) filled_n, COUNT(DISTINCT mobile) phones
FROM luckyus_iupushsms.t_sent_verifycode_sms
WHERE tenant='LKUS' AND create_time >= '{t0}'
GROUP BY d, ac_group, area_code
ORDER BY d, sends DESC
