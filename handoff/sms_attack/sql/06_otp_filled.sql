-- Per-message OTP outcome. `mobile` is ciphertext, but `mask_no` exposes
-- area_code + first digit + '*****' + last 4, which is enough to join back to the
-- plaintext phone in the risk log on (area_code, last4) within a tight time window.
SELECT create_time, TRIM(LEADING '+' FROM area_code) AS area_code, mask_no,
       filled, provider, from_app_name, deliver_time
FROM luckyus_iupushsms.t_sent_verifycode_sms
WHERE tenant='LKUS' AND create_time >= '{t0}'
