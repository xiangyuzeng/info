"""Shared 口径 (definitions) for every LKUS_push analysis.

Every definition here is stated in out/00_数据口径与数据质量说明.md. Nothing that
touches a published number may be redefined ad hoc elsewhere.
"""
import json
import os

import numpy as np
import pandas as pd

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
RISK_PARQUET = os.path.join(DATA, "risk_log.parquet")

# Storage timezone verified empirically: NOW() == UTC_TIMESTAMP(), @@time_zone='UTC'.
EDT_OFFSET_H = -4          # US Eastern in September (EDT = UTC-4)
BEIJING_OFFSET_H = 8

US_CODES = {"1"}
CN_CODES = {"86"}
ATTACK_START = pd.Timestamp("2026-09-03")     # first day non-+1 sends break baseline
PRE_ATTACK = ("2026-08-09", "2026-09-03")     # 误伤 baseline window (non-+1 ~= legit)


def norm_cc(s):
    """Area codes are stored with '+' in MySQL and without it in the warehouse view."""
    return s.astype("string").str.strip().str.lstrip("+").replace({"": pd.NA})


def ac_group(cc):
    """+1 / +86 / 非+1+86 / 未知 -- four buckets, never fold 未知 into 非美国."""
    return np.where(cc.isna(), "未知",
           np.where(cc.isin(US_CODES), "+1",
           np.where(cc.isin(CN_CODES), "+86", "非+1/+86")))


def ip_country_group(s):
    """美国 / 非美国 / 未知 -- three buckets. Null ip_country is never 非美国."""
    v = s.astype("string").str.strip()
    return np.where(v.isna() | (v == ""), "未知",
           np.where(v == "美国", "美国", "非美国"))


def token_bucket(score, lo=0.3):
    """<=0.3 / >0.3 / 空置. Blank is NEVER treated as low (David's rule 9.1)."""
    s = pd.to_numeric(score, errors="coerce")
    return np.where(s.isna(), "空置", np.where(s <= lo, f"<={lo}", f">{lo}"))


def _as_list(v):
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return []
    if isinstance(v, list):
        return [x for x in v if x]
    try:
        parsed = json.loads(v)
    except (TypeError, ValueError):
        return []
    return [x for x in parsed if x] if isinstance(parsed, list) else []


def _as_dict(v):
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return {}
    if isinstance(v, dict):
        return v
    try:
        parsed = json.loads(v)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


FEATURE_COLS = {
    "f_phone_1d":      "手机号近1天的访问次数",
    "f_phone_1m":      "手机号近1分钟的访问次数",
    "f_phone_5m":      "手机号近5分钟的访问次数",
    "f_phone_30m":     "手机号近30分钟的访问次数",
    "f_ac_1m":         "区号近1分钟的访问次数",
    "f_ac_5m":         "区号近5分钟的访问次数",
    "f_ac_60m":        "区号近60分钟的访问次数",
    "f_ac_1d":         "区号近1天内的访问次数",
    "f_ip_1m":         "IP近1分钟的访问次数",
    "f_ip_5m_same":    "同IP近5分钟的访问次数",
    "f_ip_phone_1m":   "IP近1分钟关联的手机号个数",
    "f_ip_phone_5m":   "IP近5分钟关联的手机号个数",
    "f_ip_phone_10m":  "IP近10分钟关联的手机号个数",
    "f_ip_phone_60m":  "IP近60分钟关联的手机号个数",
    "f_ipc_phone_1m":  "IPC段近1分钟关联的手机号个数",
    "f_ipc_phone_10m": "IPC段近10分钟关联的手机号个数",
    "f_ip_cc_60m":     "IP近60分钟关联的国家区号个数",
    "f_phone_ipcity":  "同手机号30分钟关联的IP city个数",
    "f_ac_nonus_60m":  "同区号近60分钟非美国IP访问次数",
    "f_ac_notoken_60m": "同区号近60分钟未携带recaptchaV3token 访问次数",
    "f_req_1m":        "一分钟请求量",
    # renamed/reshaped variants that existed only in the 2026-08-27~09-05 feature set.
    # Different windows => genuinely different features, kept separate, never merged.
    "f_req_1h":        "一小时请求量",
    "f_ip_10m_same":   "同IP近10分钟的访问次数",
}


def load_risk(path=RISK_PARQUET):
    """Load the risk log and attach every derived 口径 column."""
    df = pd.read_parquet(path)
    df["create_time"] = pd.to_datetime(df["create_time"])
    df["ts_edt"] = df["create_time"] + pd.Timedelta(hours=EDT_OFFSET_H)
    df["date_utc"] = df["create_time"].dt.date
    df["date_edt"] = df["ts_edt"].dt.date
    df["hour_edt"] = df["ts_edt"].dt.hour

    df["cc"] = norm_cc(df["country_code"].fillna(df["cc_raw"]))
    df["ac_group"] = ac_group(df["cc"])
    df["ipc_group"] = ip_country_group(df["real_ip_country"])
    df["score"] = pd.to_numeric(df["recap_score"], errors="coerce")
    df["token_bucket"] = token_bucket(df["score"])
    df["has_token"] = df["recap_token_len"].fillna(0) > 0

    df["hit_online_l"] = df["hit_online"].map(_as_list)
    df["hit_pre_l"] = df["hit_preonline"].map(_as_list)
    df["n_hit_online"] = df["hit_online_l"].str.len()

    feats = df["feats"].map(_as_dict)
    for col, name in FEATURE_COLS.items():
        df[col] = pd.to_numeric(feats.map(lambda d, n=name: d.get(n)), errors="coerce")

    df["ip_c"] = df["real_ip"].astype("string").str.rsplit(".", n=1).str[0]
    df["ip_b"] = df["real_ip"].astype("string").str.split(".").str[:2].str.join(".")
    df["brand"] = (df["user_agent"].astype("string")
                   .str.extract(r"\(([^;)]+)[;)]", expand=False).str.strip())
    df["is_attack_window"] = df["create_time"] >= ATTACK_START
    return df


def hit(df, strategy_id):
    """Boolean mask: did this strategy hit, whether it is ONLINE or PREONLINE?"""
    return (df["hit_online_l"].map(lambda l: strategy_id in l)
            | df["hit_pre_l"].map(lambda l: strategy_id in l))


def mask_phone(cc, phone):
    """区号 + 前3位, per the task's PII rule."""
    p = "" if phone is None else str(phone)
    return f"+{cc}-{p[:3]}***" if p else f"+{cc}-***"


def pct(n, d):
    return 0.0 if not d else round(100.0 * n / d, 1)
