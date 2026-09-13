"""Round-3 core: sets, single-field profiles, conjunction mining, recall.

Method is fixed by 段枝宏 2026-09-12: feature discovery happens ONLY on the leaked
(PASS) foreign traffic; the rest of the log is a control group used to measure false
blocks, never a discovery set. Threshold/velocity rules are not proposed as primaries.

Column aliasing: the round-3 pull uses the warehouse-style names (access_time, ip,
ip_country, recaptcha_score) while common.py / label.py were written against the
scalar-pull names (create_time, real_ip, real_ip_country, recap_score). load() maps one
onto the other so the SOP grading in label.add_evidence is reused, not reimplemented.
"""
import os

import numpy as np
import pandas as pd

from .common import (ATTACK_START, EDT_OFFSET_H, PRE_ATTACK, _as_list, ac_group,
                     ip_country_group, norm_cc, token_bucket)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT3 = os.path.join(ROOT, "out3")
DATA3 = os.path.join(OUT3, "data")

# Live at the time of this round; go-live times read from t_rms_engine_strategy.update_time
LIVE = {
    "strategy_uKSgJAVWhWlU": pd.Timestamp("2026-09-09 16:43:06"),
    "strategy_ARqkLD7E3JaK": pd.Timestamp("2026-09-10 15:50:16"),
    "strategy_rDf6oPcZ8ydk": pd.Timestamp("2026-09-10 15:51:06"),
}


def load(path=None):
    path = path or os.path.join(DATA3, "r3_riskcontrol_35d.parquet")
    df = pd.read_parquet(path)
    df["create_time"] = pd.to_datetime(df["access_time"])
    df["ts_edt"] = df["create_time"] + pd.Timedelta(hours=EDT_OFFSET_H)
    df["date_utc"] = df["create_time"].dt.date
    df["hour_edt"] = df["ts_edt"].dt.hour

    # aliases so label.add_evidence / common.hit work unchanged
    df["uid"] = df["gateway_uid"]
    df["phone"] = df["phone_no"]
    df["real_ip"] = df["ip"]
    df["real_ip_country"] = df["ip_country"]
    df["recap_score"] = df["recaptcha_score"]

    df["cc"] = norm_cc(df["country_code"])
    df["ac_group"] = ac_group(df["cc"])
    df["ipc_group"] = ip_country_group(df["real_ip_country"])
    df["score"] = pd.to_numeric(df["recaptcha_score"], errors="coerce")
    df["token_bucket"] = token_bucket(df["score"])
    # token_state comes straight from the engine's para: absent / empty / present.
    # NOT inferred from the score -- a missing score can also mean Google did not answer.
    df["has_token"] = df["token_state"] == "present"

    df["hit_online_l"] = df["hit_online"].map(_as_list)
    df["hit_pre_l"] = df["hit_preonline"].map(_as_list)

    df["ip_c"] = df["real_ip"].astype("string").str.rsplit(".", n=1).str[0]
    df["ip_b"] = df["real_ip"].astype("string").str.split(".").str[:2].str.join(".")
    df["brand"] = (df["user_agent"].astype("string")
                   .str.extract(r"\(([^;)]+)[;)]", expand=False).str.strip())
    df["ua_family"] = np.where(df["user_agent"].astype("string").str.contains("luckin coffee/", na=False), "Android-App",
                       np.where(df["user_agent"].astype("string").str.contains("LuckinCoffeeUS/", na=False), "iOS-App",
                       np.where(df["user_agent"].astype("string").str.contains("okhttp", na=False), "okhttp",
                       np.where(df["user_agent"].astype("string").str.contains("Mozilla", na=False), "WebView", "其他"))))
    df["os_family"] = np.where(df["user_agent"].astype("string").str.contains("Android", na=False), "Android",
                       np.where(df["user_agent"].astype("string").str.contains("iOS|iPhone OS", na=False, regex=True), "iOS", "未知"))
    df["phone_len"] = df["phone"].astype("string").str.len()
    df["is_attack_window"] = df["create_time"] >= ATTACK_START
    return df


def windows(df):
    """The four analysis windows, anchored on the newest row so a re-run self-dates."""
    end = df["create_time"].max()
    return {
        "t24_end": end,
        "t24_start": end - pd.Timedelta(hours=24),
        "pre_start": pd.Timestamp(PRE_ATTACK[0]),
        "pre_end": pd.Timestamp(PRE_ATTACK[1]),
    }


def sets(df):
    """A / B / C1 / C2 / C3 per the brief §8.

    A  境外区号 ∧ 非美国IP ∧ PASS，最近24h      -- discovery set
    B  境外区号 ∧ PASS，最近24h                 -- A plus the US-hosting-IP part
    C1 +1/+86 流量，同24h                       --本土正常用户对照
    C2 境外区号全量，攻击前窗口                  -- CONTAMINATED, see note
    C3 攻击期内 OTP 已填充的境外请求             -- the decisive false-block control
    """
    w = windows(df)
    last24 = df[(df.create_time > w["t24_start"]) & (df.create_time <= w["t24_end"])]
    frn = df.ac_group == "非+1/+86"

    A = last24[(last24.ac_group == "非+1/+86") & (last24.ipc_group != "美国") & (last24.result == "PASS")]
    B = last24[(last24.ac_group == "非+1/+86") & (last24.result == "PASS")]
    C1 = last24[last24.ac_group.isin(["+1", "+86"])]
    C2 = df[frn & (df.create_time >= w["pre_start"]) & (df.create_time < w["pre_end"])]
    # C3 needs otp_filled, attached by label.add_evidence; empty until then
    C3 = df[frn & df.is_attack_window & (df.get("otp_filled") == 1)] if "otp_filled" in df else df.iloc[0:0]
    return {"A": A, "B": B, "C1": C1, "C2": C2, "C3": C3}


def profile(sets_, col, top=25):
    """Single-field profile: value · count in A · share of A · counts in each control."""
    A = sets_["A"]
    vc = A[col].astype("string").value_counts(dropna=False).head(top)
    rows = []
    for val, n in vc.items():
        r = {"字段": col, "取值": val, "A中计数": int(n), "占A%": round(100 * n / max(len(A), 1), 2)}
        for k in ("B", "C1", "C2", "C3"):
            d = sets_[k]
            m = int((d[col].astype("string") == val).sum()) if len(d) else 0
            r[f"{k}中计数"] = m
            r[f"{k}中占比%"] = round(100 * m / max(len(d), 1), 2) if len(d) else 0.0
        # lift vs the +1 control: how much more common here than among real US users
        r["lift_vs_C1"] = round(r["占A%"] / r["C1中占比%"], 1) if r["C1中占比%"] else float("inf")
        rows.append(r)
    return pd.DataFrame(rows)


def evaluate_rule(sets_, mask_fn, name, rule_text, evade, token_proof, note=""):
    """Score one candidate conjunction against A/B and every control group."""
    A, B = sets_["A"], sets_["B"]
    mA, mB = mask_fn(A), mask_fn(B)
    r = {
        "候选": name, "规则(引擎语法)": rule_text,
        "A命中": int(mA.sum()), "覆盖A%": round(100 * mA.mean(), 1) if len(A) else 0.0,
        "A命中uv": int(A.loc[mA, "phone"].nunique()),
        "B命中": int(mB.sum()), "覆盖B%": round(100 * mB.mean(), 1) if len(B) else 0.0,
    }
    for k in ("C1", "C2", "C3"):
        d = sets_[k]
        m = mask_fn(d) if len(d) else pd.Series(dtype=bool)
        r[f"{k}命中"] = int(m.sum()) if len(d) else 0
        r[f"{k}命中%"] = round(100 * m.mean(), 2) if len(d) else 0.0
    r["规避成本"] = evade
    r["token缺失后仍有效"] = token_proof
    r["备注"] = note
    return r
