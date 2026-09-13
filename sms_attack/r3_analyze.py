"""Round-3 Stage 1: profile the leaked PASS traffic, mine feature conjunctions, score recall.

Run:  python -m sms_attack.r3_analyze
Writes out3/data/*.csv + feature_profiles.xlsx and prints the read-out the reports quote.
"""
import json
import os
import sys

import numpy as np
import pandas as pd

from . import r3
from .label import add_evidence
from .r3 import DATA3, OUT3

pd.set_option("display.width", 200)


# ---------------------------------------------------------------- atoms
# Every atom below must be expressible in the rule engine's own vocabulary
# (附录 B). Anything that is not is listed separately as 需新增特征.
def atoms(d):
    """name -> (boolean mask, engine-syntax fragment, evade cost)."""
    ua = d["user_agent"].astype("string")
    return {
        "cid=105":            (d["cid"].astype("string") == "105", "cid 包含 105", "低"),
        "cid∈{105,106,108}":  (d["cid"].astype("string").isin(["105", "106", "108"]),
                               "cid 包含 106,105,108", "低"),
        "token缺失":          (d["token_state"] == "absent", "字段 recaptchaV3Token 不存在", "极低"),
        "token为空串":        (d["token_state"] == "empty", "recaptchaV3Token 等于 ''", "极低"),
        "token缺失或空":      (d["token_state"].isin(["absent", "empty"]),
                               "(字段 recaptchaV3Token 不存在||recaptchaV3Token 等于 '')", "极低"),
        "分数存在且<0.3":     ((d["score"].notna()) & (d["score"] < 0.3),
                               "字段 reCAPTCHA V3风险分 存在&&reCAPTCHA V3风险分 小于 0.3", "中"),
        "分数存在且<=0.3":    ((d["score"].notna()) & (d["score"] <= 0.3),
                               "字段 reCAPTCHA V3风险分 存在&&reCAPTCHA V3风险分 小于等于 0.3", "中"),
        "分数=0":             (d["score"] == 0, "reCAPTCHA V3风险分 等于 0", "中"),
        "IP非美国":           (d["ipc_group"] == "非美国", "realIpCountry 不等于字符串 美国", "中"),
        "recapEnabled=true":  (d["recap_enabled"].astype("string") == "true",
                               "recaptchaV3Enabled 等于 true", "低"),
        "版本<1.4.30":        (d["version"].astype("string").map(_ver_lt_1_4_30),
                               "version 版本号小于 1.4.30", "低"),
    }


def _ver_lt_1_4_30(v):
    try:
        parts = [int(x) for x in str(v).split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts) < (1, 4, 30)
    except Exception:
        return False


def hot_c24(A, min_phones=10):
    """/24 blocks carrying >= min_phones distinct numbers inside the discovery set."""
    g = A.groupby("ip_c")["phone"].nunique()
    return set(g[g >= min_phones].index)


def hot_uid(A, min_phones=3):
    g = A.groupby("uid")["phone"].nunique()
    return set(g[g >= min_phones].index)


# ---------------------------------------------------------------- main
def main():
    os.makedirs(DATA3, exist_ok=True)
    df = r3.load()
    print(f"loaded {len(df):,} rows  {df.create_time.min()} → {df.create_time.max()} UTC")

    otp = pd.read_parquet(os.path.join(DATA3, "r3_otp_filled.parquet"))
    uid_sc = pd.read_parquet(os.path.join(DATA3, "r3_uid_scenes.parquet"))
    print(f"otp {len(otp):,} rows, uid_scenes {len(uid_sc):,} rows")

    d = add_evidence(df, otp=otp, uid_scenes=uid_sc)
    d.to_parquet(os.path.join(DATA3, "r3_labeled.parquet"), index=False)
    print("labelled:", d.sop_label.value_counts().to_dict())

    S = r3.sets(d)
    w = r3.windows(d)
    print(f"\nwindow (last 24h UTC): {w['t24_start']} → {w['t24_end']}")
    for k, v in S.items():
        print(f"  {k}: {len(v):,} rows, {v['phone'].nunique():,} distinct phones")

    # ---- data-quality gate: never analyse a half-empty pull -------------
    hourly = (d[d.create_time > w["t24_end"] - pd.Timedelta(hours=48)]
              .groupby(d.create_time.dt.strftime("%Y-%m-%dT%H")).size())
    hourly.to_csv(os.path.join(DATA3, "00_hourly_48h.csv"), header=["rows"])
    print(f"\n48h hourly rows: min={hourly.min()} max={hourly.max()} median={int(hourly.median())}")

    # ---- single-field profiles ------------------------------------------
    fields = ["cid", "version", "ip_country", "token_state", "token_bucket", "ua_family",
              "os_family", "brand", "cc", "ip_c", "ip_b", "recap_enabled", "phone_len",
              "hour_edt", "recap_feature_name"]
    profs = {f: r3.profile(S, f) for f in fields}
    with pd.ExcelWriter(os.path.join(DATA3, "feature_profiles.xlsx")) as xl:
        for f, p in profs.items():
            p.to_excel(xl, sheet_name=f[:28], index=False)
    print(f"\nfeature_profiles.xlsx: {len(profs)} sheets")
    for f in ["cid", "token_state", "ua_family", "version", "ip_country"]:
        print(f"\n--- {f} ---")
        print(profs[f].head(8)[["取值", "A中计数", "占A%", "C1中占比%", "C3中计数", "lift_vs_C1"]].to_string(index=False))

    # ---- candidate conjunctions -----------------------------------------
    HOT24, HOTUID = hot_c24(S["A"]), hot_uid(S["A"])
    print(f"\nhot /24: {len(HOT24)}   hot uid: {len(HOTUID)}")
    json.dump(sorted(HOT24), open(os.path.join(DATA3, "hot_c24.json"), "w"), indent=1)

    frn = lambda x: x["ac_group"] == "非+1/+86"          # noqa: E731
    A_ = atoms

    CAND = [
        ("S1  非+1/+86 && cid105 && token缺失或空",
         lambda x: frn(x) & (x["cid"].astype("string") == "105") & x["token_state"].isin(["absent", "empty"]),
         "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)&&cid 包含 105&&(字段 recaptchaV3Token 不存在||recaptchaV3Token 等于 '') 则 REJECT",
         "极低", "是 — 本条就是为 token 缺失设计"),
        ("S2  非+1/+86 && cid105/106/108 && token缺失或空",
         lambda x: frn(x) & x["cid"].astype("string").isin(["105", "106", "108"]) & x["token_state"].isin(["absent", "empty"]),
         "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)&&cid 包含 106,105,108&&(字段 recaptchaV3Token 不存在||recaptchaV3Token 等于 '') 则 REJECT",
         "极低", "是"),
        ("S3  非+1/+86 && cid105 && recapEnabled=true && token缺失或空",
         lambda x: frn(x) & (x["cid"].astype("string") == "105") & (x["recap_enabled"].astype("string") == "true") & x["token_state"].isin(["absent", "empty"]),
         "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)&&cid 包含 105&&recaptchaV3Enabled 等于 true&&(字段 recaptchaV3Token 不存在||recaptchaV3Token 等于 '') 则 REJECT",
         "极低", "是 — 且排除客户端本就不发 token 的情形"),
        ("S4  非+1/+86 && cid105 && IP非美国 && token缺失或空",
         lambda x: frn(x) & (x["cid"].astype("string") == "105") & (x["ipc_group"] == "非美国") & x["token_state"].isin(["absent", "empty"]),
         "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)&&cid 包含 105&&realIpCountry 不等于字符串 美国&&(字段 recaptchaV3Token 不存在||recaptchaV3Token 等于 '') 则 REJECT",
         "中", "是"),
        ("S5  非+1/+86 && cid105 && (分<0.3 或 token缺失或空)",
         lambda x: frn(x) & (x["cid"].astype("string") == "105") & (((x["score"].notna()) & (x["score"] < 0.3)) | x["token_state"].isin(["absent", "empty"])),
         "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)&&cid 包含 105&&((字段 reCAPTCHA V3风险分 存在&&reCAPTCHA V3风险分 小于 0.3)||字段 recaptchaV3Token 不存在||recaptchaV3Token 等于 '') 则 REJECT",
         "低", "部分 — token 缺失分支仍有效"),
        ("S6  非+1/+86 && IP C段黑名单",
         lambda x: frn(x) & x["ip_c"].isin(HOT24),
         "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)&&ip C段 命中黑名单 则 REJECT",
         "中", "是 — 不依赖 token"),
        ("S7  非+1/+86 && cid105 && IP C段黑名单",
         lambda x: frn(x) & (x["cid"].astype("string") == "105") & x["ip_c"].isin(HOT24),
         "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)&&cid 包含 105&&ip C段 命中黑名单 则 REJECT",
         "中", "是"),
        ("S8  非+1/+86 && cid105 && 版本<1.4.30",
         lambda x: frn(x) & (x["cid"].astype("string") == "105") & x["version"].astype("string").map(_ver_lt_1_4_30),
         "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)&&cid 包含 105&&version 版本号小于 1.4.30 则 REJECT",
         "极低", "是"),
        ("S9  非+1/+86 && 网关uid黑名单",
         lambda x: frn(x) & x["uid"].isin(HOTUID),
         "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)&&网关uid 命中黑名单 则 REJECT",
         "低", "是"),
        ("S10 非+1/+86 && cid105 && 分数=0",
         lambda x: frn(x) & (x["cid"].astype("string") == "105") & (x["score"] == 0),
         "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)&&cid 包含 105&&reCAPTCHA V3风险分 等于 0 则 REJECT",
         "中", "否 — 依赖分数"),
        ("S11 非+1/+86 && cid105（单条，参照上限）",
         lambda x: frn(x) & (x["cid"].astype("string") == "105"),
         "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)&&cid 包含 105 则 REJECT",
         "低", "是"),
        ("S12 非+1/+86 && cid105 && IP非美国 && (分<0.3 或 token缺失或空)",
         lambda x: frn(x) & (x["cid"].astype("string") == "105") & (x["ipc_group"] == "非美国") & (((x["score"].notna()) & (x["score"] < 0.3)) | x["token_state"].isin(["absent", "empty"])),
         "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)&&cid 包含 105&&realIpCountry 不等于字符串 美国&&((字段 reCAPTCHA V3风险分 存在&&reCAPTCHA V3风险分 小于 0.3)||字段 recaptchaV3Token 不存在||recaptchaV3Token 等于 '') 则 REJECT",
         "中", "部分"),
    ]

    rows = [r3.evaluate_rule(S, f, n, txt, ev, tk) for n, f, txt, ev, tk in CAND]
    cand = pd.DataFrame(rows).sort_values("覆盖A%", ascending=False)
    cand.to_csv(os.path.join(DATA3, "03_candidates.csv"), index=False, encoding="utf-8-sig")
    print("\n=== candidates ===")
    print(cand[["候选", "A命中", "覆盖A%", "B命中", "C1命中", "C2命中%", "C3命中", "规避成本"]].to_string(index=False))

    # ---- current recall --------------------------------------------------
    last24 = d[(d.create_time > w["t24_start"]) & (d.create_time <= w["t24_end"])]
    f24 = last24[last24.ac_group == "非+1/+86"]
    black = f24[f24.sop_label.isin(["确认黑产", "高疑似黑产"])]
    rec = {
        "窗口": f"{w['t24_start']} → {w['t24_end']} UTC",
        "非+1/+86 调用量": len(f24),
        "其中 SOP≥2类证据判黑": len(black),
        "已拦截(REJECT)": int((black.result == "REJECT").sum()),
        "召回%": round(100 * (black.result == "REJECT").mean(), 1) if len(black) else 0.0,
        "漏召回(PASS)": int((black.result == "PASS").sum()),
    }
    pd.DataFrame([rec]).to_csv(os.path.join(DATA3, "02_recall.csv"), index=False, encoding="utf-8-sig")
    print("\n=== recall ===")
    for k, v in rec.items():
        print(f"  {k}: {v}")

    # ---- raw sets for David's manual review (stay local) -----------------
    keep = ["access_time", "cid", "version", "result", "country_code", "phone_no", "ip",
            "ip_country", "ip_city", "token_state", "recap_token_len", "recaptcha_score",
            "recap_enabled", "gateway_uid", "user_agent", "ua_family", "brand", "ip_c",
            "risk_resp_detail", "hit_online", "hit_preonline", "best_strategy_id",
            "sop_label", "n_evidence", "ev_ip_cluster", "ev_phone", "ev_api", "ev_otp",
            "otp_filled", "uid_phone_n", "uid_push_only", "seq_cluster", "cc_zero_baseline"]
    for k, fn in [("A", "pass_24h_setA"), ("B", "pass_24h_setB"), ("C1", "control_C1"),
                  ("C2", "control_C2"), ("C3", "control_C3")]:
        sub = S[k][[c for c in keep if c in S[k].columns]]
        sub.to_csv(os.path.join(DATA3, f"{fn}.csv"), index=False, encoding="utf-8-sig")
    print("\nraw sets written to out3/data/ (unmasked — local only)")
    return d, S, cand


if __name__ == "__main__":
    main()
