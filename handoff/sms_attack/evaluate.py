"""Re-runnable strategy evaluation: David's nine metrics + the SOP release gate.

    python -m sms_attack.evaluate --strategy strategy_ARqkLD7E3JaK --window 5h
    python -m sms_attack.evaluate --strategy strategy_uKSgJAVWhWlU --window 24h

Every number is computed from raw rows on one window with one set of filters, so the
identities the 6h Feishu doc broke (低分按区号分组之和 == 低分按IP国家分组之和) hold by
construction and are asserted below.
"""
import argparse
import os
import re

import pandas as pd

from .common import DATA, EDT_OFFSET_H, load_risk, hit, pct
from .countries import cc_to_zh
from .label import add_evidence

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")


def parse_window(w):
    m = re.fullmatch(r"(\d+)\s*([hd])", str(w).strip().lower())
    if not m:
        raise ValueError(f"bad window {w!r}, expected e.g. 5h / 24h / 7d")
    n = int(m.group(1))
    return pd.Timedelta(hours=n if m.group(2) == "h" else n * 24)


def _buckets(sub):
    n = len(sub)
    vc = sub["token_bucket"].value_counts()
    return {"总数": n,
            "<=0.3": int(vc.get("<=0.3", 0)), "<=0.3%": pct(int(vc.get("<=0.3", 0)), n),
            ">0.3": int(vc.get(">0.3", 0)), ">0.3%": pct(int(vc.get(">0.3", 0)), n),
            "空置": int(vc.get("空置", 0)), "空置%": pct(int(vc.get("空置", 0)), n)}


def _ip_multi_phone(sub, thresh=3):
    """Share of DISTINCT IPs that touched more than `thresh` phone numbers."""
    g = sub.groupby("real_ip")["phone"].nunique()
    return int((g > thresh).sum()), int(len(g))


def nine_metrics(win, hits):
    plus1 = win[win.ac_group == "+1"]
    non_na = win[win.ac_group != "+1"]          # David's 非北美 = complement of +1
    strict = win[win.ac_group == "非+1/+86"]    # the strategy's own population
    non_us_ip = win[win.ipc_group == "非美国"]
    us_ip = win[win.ipc_group == "美国"]

    m = {"1_北美+1": _buckets(plus1), "2_非北美区号": _buckets(non_na),
         "2b_非+1_86(策略口径)": _buckets(strict),
         "3_IP非美国": _buckets(non_us_ip), "4_IP美国": _buckets(us_ip),
         "0_未知IP国家": _buckets(win[win.ipc_group == "未知"])}

    n5, d5 = _ip_multi_phone(non_us_ip); m["5_非美国IP_多手机号"] = {"命中": n5, "总IP": d5, "占比%": pct(n5, d5)}
    n6, d6 = _ip_multi_phone(us_ip);     m["6_美国IP_多手机号"]  = {"命中": n6, "总IP": d6, "占比%": pct(n6, d6)}
    n7, d7 = _ip_multi_phone(hits);      m["7_命中IP_多手机号"]  = {"命中": n7, "总IP": d7, "占比%": pct(n7, d7)}

    n8 = int((plus1.ipc_group == "非美国").sum())
    m["8_+1的IP非美国"] = {"命中": n8, "总数": len(plus1), "占比%": pct(n8, len(plus1))}

    h = hits.copy()
    h["phone_country"] = h["cc"].map(cc_to_zh)
    h["mismatch"] = h["real_ip_country"].notna() & (h["real_ip_country"] != h["phone_country"])
    m9 = (h.groupby("real_ip_country")
            .agg(不一致=("mismatch", "sum"), 命中=("mismatch", "size")).reset_index()
            .sort_values("命中", ascending=False))
    m9["占比%"] = [pct(a, b) for a, b in zip(m9["不一致"], m9["命中"])]
    m["9_命中_IP与手机号国家不一致"] = m9
    return m


def identity_check(win):
    """低分总数 must be identical whether you slice by area code or by IP country."""
    low = win[win.token_bucket == "<=0.3"]
    by_ac = low.groupby("ac_group").size().sum()
    by_ip = low.groupby("ipc_group").size().sum()
    return {"低分总数": len(low), "按区号求和": int(by_ac), "按IP国家求和": int(by_ip),
            "一致": bool(len(low) == by_ac == by_ip)}


def sop_gate(df_all, win, hits, t0, t1, high_risk=True):
    """SOP 发布前评估分级标准 (§二). High-risk 强拦截 thresholds by default."""
    span_h = (t1 - t0).total_seconds() / 3600
    prior = []
    for k in range(1, 8):
        p0, p1 = t0 - pd.Timedelta(days=k), t1 - pd.Timedelta(days=k)
        prior.append(len(df_all[(df_all.create_time >= p0) & (df_all.create_time < p1)]))
    base_calls = sum(prior) / len(prior) if prior else 0

    prior_u = []
    for k in range(1, 8):
        p0, p1 = t0 - pd.Timedelta(days=k), t1 - pd.Timedelta(days=k)
        prior_u.append(df_all[(df_all.create_time >= p0) & (df_all.create_time < p1)]["phone"].nunique())
    base_users = sum(prior_u) / len(prior_u) if prior_u else 0

    calls, users, nhit = len(win), win["phone"].nunique(), len(hits)
    min_h, rel, abs_calls, abs_users, min_sample = (30 / 60, 0.80, 8000, 3000, 20) if high_risk \
        else (20 / 60, 0.70, 3000, 1000, 10)

    wrong = int(hits["sop_label"].isin(["正常用户"]).sum()) if "sop_label" in hits else 0
    unknown = int((hits["sop_label"] == "暂无法判断").sum()) if "sop_label" in hits else 0
    confirmed = int(hits["sop_label"].isin(["确认黑产", "高疑似黑产"]).sum()) if "sop_label" in hits else 0
    acc = pct(nhit - wrong, nhit)          # 准确率 = 非误伤占比
    conf_rate = pct(confirmed, nhit)       # 确认/高疑似黑产占比 (stricter)

    rows = [
        ("观察时长", f"{span_h:.1f}h", f"≥{min_h * 60:.0f}min", span_h >= min_h),
        ("场景调用量", f"{calls:,}", f"≥近7日同期均值{rel:.0%}({base_calls * rel:,.0f}) 且 ≥{abs_calls:,}",
         calls >= base_calls * rel and calls >= abs_calls),
        ("用户量(去重手机号)", f"{users:,}", f"≥{rel:.0%}({base_users * rel:,.0f}) 且 ≥{abs_users:,}",
         users >= base_users * rel and users >= abs_users),
        ("命中样本", f"{nhit:,}", f"≥{min_sample}", nhit >= min_sample),
        ("准确率(非误伤)", f"{acc}%", "≥99.9%", acc >= 99.9),
        ("误伤率", f"{pct(wrong, nhit)}%", "≤0.1%", pct(wrong, nhit) <= 0.1),
        ("确认/高疑似黑产占比", f"{conf_rate}%", "参考(SOP无硬门槛)", None),
    ]
    gate = pd.DataFrame(rows, columns=["门槛项", "实测", "SOP要求", "达标"])
    gate["达标"] = gate["达标"].map({True: "✅", False: "❌", None: "—"})
    return gate, {"base_calls": base_calls, "base_users": base_users, "wrong": wrong,
                  "unknown": unknown, "acc": acc, "conf_rate": conf_rate,
                  "confirmed": confirmed}


def evaluate(df_all, strategy_id, t0, t1, high_risk=True):
    win = df_all[(df_all.create_time >= t0) & (df_all.create_time < t1)].copy()
    hits = win[hit(win, strategy_id)].copy()
    base = {"窗口UTC": f"{t0:%Y-%m-%d %H:%M} ~ {t1:%Y-%m-%d %H:%M}",
            "窗口EDT": f"{t0 + pd.Timedelta(hours=EDT_OFFSET_H):%m-%d %H:%M} ~ "
                       f"{t1 + pd.Timedelta(hours=EDT_OFFSET_H):%m-%d %H:%M}",
            "场景总调用量": len(win), "策略命中量": len(hits),
            "策略命中率%": pct(len(hits), len(win)),
            "命中中当时PASS": int((hits.risk_result == "PASS").sum()),
            "命中中当时REJECT": int((hits.risk_result == "REJECT").sum())}
    gate, extra = sop_gate(df_all, win, hits, t0, t1, high_risk)
    return {"base": base, "metrics": nine_metrics(win, hits), "identity": identity_check(win),
            "gate": gate, "gate_extra": extra, "win": win, "hits": hits}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strategy", required=True)
    ap.add_argument("--window", default="24h")
    ap.add_argument("--end", default=None, help="window end, UTC ISO; default = max(create_time)")
    a = ap.parse_args()

    df = load_labeled()
    t1 = pd.Timestamp(a.end) if a.end else df["create_time"].max()
    t0 = t1 - parse_window(a.window)
    r = evaluate(df, a.strategy, t0, t1)

    print(f"\n=== {a.strategy} | {a.window} ===")
    for k, v in r["base"].items():
        print(f"  {k}: {v}")
    print("\n-- 口径自检 --", r["identity"])
    print("\n-- SOP 门槛 --"); print(r["gate"].to_string(index=False))
    print("\n-- 九项 --")
    for k, v in r["metrics"].items():
        print(f"  {k}: {v if not isinstance(v, pd.DataFrame) else chr(10) + v.to_string(index=False)}")


def load_labeled():
    """Prefer the cached labelled frame so every report shares one labelling run."""
    p = os.path.join(DATA, "risk_labeled.parquet")
    if os.path.exists(p):
        d = pd.read_parquet(p)
        d["create_time"] = pd.to_datetime(d["create_time"])
        return d
    otp = os.path.join(DATA, "otp_filled.csv")
    uid = os.path.join(DATA, "uid_scenes.csv")
    return add_evidence(load_risk(),
                        otp=pd.read_csv(otp) if os.path.exists(otp) else None,
                        uid_scenes=pd.read_csv(uid) if os.path.exists(uid) else None)


if __name__ == "__main__":
    main()
