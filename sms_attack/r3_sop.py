"""发布前评估表 metrics, per SOP §二 and the brief's corrected accuracy formula.

Differs from r2.sop_metrics in one place that matters: 准确率 subtracts BOTH 风险样本量
and 暂无法判断样本量 from the numerator, per the brief. r2 subtracted only 风险样本量.
SOP §3.7 forbids relabelling 暂无法判断 upward to flatter the accuracy, so leaving it in
the numerator would do exactly what the SOP prohibits.

⚠ 风险样本量 is read here as "正常用户 caught by the strategy" (i.e. 误伤), which is what
the SEA sample implies (命中 200 / 风险样本 0 / 准确率 100%). This reading is still
pending 田志鲔's confirmation -- see out3/05_人工确认清单.md item 3.

用户量 = deduplicated phone numbers: the scene is pre-login and user_no is ~97% null.
"""
import pandas as pd

# SOP §二 发布前评估分级标准表
GATES = {
    "普通策略":         dict(min_minutes=20, rel=0.70, abs_calls=3000, abs_users=1000, min_sample=10),
    "高风险强拦截策略": dict(min_minutes=30, rel=0.80, abs_calls=8000, abs_users=3000, min_sample=20),
}
MIN_ACC, MAX_FP = 99.9, 0.1


def _pct(n, d, nd=1):
    return round(100 * n / d, nd) if d else 0.0


def sop_metrics(d, hit_mask, t0, t1, label=""):
    w = d[(d.create_time >= t0) & (d.create_time < t1)]
    h = w[hit_mask.reindex(w.index, fill_value=False)]
    dur = (t1 - t0).total_seconds()

    prior_calls, prior_users = [], []
    for k in range(1, 8):
        p = d[(d.create_time >= t0 - pd.Timedelta(days=k)) & (d.create_time < t1 - pd.Timedelta(days=k))]
        prior_calls.append(len(p))
        prior_users.append(p["phone"].nunique())

    risk = int((h.sop_label == "正常用户").sum())          # 风险样本量 = 误伤的正常用户
    unknown = int((h.sop_label == "暂无法判断").sum())      # 暂无法判断样本量
    n = len(h)
    return {
        "label": label,
        "观察起": t0, "观察止": t1,
        "实际观察时长": f"{int(dur//86400)}天{int(dur%86400//3600)}小时{int(dur%3600//60)}分钟",
        "观察分钟": dur / 60,
        "整体调用量": len(w),
        "整体用户量": int(w["phone"].nunique()),
        "命中pv": n, "命中uv": int(h["phone"].nunique()),
        "风险样本量": risk, "暂无法判断样本量": unknown,
        "准确率%": _pct(n - risk - unknown, n, 3),
        "误伤比例%": _pct(risk, n, 3),
        "近7日同期平均调用量": round(sum(prior_calls) / 7),
        "近7日同期平均用户量": round(sum(prior_users) / 7),
        "hits": h, "win": w,
    }


def gate(m, kind="高风险强拦截策略"):
    """Row-by-row SOP release gate. Returns a frame plus an overall pass/fail."""
    g = GATES[kind]
    rows = [
        ("最低观察时长", f"≥{g['min_minutes']}分钟", f"{m['观察分钟']:.0f}分钟",
         m["观察分钟"] >= g["min_minutes"]),
        ("最低整体调用量", f"≥近7日同期均值{g['rel']:.0%} 且 ≥{g['abs_calls']}",
         f"{m['整体调用量']} (均值{m['近7日同期平均调用量']})",
         m["整体调用量"] >= g["abs_calls"] and m["整体调用量"] >= g["rel"] * max(m["近7日同期平均调用量"], 1)),
        ("最低整体用户量", f"≥近7日同期均值{g['rel']:.0%} 且 ≥{g['abs_users']}",
         f"{m['整体用户量']} (均值{m['近7日同期平均用户量']})",
         m["整体用户量"] >= g["abs_users"] and m["整体用户量"] >= g["rel"] * max(m["近7日同期平均用户量"], 1)),
        ("命中样本参考门槛", f"≥{g['min_sample']}", f"{m['命中pv']}", m["命中pv"] >= g["min_sample"]),
        ("最低准确率", f"≥{MIN_ACC}%", f"{m['准确率%']}%", m["准确率%"] >= MIN_ACC),
        ("最高误伤比例", f"≤{MAX_FP}%", f"{m['误伤比例%']}%", m["误伤比例%"] <= MAX_FP),
    ]
    df = pd.DataFrame(rows, columns=["门槛项", "要求", "实测", "达标"])
    return df, bool(df["达标"].all())
