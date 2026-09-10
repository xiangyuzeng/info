"""All published numbers are computed here, once, so every report and chat message
quotes the same figure. Each function returns a DataFrame that is also dumped to
out/data/*.csv so any number in a report can be traced to a table.
"""
import os

import pandas as pd

from .common import DATA, pct, hit
from .countries import cc_to_zh

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")
OUT_DATA = os.path.join(OUT, "data")

BLACK = ["确认黑产", "高疑似黑产"]


def load():
    d = pd.read_parquet(os.path.join(DATA, "risk_labeled.parquet"))
    d["create_time"] = pd.to_datetime(d["create_time"])
    return d


def dump(df, name, index=False):
    os.makedirs(OUT_DATA, exist_ok=True)
    df.to_csv(os.path.join(OUT_DATA, name), index=index)
    return df


def daily_overview(d):
    g = d.groupby("date_utc").agg(
        场景调用量=("id", "size"),
        PASS=("risk_result", lambda s: (s == "PASS").sum()),
        REJECT=("risk_result", lambda s: (s == "REJECT").sum()),
        REVIEW=("risk_result", lambda s: (s == "REVIEW").sum()))
    non = d[d.ac_group == "非+1/+86"].groupby("date_utc").agg(
        非1_86调用=("id", "size"),
        非1_86_PASS=("risk_result", lambda s: (s == "PASS").sum()))
    p1 = d[d.ac_group == "+1"].groupby("date_utc").size().rename("plus1_调用")
    out = g.join(non).join(p1).fillna(0).astype(int).reset_index()
    return dump(out, "01_daily_overview.csv")


def feature_name_churn(d):
    """The RMS feature catalogue was renamed mid-attack; queries that match feature
    names literally silently lose whole windows. This table is the evidence."""
    g = (d.groupby(["date_utc", "recap_feature_name"]).size()
           .unstack(fill_value=0).reset_index())
    return dump(g, "00_feature_name_churn.csv")


def score_coverage(d):
    g = d.groupby("date_utc").agg(行数=("id", "size"),
                                  score缺失=("score", lambda s: s.isna().sum()),
                                  无token=("recap_token_len", lambda s: (s.fillna(0) == 0).sum()))
    g["score缺失率%"] = [pct(a, b) for a, b in zip(g["score缺失"], g["行数"])]
    g["无token率%"] = [pct(a, b) for a, b in zip(g["无token"], g["行数"])]
    return dump(g.reset_index(), "00_score_coverage.csv")


def threshold_evasion(d, since="2026-09-05", thresholds=(10, 15, 20, 25, 30)):
    """The online rule is 区号近60分钟的访问次数 > 30. Measure how much of the attack
    deliberately sits underneath it."""
    a = d[(d.create_time >= pd.Timestamp(since)) & (d.ac_group == "非+1/+86")].copy()
    a["hr"] = a.create_time.dt.floor("h")
    pc = a.groupby(["cc", "hr"]).size().rename("n").reset_index()
    top = a.cc.value_counts().head(12).index
    pc = pc[pc.cc.isin(top)]
    per = pc.groupby("cc")["n"].agg(小时数="count", 均值="mean", 中位="median", 峰值="max").round(1)
    per["小时数≤30"] = pc[pc.n <= 30].groupby("cc").size().reindex(per.index).fillna(0).astype(int)
    per["规避率%"] = [pct(a_, b) for a_, b in zip(per["小时数≤30"], per["小时数"])]
    dump(per.reset_index(), "04_threshold_evasion_by_cc.csv")
    tot = int(pc.n.sum())
    curve = pd.DataFrame([{"阈值(区号近60分钟>N)": t,
                           "仍可规避的请求数": int(pc[pc.n <= t].n.sum()),
                           "占攻击请求%": pct(int(pc[pc.n <= t].n.sum()), tot)} for t in thresholds])
    dump(curve, "04_threshold_curve.csv")
    return per.reset_index(), curve, tot


def hourly_completeness(d, day):
    x = d[(d.create_time >= pd.Timestamp(day)) & (d.create_time < pd.Timestamp(day) + pd.Timedelta(days=1))]
    g = x.groupby(x.create_time.dt.hour).agg(
        行数=("id", "size"),
        非1_86=("ac_group", lambda s: (s == "非+1/+86").sum()),
        plus1=("ac_group", lambda s: (s == "+1").sum())).reset_index()
    g.columns = ["UTC小时", "行数", "非+1/+86", "+1"]
    g["EDT小时"] = (g["UTC小时"] - 4) % 24
    return dump(g, f"00_hourly_{day.replace('-', '')}.csv")


def edt_profile(d, since="2026-09-05"):
    r = d[d.create_time >= pd.Timestamp(since)]
    a = r[r.ac_group == "非+1/+86"].groupby("hour_edt").size().rename("非+1/+86")
    b = r[r.ac_group == "+1"].groupby("hour_edt").size().rename("+1")
    out = pd.concat([a, b], axis=1).fillna(0).astype(int)
    out["非+1占比%"] = [pct(x, x + y) for x, y in zip(out["非+1/+86"], out["+1"])]
    return dump(out.reset_index(), "05_edt_hour_profile.csv")


def recall_table(d, t0, t1):
    w = d[(d.create_time >= t0) & (d.create_time < t1)]
    proxy = (w.token_bucket == "<=0.3") & (w.ac_group == "非+1/+86")
    mine = w.sop_label.isin(BLACK)
    blocked = w.risk_result == "REJECT"
    h172 = hit(w, "strategy_uKSgJAVWhWlU")
    harq = hit(w, "strategy_ARqkLD7E3JaK")
    rows = []
    for nm, lab in [("田志鲔口径(token≤0.3且非+1/+86)", proxy), ("本文黑产标签(SOP≥2类交叉)", mine)]:
        tot = int(lab.sum())
        rows.append({
            "黑产口径": nm, "黑产总量": tot,
            "当前ONLINE拦截": int((lab & blocked).sum()), "ONLINE召回%": pct(int((lab & blocked).sum()), tot),
            "172单独命中": int((lab & h172).sum()), "172召回%": pct(int((lab & h172).sum()), tot),
            "ONLINE+ARqk": int((lab & (blocked | harq)).sum()),
            "ONLINE+ARqk召回%": pct(int((lab & (blocked | harq)).sum()), tot),
            "漏召回(PASS)": int((lab & ~blocked).sum()), "漏召回%": pct(int((lab & ~blocked).sum()), tot)})
    return dump(pd.DataFrame(rows), "02_recall.csv")


def leak_breakdown(d, t0, t1):
    w = d[(d.create_time >= t0) & (d.create_time < t1)]
    leak = w[w.sop_label.isin(BLACK) & (w.risk_result != "REJECT")]
    frames = []
    for col, nm in [("ipc_group", "IP国家组"), ("real_ip_country", "IP国家"), ("token_bucket", "token桶"),
                    ("cid", "cid"), ("version", "版本"), ("cc", "目的区号")]:
        vc = leak[col].value_counts().head(8)
        frames.append(pd.DataFrame({"维度": nm, "取值": vc.index.astype(str),
                                    "漏召回条数": vc.values,
                                    "占漏召回%": [pct(v, len(leak)) for v in vc.values]}))
    return dump(pd.concat(frames, ignore_index=True), "02_leak_breakdown.csv"), len(leak)


def candidate_table(d, t0, t1, cands):
    """Incremental recall + 误伤, measured from real PREONLINE hits (no re-implementation)."""
    w = d[(d.create_time >= t0) & (d.create_time < t1)]
    pre = d[(d.create_time >= pd.Timestamp("2026-08-09")) & (d.create_time < pd.Timestamp("2026-09-03"))]
    mine = w.sop_label.isin(BLACK)
    blocked = w.risk_result == "REJECT"
    leak = w[mine & ~blocked]
    st = pd.read_csv(os.path.join(DATA, "strategies.csv")).set_index("strategy_id")
    rows = []
    for sid in cands:
        hw, hp = hit(w, sid), hit(pre, sid)
        inc = int(hit(leak, sid).sum())
        wrong = int((w[hw].sop_label == "正常用户").sum())
        rows.append({
            "策略": sid, "状态": {1: "ONLINE", 2: "预上线", 0: "关闭"}.get(int(st.loc[sid, "status"]), "?"),
            "动作": st.loc[sid, "result_code"],
            "规则": str(st.loc[sid, "strategy_name"]),
            "24h命中量": int(hw.sum()), "增量召回": inc, "占漏召回%": pct(inc, len(leak)),
            "命中中正常用户": wrong, "误伤%": pct(wrong, int(hw.sum())),
            "攻击前窗命中": int(hp.sum()), "攻击前命中中+1": int((pre[hp].ac_group == "+1").sum()),
            "攻击前命中中正常用户": int((pre[hp].sop_label == "正常用户").sum()),
            "攻击前命中中OTP已填充": int((pre[hp].otp_filled == 1).sum())})
    return dump(pd.DataFrame(rows).sort_values("增量召回", ascending=False), "04_candidates.csv")


def cohort_profile(d, since="2026-09-04"):
    a = d[d.create_time >= pd.Timestamp(since)]
    non = a[a.ac_group == "非+1/+86"]
    defs = [("美国IP·非+1/+86", non[non.ipc_group == "美国"]),
            ("非美国IP·非+1/+86", non[non.ipc_group == "非美国"]),
            ("+1 正常基线", a[a.ac_group == "+1"])]
    rows = []
    for nm, x in defs:
        ipp = x.groupby("real_ip")["phone"].nunique()
        rows.append({"cohort": nm, "请求数": len(x), "独立IP": x.real_ip.nunique(),
                     "独立手机号": x.phone.nunique(),
                     "IP中位手机号数": float(ipp.median()) if len(ipp) else 0,
                     "IP>3手机号占比%": pct(int((ipp > 3).sum()), len(ipp)),
                     "低分token%": pct(int((x.token_bucket == "<=0.3").sum()), len(x)),
                     "cid105%": pct(int((x.cid == "105").sum()), len(x)),
                     "iPhone%": pct(int((x.brand == "iPhone").sum()), len(x)),
                     "仅调短信uid%": pct(int(x.uid_push_only.sum()), len(x)),
                     "确认黑产%": pct(int((x.sop_label == "确认黑产").sum()), len(x))})
    return dump(pd.DataFrame(rows), "03_cohort_profile.csv")


def upush_series():
    o = pd.read_csv(os.path.join(DATA, "upush_sends.csv"))
    g = o.groupby(["d", "ac_group"])[["sends", "filled_n"]].sum().reset_index()
    s = g.pivot(index="d", columns="ac_group", values="sends").fillna(0).astype(int)
    f = g.pivot(index="d", columns="ac_group", values="filled_n").fillna(0).astype(int)
    out = pd.DataFrame({"日期": s.index,
                        "+1发送": s.get("+1", 0).values, "其他区号发送": s.get("other", 0).values,
                        "+1填充率%": [pct(a, b) for a, b in zip(f.get("+1", 0), s.get("+1", 1))],
                        "其他区号填充率%": [pct(a, b) for a, b in zip(f.get("other", 0), s.get("other", 1))]})
    return dump(out, "06_upush_daily.csv")


STATUS_ZH = {1: "ONLINE", 2: "预上线", 0: "关闭"}


def measures_timeline(since="2026-08-27"):
    """Measure timeline from the RMS config table.

    Caveat: `update_time` records only the LAST change to a strategy, so a strategy
    touched several times appears once, at its latest state. `t_oplog` carries no rows
    after 2026-09-01, so it cannot supply the missing intermediate history.
    """
    s = pd.read_csv(os.path.join(DATA, "strategies.csv"))
    s["update_time"] = pd.to_datetime(s["update_time"])
    s = s[s.update_time >= pd.Timestamp(since)]
    g = (s.groupby([s.update_time.dt.date, "status"])
           .agg(条数=("strategy_id", "size"),
                策略=("strategy_id", lambda x: " ".join(x)))
           .reset_index().rename(columns={"update_time": "日期", "status": "状态"}))
    g["状态"] = g["状态"].map(STATUS_ZH)
    return dump(g, "06_measures_timeline.csv")
