"""黑产分级 per 风控策略运营SOP §3.7.

Core rule from the SOP: 不得凭单一特征定性; ≥2 类特征交叉印证才可判"确认黑产".
Thresholds are derived from the pre-attack window wherever possible rather than
hand-picked, so each one can be defended as "this is what legitimate traffic does".

Evidence categories (SOP 3.2/3.3/3.4/3.5 + OTP behaviour):
  ev_ip_cluster  IP/设备聚集
  ev_phone       手机号风险
  ev_api         API链路异常/自动化
  ev_device      设备指纹
  ev_otp         OTP 行为（发出去但从未被填充）
"""
import numpy as np
import pandas as pd
import phonenumbers

from .common import PRE_ATTACK, pct

LABELS = ["确认黑产", "高疑似黑产", "正常用户", "暂无法判断"]


def phone_valid(cc, phone):
    try:
        return phonenumbers.is_valid_number(phonenumbers.parse(f"+{cc}{phone}", None))
    except Exception:
        return None


def legit_area_baseline(df):
    """Area codes that carried real traffic BEFORE the attack = codes we may not blanket-block."""
    pre = df[(df.create_time >= PRE_ATTACK[0]) & (df.create_time < PRE_ATTACK[1])]
    return pre.groupby("cc").size()


def sequential_cluster(df, gap=1000, min_size=3):
    """Phones requested from the same IP whose numeric values sit within `gap` of each other.

    Mat-pool / generated-range signature: 99175861 / 99175851 / 99175834 ...
    """
    flag = pd.Series(False, index=df.index)
    num = pd.to_numeric(df["phone"], errors="coerce")
    for ip, grp in df.groupby("real_ip"):
        vals = num.loc[grp.index].dropna().sort_values()
        if len(vals) < min_size:
            continue
        run, prev = [vals.index[0]], vals.iloc[0]
        for idx, v in list(vals.items())[1:]:
            if v - prev <= gap:
                run.append(idx)
            else:
                if len(run) >= min_size:
                    flag.loc[run] = True
                run = [idx]
            prev = v
        if len(run) >= min_size:
            flag.loc[run] = True
    return flag


def add_evidence(df, otp=None, uid_scenes=None):
    """Attach the five evidence flags plus the SOP grade. Returns a new frame."""
    d = df.copy()

    # --- 1. IP / 设备聚集 (SOP 3.2) -------------------------------------
    uid_phones = d.groupby("uid")["phone"].transform("nunique")
    d["uid_phone_n"] = uid_phones
    d["ev_ip_cluster"] = (
        (d["f_ip_phone_60m"] > 3)
        | (d["f_ipc_phone_10m"] >= 10)
        | (uid_phones >= 3)
        | (d["f_ip_cc_60m"] >= 3)
    ).fillna(False)

    # --- 2. 手机号风险 (SOP 3.3) ----------------------------------------
    base = legit_area_baseline(d)
    zero_baseline = set(base[base == 0].index) | (set(d["cc"].dropna()) - set(base.index))
    d["cc_zero_baseline"] = d["cc"].isin(zero_baseline)
    d["seq_cluster"] = sequential_cluster(d)
    valid = {(cc, p): phone_valid(cc, p)
             for cc, p in d[["cc", "phone"]].drop_duplicates().itertuples(index=False)
             if pd.notna(cc) and pd.notna(p)}
    d["phone_invalid"] = [
        valid.get((cc, p)) is False for cc, p in zip(d["cc"], d["phone"])
    ]
    d["ev_phone"] = (d["cc_zero_baseline"] | d["seq_cluster"] | d["phone_invalid"]).fillna(False)

    # --- 3. API链路 / 自动化 (SOP 3.4) ----------------------------------
    no_token = (d["recap_token_len"].fillna(0) == 0)
    zero_score = (d["score"] == 0)
    if uid_scenes is not None and len(uid_scenes):
        push_only = set(uid_scenes[uid_scenes["n_other_scenes"] == 0]["uid"])
        d["uid_push_only"] = d["uid"].isin(push_only)
    else:
        d["uid_push_only"] = False
    # no_token is deliberately NOT evidence: it fires on 9.2% of the legitimate +1
    # baseline and 0% of attack traffic (this actor always presents a token and simply
    # scores badly). Using it would misclassify real users.
    d["no_token"] = no_token
    d["ev_api"] = (zero_score | d["uid_push_only"]).fillna(False)

    # --- 4. 设备指纹 (SOP 3.5) -- NOT AVAILABLE in this scene ------------
    # did / device_id / tongdun_device_id are NULL for every LKUS_push row, so there is
    # no real device fingerprint to cross-check. The only device-ish field is the
    # userAgent brand/model, and "brand absent from the US baseline" fires on 99.5% of
    # non-+1 rows -- i.e. it is the area-code condition restated, not independent
    # evidence. Per SOP 3.7 (不得凭单一特征定性) it is therefore kept as descriptive
    # colour for the 黑产评估依据 narrative and excluded from the evidence count.
    pre = d[(d.create_time >= PRE_ATTACK[0]) & (d.create_time < PRE_ATTACK[1]) & (d.ac_group == "+1")]
    share = pre["brand"].value_counts(normalize=True) if len(pre) else pd.Series(dtype=float)
    rare = set(share[share < 0.01].index) | (set(d["brand"].dropna()) - set(share.index))
    d["brand_rare_in_us"] = d["brand"].isin(rare)
    d["ev_device"] = False  # category unavailable -- see note above

    # --- 5. OTP 行为 ------------------------------------------------------
    d["ev_otp"] = False
    d["otp_filled"] = np.nan
    if otp is not None and len(otp):
        d = _join_otp(d, otp)
        d["ev_otp"] = (d["otp_filled"] == 0)

    # 设备指纹 excluded: no usable fingerprint field in this scene (see above).
    cats = ["ev_ip_cluster", "ev_phone", "ev_api", "ev_otp"]
    d["n_evidence"] = d[cats].sum(axis=1)

    strong = d["ev_ip_cluster"] | d["ev_otp"]
    looks_legit = (
        (d["otp_filled"] == 1)
        | ((d["ac_group"] == "+1") & (d["score"] > 0.7) & (d["f_ip_phone_60m"] <= 1))
    )
    d["sop_label"] = np.select(
        [looks_legit & (d["n_evidence"] < 2), d["n_evidence"] >= 2, strong & (d["n_evidence"] == 1)],
        ["正常用户", "确认黑产", "高疑似黑产"],
        default="暂无法判断",
    )
    return d


def _join_otp(d, otp):
    """Link each PASSed request to the SMS it produced via (area_code, last4) + time."""
    o = otp.copy()
    o["create_time"] = pd.to_datetime(o["create_time"])
    o["key"] = o["area_code"].astype(str) + "|" + o["last4"].astype(str)
    o = o.sort_values("create_time")[["create_time", "key", "filled"]]

    d = d.sort_values("create_time")
    d["key"] = d["cc"].astype(str) + "|" + d["phone"].astype(str).str[-4:]
    merged = pd.merge_asof(
        d, o, on="create_time", by="key", direction="nearest",
        tolerance=pd.Timedelta("2min"), suffixes=("", "_otp"),
    )
    merged["otp_filled"] = merged["filled"]
    return merged.drop(columns=["filled"]).sort_index()


def label_summary(d):
    tot = len(d)
    rows = [{"分级": k, "条数": int((d.sop_label == k).sum()),
             "占比%": pct(int((d.sop_label == k).sum()), tot)} for k in LABELS]
    return pd.DataFrame(rows)
