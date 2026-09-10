"""Pull the last N days of LKUS_push risk-control rows, Doris-query-equivalent.

Why this exists: the warehouse copy (t_iriskcontrol_log) needs a Doris read-only
account we do not have, and selecting featureDetail raw there moves ~20.6 KB/row.
This goes to the upstream sharded MySQL source and flattens featureDetail server-side.

    MCP_DB_GATEWAY_SSE=http://<gateway>:8080/sse python -m sms_attack.pull_20d --days 20
"""
import argparse
import json
import os
import time

import pandas as pd

from .common import FEATURE_COLS
from .mcp_client import MCPGateway

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")
RISK_SERVER = "aws-luckyus-iriskcontrolservice-rw"
N_SHARDS = 64
HERE = os.path.dirname(os.path.abspath(__file__))


def pull(days=20, verbose=True):
    tpl = open(os.path.join(HERE, "sql", "08_riskcontrol_20d.sql"), encoding="utf-8").read()
    gw = MCPGateway().connect()
    rows, t0 = [], time.time()
    try:
        for shard in range(N_SHARDS):
            sql = tpl.format(tbl=f"t_access_log_{shard:04d}", days=days)
            rows.extend(gw.mysql_query(RISK_SERVER, sql).get("rows", []))
            if verbose and (shard + 1) % 8 == 0:
                print(f"  shard {shard+1:>2}/{N_SHARDS}  rows={len(rows):>7}  "
                      f"{time.time()-t0:.0f}s", flush=True)
    finally:
        gw.close()
    return pd.DataFrame(rows)


def expand_features(df):
    """feats_json -> one column per feature, reusing the shared FEATURE_COLS map so the
    column names never drift from the rest of the pipeline."""
    def as_dict(v):
        if not v or (isinstance(v, float) and pd.isna(v)):
            return {}
        if isinstance(v, dict):
            return v
        try:
            d = json.loads(v)
        except (TypeError, ValueError):
            return {}
        return d if isinstance(d, dict) else {}

    parsed = df["feats_json"].map(as_dict)
    for col, name in FEATURE_COLS.items():
        df[col] = pd.to_numeric(parsed.map(lambda d, n=name: d.get(n)), errors="coerce")
    return df


ORDERED = (["access_time", "access_time_mn", "access_time_dt", "access_time_hr",
            "cid", "scene_id", "l1_scene", "l2_scene", "result", "version",
            "country_code", "phone_no", "user_no", "ip", "ip_country", "ip_province", "ip_city",
            "risk_resp_code", "risk_resp_detail", "risk_resp_message", "risk_resp_result"]
           + list(FEATURE_COLS) + ["recaptcha_score",
                                   "gateway_uid", "user_agent", "hit_online", "hit_preonline",
                                   "best_strategy_id", "feats_json", "id"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=20)
    a = ap.parse_args()

    print(f"pulling LKUS_push, last {a.days} days, {N_SHARDS} shards "
          f"(featureDetail flattened server-side)")
    df = pull(a.days)
    df["access_time"] = pd.to_datetime(df["access_time"])
    df = expand_features(df).sort_values("access_time").reset_index(drop=True)
    df["recaptcha_score"] = pd.to_numeric(df["recaptcha_score"], errors="coerce")
    df = df[[c for c in ORDERED if c in df.columns]]

    end = df["access_time"].max().strftime("%Y%m%d")
    base = os.path.join(OUT, f"lkus_riskcontrol_{a.days}d_{end}")
    # utf-8-sig so Excel / WPS open it without mojibake
    df.to_csv(base + ".csv", index=False, encoding="utf-8-sig")
    df.to_parquet(base + ".parquet", index=False)
    print(f"\n{len(df):,} 行 × {len(df.columns)} 列")
    print(f"  {base}.csv      {os.path.getsize(base+'.csv')/1e6:.1f} MB")
    print(f"  {base}.parquet  {os.path.getsize(base+'.parquet')/1e6:.1f} MB")
    print(f"  窗口 {df.access_time.min()} → {df.access_time.max()} (UTC)")
    return df


if __name__ == "__main__":
    main()
