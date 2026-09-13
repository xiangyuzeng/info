"""Round-3 pull: LKUS_push rows with token state, for feature analysis on PASS traffic.

Same 64-shard sweep as pull_20d, but against sql/10_riskcontrol_r3.sql, which adds
recap_token_len / token_state. Round 3 turns on whether a reCAPTCHA token was presented
at all, and the 20-day dump from 09-10 cannot answer that.

One pull serves four windows: the last-24h PASS sets (A/B), the pre-attack control
(needs 08-09 onward, hence 35 days), post-go-live observation of 172 / ARqk / rDf6,
and the 7-day same-period means the SOP release gate requires.

    MCP_DB_GATEWAY_SSE=http://<gateway>:8080/sse python -m sms_attack.r3_pull --days 35
"""
import argparse
import os
import time

import pandas as pd

from .common import FEATURE_COLS
from .mcp_client import MCPGateway
from .pull_20d import expand_features

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out3")
RISK_SERVER = "aws-luckyus-iriskcontrolservice-rw"
N_SHARDS = 64
HERE = os.path.dirname(os.path.abspath(__file__))
SQL = "10_riskcontrol_r3.sql"

ORDERED = (["access_time", "access_time_mn", "access_time_dt", "access_time_hr",
            "cid", "scene_id", "l1_scene", "l2_scene", "result", "version",
            "country_code", "phone_no", "user_no", "ip", "ip_country", "ip_province", "ip_city",
            "risk_resp_code", "risk_resp_detail", "risk_resp_message", "risk_resp_result"]
           + list(FEATURE_COLS)
           + ["recaptcha_score", "recap_token_len", "token_state", "recap_enabled",
              "recap_action", "recap_feature_name", "app",
              "gateway_uid", "user_agent", "hit_online", "hit_preonline",
              "best_strategy_id", "best_pre_strategy_id", "feats_json", "id"])


def pull(days, verbose=True):
    tpl = open(os.path.join(HERE, "sql", SQL), encoding="utf-8").read()
    gw = MCPGateway().connect()
    rows, t0, empty = [], time.time(), 0
    try:
        for shard in range(N_SHARDS):
            sql = tpl.format(tbl=f"t_access_log_{shard:04d}", days=days)
            got = gw.mysql_query(RISK_SERVER, sql).get("rows", [])
            # a silently-empty shard is the platform-instability signature (see out/00);
            # count them so the caller can refuse to analyse a half-empty pull
            if not got:
                empty += 1
            rows.extend(got)
            if verbose and (shard + 1) % 8 == 0:
                print(f"  shard {shard+1:>2}/{N_SHARDS}  rows={len(rows):>7}  "
                      f"{time.time()-t0:.0f}s", flush=True)
    finally:
        gw.close()
    if empty:
        print(f"  ⚠ {empty}/{N_SHARDS} shards returned zero rows")
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=35)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    os.makedirs(OUT, exist_ok=True)
    print(f"pulling LKUS_push, last {a.days} days, {N_SHARDS} shards")
    df = pull(a.days)
    df["access_time"] = pd.to_datetime(df["access_time"])
    df = expand_features(df).sort_values("access_time").reset_index(drop=True)
    for c in ("recaptcha_score", "recap_token_len"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df[[c for c in ORDERED if c in df.columns]]

    base = a.out or os.path.join(OUT, "data", f"r3_riskcontrol_{a.days}d")
    os.makedirs(os.path.dirname(base), exist_ok=True)
    df.to_parquet(base + ".parquet", index=False)
    print(f"\n{len(df):,} 行 × {len(df.columns)} 列")
    print(f"  {base}.parquet  {os.path.getsize(base+'.parquet')/1e6:.1f} MB")
    print(f"  窗口 {df.access_time.min()} → {df.access_time.max()} (UTC)")
    print(f"  result: {df.result.value_counts().to_dict()}")
    print(f"  token_state: {df.token_state.value_counts().to_dict()}")
    return df


if __name__ == "__main__":
    main()
