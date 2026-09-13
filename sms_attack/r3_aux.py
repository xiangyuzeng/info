"""Round-3 auxiliary pulls: OTP hard labels and gateway-uid scene coverage.

Both SQL files already existed but had no driver -- they were pasted into the MCP tool
by hand in round 1. These are the two evidence sources the SOP grading depends on:

  * t_sent_verifycode_sms.filled -- the only ground truth for "a real person received
    this code and typed it in". The attack area codes sit at filled=0 for entire days.
  * uid -> which scenes it ever touches -- SOP 3.4, a uid that only ever asks for an OTP
    and never logs in or orders is a script, not a customer.

    MCP_DB_GATEWAY_SSE=http://<gateway>:8080/sse python -m sms_attack.r3_aux --days 35
"""
import argparse
import os
import time

import pandas as pd

from .mcp_client import MCPGateway

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out3", "data")
RISK_SERVER = "aws-luckyus-iriskcontrolservice-rw"
PUSH_SERVER = "aws-luckyus-upush-rw"
N_SHARDS = 64
HERE = os.path.dirname(os.path.abspath(__file__))


def otp(t0):
    sql = open(os.path.join(HERE, "sql", "06_otp_filled.sql"), encoding="utf-8").read().format(t0=t0)
    gw = MCPGateway().connect()
    try:
        rows = gw.mysql_query(PUSH_SERVER, sql).get("rows", [])
    finally:
        gw.close()
    df = pd.DataFrame(rows)
    if not df.empty:
        # mask_no is area_code + first digit + '*****' + last4; last4 is the join key
        df["last4"] = df["mask_no"].astype(str).str[-4:]
        df["create_time"] = pd.to_datetime(df["create_time"])
    return df


def uid_scenes(t0, t1, verbose=True):
    tpl = open(os.path.join(HERE, "sql", "07_uid_scenes.sql"), encoding="utf-8").read()
    gw = MCPGateway().connect()
    rows, st = [], time.time()
    try:
        for shard in range(N_SHARDS):
            sql = tpl.format(tbl=f"t_access_log_{shard:04d}", t0=t0, t1=t1)
            rows.extend(gw.mysql_query(RISK_SERVER, sql).get("rows", []))
            if verbose and (shard + 1) % 16 == 0:
                print(f"  uid shard {shard+1}/{N_SHARDS} rows={len(rows)} "
                      f"{time.time()-st:.0f}s", flush=True)
    finally:
        gw.close()
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    # pivot (uid, scene_id, n) -> uid, n_push, n_other_scenes. This step was ad hoc in
    # round 1 and is pinned here so the label pipeline is reproducible.
    df["n"] = pd.to_numeric(df["n"], errors="coerce").fillna(0)
    push = df[df.scene_id == "LKUS_push"].groupby("uid")["n"].sum().rename("n_push")
    other = df[df.scene_id != "LKUS_push"].groupby("uid")["n"].sum().rename("n_other_scenes")
    out = pd.concat([push, other], axis=1).fillna(0).astype(int).reset_index()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=35)
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)

    t0 = (pd.Timestamp.utcnow().tz_localize(None) - pd.Timedelta(days=a.days)).strftime("%Y-%m-%d %H:%M:%S")
    t1 = (pd.Timestamp.utcnow().tz_localize(None) + pd.Timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    print(f"window {t0} → {t1} (UTC)")

    print("1/2 OTP filled (upush)")
    o = otp(t0)
    o.to_parquet(os.path.join(OUT, "r3_otp_filled.parquet"), index=False)
    print(f"  {len(o):,} rows; filled={int(o.filled.sum()) if len(o) else 0}")

    print("2/2 uid scene coverage (64 shards)")
    u = uid_scenes(t0, t1)
    u.to_parquet(os.path.join(OUT, "r3_uid_scenes.parquet"), index=False)
    if len(u):
        print(f"  {len(u):,} uids; push-only={int((u.n_other_scenes == 0).sum()):,}")


if __name__ == "__main__":
    main()
