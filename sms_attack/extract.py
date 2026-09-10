"""Pull LKUS_push risk-control requests from the 64 sharded access-log tables.

The risk log is sharded by Sharding-JDBC across t_access_log_0000..0063, so a full
window means one query per shard. Volume is small (~7k rows/day fleet-wide), so we
pull everything in the window rather than sampling.

Usage:
    python -m sms_attack.extract --from 2026-08-09 --to 2026-09-11
"""
import argparse
import json
import os
import time
from datetime import datetime, timedelta

import pandas as pd

from .mcp_client import MCPGateway

RISK_SERVER = "aws-luckyus-iriskcontrolservice-rw"
N_SHARDS = 64
HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(os.path.dirname(HERE), "data")


def _sql(name):
    with open(os.path.join(HERE, "sql", name), encoding="utf-8") as fh:
        return fh.read()


def pull_window(t0, t1, chunk_days=7, verbose=True):
    """Return a DataFrame of every LKUS_push request in [t0, t1)."""
    tpl = _sql("02_scalar_pull.sql")
    spans = []
    cur = datetime.fromisoformat(t0)
    end = datetime.fromisoformat(t1)
    while cur < end:
        nxt = min(cur + timedelta(days=chunk_days), end)
        spans.append((cur.strftime("%Y-%m-%d %H:%M:%S"), nxt.strftime("%Y-%m-%d %H:%M:%S")))
        cur = nxt

    gw = MCPGateway().connect()
    rows, started = [], time.time()
    try:
        for shard in range(N_SHARDS):
            tbl = f"t_access_log_{shard:04d}"
            for s0, s1 in spans:
                sql = tpl.format(tbl=tbl, t0=s0, t1=s1)
                res = gw.mysql_query(RISK_SERVER, sql)
                rows.extend(res.get("rows", []))
            if verbose and (shard + 1) % 8 == 0:
                print(f"  shard {shard + 1:>2}/{N_SHARDS}  rows={len(rows):>7}  "
                      f"{time.time() - started:.0f}s", flush=True)
    finally:
        gw.close()
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="t0", required=True)
    ap.add_argument("--to", dest="t1", required=True)
    ap.add_argument("--out", default=os.path.join(DATA, "risk_log.parquet"))
    a = ap.parse_args()

    print(f"pulling LKUS_push {a.t0} -> {a.t1} (UTC) across {N_SHARDS} shards")
    df = pull_window(a.t0, a.t1)
    df["create_time"] = pd.to_datetime(df["create_time"])
    df = df.sort_values("create_time").reset_index(drop=True)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    df.to_parquet(a.out, index=False)
    print(f"{len(df):,} rows -> {a.out}")
    print(df["create_time"].agg(["min", "max"]).to_string())


if __name__ == "__main__":
    main()
