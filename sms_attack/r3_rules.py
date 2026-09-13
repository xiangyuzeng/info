"""Resolve a strategy's rule ids into the engine's own rule text.

The 策略名称 field of the approval form must carry the rule in engine syntax, not a
paraphrase. docs/07 paraphrased it ("区号非美国 && 区号非中国") and the transcriber flagged
that as something to stop doing, because a paraphrase is exactly the 近义字段混淆 the SOP
§1.1 check is meant to catch. So the text is rebuilt from t_rms_engine_rule rather than
retyped.

Cache is written to out3/data/rules.json so the reports are reproducible offline.
"""
import json
import os
import re

from .mcp_client import MCPGateway
from .r3 import DATA3

SERVER = "aws-luckyus-iriskcontrolservice-rw"
CACHE = os.path.join(DATA3, "rules.json")


def fetch(force=False):
    if os.path.exists(CACHE) and not force:
        return json.load(open(CACHE, encoding="utf-8"))
    gw = MCPGateway().connect()
    try:
        rules = gw.mysql_query(SERVER, "SELECT rule_id, rule_name, rule_express, condition_type,"
                                       " feature_id FROM luckyus_iriskcontrolservice.t_rms_engine_rule"
                               ).get("rows", [])
        strat = gw.mysql_query(SERVER, "SELECT id, strategy_id, strategy_name, status, result_code,"
                                       " strategy_express, scene_id, operator, create_time, update_time"
                                       " FROM luckyus_iriskcontrolservice.t_rms_engine_strategy"
                                       " WHERE scene_id='LKUS_push'").get("rows", [])
    finally:
        gw.close()
    out = {"rules": {r["rule_id"]: r for r in rules},
           "strategies": {s["strategy_id"]: s for s in strat}}
    os.makedirs(DATA3, exist_ok=True)
    json.dump(out, open(CACHE, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    return out


def express_to_text(express, rules):
    """rule_xxx && (rule_yyy||rule_zzz)  ->  the same shape with rule_name substituted."""
    def sub(m):
        rid = m.group(0)
        r = rules.get(rid)
        return r["rule_name"] if r else rid
    return re.sub(r"rule_[A-Za-z0-9]+", sub, express or "")


def strategy_text(strategy_id, cache=None):
    c = cache or fetch()
    s = c["strategies"].get(strategy_id)
    if not s:
        return None
    txt = express_to_text(s["strategy_express"], c["rules"])
    return f"{txt} 则 {s['result_code']}"


if __name__ == "__main__":
    c = fetch()
    for sid in ("strategy_uKSgJAVWhWlU", "strategy_ARqkLD7E3JaK", "strategy_rDf6oPcZ8ydk",
                "strategy_bTCEWBZggaAP", "strategy_MGj5bfGOijOi"):
        print(f"\n{sid}\n  {strategy_text(sid, c)}")
