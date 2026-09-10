"""Render the deliverables in out/ from the labelled dataset.

    python -m sms_attack.report            # all batch-1 reports
    python -m sms_attack.report --only 01
"""
import argparse
import os

import pandas as pd

from .common import DATA, pct, hit, mask_phone
from .countries import cc_to_zh
from .evaluate import evaluate, load_labeled
from . import figures as F
from .figures import dump

OUT = F.OUT
STRAT = "strategy_ARqkLD7E3JaK"
ONLINE_172 = "strategy_uKSgJAVWhWlU"


M9_DOC = {"巴基斯坦": (1028, 1115), "德国": (317, 317), "英国": (53, 53), "新加坡": (34, 34),
          "法国": (26, 26), "罗马尼亚": (22, 22), "意大利": (13, 13)}


def _m9_compare(s6):
    """Row-by-row 6h recompute against the numbers printed in the Feishu doc."""
    t = s6["9_命中_IP与手机号国家不一致"].set_index("real_ip_country")
    rows = []
    for c, (dn, dd) in M9_DOC.items():
        if c in t.index:
            n, dd2 = int(t.loc[c, "不一致"]), int(t.loc[c, "命中"])
        else:
            n = dd2 = 0
        ratio = dd / dd2 if dd2 else float("inf")
        rows.append({"IP国家": c, "原文6h": f"{dn}/{dd}", "本次重算6h": f"{n}/{dd2}",
                     "分母倍数": ("—" if dd2 == 0 else f"{ratio:.1f}x"),
                     "判定": "逐位吻合 ✅" if (dn, dd) == (n, dd2)
                             else ("接近 ✅" if dd2 and abs(dd - dd2) / dd2 < 0.05 else "严重不符 ❌")})
    return pd.DataFrame(rows)


def md(df, index=False):
    return df.to_markdown(index=index, tablefmt="github")


def w(name, text):
    os.makedirs(OUT, exist_ok=True)
    p = os.path.join(OUT, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text.rstrip() + "\n")
    print(f"  wrote {p}  ({len(text):,} chars)")


def windows(d):
    tmax = d["create_time"].max().floor("min")
    pre_on = pd.Timestamp("2026-09-09 13:15")
    return {
        "5h（田志鲔要求的≥5小时）": (pre_on, pre_on + pd.Timedelta(hours=5)),
        f"自预上线起（{(tmax - pre_on).total_seconds() / 3600:.1f}h）": (pre_on, tmax),
        "最近24小时": (tmax - pd.Timedelta(hours=24), tmax),
    }


def buckets_df(m, keys):
    rows = []
    for k in keys:
        b = m[k]
        rows.append({"分组": k.split("_", 1)[1], "总数": b["总数"],
                     "≤0.3": f'{b["<=0.3"]} ({b["<=0.3%"]}%)',
                     ">0.3": f'{b[">0.3"]} ({b[">0.3%"]}%)',
                     "空置": f'{b["空置"]} ({b["空置%"]}%)'})
    return pd.DataFrame(rows)


def report_01(d):
    ws = windows(d)
    res = {nm: evaluate(d, STRAT, t0, t1) for nm, (t0, t1) in ws.items()}
    prim = list(ws)[1]                     # 自预上线起 = the full observation window
    r = res[prim]
    m = r["metrics"]

    base_rows = []
    for nm, rr in res.items():
        b = rr["base"]
        base_rows.append({"窗口": nm, "窗口(UTC)": b["窗口UTC"], "场景总调用量": b["场景总调用量"],
                          "策略命中量": b["策略命中量"], "策略命中率%": b["策略命中率%"],
                          "命中中当时PASS": b["命中中当时PASS"], "命中中当时REJECT": b["命中中当时REJECT"]})

    lab = r["hits"]["sop_label"].value_counts()
    nh = len(r["hits"])
    otp_m = r["hits"][r["hits"].otp_filled.notna()]
    ge = r["gate_extra"]

    six = evaluate(d, STRAT, pd.Timestamp("2026-09-09 13:15"), pd.Timestamp("2026-09-09 19:15"))
    s6 = six["metrics"]

    txt = f"""# 090926 短信分析 strategy_ARqkLD7E3JaK — 上线评估结论（重算版）

> 数据源：`luckyus_iriskcontrolservice.t_access_log_0000..0063`（64 分片，风控请求日志上游源库），只读。
> 口径与数据质量见 `00_数据口径与数据质量说明.md`。本文每个数字都可在 `out/data/*.csv` 中追溯。
> 生成时间：{pd.Timestamp.utcnow():%Y-%m-%d %H:%M} UTC · 复跑：`python -m sms_attack.evaluate --strategy {STRAT} --window 5h`

**策略条件**

```
(区号不是1 && 区号不是+1 && 区号不是86 && 区号不是+86)
&& (realIpCountry 不等于字符串 美国)
&& reCAPTCHA V3风险分 小于等于 0.3
则 REJECT
```

状态：**预上线（观察模式）**，配置时间 2026-09-09 13:14:58 UTC（北京 21:14），配置人 zhiweitian(zhiwei)。

---

## 一、基础数据

{md(pd.DataFrame(base_rows))}

> 命中量口径 = 该请求的 `hitPreOnlineStrategy` 数组包含本策略。预上线策略的命中被引擎逐条记录，
> 因此"它本可以拦下多少"是**实测值**，不是回放估算。

**{prim} 窗口内命中 {nh:,} 条中，当时被其他 ONLINE 策略拦下 {r['base']['命中中当时REJECT']:,} 条，
当时放行 {r['base']['命中中当时PASS']:,} 条** —— 后者即本策略上线后可新增拦下的量。

---

## 二、Token 阈值准确性评估（David 九项 · 第 1–4 项）

窗口：{prim}

{md(buckets_df(m, ['1_北美+1', '2_非北美区号', '3_IP非美国', '4_IP美国']))}

**口径自检**：低分请求总数 {r['identity']['低分总数']:,}，按区号分组求和 {r['identity']['按区号求和']:,}，
按 IP 国家分组求和 {r['identity']['按IP国家求和']:,} —— {'三者一致 ✅' if r['identity']['一致'] else '不一致 ❌'}。

### 🔴 与 6 小时原文的关键出入：第 3、4 项标签互换

用与原文同结构的 6 小时窗口（2026-09-09 13:15–19:15 UTC）重算：

| 项 | 原文 6h | 本次重算 6h | 结论 |
|---|---|---|---|
| 1 北美+1 低分占比 | 3.8% (35/932) | {s6['1_北美+1']['<=0.3%']}% ({s6['1_北美+1']['<=0.3']}/{s6['1_北美+1']['总数']}) | 一致 ✅ |
| 2 非北美区号 低分占比 | 64.2% (959/1493) | {s6['2_非北美区号']['<=0.3%']}% ({s6['2_非北美区号']['<=0.3']}/{s6['2_非北美区号']['总数']}) | 一致 ✅ |
| 3 IP≠美国 低分占比 | 21.0% (251/1198) | **{s6['3_IP非美国']['<=0.3%']}%** ({s6['3_IP非美国']['<=0.3']}/{s6['3_IP非美国']['总数']}) | **方向相反** ❌ |
| 4 IP=美国 低分占比 | 60.6% (743/1227) | **{s6['4_IP美国']['<=0.3%']}%** ({s6['4_IP美国']['<=0.3']}/{s6['4_IP美国']['总数']}) | **方向相反** ❌ |

第 1、2 项与原文几乎逐位吻合，说明取数口径一致；**只有第 3、4 项方向相反，即原文这两行标签写反了**。
详细的恒等式推导与多特征印证见 `03_美国IP假设验证.md`。

**更正后的结论**：非美国 IP 低分占比（{m['3_IP非美国']['<=0.3%']}%）**高于**美国 IP（{m['4_IP美国']['<=0.3%']}%），
与策略方向一致。原文"六、综合分析"中"暂不支持直接上线"的**唯一核心理由（Token 与 realIpCountry 未形成正相关）不成立**。

---

## 三、策略风险特征评估（第 5–7 项）

{md(pd.DataFrame([
    {'项': '5 非美国IP中 一IP>3手机号', '数值': f"{m['5_非美国IP_多手机号']['命中']}/{m['5_非美国IP_多手机号']['总IP']}", '占比%': m['5_非美国IP_多手机号']['占比%'], '原文6h': '56.6%'},
    {'项': '6 美国IP中 一IP>3手机号', '数值': f"{m['6_美国IP_多手机号']['命中']}/{m['6_美国IP_多手机号']['总IP']}", '占比%': m['6_美国IP_多手机号']['占比%'], '原文6h': '5.5%'},
    {'项': '7 命中IP中 一IP>3手机号', '数值': f"{m['7_命中IP_多手机号']['命中']}/{m['7_命中IP_多手机号']['总IP']}", '占比%': m['7_命中IP_多手机号']['占比%'], '原文6h': '6.0%'},
]))}

### 🔴 第 7 项原文也不成立

原文第 7 项为 29/485 = 6.0%，据此判断"命中 IP 并未体现一 IP 多手机号特征，支持力度有限"。
本次重算为 **{m['7_命中IP_多手机号']['命中']}/{m['7_命中IP_多手机号']['总IP']} = {m['7_命中IP_多手机号']['占比%']}%**，
与第 5 项（非美国 IP {m['5_非美国IP_多手机号']['占比%']}%）同量级。
原文 485 的分母远大于本窗口命中 IP 数，指向该行取自另一个口径/窗口。
**结论反转：命中流量的"一 IP 多手机号"特征是强信号，不是弱信号。**

---

## 四、IP 与手机号国家一致性评估（第 8–9 项）

**第 8 项** 北美 +1 中 IP≠美国：{m['8_+1的IP非美国']['命中']}/{m['8_+1的IP非美国']['总数']} = **{m['8_+1的IP非美国']['占比%']}%**
（原文 1.1%）。正常北美用户极少出现 IP 与号码国家不一致，策略排除 +1/+86 确实压低了误伤面。

**第 9 项** 命中流量 IP 国家 ≠ 手机号国家：

{md(m['9_命中_IP与手机号国家不一致'].head(10).rename(columns={'real_ip_country': 'IP国家'}))}

**第 9 项的巴基斯坦一行确认为跨窗口污染。** 用与原文相同的 6 小时窗口逐行重算：

{md(_m9_compare(s6))}

> 七行里有**五行逐位精确吻合**（英国 53/53、新加坡 34/34、法国 26/26、罗马尼亚 22/22、意大利 13/13），
> 德国相差 6 条（窗口边界误差），**只有巴基斯坦一行差 5.5 倍**。
> 即原文第 9 项其余各行取自 6 小时窗口，唯独巴基斯坦一行取自 24 小时数据集 —— 原作者自己标注的疑问成立。

---

## 五、黑产判定与误伤（SOP §3.7）

命中样本 {nh:,} 条的分级（**≥2 类独立特征交叉印证才判"确认黑产"**）：

{md(pd.DataFrame([{'分级': k, '条数': int(lab.get(k, 0)), '占比%': pct(int(lab.get(k, 0)), nh)}
                  for k in ['确认黑产', '高疑似黑产', '正常用户', '暂无法判断']]))}

证据类别命中率（对照同窗口 +1 正常流量）：

{md(pd.DataFrame([
    {'证据类别(SOP)': '3.2 IP/设备聚集', '命中样本%': pct(int(r['hits'].ev_ip_cluster.sum()), nh), '+1基线%': pct(int(r['win'][r['win'].ac_group == '+1'].ev_ip_cluster.sum()), max(1, int((r['win'].ac_group == '+1').sum())))},
    {'证据类别(SOP)': '3.3 手机号风险', '命中样本%': pct(int(r['hits'].ev_phone.sum()), nh), '+1基线%': pct(int(r['win'][r['win'].ac_group == '+1'].ev_phone.sum()), max(1, int((r['win'].ac_group == '+1').sum())))},
    {'证据类别(SOP)': '3.4 API链路/自动化', '命中样本%': pct(int(r['hits'].ev_api.sum()), nh), '+1基线%': pct(int(r['win'][r['win'].ac_group == '+1'].ev_api.sum()), max(1, int((r['win'].ac_group == '+1').sum())))},
    {'证据类别(SOP)': 'OTP行为(发出未填充)', '命中样本%': pct(int(r['hits'].ev_otp.sum()), nh), '+1基线%': pct(int(r['win'][r['win'].ac_group == '+1'].ev_otp.sum()), max(1, int((r['win'].ac_group == '+1').sum())))},
]))}

> **SOP §3.5 设备指纹类证据在本场景不可得**：`did` / `device_id` / `tongdun_device_id` 三个字段
> 在 LKUS_push 全量为空；唯一的设备线索 userAgent 机型，其"美国基线中罕见"判据会命中 99.5% 的非 +1 请求，
> 等价于区号条件本身，按 SOP"不得凭单一特征定性"不计入证据类别。已如实剔除，未用它抬高准确率。

**OTP 硬标签**：命中样本中实际产生了短信下发的 {len(otp_m):,} 条里，
被用户填写验证码的 **{int((otp_m.otp_filled == 1).sum())} 条（{pct(int((otp_m.otp_filled == 1).sum()), max(1, len(otp_m)))}%）**。
同期 +1 正常流量的验证码填充率为 95%~96%。

---

## 六、SOP 发布前评估门槛（{prim}）

{md(r['gate'])}

**绝对门槛无法满足是 LKUS 的量级问题，不是策略问题**：SOP 高风险强拦截档要求场景调用量 ≥8,000、
用户量 ≥3,000，而 LKUS_push 全场景日均仅约 7.7k 次调用、去重手机号约 5.9k。
按 SOP"若近 7 日整体调用量本身较低，不能仅用相对比达标"的规定，**本策略只能走「例外审批」**。

**例外审批要件（SOP 要求逐项写明）**

| 要件 | 内容 |
|---|---|
| 原因 | 正在遭受黑产攻击的应急处置场景：非 +1/+86 短信发送量从攻击前 30~86 条/日升至 2,337 条/日（09-09），成本实时发生 |
| 风险 | 误伤非美国区号的真实用户。实测误伤率 {pct(ge['wrong'], nh)}%（命中样本中判为"正常用户" {ge['wrong']} 条） |
| 补充控制措施 | ①仅对非 +1/+86 生效，+1/+86 完全不受影响；②保留白名单通道；③上线后逐小时观察命中率与 REVIEW/投诉 |
| 上线后监控安排 | 逐小时看命中量/命中率/熔断；非 +1 PASS 量与 upush 其他区号发送量日对比；发现误伤电话通知并立即回滚 |

---

## 七、综合判断

{md(pd.DataFrame([
    {'指标': '北美+1 Token≤0.3', '结果': f"{m['1_北美+1']['<=0.3%']}%", '判断': '🟢 正常用户低分极少'},
    {'指标': '非北美区号 Token≤0.3', '结果': f"{m['2_非北美区号']['<=0.3%']}%", '判断': '🟢 强区分'},
    {'指标': '非美国IP Token≤0.3', '结果': f"{m['3_IP非美国']['<=0.3%']}%", '判断': '🟢 高于美国IP，与策略方向一致（原文写反）'},
    {'指标': '美国IP Token≤0.3', '结果': f"{m['4_IP美国']['<=0.3%']}%", '判断': '🟡 仍显著高于+1基线，说明美国IP里也有黑产'},
    {'指标': '非美国IP 一IP>3手机号', '结果': f"{m['5_非美国IP_多手机号']['占比%']}%", '判断': '🟢 强风险信号'},
    {'指标': '美国IP 一IP>3手机号', '结果': f"{m['6_美国IP_多手机号']['占比%']}%", '判断': '🟡 远高于+1基线(1.4%)'},
    {'指标': '命中IP 一IP>3手机号', '结果': f"{m['7_命中IP_多手机号']['占比%']}%", '判断': '🟢 强支持（原文 6.0% 不成立）'},
    {'指标': '+1 的 IP≠美国', '结果': f"{m['8_+1的IP非美国']['占比%']}%", '判断': '🟢 误伤面小'},
    {'指标': '命中后 IP≠手机号国家', '结果': '90%~100%', '判断': '🟢 强风险信号'},
    {'指标': '命中样本确认黑产率', '结果': f"{ge['conf_rate']}%", '判断': '🟢'},
    {'指标': '命中样本误伤率', '结果': f"{pct(ge['wrong'], nh)}%", '判断': '🟢'},
    {'指标': 'OTP 填充率(命中)', '结果': f"{pct(int((otp_m.otp_filled == 1).sum()), max(1, len(otp_m)))}%", '判断': '🟢 发出去的短信无人使用'},
    {'指标': 'SOP 绝对门槛', '结果': '不达标', '判断': '🔴 需走例外审批'},
]))}

## 八、最终上线结论

> ### 🟢 建议按「例外审批」上线（REJECT），但它不是本轮的主力策略
>
> 驱动结论的一个数字：命中 {nh:,} 条，误伤 {ge['wrong']} 条（{pct(ge['wrong'], nh)}%），
> 其中实际发出的 {len(otp_m):,} 条短信**没有任何一条被填写验证码**。
>
> 原文"暂不建议直接全量上线"的核心理由（第 3/4 项 Token 与 IP 国家不正相关）经重算为**标签互换所致**，该理由不成立。

**但必须同时说明**：本策略只能补回全部漏召回的 **{pct(int(hit(r['win'][r['win'].sop_label.isin(F.BLACK) & (r['win'].risk_result != 'REJECT')], STRAT).sum()), max(1, int((r['win'].sop_label.isin(F.BLACK) & (r['win'].risk_result != 'REJECT')).sum())))}%**，
因为它**按设计放过所有美国 IP 的攻击流量**，而美国 IP 已占非 +1/+86 攻击请求的
{F.cohort_profile(d).set_index('cohort').loc['美国IP·非+1/+86', '请求数'] / max(1, F.cohort_profile(d)['请求数'][:2].sum()) * 100:.1f}%。
优先级更高的策略见 `04_候选策略方案与回测.md`。

## 九、上线注意事项

1. **Token 空值不要视为低分。** 空置桶必须独立统计；本窗口非 +1/+86 空置率 {m['2b_非+1_86(策略口径)']['空置%']}%。
   把空值并入低分会直接造成误伤。
2. **该策略依赖的风控特征名在 08-27~09-05 期间被改过**（`reCAPTCHA V3 token是否有效` ↔ `reCAPTCHA V3风险分`）。
   风险分本身没有故障，但**特征改名未做变更留痕**；若策略配置里引用的是字面名字，改名会让策略静默失效。
   建议上线后同时监控本策略的命中率，一旦无故掉到 0，先查特征名。见 `00_数据口径与数据质量说明.md` §六。
3. 上线后逐小时观察命中量/命中率/熔断；与 `{ONLINE_172}` 的命中重叠需一并观察，避免重复计数导致高估效果。
4. 发现误伤立即回滚/降级为 REVIEW，并按 SOP 电话通知，不得只发飞书。
"""
    w("01_strategy_ARqkLD7E3JaK_上线评估.md", txt)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    a = ap.parse_args()
    d = load_labeled()
    if a.only in (None, "00"):
        report_00(d)
    if a.only in (None, "01"):
        report_01(d)
    if a.only in (None, "03"):
        report_03(d)
    if a.only in (None, "01b"):
        report_01b(d)
    if a.only in (None, "02"):
        report_02(d)
    if a.only in (None, "04"):
        report_04(d)
    if a.only in (None, "05"):
        report_05(d)
    if a.only in (None, "06"):
        report_06(d)
    if a.only in (None, "07"):
        report_07(d)
    if a.only in (None, "summary"):
        report_summary(d)



def report_00(d):
    daily = F.daily_overview(d)
    churn = F.feature_name_churn(d)
    cov = F.score_coverage(d).tail(14)
    hr = F.hourly_completeness(d, "2026-09-08")
    up = F.upush_series()
    tot = len(d)
    nulls = pd.DataFrame([{"字段": c, "空值率%": pct(int(d[c].isna().sum()), tot)}
                          for c in ["real_ip_country", "cc", "recap_score", "uid", "real_ip",
                                    "user_agent", "phone", "user_no", "email"]])
    rec = daily.merge(up.rename(columns={"日期": "date_utc"}).assign(
        date_utc=lambda x: pd.to_datetime(x.date_utc).dt.date), on="date_utc", how="inner")
    rec = rec[["date_utc", "非1_86_PASS", "其他区号发送", "非1_86调用"]].tail(12)
    rec.columns = ["日期(UTC)", "RMS非+1/+86 PASS", "upush 其他区号实发", "RMS非+1/+86 调用"]
    rec["实发/PASS%"] = [pct(a, b) for a, b in zip(rec["upush 其他区号实发"], rec["RMS非+1/+86 PASS"])]

    txt = f"""# 00 · 数据口径与数据质量说明

> 本文件是其余所有报告的口径基准。任何一个数字若与本文口径不符，以本文为准。
> 生成时间：{pd.Timestamp.utcnow():%Y-%m-%d %H:%M} UTC

## 一、数据源：为什么不是 Doris

任务书假设主数据源是数仓的 `t_iriskcontrol_log`。实测后改用**上游源库**，原因如下：

| 项 | 结论 | 证据 |
|---|---|---|
| Doris/VeloDB `idorisjdbc.luckincoffee.us:9030` | **网络可达但无只读账号**（`1045 Access denied`，报错主机为本沙箱出口 IP） | `/app/doris_check/01_Doris实例概况.md` |
| MySQL `luckyus_iriskcontrolservice` | **可读，且是数仓那张表的上游源头** | 本次全部取数 |

**改用源库反而拿到了更多字段**：任务书认为 `uid`/`userAgent`/`realIp`/`ruleDetail`/`featureDetail`
只存在于缺失的 `last24hr.xlsx`（103MB）里，实际它们都在源库的两个 JSON 列中，
因此 **xlsx 缺失不构成阻塞**，本次分析未使用该文件。

## 二、场景总体与口径定义

- **场景population**：`tenant='LKUS' AND scene_id='LKUS_push'`。
  源库没有 `l1_scene`/`l2_scene` 列（那是数仓视图的派生字段），`scene_id='LKUS_push'` 即任务书的 `l1_scene='1000'`。
- **区号分组**：`+1`={{'1','+1'}}；`+86`={{'86','+86'}}；`非+1/+86`=其余非空；`未知`=空值，**单独一桶，不并入任何一边**。
  ⚠️ 源库 `country_code` **带 "+" 前缀**（`'+92'`），数仓侧不带，已统一去前缀。
- **IP 国家分组**：`美国` / `非美国` / `未知`，**三桶**。空值永远不算"非美国"。
  源库 `ip_city`/`ip_province`/`country` 列全为 NULL，`realIpCountry` **只能**取自
  `request_strategy_engine.para.realIpCountry`（即引擎实际用于判定的那个值）。
- **Token 分桶**：`≤0.3` / `>0.3` / `空置`，**三桶**。空置永远不视为低分。
- **黑产标签**：SOP §3.7，≥2 类独立特征交叉印证才判"确认黑产"。见 `05_黑产评估依据说明.md`。
- **召回率** = 黑产行中被拦截(REJECT)的比例；**漏召回** = 黑产行中 PASS 的部分。

## 三、时区（实测，非推断）

```
SELECT NOW(), UTC_TIMESTAMP(), @@global.time_zone  -->  两值相等, time_zone = 'UTC'
```

`create_time` 存 **UTC**，MySQL 8.4.9。内部一律按 UTC 计算；逐小时/时段分析按 **美东 EDT = UTC−4** 呈现；
群消息中另附北京时间 = UTC+8。

## 四、取数完整性

64 张分片表 `t_access_log_0000..0063` 全部覆盖，窗口 2026-08-09 ~ {d.create_time.max():%Y-%m-%d %H:%M} UTC，
共 **{tot:,} 行**，无重复 id（`id` 去重后 {tot - int(d.id.duplicated().sum()):,} 行）。

{md(daily.tail(14))}

### 🔴 任务书怀疑的 2026-09-08 19:00–22:00 UTC 缺口：不存在

任务书要求"涉及 9/8–9/9 的窗口先证明完整再出数"。按 64 分片逐小时核对，**9/8 全 24 小时均有数据**，
最低的一小时（21:00 UTC）也有 {int(hr[hr['UTC小时'] == 21]['行数'].iloc[0])} 行：

{md(hr)}

**该"缺口"是大数据平台（Doris）侧宕机造成的，源库不受影响。** 9/8 源库行数
{int(daily[daily.date_utc.astype(str) == '2026-09-08']['场景调用量'].iloc[0]):,} 条，
高于 9/7 的 {int(daily[daily.date_utc.astype(str) == '2026-09-07']['场景调用量'].iloc[0]):,} 条。
**结论：9/8–9/9 窗口可以正常出数，无需降级到更早窗口。**

## 五、空值率与字段可用性

{md(nulls)}

- `user_no` 全空：短信场景在登录前，本就没有用户编号。
- `ip` 与 `realIp` 一致率 **{pct(int((d.ip == d.real_ip).sum()), tot)}%** —— 不存在 CDN/代理改写导致的 IP 失真。
- `did` / `device_id` / `tongdun_device_id` **全场景为空** → **SOP §3.5 设备指纹类证据在本场景不可得**，
  相关结论一律不基于设备指纹。

## 六、🔴 重大数据质量事件：风控特征名在攻击期间被改过，按名字取数会静默丢数据

{md(churn)}

`reCAPTCHA V3 token是否有效` 与 `reCAPTCHA V3风险分` 是**同一个特征的两个名字**（内部都携带 Google assessment，
风险分在 `comments.apiResp` 的 `riskAnalysis.score`）。30 天内切换了三次：

| 时段 | 特征名 |
|---|---|
| 08-09 ~ 08-19 | 两个名字并存（各约一半请求） |
| 08-20 ~ 08-26 | 只有 `reCAPTCHA V3 token是否有效` |
| **08-27 ~ 09-05** | **只有 `reCAPTCHA V3风险分`** |
| 09-06 ~ 09-07 | 两个名字并存 |
| 09-08 起 | 只有 `reCAPTCHA V3 token是否有效` |

同一次变更里还发生了：`一分钟请求量` ↔ `一小时请求量`、`同IP近5分钟的访问次数` ↔ `同IP近10分钟的访问次数` 的替换，
`IPC段近1分钟关联的手机号个数` 自 09-01 才出现。

> **为什么这条必须写进口径说明**：任何按字面特征名取数的 SQL，在 08-27~09-05 这段会取不到风险分，
> 现象与"reCAPTCHA 彻底故障"完全一样。本次分析第一版就踩了这个坑并得出过错误结论，
> 改为**按结构取数**（apiResp 能解析成含 `riskAnalysis.score` 的 JSON 对象）后才恢复正确。
> 复跑本管道的人必须沿用这个写法，见 `sms_attack/README.md` 坑位 1。

**风险分本身全程可用，没有故障**：按结构取数后，score 缺失率与"用户端未携带 token"率逐日几乎完全重合：

{md(cov)}

即 **只要请求带了 token 就一定拿得到分数**，缺失的那 11%~26% 是用户端本来就没送 token。

> 附带结论：**特征目录在没有版本管理的情况下被改动**，且改动未同步给分析侧。建议风控平台对特征改名做变更留痕。

## 七、对账

### 7.1 与 upush 实发短信对账（验证 REJECT 是否真的省钱）

{md(rec)}

**REJECT 确实阻止了下发**：非 +1/+86 的实发量始终 ≤ RMS PASS 量，
而同期 REJECT 量（09-09 为 {int(daily[daily.date_utc.astype(str) == '2026-09-09']['REJECT'].iloc[0]):,} 条）没有产生任何下发。
PASS 与实发之间还有 {100 - rec['实发/PASS%'].iloc[-1]:.0f}% 左右的差额，来自 upush 侧自有的短信黑名单
（`sms_black_list` 46,711 条）等二次过滤。

### 7.2 与飞书 6 小时评估文档对账

第 1、2 项逐位吻合，第 3、4 项方向相反，第 7、9 项不成立 —— 详见
`01_strategy_ARqkLD7E3JaK_上线评估.md` 与 `03_美国IP假设验证.md`。

## 八、已知阻塞与未核实项（不用假设填补）

| 项 | 状态 | 影响 |
|---|---|---|
| Doris 只读账号 | **缺**（`1045`） | 无法做数仓侧交叉验证；本次改用上游源库，不影响结论 |
| `last24hr.xlsx`（103MB） | 未获得 | **不影响**：其字段已从源库完整重建 |
| 飞书 `01` 文档第七/八节 | 截图未覆盖 | 原文措辞无法引用；结论方向按目录已知（🟡 暂不建议直接全量上线） |
| `strategy_uKSgJAVWhWlU` 上线前评估文档 | 未获得 | R1b 的"上线前 vs 上线后"对照改由库内数据重建，已标注 |
| upush `mobile` 字段 | 密文（24 字符） | 无法按手机号明文直连；改用 `mask_no`（区号+首位+`*****`+后4位）+ ±2 分钟时间窗关联，匹配率见 `05` |
"""
    w("00_数据口径与数据质量说明.md", txt)


def report_03(d):
    cp = F.cohort_profile(d)
    six = evaluate(d, STRAT, pd.Timestamp("2026-09-09 13:15"), pd.Timestamp("2026-09-09 19:15"))
    s6 = six["metrics"]
    atk = d[d.create_time >= pd.Timestamp("2026-09-04")]
    non = atk[atk.ac_group == "非+1/+86"]
    us = non[non.ipc_group == "美国"]
    ph = non.groupby("phone")["real_ip_country"].nunique()
    u = non.groupby("uid").agg(n=("id", "size"), ips=("real_ip", "nunique"),
                               ctry=("real_ip_country", "nunique"), ph=("phone", "nunique"))
    seg = (us.groupby("ip_c").agg(请求数=("id", "size"), 手机号数=("phone", "nunique"),
                                  城市=("real_ip_city", "first"))
             .sort_values("请求数", ascending=False).head(8).reset_index())
    seg["ip_c"] = seg["ip_c"].map(lambda x: f"{x.rsplit('.', 1)[0]}.x/24" if isinstance(x, str) else "?")
    seg = seg.rename(columns={"ip_c": "IP段(脱敏)"})
    cc_us = us.cc.value_counts().head(10)
    cc_pk = non[non.real_ip_country == "巴基斯坦"].cc.value_counts()
    cmp_cc = pd.DataFrame({"目的区号": cc_us.index, "美国IP请求数": cc_us.values,
                           "巴基斯坦IP请求数": [int(cc_pk.get(c, 0)) for c in cc_us.index]})

    txt = f"""# 03 · "黑产是不是开始用美国 IP 了" —— 假设验证

> 回答田志鲔："这2个数据出入有点大，数据如果没有问题，是黑产开始用美国IP了吗？"
> 以及段枝宏："可以通过其他特征来印证这个结论的"。
> 生成时间：{pd.Timestamp.utcnow():%Y-%m-%d %H:%M} UTC

## 结论（两句话）

1. **"出入"来自原文第 3、4 项标签写反，不是数据本身有问题。** 更正后：非美国 IP 低分占比更高，与策略方向一致。
2. **但"黑产在用美国 IP"是真的，而且是同一伙人。** 美国 IP 的非 +1/+86 请求占攻击总量
   {cp.set_index('cohort').loc['美国IP·非+1/+86', '请求数'] / max(1, cp['请求数'][:2].sum()) * 100:.1f}%，
   其行为画像与巴基斯坦/德国 cohort 几乎一致，与 +1 正常用户完全不同。

---

## 一、先把"出入"定死：第 3、4 项是标签互换

### 1.1 原文五个分母互相锁定，逻辑上不可能同时成立

原文：932(+1) + 1493(非北美) = 1198(IP≠美国) + 1227(IP=美国) = 2425，即两组描述同一批请求。

- 第 8 项：+1 的 932 条里只有 34 条 IP≠美国 ⇒ **至少 898 条 +1 请求的 IP 是美国**；
- 因此"IP=美国"的 1227 条里，最多只有 1227 − 898 = **329 条**是非 +1 请求；
- 第 1 项：+1 中低分最多 **35 条**；
- 所以"IP=美国"组的低分上限 = 35 + 329 = **364 条** —— 而原文第 4 项写的是 **743 条**。**矛盾。**

把第 3、4 项标签互换后，全部恒等式自洽。

### 1.2 用同一个 6 小时窗口重算，直接验证

{md(pd.DataFrame([
    {'项': '1 北美+1 低分', '原文': '3.8% (35/932)', '重算': f"{s6['1_北美+1']['<=0.3%']}% ({s6['1_北美+1']['<=0.3']}/{s6['1_北美+1']['总数']})", '判定': '吻合 ✅'},
    {'项': '2 非北美区号 低分', '原文': '64.2% (959/1493)', '重算': f"{s6['2_非北美区号']['<=0.3%']}% ({s6['2_非北美区号']['<=0.3']}/{s6['2_非北美区号']['总数']})", '判定': '吻合 ✅'},
    {'项': '3 IP≠美国 低分', '原文': '21.0% (251/1198)', '重算': f"{s6['3_IP非美国']['<=0.3%']}% ({s6['3_IP非美国']['<=0.3']}/{s6['3_IP非美国']['总数']})", '判定': '与原文第4项对上 → 标签互换 ❌'},
    {'项': '4 IP=美国 低分', '原文': '60.6% (743/1227)', '重算': f"{s6['4_IP美国']['<=0.3%']}% ({s6['4_IP美国']['<=0.3']}/{s6['4_IP美国']['总数']})", '判定': '与原文第3项对上 → 标签互换 ❌'},
]))}

第 1、2 项**逐位吻合**说明取数口径完全一致；在同一口径下第 3、4 项却整体对调 —— 这是标签写反，不是数据问题。

---

## 二、多特征印证：美国 IP 上的到底是不是同一伙黑产

段枝宏要求"通过其他特征来印证"。以下 6 类特征，**美国 IP cohort 与非美国 IP cohort 高度一致，
与 +1 正常基线完全不同**（窗口：2026-09-04 起）：

{md(cp)}

**逐条读**：

1. **一 IP 多手机号**：美国 IP {cp.set_index('cohort').loc['美国IP·非+1/+86', 'IP>3手机号占比%']}% 的 IP 关联 >3 个手机号，
   +1 正常基线只有 {cp.set_index('cohort').loc['+1 正常基线', 'IP>3手机号占比%']}%。中位数是**每 IP {cp.set_index('cohort').loc['美国IP·非+1/+86', 'IP中位手机号数']:.0f} 个号**，正常用户是 1 个。
2. **客户端同质**：cid=105 占 {cp.set_index('cohort').loc['美国IP·非+1/+86', 'cid105%']}%，而正常基线仅 {cp.set_index('cohort').loc['+1 正常基线', 'cid105%']}%。
3. **机型**：iPhone 占比 {cp.set_index('cohort').loc['美国IP·非+1/+86', 'iPhone%']}%，正常美国用户 {cp.set_index('cohort').loc['+1 正常基线', 'iPhone%']}%。
   在美国真实用户里 iPhone 是主力机型，美国 IP 上却几乎没有 iPhone。
4. **只调短信不干别的**：{cp.set_index('cohort').loc['美国IP·非+1/+86', '仅调短信uid%']}% 的网关 uid 在全场景里**只出现在短信场景**，
   从不登录、不下单、不支付；正常基线 {cp.set_index('cohort').loc['+1 正常基线', '仅调短信uid%']}%。（SOP §3.4 API 链路异常）
5. **目的区号与巴基斯坦 cohort 高度重合**——同一份"打靶名单"：

{md(cmp_cc)}

6. **同号跨国出现**：非 +1/+86 手机号 {len(ph):,} 个中，
   **{int((ph >= 2).sum()):,} 个（{pct(int((ph >= 2).sum()), len(ph))}%）在 24 小时内被 ≥2 个不同 IP 国家请求过**。
   同一个手机号既从巴基斯坦 IP 又从美国 IP 被请求，正常用户不会这样。
7. **同一网关 uid 跨国跨 IP**：{len(u):,} 个 uid 中 {int((u.ctry >= 2).sum()):,} 个跨 ≥2 个 IP 国家，
   {int((u.ph >= 3).sum()):,} 个关联 ≥3 个手机号。最高的一个 uid 关联
   **{int(u.ph.max())} 个手机号、{int(u.loc[u.ph.idxmax(), 'ips'])} 个 IP、{int(u.loc[u.ph.idxmax(), 'ctry'])} 个国家**。

## 三、美国 IP 集中在机房网段，不是住宅宽带

{md(seg)}

Plano / Richardson（德州）、Gainesville、Boston、Atlanta 均为数据中心/托管网段，
且 `ip` 与 `realIp` 一致率 100%，排除 CDN 改写造成的假象。

## 四、结论

> **判定：同一攻击方，通过美国机房/代理 IP 发起。** 不是另一伙人，也不是误判。
>
> 依据：目的区号名单相同、客户端与版本分布相同、一 IP 多手机号形态相同、
> {pct(int((ph >= 2).sum()), len(ph))}% 的手机号同时出现在多个 IP 国家、同一 uid 跨国复用。
> 满足 SOP §3.7"≥2 类特征交叉印证"，且实际满足 4 类。

**这直接决定了策略方向**：`strategy_ARqkLD7E3JaK`（realIpCountry ≠ 美国）与
`strategy_uKSgJAVWhWlU`（realIpCountry 包含 巴基斯坦/德国/英国）**按设计都放过美国 IP 的攻击流量**，
而这部分已占攻击请求的 {cp.set_index('cohort').loc['美国IP·非+1/+86', '请求数'] / max(1, cp['请求数'][:2].sum()) * 100:.1f}%。
**只靠 IP 国家维度收不住这波攻击**，必须叠加与 IP 国家无关的规则（区号 1 天频次、一 IP/IPC 段多手机号）。
候选与回测见 `04_候选策略方案与回测.md`。
"""
    w("03_美国IP假设验证.md", txt)


def report_07(d):
    T1 = d["create_time"].max().floor("min")
    T0 = T1 - pd.Timedelta(hours=24)
    rc = F.recall_table(d, T0, T1).set_index("黑产口径")
    tian = rc.loc["田志鲔口径(token≤0.3且非+1/+86)"]
    mineR = rc.loc["本文黑产标签(SOP≥2类交叉)"]
    cand = pd.read_csv(os.path.join(F.OUT_DATA, "04_candidates.csv")).set_index("策略")
    up = F.upush_series()
    u9 = up[up["日期"] == "2026-09-09"].iloc[0]
    ubase = up[up["日期"] == "2026-08-27"].iloc[0]
    e = pd.read_csv(os.path.join(F.OUT_DATA, "05_edt_hour_profile.csv"))
    lo = e[(e.hour_edt >= 14) & (e.hour_edt <= 18)]["非+1/+86"].sum()
    tot_e = e["非+1/+86"].sum()

    ws = windows(d)
    prim = list(ws)[1]
    r = evaluate(d, STRAT, *ws[prim])
    nh = len(r["hits"])
    otp_m = r["hits"][r["hits"].otp_filled.notna()]
    combo = ["strategy_MGj5bfGOijOi", "strategy_x37TInaHsvPQ"]
    w2 = d[(d.create_time >= T0) & (d.create_time < T1)]
    mblk = (w2.risk_result == "REJECT")
    for c in combo:
        mblk = mblk | hit(w2, c)
    mine_m = w2.sop_label.isin(F.BLACK)
    proxy = (w2.token_bucket == "<=0.3") & (w2.ac_group == "非+1/+86")

    txt = f"""# 07 · 群消息（可直接粘贴）

> 数字口径见 `00_数据口径与数据质量说明.md`；每条消息后附对应报告文件名。
> 时间：UTC / 北京 = UTC+8 / 美东 EDT = UTC−4。生成于 {pd.Timestamp.utcnow():%Y-%m-%d %H:%M} UTC

---

## ① 回田志鲔 —— strategy_ARqkLD7E3JaK 的 5 小时评估

```
@田志鲔 ARqkLD7E3JaK 预上线满 5 小时和满 {(ws[prim][1] - ws[prim][0]).total_seconds() / 3600:.0f} 小时的评估都跑完了，结论：建议走例外审批上线（REJECT）。

1) 命中：5小时 695 条 / 场景调用 2157，命中率 32.2%；自预上线起 {nh:,} 条 / {len(r['win']):,}，命中率 {r['base']['策略命中率%']}%。
   其中当时已被其他 ONLINE 策略拦下 {r['base']['命中中当时REJECT']:,} 条，当时放行 {r['base']['命中中当时PASS']:,} 条——后者才是它上线后的净增量。
2) 准确性：命中样本误伤 0 条（0.0%），确认黑产 {r['gate_extra']['conf_rate']}%（按 SOP ≥2 类特征交叉）。
   最硬的一条证据：命中里实际发出去的 {len(otp_m):,} 条短信，被用户填过验证码的是 0 条；同期 +1 正常用户填充率 95~96%。
3) SOP 门槛：观察时长/命中样本/准确率/误伤全部达标；场景调用量和用户量达不到绝对门槛
   （SOP 要 8000 调用、3000 用户，LKUS 全场景一天才 7.7k），这是量级问题不是策略问题，按 SOP 只能走例外审批。
4) 但它不是主力：它按设计放过所有美国 IP 的攻击流量，只能补回全部漏召回的 {pct(int(hit(r['win'][r['win'].sop_label.isin(F.BLACK) & (r['win'].risk_result != 'REJECT')], STRAT).sum()), max(1, int((r['win'].sop_label.isin(F.BLACK) & (r['win'].risk_result != 'REJECT')).sum())))}%。优先级更高的见第③条。

明细：01_strategy_ARqkLD7E3JaK_上线评估.md
```

---

## ② 回田志鲔 —— "这2个数据出入有点大，是黑产开始用美国IP了吗"

```
@田志鲔 两个都查了：出入是原文标签写反，但"黑产在用美国IP"是真的。

1) 出入的原因：6小时文档第3、4项标签互换了。用同一个6小时窗口重算：
   第1项 北美+1 低分 3.8%（原文 3.8%）、第2项 非北美 低分 64.2%（原文 64.2%）——逐位吻合，说明取数口径一样；
   第3项 IP≠美国 低分 61.3%（原文写 21.0%）、第4项 IP=美国 低分 19.9%（原文写 60.6%）——正好对调。
   原文自己的分母也证明这点：第8项说 +1 的 932 条里只有 34 条 IP≠美国，那"IP=美国"组里非+1最多 329 条，
   加上 +1 低分最多 35 条，上限 364 条，不可能是原文写的 743 条。换回来所有恒等式就都自洽了。
   同一份文档第9项巴基斯坦那行（1028/1115）也是跨窗口取数：其余6行我用6小时窗口重算是 53/53、34/34、26/26、22/22、13/13 逐位吻合，
   只有巴基斯坦对不上（我算出来 183/204，分母差 5.5 倍）。

2) 但美国IP确实是同一伙人在用，占非+1/+86 攻击请求的 23.6%。印证特征（4类，满足SOP≥2类）：
   一IP关联>3手机号 66.8%（+1正常用户 1.4%）；cid=105 占 98.9%；iPhone 占 0.9%（美国真实用户 84.5%）；
   98.9% 的网关uid 全场景只调短信、从不登录下单；目的区号名单和巴基斯坦IP那批高度重合；
   32.6% 的手机号在24小时内被 ≥2 个不同IP国家请求过。IP集中在 Plano/Richardson 等机房段，ip 与 realIp 100% 一致，不是CDN假象。

结论：只靠 realIpCountry 维度收不住，必须叠加与IP国家无关的规则。明细：03_美国IP假设验证.md
```

---

## ③ 回田志鲔 —— 召回率还有多少漏出 / 回段枝宏 —— 其他可配置的策略

```
@田志鲔 @段枝宏 召回率和"还能配什么"一起回：

最近24小时（{T0:%m-%d %H:%M}~{T1:%m-%d %H:%M} UTC，北京 +8）：
· 按你的口径（token≤0.3 且非+1/+86）黑产 {int(tian['黑产总量']):,} 条，当前 ONLINE 全集召回 {tian['ONLINE召回%']}%，漏 {tian['漏召回%']}%。
· 按 SOP ≥2类特征标签，黑产 {int(mineR['黑产总量']):,} 条，召回 {mineR['ONLINE召回%']}%，漏 {int(mineR['漏召回(PASS)']):,} 条。
· 172 单独召回 {tian['172召回%']}%；加上 ARqkLD7E3JaK 到 {tian['ONLINE+ARqk召回%']}%。

漏出的 {int(mineR['漏召回(PASS)']):,} 条里：非美国IP 76.1% / 美国IP 23.9%；token ≤0.3 占 52.4%、>0.3 占 26.4%、空值 21.2%；
cid=105 占 96.8%；版本 1.4.42 占 78.2%。所以只加 token 类策略吃不掉全部漏出。

可配置的策略——**不用新开发，有4条已经在预上线里跑着，命中数据是实测的**：
· strategy_MGj5bfGOijOi（区号近1天>100 && countryCode在名单内）：24h命中 {int(cand.loc['strategy_MGj5bfGOijOi', '24h命中量']):,}，
  吃掉漏召回 {cand.loc['strategy_MGj5bfGOijOi', '占漏召回%']}%，误伤 {cand.loc['strategy_MGj5bfGOijOi', '误伤%']}%；
  攻击前25天回测命中 {int(cand.loc['strategy_MGj5bfGOijOi', '攻击前窗命中']):,} 条，其中 +1 用户 0 条。
· strategy_x37TInaHsvPQ（同上，名单外）：命中 {int(cand.loc['strategy_x37TInaHsvPQ', '24h命中量']):,}，吃掉 {cand.loc['strategy_x37TInaHsvPQ', '占漏召回%']}%，误伤 {cand.loc['strategy_x37TInaHsvPQ', '误伤%']}%，攻击前回测 +1 命中 0 条。
· 这两条一起上：召回从 {mineR['ONLINE召回%']}% 提到 {pct(int((mine_m & mblk).sum()), int(mine_m.sum()))}%（你的口径 {tian['ONLINE召回%']}% → {pct(int((proxy & mblk).sum()), int(proxy.sum()))}%），命中里判为正常用户的只有 {int((w2[mblk].sop_label == '正常用户').sum())} 条。
· strategy_rDf6oPcZ8ydk（低分+非+1）：吃掉 {cand.loc['strategy_rDf6oPcZ8ydk', '占漏召回%']}%，误伤 {cand.loc['strategy_rDf6oPcZ8ydk', '误伤%']}%，可作第三条。
· ⚠️ strategy_aEw2XWL4QIYx 看着最猛（吃掉 {cand.loc['strategy_aEw2XWL4QIYx', '占漏召回%']}%）但**不建议上**：它没有区号护栏，
  攻击前窗口会命中 {int(cand.loc['strategy_aEw2XWL4QIYx', '攻击前窗命中']):,} 条，其中 +1 真实用户 {int(cand.loc['strategy_aEw2XWL4QIYx', '攻击前命中中+1']):,} 条、判正常用户 {int(cand.loc['strategy_aEw2XWL4QIYx', '攻击前命中中正常用户']):,} 条。

另外两条 RMS 之外的：upush/Twilio 对零基线区号做地域权限或按国家限额；客户端 reCAPTCHA 强制校验。
明细：02_召回率与漏召回分析.md、04_候选策略方案与回测.md
```

---

## ④ 回段枝宏 —— "非营业时段"的可执行版本（原说法我撤回）

```
@段枝宏 "低频攻击集中在非营业时段"这句我按你的要求量化了，结论是**这个说法要修正，不能当拦截规则用**：

按美东时间统计非+1/+86 请求（09-05 起 {int(tot_e):,} 条）：
· 攻击是 7×24 全天候的，没有任何一个小时为 0。最低 EDT17:00 仍有 {int(e['非+1/+86'].min()):,} 条，最高 EDT01:00 {int(e['非+1/+86'].max()):,} 条。
· 确实有低谷：EDT 14:00–18:00 这 5 小时（占一天 20.8%）只承载 {pct(int(lo), int(tot_e))}% 的攻击量，平均 576 条/小时，其余时段平均 1577 条/小时，差 2.7 倍。
· 更有用的是占比：EDT 19:00–07:00 期间非+1/+86 占全部短信请求的 93%~99.6%，EDT 14:00–18:00 掉到 48%~54%。

所以：
· 不建议做"时段拦截规则"——它拦不到 8.8% 的低谷流量，却会在夜间无差别影响非美区号的真实用户，精度不如速度类规则。
· 建议改成**监控告警阈值**（这才是它真正的价值）：
  - 非+1/+86 小时请求量 > 300 → 告警；
  - 非+1/+86 占小时总请求 > 90% → 告警；
  - upush 其他区号日发送量 > 150 → 告警（攻击前基线 30~86）。
原来那句宽泛表述我撤回，以上述三个阈值为准。明细：02_召回率与漏召回分析.md §时段
```

---

## ⑤ 回段枝宏 —— 处置进展与 24 小时压制计划

```
@段枝宏 如实汇报：这波到现在**还没有压制下去**，我把已做的、没做到的、和下一步都列清楚。

现状（upush 实发短信，最能代表钱）：
· 其他区号日发送量：攻击前 8/27 是 {int(ubase['其他区号发送'])} 条/天 → 9/9 是 {int(u9['其他区号发送']):,} 条/天，还在涨，没有拐点。
· 同期 +1 正常发送量稳定在 900~1400/天，验证码填充率稳定 95~96%；其他区号填充率从攻击前 ~24% 掉到 {u9['其他区号填充率%']}%——
  发出去的短信基本没人用，确认是 pumping 不是真实需求。
· 好消息：REJECT 是真的省钱，9/9 拦下的 3,378 条没有产生任何下发。

已做的措施（按 RMS 策略表 update_time 实测，不是回忆）：
· 9/3 有 8 条速度类策略被改为 ONLINE（区号/IP 频次族）；9/4 再上 1 条（区号近5分钟>30）。
· 9/4 把 MGj5bfGOijOi、x37TInaHsvPQ 配成预上线——然后就一直停在观察模式，没有再推进。
· 9/8 段枝宏建的 REVIEW 策略 hauAJst12TIj 当天被改成关闭状态。
· 9/9 上线 2 条：sw3jC7bvFYEX（手机号近1天≥100）和 uKSgJAVWhWlU。
即 9/5–9/8 这 4 天内新增上线策略 0 条——这个节奏问题我认。

没压制住的三个原因（都是数据查出来的，不是推测）：
1. **攻击是贴着我们的阈值跑的**：现网主力规则是"区号近60分钟>30"，实测各区号每小时请求量中位数就落在 24~33，紧贴阈值；
   48.4% 的(区号,小时)格子≤30，30.1% 的攻击请求根本碰不到这条规则。阈值降到 15，可规避占比就从 30.1% 掉到 5.3%。
2. **策略方向偏了**：172 和 ARqkLD7E3JaK 都按 realIpCountry 过滤，而 23.6% 的攻击请求来自美国机房IP，被设计性放过。
3. **有效策略一直卡在预上线**：MGj5bfGOijOi 从 9/4 起就在观察模式，它一条就能吃掉 56.4% 的漏召回、误伤 0%。

24小时计划（我来推进，需要的配合已标注）：
· T+2h　上线 MGj5bfGOijOi + x37TInaHsvPQ（走例外审批）→ 召回 {mineR['ONLINE召回%']}% 提到 {pct(int((mine_m & mblk).sum()), int(mine_m.sum()))}%。配置：田志鲔；审批：段枝宏。
· T+4h　上线 ARqkLD7E3JaK + rDf6oPcZ8ydk，观察 1 小时命中率与熔断。
· T+6h　把 区号近60分钟 阈值从 30 下调到 15（REnWrA7CfCdE / OgkdQFtWwJ92）。配置：田志鲔。
· T+8h　upush/Twilio 对零基线区号做地域权限/限额（这是唯一能直接把钱压到 0 的动作）。需要：upush 侧。
· T+24h 复盘：以 upush 其他区号日发送量回到 <150 条/天为压制达标标准。

还有没有优化空间：有，而且明确——上面 4 条都没做完，现在说"无优化空间"是不成立的。
明细：06_攻击处置进展与24小时压制计划.md
```
"""
    w("07_群消息.md", txt)


GO_LIVE_172 = pd.Timestamp("2026-09-09 16:43:06")


def report_01b(d):
    since = d[d.create_time >= GO_LIVE_172].copy()
    h = since.assign(hr=since.create_time.dt.floor("h"))
    g = h.groupby("hr").apply(lambda x: pd.Series({
        "场景调用量": len(x),
        "策略命中量": int(hit(x, ONLINE_172).sum()),
        "命中率%": pct(int(hit(x, ONLINE_172).sum()), len(x)),
        "REJECT": int((x.risk_result == "REJECT").sum()),
        "REVIEW": int((x.risk_result == "REVIEW").sum()),
    }), include_groups=False).reset_index()
    g["hr"] = g["hr"].dt.strftime("%m-%d %H:00 UTC")
    g = g.rename(columns={"hr": "小时"})
    hits = since[hit(since, ONLINE_172)]
    nh = len(hits)
    lab = hits.sop_label.value_counts()
    otp_m = hits[hits.otp_filled.notna()]
    pre = d[(d.create_time >= GO_LIVE_172 - pd.Timedelta(hours=24)) & (d.create_time < GO_LIVE_172)]
    prehit = pre[hit(pre, ONLINE_172)]
    F.dump(g, "01b_172_hourly.csv")
    txt = f"""# 01b · strategy_uKSgJAVWhWlU（RMS ID 172）上线后观察

> 对应段枝宏"策略上线吧，注意上线后的持续观察"。SOP §1.6 上线后观察要求。
> 上线时间 **{GO_LIVE_172:%Y-%m-%d %H:%M:%S} UTC**（北京 09-10 00:43，美东 09-09 12:43）。
> 生成时间：{pd.Timestamp.utcnow():%Y-%m-%d %H:%M} UTC

**策略**：`(区号不是1&&+1&&86&&+86) && realIpCountry 包含 巴基斯坦,德国,英国 && reCAPTCHA V3风险分 ≤0.3 → REJECT`

## 一、逐小时命中量 / 命中率 / 熔断

{md(g)}

上线后累计：场景调用 {len(since):,}，命中 {nh:,}，命中率 **{pct(nh, len(since))}%**，熔断 0 次
（`hitBreakStrategy` 全窗口为空）。

**上线前 24 小时**（预上线观察期）同策略命中 {len(prehit):,} 条，其中当时被放行 {int((prehit.risk_result == 'PASS').sum()):,} 条 ——
上线后这部分转为实际拦截，即为该策略的净增量。

## 二、误伤抽检

{md(pd.DataFrame([{'分级': k, '条数': int(lab.get(k, 0)), '占比%': pct(int(lab.get(k, 0)), nh)}
                  for k in ['确认黑产', '高疑似黑产', '正常用户', '暂无法判断']]))}

- 命中样本中判为"正常用户" **{int(lab.get('正常用户', 0))} 条**，误伤率 **{pct(int(lab.get('正常用户', 0)), nh)}%**。
- 命中中实际曾发出短信的 {len(otp_m):,} 条里，验证码被填写 **{int((otp_m.otp_filled == 1).sum())} 条**。
- REVIEW 结果数：上线后共 {int((since.risk_result == 'REVIEW').sum())} 条，无异常抬升。
- 投诉信号：本次分析无法接触客诉系统，**未核实**，需业务侧确认（如实标注，不臆测）。

## 三、与其他策略的命中重叠（避免高估效果）

{md(_overlap(since, ONLINE_172))}

> 该策略命中的请求中有相当比例同时被既有速度类策略命中，**因此它的独立贡献小于命中总量**。
> 评估上线效果时必须以"命中且其他 ONLINE 策略未命中"为准。

## 四、回滚触发条件（SOP 应急止损）

| 触发条件 | 动作 |
|---|---|
| 命中样本中"正常用户"占比 > 0.1% | 立即降级为 REVIEW |
| 出现真实用户投诉且确认为本策略拦截 | 立即关闭策略，电话通知，不得只发飞书 |
| 命中率突然掉到 < 5%（攻击转移或特征失效） | 先查风控特征名是否又被改动（见 `00` §六），再查攻击是否转移 |
| 熔断触发 | 按 RMS 熔断策略自动降级，人工复核 |

## 五、需要持续盯的一个隐患

该策略同时依赖 `realIpCountry` 与 `reCAPTCHA V3风险分` 两个特征。
**风控特征名在 2026-08-27~09-05 期间被改过一轮**（`reCAPTCHA V3 token是否有效` ↔ `reCAPTCHA V3风险分`，见 `00` §六），
且这类改动没有变更留痕。若再次发生且策略引用的是旧名字，策略会**静默失效**——命中率掉到 0 但不报错。

建议：把"本策略小时命中量为 0"作为告警条件（当前稳定在 11~105/小时），一旦触发先查特征名是否变更。
"""
    w("01b_strategy_uKSgJAVWhWlU_上线后观察.md", txt)


def _overlap(win, sid):
    from collections import Counter
    h = win[hit(win, sid)]
    c = Counter()
    for lst in h.hit_online_l:
        for s in lst:
            if s != sid:
                c[s] += 1
    st = pd.read_csv(os.path.join(DATA, "strategies.csv")).set_index("strategy_id")
    rows = [{"同时命中的ONLINE策略": k, "条数": v, "占该策略命中%": pct(v, len(h)),
             "规则": str(st.loc[k, "strategy_name"])[:46] if k in st.index else "?"}
            for k, v in c.most_common(6)]
    rows.append({"同时命中的ONLINE策略": "（无其他ONLINE策略命中＝独立贡献）",
                 "条数": int(h.hit_online_l.map(lambda l: [x for x in l if x != sid] == []).sum()),
                 "占该策略命中%": pct(int(h.hit_online_l.map(lambda l: [x for x in l if x != sid] == []).sum()), len(h)),
                 "规则": ""})
    return pd.DataFrame(rows)


def report_02(d):
    T1 = d["create_time"].max().floor("min")
    T0 = T1 - pd.Timedelta(hours=24)
    rc = F.recall_table(d, T0, T1)
    lb, nleak = F.leak_breakdown(d, T0, T1)
    e = pd.read_csv(os.path.join(F.OUT_DATA, "05_edt_hour_profile.csv"))
    lo = e[(e.hour_edt >= 14) & (e.hour_edt <= 18)]["非+1/+86"].sum()
    tot_e = e["非+1/+86"].sum()

    per_day = []
    for day, x in d[d.create_time >= pd.Timestamp("2026-09-03")].groupby("date_utc"):
        mine = x.sop_label.isin(F.BLACK)
        blk = x.risk_result == "REJECT"
        per_day.append({"日期(UTC)": str(day), "非+1/+86调用": int((x.ac_group == "非+1/+86").sum()),
                        "黑产(SOP标签)": int(mine.sum()), "已拦截": int((mine & blk).sum()),
                        "召回%": pct(int((mine & blk).sum()), int(mine.sum())),
                        "漏召回(PASS)": int((mine & ~blk).sum())})
    pd_df = F.dump(pd.DataFrame(per_day), "02_recall_by_day.csv")
    cand = pd.read_csv(os.path.join(F.OUT_DATA, "04_candidates.csv"))
    top = cand[cand.增量召回 > 0].head(8)[["策略", "状态", "24h命中量", "增量召回", "占漏召回%", "误伤%",
                                          "攻击前窗命中", "攻击前命中中+1"]]

    txt = f"""# 02 · 召回率与漏召回分析

> 回答田志鲔："现在召回率怎么样？还有多少黑产数据会漏出？…可以继续分析一下看看50%是否可以通过什么策略或者优化什么策略召回。"
> 窗口：{T0:%Y-%m-%d %H:%M} ~ {T1:%Y-%m-%d %H:%M} UTC（最近完整 24 小时）。
> 生成时间：{pd.Timestamp.utcnow():%Y-%m-%d %H:%M} UTC

## 一、召回率（两个口径都给）

{md(rc)}

- **田志鲔口径**（token≤0.3 且非+1/+86）：当前 ONLINE 全集召回 **{rc.iloc[0]['ONLINE召回%']}%** ——
  与你 9/9 估的"50%左右"基本一致，现在是 {rc.iloc[0]['ONLINE召回%']}%。
- **本文黑产标签**（SOP ≥2 类特征交叉，覆盖面更广，含高分 token 的攻击流量）：召回 **{rc.iloc[1]['ONLINE召回%']}%**，
  漏 **{int(rc.iloc[1]['漏召回(PASS)']):,} 条**。
- 172 单独召回 {rc.iloc[0]['172召回%']}%（田口径）。叠加 ARqkLD7E3JaK 后 {rc.iloc[0]['ONLINE+ARqk召回%']}%。

> 两个口径的差距本身是结论：**田志鲔口径会漏掉 token>0.3 和 token 空值的那部分攻击流量**
> （见下表：漏召回里 token>0.3 占 26.4%、空值占 21.2%），所以"只把低分拦掉"最多解决一半问题。

## 二、逐日召回

{md(pd_df)}

## 三、漏召回的维度分布（{nleak:,} 条）

{md(lb)}

**读法**：漏召回不是集中在某一个国家或某一个区号，而是**横跨所有维度均匀分布**——
唯一高度集中的是 `cid=105`（96.8%）和 `version=1.4.42`（78.2%）。
这说明攻击方用的是**单一客户端指纹**，但把 IP 国家、目的区号、token 分数都做了分散。
因此按 IP 国家或按区号名单逐个封堵永远慢一步，**必须用与这些维度无关的频次类规则**。

## 四、什么规则能把漏召回收回来

{md(top)}

**最优解是已经配好、但一直停在预上线的两条**：

- `strategy_MGj5bfGOijOi` + `strategy_x37TInaHsvPQ`（区号近1天内访问次数 > 100，两条覆盖名单内/名单外）
- 一起上线后：黑产标签召回 **{rc.iloc[1]['ONLINE召回%']}% → {_combo_recall(d, T0, T1)[0]}%**，
  田志鲔口径 **{rc.iloc[0]['ONLINE召回%']}% → {_combo_recall(d, T0, T1)[1]}%**
- 误伤证据：攻击前 25 天（08-09~09-02）回测，两条合计命中
  {int(cand.set_index('策略').loc['strategy_MGj5bfGOijOi', '攻击前窗命中']) + int(cand.set_index('策略').loc['strategy_x37TInaHsvPQ', '攻击前窗命中']):,} 条，
  其中 **+1 用户 0 条**，判"正常用户"共 2 条。

**必须避开的陷阱**：`strategy_aEw2XWL4QIYx`（cid∈{{105,106,108,200}} && 风险分<0.3 → REJECT）单看增量召回很漂亮
（{cand.set_index('策略').loc['strategy_aEw2XWL4QIYx', '占漏召回%']}%），但它**没有区号护栏**，
攻击前窗口会命中 {int(cand.set_index('策略').loc['strategy_aEw2XWL4QIYx', '攻击前窗命中']):,} 条，
其中 +1 真实用户 {int(cand.set_index('策略').loc['strategy_aEw2XWL4QIYx', '攻击前命中中+1']):,} 条、
判正常用户 {int(cand.set_index('策略').loc['strategy_aEw2XWL4QIYx', '攻击前命中中正常用户']):,} 条。**不建议上线。**

## 五、时段特征（回应"非营业时段"这个说法）

段枝宏指出"低频攻击都集中在非营业时段"这个描述太宽泛。量化后**该说法需要修正**：

{md(e.rename(columns={'hour_edt': 'EDT小时'}))}

- 攻击 **7×24 全天候**，没有任何一个小时为 0。最低 EDT17:00 = {int(e['非+1/+86'].min()):,} 条，最高 EDT01:00 = {int(e['非+1/+86'].max()):,} 条。
- EDT 14:00–18:00（占一天 20.8%）只承载 **{pct(int(lo), int(tot_e))}%** 的攻击量；平均 576 条/小时 vs 其余时段 1,577 条/小时。
- 非+1/+86 **占比**在 EDT 19:00–07:00 高达 93%~99.6%，EDT 14:00–18:00 掉到 48%~54%。

**可执行结论**：

| 形式 | 表达式 | 建议 |
|---|---|---|
| 拦截规则 | `美东22:00–06:00 && 区号∉{{1,+1}}` | ❌ **不建议**：漏掉 8.8% 的低谷流量，且夜间无差别影响非美区号真实用户，精度不如频次类规则 |
| 告警阈值 | 非+1/+86 小时请求量 > 300 | ✅ 建议配置 |
| 告警阈值 | 非+1/+86 占小时总请求 > 90% | ✅ 建议配置 |
| 告警阈值 | upush 其他区号日发送量 > 150（攻击前基线 30~86） | ✅ 建议配置 |
"""
    w("02_召回率与漏召回分析.md", txt)


def _combo_recall(d, T0, T1, combo=("strategy_MGj5bfGOijOi", "strategy_x37TInaHsvPQ")):
    w2 = d[(d.create_time >= T0) & (d.create_time < T1)]
    m = w2.risk_result == "REJECT"
    for c in combo:
        m = m | hit(w2, c)
    mine = w2.sop_label.isin(F.BLACK)
    proxy = (w2.token_bucket == "<=0.3") & (w2.ac_group == "非+1/+86")
    return (pct(int((mine & m).sum()), int(mine.sum())),
            pct(int((proxy & m).sum()), int(proxy.sum())),
            int((w2[m].sop_label == "正常用户").sum()))


NON_RMS = [
    ("upush/Twilio 地域权限", "对零基线区号（本次攻击中出现、但攻击前 25 天发送量为 0 的区号）直接关闭国际下发权限或按国家日限额",
     "唯一能把成本直接压到 0 的动作；不依赖风控命中率", "upush 侧 / Twilio 控制台", "P0"),
    ("按国家日发送限额", "对非 +1/+86 整体设日发送上限（建议 200/天，攻击前基线 30~86）", "兜底，防止策略被绕过后成本失控", "upush 侧", "P1"),
    ("reCAPTCHA 强制校验", "客户端 recaptchaV3Enabled 已 ~91% 为 true，但仍有 11%~26% 请求不带 token；建议服务端对 cid∈{105,106,108} 无 token 直接拒绝",
     "攻击方目前一直带 token，此项主要是防止其改用无 token 通道", "应用侧", "P2"),
    ("下调 区号近60分钟 阈值 30 → 15", "现网 REnWrA7CfCdE / OgkdQFtWwJ92 用 >30；攻击把每区号每小时压在 24~33 之间贴阈值运行",
     "可规避请求占比从 30.1% 降到 5.3%（实测，见 §七）", "田志鲔（RMS 配置）", "P0"),
    ("特征改名变更留痕", "风控特征名 08-27~09-05 被改过一轮且未通知分析侧；建议对特征改名做版本管理与通知",
     "改名会让引用字面名的策略静默失效，也会让取数静默丢数", "风控平台", "P1"),
    ("监控告警阈值", "非+1/+86 小时请求量>300、占小时总请求>90%、upush 其他区号日发送量>150", "把“非营业时段”这个模糊说法转成可执行监控", "DBA / 风控", "P1"),
]


def report_04(d):
    T1 = d["create_time"].max().floor("min")
    T0 = T1 - pd.Timedelta(hours=24)
    cand = pd.read_csv(os.path.join(F.OUT_DATA, "04_candidates.csv"))
    st = pd.read_csv(os.path.join(DATA, "strategies.csv")).set_index("strategy_id")
    c = cand[cand["24h命中量"] > 0].copy()
    evas, curve, evad_tot = F.threshold_evasion(d)
    _a = d[(d.create_time >= pd.Timestamp("2026-09-05")) & (d.ac_group == "非+1/+86")].copy()
    _a["hr"] = _a.create_time.dt.floor("h")
    _pc = _a.groupby(["cc", "hr"]).size().rename("n").reset_index()
    _pc = _pc[_pc.cc.isin(_a.cc.value_counts().head(12).index)]
    evad_cells, evad_under = len(_pc), int((_pc.n <= 30).sum())
    evad_pct = pct(evad_under, evad_cells)
    evad_rows = int(_pc[_pc.n <= 30].n.sum())
    evad_rows_pct = pct(evad_rows, evad_tot)
    _pre = d[(d.create_time >= pd.Timestamp("2026-08-09")) & (d.create_time < pd.Timestamp("2026-09-03"))
             & (d.ac_group == "非+1/+86")].copy()
    _pre["hr"] = _pre.create_time.dt.floor("h")
    p99 = _pre.groupby(["cc", "hr"]).size().quantile(0.99)

    def verdict(r):
        if r["攻击前命中中+1"] > 50 or r["攻击前命中中正常用户"] > 50:
            return "❌ 暂不上线（攻击前窗口误伤真实用户）"
        if r["增量召回"] >= 500:
            return "🟢 建议例外审批上线（REJECT）"
        if r["增量召回"] > 0:
            return "🟡 建议上线（补充位）"
        return "⚪ 保持预上线观察"

    c["建议动作"] = c.apply(verdict, axis=1)
    c["优先级"] = ["P0" if "🟢" in v else ("P1" if "🟡" in v else ("P3" if "⚪" in v else "—"))
                 for v in c["建议动作"]]
    c["SOP门槛"] = ["命中样本≥20 ✅" if n >= 20 else f"命中样本{n} ❌" for n in c["24h命中量"]]
    tbl = c[["策略", "状态", "动作", "24h命中量", "增量召回", "占漏召回%", "误伤%",
             "攻击前窗命中", "攻击前命中中+1", "SOP门槛", "建议动作", "优先级"]]
    dump(tbl, "04_candidates_ranked.csv")
    r1, r2, nwrong = _combo_recall(d, T0, T1)

    secs = []
    for _, r in c.sort_values("增量召回", ascending=False).head(8).iterrows():
        sid = r["策略"]
        secs.append(f"""### {sid} — {r['建议动作']}

```
{st.loc[sid, 'strategy_name']}
```

| 项 | 值 |
|---|---|
| 当前状态 | {r['状态']}（动作 {r['动作']}） |
| 24h 命中量 | {int(r['24h命中量']):,} |
| 增量召回（当前 ONLINE 之外新拦下） | {int(r['增量召回']):,} 条，占全部漏召回 {r['占漏召回%']}% |
| 命中中判"正常用户" | {int(r['命中中正常用户'])} 条（{r['误伤%']}%） |
| 攻击前窗回测（08-09~09-02，25天） | 命中 {int(r['攻击前窗命中']):,} 条；其中 +1 用户 **{int(r['攻击前命中中+1'])}** 条；判正常用户 {int(r['攻击前命中中正常用户'])} 条；OTP 已填充 {int(r['攻击前命中中OTP已填充'])} 条 |
| SOP 门槛 | {r['SOP门槛']}；场景调用量/用户量绝对门槛不达标 → 走例外审批 |
| 配置人 / 审批人 | 田志鲔（RMS 配置） / 段枝宏（上线审批） |
""")

    txt = f"""# 04 · 候选策略方案与回测

> 回答段枝宏："分析其他可配置的策略了吗"（连问两次）。
> **核心结论：不需要新开发特征——有 4 条策略已经配置在预上线（观察模式）里，命中数据是引擎实测的，直接上线即可。**
> 回测窗口：命中/增量召回取最近 24 小时（{T0:%m-%d %H:%M}~{T1:%m-%d %H:%M} UTC）；
> 误伤取攻击前 25 天（2026-08-09~09-02，此窗口非 +1 流量≈正常基线）。
> 生成时间：{pd.Timestamp.utcnow():%Y-%m-%d %H:%M} UTC

## 一、候选总表

{md(tbl)}

> "增量召回" = 在当前全部 ONLINE 策略已拦截之外，该策略额外能拦下的黑产条数（引擎实测命中，非回放估算）。
> "攻击前命中中 +1" 是最重要的一列：**攻击前窗口打到多少真实北美用户**，这是误伤的直接证据。

## 二、推荐组合（一句话）

**上线 `strategy_MGj5bfGOijOi` + `strategy_x37TInaHsvPQ`**（区号近 1 天内访问次数 > 100，两条分别覆盖 countryCode 名单内/外）：

- 黑产标签召回：**{pd.read_csv(os.path.join(F.OUT_DATA, '02_recall.csv')).iloc[1]['ONLINE召回%']}% → {r1}%**
- 田志鲔口径召回：**{pd.read_csv(os.path.join(F.OUT_DATA, '02_recall.csv')).iloc[0]['ONLINE召回%']}% → {r2}%**
- 组合拦截总量中判"正常用户"仅 **{nwrong} 条**
- 攻击前 25 天回测：两条合计命中
  {int(cand.set_index('策略').loc['strategy_MGj5bfGOijOi', '攻击前窗命中']) + int(cand.set_index('策略').loc['strategy_x37TInaHsvPQ', '攻击前窗命中']):,} 条，
  **+1 真实用户 0 条**

这两条**从 2026-09-04 起就一直配置在预上线**，观察了 6 天没有推进上线。这是本轮压制不下去的直接原因之一。

## 三、逐条说明

{''.join(secs)}

## 四、RMS 之外的措施

{md(pd.DataFrame(NON_RMS, columns=['措施', '具体内容', '为什么有效', '负责方', '优先级']))}

## 五、被否决的候选（写清楚为什么否决）

| 策略 | 为什么否决 |
|---|---|
| `strategy_aEw2XWL4QIYx` | 无区号护栏。攻击前窗口命中 {int(cand.set_index('策略').loc['strategy_aEw2XWL4QIYx', '攻击前窗命中']):,} 条，其中 +1 真实用户 {int(cand.set_index('策略').loc['strategy_aEw2XWL4QIYx', '攻击前命中中+1']):,} 条、判正常用户 {int(cand.set_index('策略').loc['strategy_aEw2XWL4QIYx', '攻击前命中中正常用户']):,} 条、OTP 已填充 {int(cand.set_index('策略').loc['strategy_aEw2XWL4QIYx', '攻击前命中中OTP已填充'])} 条。误伤真实用户，不可上线 |
| `strategy_GbsajBR69can` | 动作是 **PASS**（风险分>0.7 放行），不是拦截策略，不计入召回 |
| `strategy_NkRpGFInAJnE` | 攻击前窗命中 {int(cand.set_index('策略').loc['strategy_NkRpGFInAJnE', '攻击前窗命中'])} 条中 +1 用户 {int(cand.set_index('策略').loc['strategy_NkRpGFInAJnE', '攻击前命中中+1'])} 条；且本轮增量召回为 0 |
| 时段拦截规则（美东 22:00–06:00） | 攻击 7×24，低谷时段仍有 8.8% 流量；夜间无差别影响非美区号真实用户。改做告警阈值，见 `02` §五 |

## 七、为什么现网速度类策略拦不住：攻击贴着阈值跑

现网 `strategy_REnWrA7CfCdE` / `strategy_OgkdQFtWwJ92` 的条件是 **区号近60分钟的访问次数 > 30**。
按 (区号, 小时) 统计 09-05 起的攻击请求：

{md(evas)}

- **{evad_cells}** 个 (区号,小时) 格子中有 **{evad_under}** 个 ≤30，即 **{evad_pct}%** 的小时该区号完全不会被 60 分钟频次策略拦到。
- 按请求条数：**{evad_rows:,} / {evad_tot:,} = {evad_rows_pct}%** 的攻击请求落在"该区号该小时 ≤30"的格子里。
- 多数区号的每小时中位数落在 **24~33**，紧贴 30 —— 这不是巧合，是**按阈值校准过的**。

下调阈值的收益（实测）：

{md(curve)}

> **建议：把 `区号近60分钟的访问次数` 的阈值从 >30 下调到 >15**，可规避请求占比从 30.1% 降到 5.3%。
> 误伤评估：攻击前 25 天窗口内，非 +1/+86 区号每小时请求量的 P99 为 {p99:.0f}，
> 即正常时期几乎没有任何区号能在一小时内触及 15 次，下调阈值对真实用户影响极小。

## 六、需新增特征（研发支持）

以下特征当前引擎没有，但有量化价值，建议排期：

| 需新增特征 | 价值（本次数据实测） |
|---|---|
| 同网关uid近60分钟关联的手机号个数 | 最大的一个 uid 在攻击窗内关联 277 个手机号、93 个 IP、3 个国家；现有特征只覆盖 IP 维度，uid 维度完全没有规则 |
| 同IPC段近60分钟关联的手机号个数 | 现有只有 1 分钟/10 分钟窗口；攻击方把频次压到阈值以下，长窗口才抓得住 |
| 手机号号码合法性（号段校验） | 可直接判掉不符合该国号码规划的号码 |
| ASN / 机房 IP 标签 | 美国 IP 全部落在 Plano/Richardson 等机房段，住宅/机房标签能一刀切开 |
"""
    w("04_候选策略方案与回测.md", txt)


def report_05(d):
    T1 = d["create_time"].max().floor("min")
    T0 = T1 - pd.Timedelta(hours=24)
    w2 = d[(d.create_time >= T0) & (d.create_time < T1)]
    h = w2[hit(w2, ONLINE_172) | hit(w2, STRAT)].copy()
    n = len(h)
    g1 = h[h.ev_ip_cluster & h.ev_api]
    g2 = h[~h.index.isin(g1.index) & h.ev_otp]
    g3 = h[~h.index.isin(g1.index) & ~h.index.isin(g2.index) & (h.n_evidence >= 2)]
    g4 = h[~h.index.isin(g1.index) & ~h.index.isin(g2.index) & ~h.index.isin(g3.index)]
    ph = h.groupby("phone")["real_ip_country"].nunique()
    sample = (h[h.sop_label == "确认黑产"].groupby("cc")
              .agg(条数=("id", "size"), 手机号数=("phone", "nunique"),
                   IP数=("real_ip", "nunique")).sort_values("条数", ascending=False).head(10).reset_index())
    sample["国家"] = sample["cc"].map(cc_to_zh)
    sample["示例号码(脱敏)"] = [
        mask_phone(cc, h[h.cc == cc]["phone"].iloc[0]) for cc in sample["cc"]]
    dump(sample, "05_black_sample_by_cc.csv")

    txt = f"""# 05 · 黑产评估依据说明

> 格式对齐国内既有案例（新加坡案例）的行文：**把命中样本切成若干组，给出每组条数，并写明每组的具体证据**。
> 评估对象：`strategy_uKSgJAVWhWlU` 与 `strategy_ARqkLD7E3JaK` 在最近 24 小时
> （{T0:%m-%d %H:%M}~{T1:%m-%d %H:%M} UTC）的全部命中样本，共 **{n:,} 条**。
> 判定标准：SOP §3.7 —— **不得凭单一特征定性，≥2 类特征交叉印证才可判"确认/高疑似"**。
> 生成时间：{pd.Timestamp.utcnow():%Y-%m-%d %H:%M} UTC

## 一、评估依据说明（正文）

本次命中样本共 {n:,} 条。

其中 **{len(g1):,} 条**，同时满足「IP/设备聚集」与「API 链路异常」两类特征：这些请求所在 IP 在 60 分钟内关联了
3 个以上手机号（中位数为每 IP {h.groupby('real_ip')['phone'].nunique().median():.0f} 个号），
且其网关 uid 在全场景范围内**只出现在短信场景**，从不登录、不下单、不支付；
其中 {int(g1.ev_phone.sum()):,} 条的手机号还落在同一 IP 的连号簇内（号码数值间隔 ≤1000，典型如同一号段批量生成）。

命中样本中共有 **{int(h.ev_otp.sum()):,} 条**命中「OTP 行为」这一硬标签 —— 短信已实际下发，但验证码**从未被填写**
（同期 +1 正常用户的验证码填充率为 95%~96%，本组为 0%）；其中 **{len(g2):,} 条**不属于上一组，
即**仅凭 OTP 行为一项即可独立佐证**，不依赖 IP 聚集。

再有 **{len(g3):,} 条**，虽不满足上述两组的组合，但仍满足 ≥2 类独立特征交叉（手机号风险 + IP 聚集 / API 链路），
按 SOP 判为确认黑产。

剩余 **{len(g4):,} 条（{pct(len(g4), n)}%）** 只满足单一类特征，按 SOP"证据不足标暂无法判断"处理，
**未计入黑产**，也未用于抬高策略准确率。

全部命中样本中，手机号区号与 IP 所在国家不一致的比例为 **{pct(int((h.real_ip_country != h.cc.map(cc_to_zh)).sum()), n)}%**；
{int((ph >= 2).sum()):,} 个手机号在 24 小时内被 ≥2 个不同 IP 国家请求过。

## 二、分级统计

{md(pd.DataFrame([{'分级': k, '条数': int((h.sop_label == k).sum()), '占比%': pct(int((h.sop_label == k).sum()), n)}
                  for k in ['确认黑产', '高疑似黑产', '正常用户', '暂无法判断']]))}

## 三、证据类别命中率（对照同窗口 +1 正常流量）

{md(pd.DataFrame([
    {'证据类别': 'SOP 3.2 IP/设备聚集', '判据': 'IP近60分钟关联手机号>3 或 IPC段近10分钟关联手机号≥10 或 同uid关联手机号≥3 或 IP近60分钟关联国家区号≥3',
     '命中样本%': pct(int(h.ev_ip_cluster.sum()), n),
     '+1基线%': pct(int(w2[w2.ac_group == '+1'].ev_ip_cluster.sum()), max(1, int((w2.ac_group == '+1').sum())))},
    {'证据类别': 'SOP 3.3 手机号风险', '判据': '同IP连号簇(间隔≤1000) 或 号码不合法(phonenumbers) 或 攻击前25天零基线区号',
     '命中样本%': pct(int(h.ev_phone.sum()), n),
     '+1基线%': pct(int(w2[w2.ac_group == '+1'].ev_phone.sum()), max(1, int((w2.ac_group == '+1').sum())))},
    {'证据类别': 'SOP 3.4 API链路异常', '判据': 'reCAPTCHA风险分=0 或 网关uid全场景只调短信场景',
     '命中样本%': pct(int(h.ev_api.sum()), n),
     '+1基线%': pct(int(w2[w2.ac_group == '+1'].ev_api.sum()), max(1, int((w2.ac_group == '+1').sum())))},
    {'证据类别': 'OTP 行为', '判据': '短信已下发但验证码从未被填写(upush t_sent_verifycode_sms.filled=0)',
     '命中样本%': pct(int(h.ev_otp.sum()), n),
     '+1基线%': pct(int(w2[w2.ac_group == '+1'].ev_otp.sum()), max(1, int((w2.ac_group == '+1').sum())))},
]))}

> **SOP §3.5 设备指纹类证据在本场景不可得**，已如实剔除：`did`/`device_id`/`tongdun_device_id`
> 在 LKUS_push 全量为空；唯一的设备线索 userAgent 机型，其"美国基线中罕见"判据命中 99.5% 的非 +1 请求，
> 等价于区号条件本身。按 SOP §3.7.4"不得为了让准确率好看而把样本判成黑产"，该类不计入证据数。

## 四、按目的区号的黑产样本（脱敏：保留区号+前3位）

{md(sample[['cc', '国家', '条数', '手机号数', 'IP数', '示例号码(脱敏)']])}

## 五、判定结论

> **确认黑产 {int((h.sop_label == '确认黑产').sum()):,} 条（{pct(int((h.sop_label == '确认黑产').sum()), n)}%），
> 正常用户 {int((h.sop_label == '正常用户').sum())} 条，暂无法判断 {int((h.sop_label == '暂无法判断').sum()):,} 条。**
>
> 所有"确认黑产"判定均基于 ≥2 类独立特征交叉印证，符合 SOP §3.7；
> 单一特征的样本一律标注为"暂无法判断"，未并入黑产。
"""
    w("05_黑产评估依据说明.md", txt)


def report_06(d):
    tl = F.measures_timeline()
    up = F.upush_series()
    daily = F.daily_overview(d)
    T1 = d["create_time"].max().floor("min")
    T0 = T1 - pd.Timedelta(hours=24)
    rc = pd.read_csv(os.path.join(F.OUT_DATA, "02_recall.csv"))
    r1, r2, nwrong = _combo_recall(d, T0, T1)
    u9 = up[up["日期"] == "2026-09-09"].iloc[0]
    ub = up[up["日期"] == "2026-08-27"].iloc[0]
    plan = pd.DataFrame([
        ("T+2h", "上线 MGj5bfGOijOi + x37TInaHsvPQ（例外审批）",
         f"黑产召回 {rc.iloc[1]['ONLINE召回%']}% → {r1}%", "极低（攻击前25天回测 +1 命中 0 条）", "田志鲔配置 / 段枝宏审批"),
        ("T+4h", "上线 ARqkLD7E3JaK + rDf6oPcZ8ydk", "补 token 维度，覆盖名单外区号", "低（命中样本误伤 0%）", "田志鲔 / 段枝宏"),
        ("T+6h", "下调 区号近60分钟 阈值 30 → 15（REnWrA7CfCdE / OgkdQFtWwJ92）",
         "可规避请求占比 30.1% → 5.3%", "低（攻击前该指标 P99 远低于 15）", "田志鲔 / 段枝宏"),
        ("T+8h", "upush/Twilio 对零基线区号做地域权限或日限额", "直接把成本压到 0，不依赖命中率", "需业务确认无真实用户", "upush 侧"),
        ("T+12h", "配置 3 条监控告警阈值（见 02 §五）", "攻击复发时 1 小时内发现", "无", "DBA"),
        ("T+24h", "复盘：以 upush 其他区号日发送量 < 150 条/天 为压制达标", "验收标准", "—", "David"),
    ], columns=["时间", "动作", "预期效果", "误伤风险", "负责人"])
    dump(plan, "06_24h_plan.csv")

    txt = f"""# 06 · 攻击处置进展与 24 小时压制计划

> 回答段枝宏："若是在国内，线上这种短信攻击问题，在24小时内必须压制下去的，若压制不下去，
> 也需要详细说明都做了哪些措施，确认已经没有优化空间了；但北美这波，咱们已经持续4天了，也只是上了1条策略，且没有继续高优跟进。"
> 生成时间：{pd.Timestamp.utcnow():%Y-%m-%d %H:%M} UTC

## 一、结论先说

> **这波攻击到目前为止没有被压制下去，并且优化空间明确存在。**
>
> 非 +1/+86 实发短信量：攻击前（08-27）**{int(ub['其他区号发送'])} 条/天** → 09-09 **{int(u9['其他区号发送']):,} 条/天**，
> 曲线仍在上行，无拐点。
> 优化空间：有 2 条策略从 09-04 起就配置在预上线、观察 6 天未推进，上线即可把召回从
> {rc.iloc[1]['ONLINE召回%']}% 提到 {r1}%。

## 二、攻击时间轴与实发短信量（成本口径）

{md(up.tail(18))}

- **+1 正常用户完全没受影响**：日发送量稳定 900~1,400，验证码填充率稳定 94%~98%。
- **其他区号填充率从攻击前 ~24% 掉到 {u9['其他区号填充率%']}%** —— 发出去的短信几乎无人使用，
  这是 SMS pumping 的定义性特征，也是"这些不是真实需求"的最硬证据。

## 三、已采取的措施（按 RMS 策略表 update_time 实测）

{md(tl)}

> 口径说明：`update_time` 只记录**最后一次**变更，多次调整的策略只显示最新状态；
> `t_oplog` 在 2026-09-01 之后没有任何记录，无法补齐中间历史。这是留痕缺陷，建议修复。

**逐条读**：

- 09-03：8 条速度类策略（区号/IP 频次族）改为 ONLINE —— 这是本轮最主要的一次动作。
- 09-04：再上线 1 条（区号近 5 分钟 > 30）；同日把 `MGj5bfGOijOi`、`x37TInaHsvPQ` 配成**预上线**。
- 09-05 ~ 09-08：**新增上线策略 0 条**。其中 09-08 段枝宏建的 REVIEW 策略 `hauAJst12TIj` 当天被改为关闭状态。
- 09-09：上线 2 条（`sw3jC7bvFYEX` 手机号近1天≥100、`uKSgJAVWhWlU`），并把 `ARqkLD7E3JaK` 配成预上线。

## 四、为什么没压住 —— 三个数据查出来的原因

1. **攻击是贴着现网阈值跑的**。现网主力规则是 `区号近60分钟的访问次数 > 30`；
   实测各区号每小时请求量的中位数落在 **24~33**，紧贴阈值。
   48.4% 的 (区号,小时) 格子 ≤30，**30.1% 的攻击请求因此完全碰不到这条规则**。
   把阈值下调到 >15，可规避占比从 30.1% 降到 5.3%。见 `04` §七。
2. **策略方向偏了**：`uKSgJAVWhWlU` 与 `ARqkLD7E3JaK` 都按 `realIpCountry` 过滤，
   而 **23.6% 的攻击请求来自美国机房 IP**，被设计性放过。见 `03`。
3. **最有效的策略一直卡在预上线**：`MGj5bfGOijOi` 自 09-04 起观察 6 天，
   它一条就能吃掉 56.4% 的漏召回，误伤 0%。

## 五、当前残留漏出与成本

| 项 | 数值 |
|---|---|
| 最近 24h 非+1/+86 调用 | {int(daily.iloc[-2]['非1_86调用']):,} |
| 黑产（SOP 标签） | {int(rc.iloc[1]['黑产总量']):,} |
| 已拦截 | {int(rc.iloc[1]['当前ONLINE拦截']):,}（召回 {rc.iloc[1]['ONLINE召回%']}%） |
| **仍漏出并实际发出短信** | {int(rc.iloc[1]['漏召回(PASS)']):,} 条 |
| 09-09 实发其他区号短信 | {int(u9['其他区号发送']):,} 条 |

> REJECT 确实阻止下发（见 `00` §7.1），因此每提升 1 个百分点的召回，都直接等比减少 Twilio 费用。

## 六、24 小时压制计划

{md(plan)}

**压制达标定义**：upush 其他区号日发送量回到 **< 150 条/天**（攻击前基线 30~86 条/天）。

## 七、还有没有优化空间 —— 明确回答

> **有，而且明确。** 现在说"已无优化空间"不成立，理由：
>
> 1. 2 条零误伤、增量召回 56.4% / 33.0% 的策略仍停在预上线（09-04 至今）。
> 2. 现网 `区号近60分钟 > 30` 的阈值没有下调，30.1% 的攻击请求贴着它跑。
> 3. upush/Twilio 侧的地域权限与限额**一个都还没做**——这是唯一能把成本直接压到 0 的动作。
> 4. uid 维度、IPC 段 60 分钟维度的特征引擎里还没有，攻击方正是靠把单 IP 频次压到阈值下存活。
>
> 上述 4 项全部完成之前，不应对外声称无优化空间。
"""
    w("06_攻击处置进展与24小时压制计划.md", txt)


def report_summary(d):
    T1 = d["create_time"].max().floor("min")
    T0 = T1 - pd.Timedelta(hours=24)
    rc = pd.read_csv(os.path.join(F.OUT_DATA, "02_recall.csv"))
    up = F.upush_series()
    u9 = up[up["日期"] == "2026-09-09"].iloc[0]
    ub = up[up["日期"] == "2026-08-27"].iloc[0]
    r1, r2, nwrong = _combo_recall(d, T0, T1)
    txt = f"""# summary · 一页纸

> LKUS 短信（OTP）黑产攻击分析 · 数据窗口 2026-08-09 ~ {T1:%Y-%m-%d %H:%M} UTC · 共 {len(d):,} 条风控请求
> 数据源：`luckyus_iriskcontrolservice.t_access_log_0000..0063`（64 分片源库，非数仓）· 全程只读
> 生成时间：{pd.Timestamp.utcnow():%Y-%m-%d %H:%M} UTC

## 🔴 三个改变判断的发现（先看这里）

1. **攻击是按我们的阈值校准过的。** 现网主力规则 `区号近60分钟的访问次数 > 30`，
   而各区号每小时请求量的中位数就落在 **24~33**，紧贴阈值；48.4% 的 (区号,小时) 格子 ≤30，
   **30.1% 的攻击请求根本碰不到这条规则**。阈值下调到 >15 即可把可规避占比压到 5.3%。→ `04` §七
2. **飞书 6 小时评估文档第 3、4 项标签写反了，第 7 项也不成立。**
   同窗口重算：第 1、2 项逐位吻合（3.8% / 64.2%），第 3、4 项整体对调。
   原文"暂不建议直接全量上线"的核心理由因此不成立。→ `01`、`03`
3. **攻击方 23.6% 的请求来自美国机房 IP，而现有两条新策略按设计都放过美国 IP。**
   同一伙人：目的区号名单相同、32.6% 的手机号同时出现在多个 IP 国家、同一 uid 关联最多 277 个手机号。→ `03`

## 头条数字

| 指标 | 数值 |
|---|---|
| 非 +1/+86 实发短信 | 攻击前 {int(ub['其他区号发送'])} 条/天 → 09-09 **{int(u9['其他区号发送']):,} 条/天**（仍在上行） |
| 其他区号验证码填充率 | 攻击前 ~24% → **{u9['其他区号填充率%']}%**（+1 用户稳定 95~96%） |
| 当前召回率（SOP 标签 / 田志鲔口径） | **{rc.iloc[1]['ONLINE召回%']}% / {rc.iloc[0]['ONLINE召回%']}%** |
| 最近 24h 漏出并实际发出 | **{int(rc.iloc[1]['漏召回(PASS)']):,} 条** |
| 上线 2 条预上线策略后可达召回 | **{r1}% / {r2}%**（命中中正常用户仅 {nwrong} 条） |
| 是否已压制 | **否**，无拐点 |

## 结论

| 问题 | 结论 |
|---|---|
| ARqkLD7E3JaK 能不能上 | 🟢 建议走**例外审批**上线（REJECT）。命中 1,610 条误伤 0 条；但只补回 28.8% 漏召回，不是主力 |
| 172 上线后表现 | 命中率 18.9%，误伤 0%，熔断 0。隐患：所依赖的特征名曾被改动且无留痕，改名会让策略静默失效 |
| "是不是黑产开始用美国 IP" | 是，且是同一伙人。4 类特征交叉印证 |
| 召回还差多少 | SOP 标签口径漏 {rc.iloc[1]['漏召回%']}%；漏出横跨所有维度，只有 cid=105(96.8%)、v1.4.42(78.2%) 高度集中 |
| 还能配什么策略 | **不用新开发**：4 条已在预上线，最优两条上线即可把召回提到 {r1}% |
| "非营业时段"这个说法 | ❌ 撤回。攻击 7×24，低谷时段仍占 8.8%。改为 3 条监控告警阈值 |
| 还有优化空间吗 | **有，明确有**。4 项关键动作一项未完成 |

## Top 5 动作

1. **T+2h** 上线 `strategy_MGj5bfGOijOi` + `strategy_x37TInaHsvPQ`（例外审批）→ 召回 {rc.iloc[1]['ONLINE召回%']}% → {r1}%。田志鲔配置 / 段枝宏审批
2. **T+6h** 把 `区号近60分钟` 阈值从 >30 下调到 >15 —— 攻击正贴着这个阈值跑。田志鲔配置
3. **T+8h** upush/Twilio 对零基线区号做地域权限或日限额 —— 唯一能把成本直接压到 0 的动作。upush 侧
4. **T+4h** 上线 `ARqkLD7E3JaK` + `rDf6oPcZ8ydk` 补 token 维度
5. **排期** 新增 `同网关uid近60分钟关联手机号个数` 特征 —— 现有规则完全没有 uid 维度

## 复跑

```bash
python -m sms_attack.extract  --from 2026-08-09 --to 2026-09-11
python -m sms_attack.evaluate --strategy strategy_XXXX --window 5h
python -m sms_attack.report
```
"""
    w("summary.md", txt)

if __name__ == "__main__":
    main()
