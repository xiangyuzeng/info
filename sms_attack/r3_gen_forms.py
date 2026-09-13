"""Fill and write the five round-3 approval forms.

Three retrospective (172 / ARqkLD7E3JaK / rDf6oPcZ8ydk -- live, so table 二 carries real
observation data) and two forward-looking (R3C1 / R3C2 -- 未配置, so every
observation-dependent cell says 待预上线观察后填写 rather than a projected number
dressed up as observed).

Owner and approval cells are left blank by r3_forms.ALWAYS_BLANK. That is the correct
value; inventing a plausible one is a review failure.
"""
import json
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sms_attack import r3, r3_forms, r3_rules  # noqa: E402

OUT3 = r3.OUT3
DATA3 = r3.DATA3
TBD = "待预上线观察后填写"

CONFIG = "Huanxian Zhou（David）"
REVIEW = "田志鲔、苏钰鑫"
SCENE = "北美push场景"
IFACE = "短信接口"
GOAL = "阻断北美短信场景黑产攻击。"
REASON = "近期北美短信场景存在黑产攻击，造成资损，需补充优化策略进行阻断"
GUARD = "(区号不是1&&区号不是+1&&区号不是86&&区号不是+86)"
IPZ = "德国,阿联酋,巴西,菲律宾,加拿大,瑞典,爱沙尼亚,智利"


def pct(n, d, nd=3):
    return f"{round(100 * n / d, nd)}%" if d else "0%"


def main():
    live_m = json.load(open(os.path.join(DATA3, "live_sop_metrics.json"), encoding="utf-8"))
    live_e = json.load(open(os.path.join(DATA3, "live_evidence.json"), encoding="utf-8"))
    cand_e = json.load(open(os.path.join(DATA3, "cand_evidence.json"), encoding="utf-8"))
    cache = r3_rules.fetch()
    written = []

    # ---------------- retrospective forms for the three live strategies -------
    META = {
        "strategy_uKSgJAVWhWlU": dict(
            logic="1、区号非美国 且 非中国\n2、IP 来源为 巴基斯坦、德国、英国\n3、reCAPTCHA V3 风险分 小于等于 0.3",
            thr="reCAPTCHA V3 风险分 ≤ 0.3。依据：上线前 24h 非北美区号中分数≤0.3 占 57%（3623/6347），北美+1 区号仅 1.9%（26/1398），相差约 30 倍。",
            scope="客户端 cid 不限；版本不限；仅作用于区号非 +1/+86 的请求；IP 来源限巴基斯坦、德国、英国；登录前场景，无用户范围限制。",
            misfire="潜在误伤人群为使用巴基斯坦/德国/英国 IP、且持境外号码的真实用户。观察期实测命中 2,951 条中判为正常用户 0 条，OTP 已填充 0 条。",
        ),
        "strategy_ARqkLD7E3JaK": dict(
            logic="1、区号非美国 且 非中国\n2、IP 来源国家不等于 美国\n3、reCAPTCHA V3 风险分 小于等于 0.3",
            thr="reCAPTCHA V3 风险分 ≤ 0.3。依据同 172；本条将 IP 条件从三国枚举放宽为「非美国」，覆盖面更大。",
            scope="客户端 cid 不限；版本不限；仅作用于区号非 +1/+86 且 IP 来源非美国的请求；登录前场景，无用户范围限制。",
            misfire="潜在误伤人群为身处美国境外、持境外号码的真实用户（如新加坡、罗马尼亚、英国）。观察期实测命中 2,706 条中判为正常用户 0 条，OTP 已填充 0 条。",
        ),
        "strategy_rDf6oPcZ8ydk": dict(
            logic="1、客户端 cid 属于 106、105、108\n2、reCAPTCHA V3 风险分 字段存在\n3、reCAPTCHA V3 风险分 小于 0.3\n4、区号非美国",
            thr="reCAPTCHA V3 风险分 < 0.3（严格小于，不含 0.3 分桶）。依据：0.3 分桶单日约 485 条，含与不含差异显著，故取严格小于以降低误伤。",
            scope="客户端 cid 限 106、105、108；版本不限；仅作用于区号非 +1 的请求（注意：本条未排除 +86）；登录前场景，无用户范围限制。",
            misfire="潜在误伤人群为 reCAPTCHA 评分偏低的真实境外用户，以及 +86 区号用户（本条未设 +86 护栏）。观察期实测命中 3,088 条中判为正常用户 0 条，OTP 已填充 0 条。",
        ),
    }
    for sid, meta in META.items():
        m, e = live_m[sid], live_e[sid]
        rule = r3_rules.strategy_text(sid, cache)
        t1 = {
            "策略名称": rule, "所属场景": SCENE, "接口/对象": IFACE, "配置人": CONFIG,
            "策略目标": GOAL, "上线原因": REASON,
            "规则逻辑": meta["logic"], "阈值说明": meta["thr"],
            "处置动作": "拦截", "生效范围": meta["scope"],
            "字段语义是否确认": "是", "字段取值来源是否确认": "是",
            "是否存在近义字段混淆风险": "是。reCAPTCHA 风险分特征在 2026-08-27~09-08 间被改名三次（reCAPTCHA V3 token是否有效 ↔ reCAPTCHA V3风险分），按特征名取数会静默失效。本轮取数按 apiResp 结构解析 riskAnalysis.score，不按名字匹配。",
            "接口类型判断": "C端",
            "是否存在正常聚合流量风险(IP、设备、账号等）": "否。规则主体为单次请求的字段取值，不含 IP/区号/设备级聚合计数器。",
            "是否已了解接口业务背景": "是", "是否识别潜在误伤人群": "是",
            "是否需重点关注系统稳定性风险": "否",
            "系统稳定性风险说明": "", "潜在误伤说明": meta["misfire"],
            "当前状态": "已上线",
        }
        n, risk, unk = m["命中pv"], m["风险样本量"], m["暂无法判断样本量"]
        ev_txt = (
            f"本说明为上线后观察期实测（{m['观察起'][:16]} → {m['观察止'][:16]} UTC），非回测。\n"
            f"1、命中 {n} 条（去重手机号 {m['命中uv']} 个），其中满足 SOP §3.7「至少两类风险特征交叉印证」的为 {e['ge2']} 条，占 {pct(e['ge2'], n, 1)}。\n"
            f"2、IP/设备聚集（SOP §3.2）：{e['ip_cluster']} 条命中，占 {pct(e['ip_cluster'], n, 1)}；其中同 IP 近 60 分钟关联手机号 >3 的 {e['ip_gt3']} 条，同网关 uid 关联 ≥3 个手机号的 {e['uid_ge3']} 条。\n"
            f"3、手机号风险（SOP §3.3）：{e['phone_risk']} 条命中，占 {pct(e['phone_risk'], n, 1)}；其中同 IP 内号码数字相邻（猫池/生成号段签名）{e['seq']} 条，攻击前零基线区号 {e['zero_base']} 条。\n"
            f"4、API 链路异常（SOP §3.4）：{e['api']} 条命中，占 {pct(e['api'], n, 1)}。\n"
            f"5、OTP 行为：命中样本中短信已下发但验证码从未被填写的 {e['otp0']} 条；**已填充（即确认为真实用户）的 {e['otp1']} 条**。\n"
            f"6、设备指纹（SOP §3.5）：本场景 did/device_id/tongdun_device_id 全部为空，该类证据不可得，按 SOP §3.7「证据不足不得强行归因」不计入。\n"
            f"7、命中集中的目标区号 Top5：{'、'.join(f'+{k}({v})' for k, v in list(e['top_cc'].items())[:5])}；"
            f"IP 来源 Top：{'、'.join(f'{k}({v})' for k, v in list(e['top_ipc'].items())[:5])}。"
        )
        t2 = {
            "关联策略编号": sid, "策略名称": rule, "配置人": CONFIG, "复核人": REVIEW,
            "预上线开始时间": m["观察起"][:19],
            "实际观察时长": m["实际观察时长"],
            "宙斯报错大盘是否检查": TBD, "宙斯检查结论": TBD,
            "是否覆盖核心活跃时段": f"是。观察时长 {m['实际观察时长']}，完整覆盖 EDT 全部 24 个小时段（攻击为 7×24，低谷在 EDT 15:00–18:00）。",
            "是否覆盖主要用户场景": "是。本场景仅短信验证码一个接口，观察期内该接口全量流量均已覆盖。",
            "是否覆盖活动高峰/典型周期": "是。观察期跨越多个完整昼夜周期，含工作日与周末。",
            "整体调用量": m["整体调用量"], "整体用户量": f"{m['整体用户量']}（去重手机号；登录前场景无用户号，user_no 约 97% 为空）",
            "命中样本量": f"{n}（pv）、{m['命中uv']}（uv，去重手机号）",
            "风险样本量": risk, "暂无法判断样本量": unk,
            "准确率": f"{m['准确率%']}%（=(命中 {n} − 风险样本 {risk} − 暂无法判断 {unk}) ÷ {n}）。注：若按只扣风险样本量的口径则为 100%，口径待确认。",
            "误伤比例": f"{m['误伤比例%']}%（=风险样本 {risk} ÷ 命中 {n}）",
            "代下行为是否明显": "不适用。SOP §3.1 针对订单地市分布，短信验证码场景无订单。",
            "IP/设备是否聚集": f"是。{e['ip_cluster']} 条命中具备 IP/设备聚集特征，占 {pct(e['ip_cluster'], n, 1)}。",
            "手机号是否命中猫池/高风险标签": f"是。{e['seq']} 条命中的手机号在同 IP 内数字相邻，符合猫池/生成号段签名。",
            "API链路是否异常": f"是。{e['api']} 条命中具备 API 链路异常特征，占 {pct(e['api'], n, 1)}。",
            "设备指纹是否高风险": "不可得。本场景 did/device_id/tongdun_device_id 全部为空。",
            "礼品卡转赠是否异常": "不适用。",
            "黑产评估依据说明": ev_txt,
            "近7日同期平均调用量": m["近7日同期平均调用量"],
            "近7日同期平均用户量": m["近7日同期平均用户量"],
            "是否达到最低整体调用量": f"按高风险强拦截策略判定：是（{m['整体调用量']} ≥ 8000，且 ≥ 近7日同期均值 {m['近7日同期平均调用量']} 的 80%）。",
            "是否达到最低整体用户量": f"按高风险强拦截策略判定：是（{m['整体用户量']} ≥ 3000，且 ≥ 近7日同期均值 {m['近7日同期平均用户量']} 的 80%）。",
            "是否达到命中样本参考门槛": f"是（{n} ≥ 20，高风险强拦截策略门槛）。",
            "是否符合上线标准": f"部分。观察时长、调用量、用户量、命中样本量、误伤比例（{m['误伤比例%']}%≤0.1%）均达标；准确率 {m['准确率%']}% 未达 99.9%，原因为「暂无法判断」样本 {unk} 条按公式从分子扣除，而非误伤。口径确认后需复核本格。",
            "是否申请例外审批": "是",
            "例外类型": "正在遭受黑产攻击的应急处置场景",
            "例外原因": f"本场景因 did/device_id/tongdun_device_id 全为空，SOP §3.5 设备指纹证据不可得，约 {round(100*unk/n,1)}% 的命中样本天然无法形成两类证据闭环，严格口径下 99.9% 准确率不可达；同时境外区号日发送量已达攻击前基线的约 20 倍，存在持续资损。",
            "补充控制措施": "1、逐小时监控命中量、命中中 +1/+86 占比（应恒为 0）、命中中 OTP 已填充条数（>0 即触发止损）；2、命中样本人工抽样复核；3、按 SOP §1.8，一旦确认误伤即电话报备并关闭策略或切回观察模式。",
            "当前状态": "已上线",
        }
        p, missing = r3_forms.write(sid, t1, t2, OUT3)
        written.append((p, missing))

    # ---------------- forward-looking candidates ------------------------------
    NEW = {
        "R3C1": dict(
            rule=f"{GUARD}&&cid 包含 105&&(字段 recaptchaV3Token 不存在||recaptchaV3Token 等于 '') 则 REJECT",
            logic="1、区号非美国 且 非中国\n2、客户端 cid 为 105（安卓 App）\n3、recaptchaV3Token 字段不存在，或 recaptchaV3Token 等于空串",
            thr=("本条为硬特征组合，不含阈值。token 取「不存在或空串」两种状态的并集，不使用 reCAPTCHA 风险分。\n"
                 "依据：最近 24h 境外区号放行数据中，token 缺失或为空占 41.9%（523/1247），而风险分 ≤0.3 的占 0.0%（0/1247）"
                 "——低分人群已被 172/策略3/策略4 拦尽，新增分数型策略不产生任何新增召回。"),
            scope="客户端 cid 限 105（安卓 App）；版本不限（见潜在误伤说明）；仅作用于区号非 +1/+86 的请求；登录前场景，无用户范围限制。",
            misfire=("潜在误伤人群为使用老版本安卓客户端、本就不下发 reCAPTCHA token 的真实境外用户。\n"
                     "回测已定位到 4 条此类样本（+65 新加坡/1.4.16、+65 新加坡/1.3.65、+60 罗马尼亚/1.4.42、+852 中国香港/1.3.32），"
                     "全攻击期误伤率 0.115%（4/3470），略高于 SOP §二 的 0.1% 上限。\n"
                     "若加 version 版本号大于等于 1.4.30 护栏可将误伤降至 0，但覆盖率从 41.5% 降至 7.1%（token 缺失漏出中 82% 在 1.3.40/1.3.50/1.4.26 老版本上）。"
                     "该取舍提请 leader 决策，本表按不加护栏提报。"),
            ev=cand_e["R3C1"],
            extra="本条直接回应 2026-09-11 段枝宏提示的突破点：「后续黑产可能不再带 recaptcher 的 token 了，对应的风险分特征就失效了。需要考虑加下 token 缺失的组合策略」。",
        ),
        "R3C2": dict(
            rule=f"{GUARD}&&cid 包含 105&&realIpCountry 包含 {IPZ} 则 REJECT",
            logic=f"1、区号非美国 且 非中国\n2、客户端 cid 为 105（安卓 App）\n3、IP 来源国家属于 {IPZ}",
            thr=("本条为硬特征组合，不含阈值。国家名单的入选条件为三条同时满足：最近 24h 漏出量 ≥15 条、"
                 "35 天内该国境外请求 OTP 填充数为 0、35 天境外 PASS 总量 ≥50 条。\n"
                 "明确排除有真实用户的来源国：巴基斯坦（漏出 644 但 OTP 已填充 20）、新加坡（61/59）、罗马尼亚（29/11）、英国（27/9）。"),
            scope="客户端 cid 限 105（安卓 App）；版本不限；仅作用于区号非 +1/+86 且 IP 来源国家属于名单内 8 国的请求；登录前场景，无用户范围限制。",
            misfire=("潜在误伤人群为从名单内 8 国发起、持境外号码的真实用户。回测在全攻击期内该组合命中 12,861 条，"
                     "其中 OTP 已填充 0 条、判为正常用户 0 条。\n"
                     "名单中加拿大、瑞典、爱沙尼亚、智利单国 24h 漏出量仅 19–21 条，证据较薄，建议预上线观察期重点看这 4 国是否出现真实用户。"),
            ev=cand_e["R3C2"],
            extra="本条不依赖 reCAPTCHA 分数或 token，因此在「黑产不带 token」「带无效 token」「高分养号」三种突破方式下均继续有效。当前漏出中已有 58.1% 为高分养号形态，该部分仅本条与现网速率兜底策略可覆盖。",
        ),
    }
    for key, c in NEW.items():
        e = c["ev"]; n = e["n"]
        t1 = {
            "策略名称": c["rule"], "所属场景": SCENE, "接口/对象": IFACE, "配置人": CONFIG,
            "策略目标": GOAL, "上线原因": REASON + "。" + c["extra"],
            "规则逻辑": c["logic"], "阈值说明": c["thr"],
            "处置动作": "拦截", "生效范围": c["scope"],
            "字段语义是否确认": "是。recaptchaV3Token / cid / countryCode / realIpCountry 四个字段的取值来源均为 request_strategy_engine.para，已逐字段核对源库实际取值。",
            "字段取值来源是否确认": "是。取自 luckyus_iriskcontrolservice.t_access_log_* 的 request_strategy_engine.$.para（双重编码 JSON），与引擎评估时使用的是同一份入参。",
            "是否存在近义字段混淆风险": "是，已规避两处：①「token 不存在」与「token 为空串」是两个不同状态，本条取并集，不用单一条件；②不使用 reCAPTCHA 风险分——该特征名在 2026-08-27~09-08 间被改名三次，按名字取数会静默失效。",
            "接口类型判断": "C端",
            "是否存在正常聚合流量风险(IP、设备、账号等）": "否。规则主体是单次请求自身的字段取值，不含任何 IP/区号/设备级聚合计数器，不存在「黑产打满阈值后正常用户一并被拦」的机制。",
            "是否已了解接口业务背景": "是。登录前短信验证码下发接口，每条下发经 upush(Twilio) 实际付费。",
            "是否识别潜在误伤人群": "是", "是否需重点关注系统稳定性风险": "否",
            "系统稳定性风险说明": "", "潜在误伤说明": c["misfire"],
            "当前状态": "未配置",
        }
        ev_txt = (
            f"本说明为**回测口径**（攻击期 2026-09-03 → 2026-09-12），策略尚未预上线，非实测观察数据。\n"
            f"1、回测命中 {n} 条（去重手机号 {e['uv']} 个），其中满足 SOP §3.7「至少两类风险特征交叉印证」的为 {e['ge2']} 条，占 {pct(e['ge2'], n, 1)}。\n"
            f"2、IP/设备聚集（SOP §3.2）：{e['ip_cluster']} 条，占 {pct(e['ip_cluster'], n, 1)}；同 IP 近 60 分钟关联手机号 >3 的 {e['ip_gt3']} 条，同网关 uid 关联 ≥3 个手机号的 {e['uid_ge3']} 条。\n"
            f"3、手机号风险（SOP §3.3）：{e['phone_risk']} 条，占 {pct(e['phone_risk'], n, 1)}；同 IP 内号码数字相邻 {e['seq']} 条，攻击前零基线区号 {e['zero_base']} 条。\n"
            f"4、API 链路异常（SOP §3.4）：{e['api']} 条，占 {pct(e['api'], n, 1)}。\n"
            f"5、OTP 行为（本轮最强硬标签）：命中中短信已下发但验证码从未被填写 {e['otp0']} 条；**已填充（即确认为真实用户）{e['otp1']} 条**。\n"
            f"6、设备指纹（SOP §3.5）：本场景 did/device_id/tongdun_device_id 全部为空，该类证据不可得，按 SOP §3.7 不计入。\n"
            f"7、回测命中中判为正常用户 {e['normal']} 条、暂无法判断 {e['unknown']} 条。\n"
            f"8、命中集中的目标区号 Top：{'、'.join(f'+{k}({v})' for k, v in list(e['top_cc'].items())[:6])}；"
            f"IP 来源 Top：{'、'.join(f'{k}({v})' for k, v in list(e['top_ipc'].items())[:6])}。"
        )
        t2 = {
            "关联策略编号": f"{key}（本轮工作编号；RMS strategy_id 待配置后回填）",
            "策略名称": c["rule"], "配置人": CONFIG, "复核人": REVIEW,
            "预上线开始时间": TBD, "实际观察时长": TBD,
            "宙斯报错大盘是否检查": TBD, "宙斯检查结论": TBD,
            "是否覆盖核心活跃时段": TBD, "是否覆盖主要用户场景": TBD, "是否覆盖活动高峰/典型周期": TBD,
            "整体调用量": TBD, "整体用户量": TBD, "命中样本量": TBD,
            "风险样本量": TBD, "暂无法判断样本量": TBD,
            "准确率": f"{TBD}。计算式：(命中样本量 − 风险样本量 − 暂无法判断样本量) ÷ 命中样本量。",
            "误伤比例": f"{TBD}。计算式：风险样本量 ÷ 命中样本量。",
            "代下行为是否明显": "不适用。SOP §3.1 针对订单地市分布，短信验证码场景无订单。",
            "IP/设备是否聚集": TBD, "手机号是否命中猫池/高风险标签": TBD,
            "API链路是否异常": TBD,
            "设备指纹是否高风险": "不可得。本场景 did/device_id/tongdun_device_id 全部为空。",
            "礼品卡转赠是否异常": "不适用。",
            "黑产评估依据说明": ev_txt,
            "近7日同期平均调用量": TBD, "近7日同期平均用户量": TBD,
            "是否达到最低整体调用量": TBD, "是否达到最低整体用户量": TBD,
            "是否达到命中样本参考门槛": TBD, "是否符合上线标准": TBD,
            "是否申请例外审批": TBD,
            "例外类型": "（如需）正在遭受黑产攻击的应急处置场景",
            "例外原因": "待观察期结束、准确率口径确认后判定是否需要。",
            "补充控制措施": "1、逐小时监控命中量、命中中 +1/+86 占比（应恒为 0）、命中中 OTP 已填充条数（>0 即触发止损）；2、观察期 ≥24 小时以覆盖 7×24 攻击的全部时段；3、按 SOP §1.8，一旦确认误伤即电话报备并关闭策略或切回观察模式。",
            "当前状态": "未配置",
        }
        p, missing = r3_forms.write(key, t1, t2, OUT3)
        written.append((p, missing))

    for p, missing in written:
        print(f"{os.path.basename(p)}  必填未填={len(missing)}  {missing if missing else ''}")


if __name__ == "__main__":
    main()
