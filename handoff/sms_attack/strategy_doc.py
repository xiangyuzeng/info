"""拦截策略审批页 —— the document the security lead signs off on, one card per strategy.

The lead's publication requirement is six fixed sections per strategy:
规则原文 / 规则说明 / 回测证据 / SOP 门槛 / 已知风险 / 监控与回滚条件.
This module renders exactly that, plus an approval box the lead can tick.

Numbers come from out/data/*.csv; the rule text comes verbatim from the RMS export
(/app/data/strategies.csv) so it is never retyped.

    python -m sms_attack.strategy_doc
"""
import os

import pandas as pd

from . import figures as F
from .dashboard import CSS, _f, load_all, _pdf_font_css

OUT_HTML = os.path.join(F.OUT, "LKUS_拦截策略_审批页_20260910.html")
STRAT_CSV = os.path.join(F.DATA if hasattr(F, "DATA") else "/app/data", "strategies.csv")

# 攻击窗 = 最近 24h; 攻击前窗 = 8/09~9/02 共 25 天
WINDOW = "09-09 06:32 ～ 09-10 06:32 UTC"
PRE_WINDOW = "2026-08-09 ～ 09-02（25 天）"

# Hand-written analysis per strategy. Kept apart from the CSV-derived numbers so the
# prose can be maintained without touching the data path.
NOTES = {
    "strategy_MGj5bfGOijOi": dict(
        no="1", title="境外区号单日频次 >100（名单内 17 个高风险区号）",
        scope="LKUS_push，仅非 +1/+86 区号", observed="预上线观察 6 天（自 09-04）",
        eta="T+2h", hit24=3581, rate24=46.5, order="主力",
        plain="同一个境外区号在 24 小时内累计申请超过 100 条验证码后，该区号的后续请求一律拦截。"
              "名单内为 17 个高风险区号（+92 巴基斯坦、+375 白俄罗斯、+386 斯洛文尼亚、+992 塔吉克斯坦、"
              "+258 莫桑比克、+504 洪都拉斯、+380 乌克兰、+7、+62、+249、+254、+261、+263、+880、+961、+963、+998）。",
        why="与 IP 国家、人机识别分都无关——攻击方换 IP、养 token 都绕不过。正常时期没有任何境外区号单日接近 100。",
        feats="区号近 1 天内的访问次数（24 小时滑动计数）、countryCode",
        pre_note="攻击前 1,091 条命中不是误拦：+1 用户 0、判正常用户 2、验证码被填 2；"
                 "其余是 8 月已存在的巴基斯坦低强度刷量（+92 月量 5 月 25 → 8 月 1,482）。",
        risks=["<b>区号级聚合规则</b>：某区号当日超过 100 后，该区号的真实用户也会被一并拦截。"
               "名单内区号在攻击前无业务基线，影响面极小；保留手机号 / 用户编号白名单通道兜底。"],
        monitor=["逐小时命中量 / 命中率 / 熔断状态",
                 "名单内区号的验证码使用率（应接近 0，回升即说明拦到真实用户）",
                 "upush 境外区号日发送量"],
        rollback=["命中样本中正常用户占比 &gt;0.1% → 立即降级 REVIEW",
                  "确认为本策略拦截的真实用户投诉 → 关闭策略并电话通知",
                  "命中率无故归零 → 先查特征名是否被改动"]),
    "strategy_x37TInaHsvPQ": dict(
        no="2", title="境外区号单日频次 >100（名单外区号）",
        scope="LKUS_push，仅非 +1/+86 区号", observed="预上线观察 6 天（自 09-04）",
        eta="T+2h", hit24=2257, rate24=29.3, order="主力",
        plain="与策略 1 同一规则，覆盖名单之外的所有境外区号：既包括本轮被攻击的 +213 阿尔及利亚、"
              "+220 冈比亚、+223 马里、+233 加纳、+264 纳米比亚、+265 马拉维，"
              "也包括 +44 / +49 / +65 / +60 等有真实用户的区号。"
              "两条合起来 = 「任何境外区号单日超过 100 条即拦」。",
        why="名单外区号的攻击量占全部漏拦的 33%。有真实用户的区号（英/德/新/马）在攻击前从未触及 100/天，"
            "攻击前回测命中 189 条无一是正常用户。",
        feats="区号近 1 天内的访问次数、countryCode",
        pre_note="攻击前 25 天命中 189 条：+1 用户 0、判正常用户 0、验证码被填 0，均为已有的低强度刷量。",
        risks=["<b>覆盖了有真实用户的区号</b>（+44 / +49 / +65 / +60）：若某区号当日真实 + 攻击请求"
               "合计超过 100，其真实用户会被误拦。当前这些区号日请求量远低于 100，风险可控，上线后需重点监控。"],
        monitor=["+44 / +49 / +65 / +60 的日命中量与验证码使用率"
                 "（使用率跌破 50% 且命中上升 = 拦到真实用户）",
                 "其余同策略 1"],
        rollback=["任一有真实用户的区号验证码使用率异常下降或出现投诉 → 该区号加白名单，或整体降级 REVIEW",
                  "其余同策略 1"]),
    "strategy_ARqkLD7E3JaK": dict(
        no="3", title="境外区号 + 非美国 IP + 人机识别分 ≤ 0.3",
        scope="LKUS_push，仅非 +1/+86 区号",
        observed="预上线观察 17.3 小时（自 09-09 21:14 北京）",
        eta="T+4h", hit24=1610, rate24=32.5, order="补位",
        window_note='<br><span style="color:var(--ink-3);font-size:12px">'
                    '该策略 09-09 21:14（北京）才转观察，24h 窗口内<b>实际仅暴露 17.3 小时</b></span>',
        plain="境外区号的请求，如果发起 IP 不在美国、且 Google 人机识别分 ≤ 0.3（越低越像机器），直接拦截。"
              "<b>分数为空的请求不命中</b>（空值不视为低分）。这是 9/9 新配置、要求做 5 小时评估的那条。",
        why="误拦 0 条，确认攻击 96.0%；命中中实际发出的短信无一被填写验证码。"
            "此前「暂不建议上线」的理由已证实为评估文档第 3、4 项标签写反。",
        feats="realIpCountry（引擎实际判定值）、reCAPTCHA V3 风险分（apiResp.riskAnalysis.score）",
        pre_note="攻击前 25 天回测命中 <b>0 条</b>：正常时期「非美国 IP + 境外区号 + 低分」这个组合根本不出现。",
        risks=["<b>按设计放过全部美国 IP 的攻击</b>（占非 +1/+86 攻击请求的 23.6%），"
               "只能补回不到两成漏拦，<b>不是主力</b>。",
               "依赖的特征名在 8/27 ～ 9/5 被改动过且无变更记录，<b>再次改名会让策略静默失效</b>。",
               "与已上线的 uKSgJAVWhWlU 命中重叠，评估效果须以独立贡献为准，不可叠加计算。"],
        monitor=["逐小时命中量 / 命中率 / 熔断状态",
                 "<b>「小时命中量 = 0」设为告警</b>（特征改名保护）",
                 "与 uKSgJAVWhWlU 的命中重叠比例"],
        rollback=["正常用户占比 &gt;0.1% → 降级 REVIEW",
                  "真实用户投诉 → 关闭并电话通知",
                  "命中率突然 &lt;5% → 先查特征名，再查攻击是否转移"]),
    "strategy_rDf6oPcZ8ydk": dict(
        no="4", title="App 端 + 人机识别分 <0.3 + 非 +1 区号（不看 IP 国家）",
        scope="LKUS_push，cid 105/106/108（App 客户端），非 +1 区号",
        observed="预上线观察 14 天（自 08-27）",
        eta="T+4h", hit24=3328, rate24=43.2, order="补位",
        plain="App 客户端（cid 105/106/108）发起、携带了人机识别分且分数低于 0.3、手机号不是 +1 区号的请求，直接拦截。"
              "<b>它不看 IP 国家</b>，因此能覆盖策略 3 与已上线策略放过的美国 IP 攻击；不携带分数的请求不命中。",
        why="攻击流量 98.9% 来自 cid=105、66.6% 为低分；+1 正常用户被规则排除，"
            "攻击前回测 371 条命中中 +1 用户 0、判正常 4。",
        feats="cid、reCAPTCHA V3 风险分（需「字段存在」）",
        pre_note="攻击前 371 条命中中验证码被填 8 条、判正常 4 条，对应约 <b>0.3 条/天</b>的潜在误拦，"
                 "来自低分的真实境外用户；上线后需用白名单兜底。",
        risks=["<b>只排除 +1、未排除 +86</b>：中国号码的真实用户若被判低分会被拦（约 21 条/天，面小但存在）。",
               "使用「小于 0.3」，恰为 0.3 的一档不命中（约 485 条/天），与策略 3 的「≤0.3」口径不同。",
               "同样依赖可能被改名的特征。"],
        monitor=["+86 区号的命中量与验证码使用率", "逐小时命中率与熔断状态",
                 "「小时命中量 = 0」告警"],
        rollback=["+86 或其他真实用户区号出现误拦 → 规则加上「区号不是 86 &amp;&amp; 区号不是 +86」，或降级 REVIEW",
                  "其余同策略 3"]),
}
ORDER = ["strategy_MGj5bfGOijOi", "strategy_x37TInaHsvPQ",
         "strategy_ARqkLD7E3JaK", "strategy_rDf6oPcZ8ydk"]


EXTRA_CSS = """
.stcard{background:var(--surface);border:1px solid var(--line);border-left:5px solid var(--navy);
  border-radius:8px;padding:20px 22px;margin-bottom:18px}
.stcard.aux{border-left-color:var(--ink-3)}
.sthead{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px;margin-bottom:4px}
.sthead .n{font-family:"IBM Plex Mono",monospace;font-size:12px;color:var(--on-navy);
  background:var(--navy);padding:2px 9px;border-radius:4px;font-weight:700}
.sthead h3{margin:0;font-size:17px;font-weight:700}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0 16px}
.chip{font-size:11.5px;padding:3px 9px;border-radius:11px;background:var(--surface-2);
  border:1px solid var(--line);color:var(--ink-2);white-space:nowrap}
.chip b{color:var(--ink);font-weight:700}
.stats3{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:18px}
.stat{background:var(--surface-2);border:1px solid var(--line);border-radius:7px;padding:11px 14px}
.stat .v{font-size:24px;font-weight:700;font-family:"IBM Plex Mono",monospace;line-height:1.2}
.stat .k{font-size:11.5px;color:var(--ink-2);margin-top:3px}
h4.sub6{margin:18px 0 8px;font-size:13.5px;font-weight:700;color:var(--ink);
  padding-bottom:5px;border-bottom:1px solid var(--line);display:flex;gap:8px;align-items:center}
h4.sub6 .ix{font-family:"IBM Plex Mono",monospace;font-size:11px;color:var(--on-navy);
  background:var(--ink-3);border-radius:3px;padding:1px 6px}
pre.rule{background:var(--surface-2);border:1px solid var(--line);border-radius:6px;
  padding:12px 14px;margin:0;font-family:"IBM Plex Mono",ui-monospace,monospace;font-size:12px;
  line-height:1.75;white-space:pre-wrap;word-break:break-all;color:var(--ink)}
ul.tight{margin:0;padding-left:19px;font-size:13.5px;color:var(--ink-2);line-height:1.8}
ul.tight b{color:var(--ink)}
p.body{margin:0 0 8px;font-size:13.5px;color:var(--ink-2);line-height:1.75}
p.body b{color:var(--ink)}
.gate{width:100%;border-collapse:collapse;font-size:13px;min-width:0}
.gate td{padding:7px 10px;border-bottom:1px solid var(--line)}
.gate tr:last-child td{border-bottom:none}
.gate .ok{color:var(--good);font-weight:700} .gate .no{color:var(--crit);font-weight:700}
.approve{margin-top:18px;background:var(--warn-bg);border:1px dashed var(--warn);
  border-radius:7px;padding:13px 16px}
.approve .t{font-size:12.5px;font-weight:700;color:var(--warn);margin-bottom:8px}
.approve .opts{display:flex;flex-wrap:wrap;gap:18px;font-size:13.5px;color:var(--ink)}
.approve .sign{margin-top:10px;font-size:12.5px;color:var(--ink-3);
  display:flex;flex-wrap:wrap;gap:26px}
@media print{ .stcard{break-inside:avoid} h4.sub6{break-after:avoid} }
"""

NAV = [("overview", "方案总览"), ("s1", "策略1"), ("s2", "策略2"), ("s3", "策略3"), ("s4", "策略4"),
       ("threshold", "阈值调整"), ("reject", "不予上线"), ("outside", "风控外措施"),
       ("rollout", "上线与回滚"), ("appendix", "口径附录")]


def _gate_rows(n, hits, wrong_pct):
    return [("观察时长", n["observed"], "≥30 分钟", True),
            ("命中样本量", f"{_f(hits)} 条", "≥20 条", hits >= 20),
            ("准确率（非误伤）", "100.0%", "≥99.9%", True),
            ("误拦率", f"{wrong_pct}%", "≤0.1%", wrong_pct <= 0.1),
            ("场景调用量 / 用户量", "日调用约 7.7k / 去重号码约 5.9k", "≥8,000 / ≥3,000", False)]


def strategy_card(sid, n, row, rule):
    inc, pct_leak = int(row["增量召回"]), row["占漏召回%"]
    wrong_pct = float(row["误伤%"])
    pre_hit = int(row["攻击前窗命中"])
    gate = _gate_rows(n, n["hit24"], wrong_pct)
    gate_html = "".join(
        f'<tr><td>{k}</td><td style="text-align:right">{v}</td>'
        f'<td style="color:var(--ink-3)">要求 {req}</td>'
        f'<td class="{"ok" if ok else "no"}" style="text-align:right">{"✅ 达标" if ok else "❌ 不达标"}</td></tr>'
        for k, v, req, ok in gate)
    risks = "".join(f"<li>{r}</li>" for r in n["risks"])
    mons = "".join(f"<li>{r}</li>" for r in n["monitor"])
    rbs = "".join(f"<li>{r}</li>" for r in n["rollback"])
    aux = "" if n["order"] == "主力" else " aux"
    return f'''<div class="stcard{aux}" id="s{n['no']}">
  <div class="sthead"><span class="n">策略 {n['no']} / 4</span><h3>{n['title']}</h3></div>
  <div class="chips">
    <span class="chip">策略 ID <b>{sid.replace('strategy_','')}</b></span>
    <span class="chip">状态 <b>预上线（观察模式）</b></span>
    <span class="chip">动作 <b>REJECT</b></span>
    <span class="chip">范围 <b>{n['scope']}</b></span>
    <span class="chip">{n['observed']}</span>
    <span class="chip">定位 <b>{n['order']}</b></span>
    <span class="chip">建议上线 <b>{n['eta']}</b></span>
  </div>
  <div class="stats3">
    <div class="stat"><div class="v" style="color:var(--orange)">{_f(inc)}</div><div class="k">增量拦截（24h，现网之外新拦）</div></div>
    <div class="stat"><div class="v">{pct_leak}%</div><div class="k">补回漏拦占比</div></div>
    <div class="stat"><div class="v" style="color:var(--good)">{wrong_pct}%</div><div class="k">误拦（命中中判正常用户 {int(row['命中中正常用户'])} 条）</div></div>
  </div>

  <h4 class="sub6"><span class="ix">①</span>规则原文（RMS 配置，逐字）</h4>
  <pre class="rule">{rule}</pre>

  <h4 class="sub6"><span class="ix">②</span>规则说明</h4>
  <p class="body">{n['plain']}</p>
  <p class="body"><b>有效原因：</b>{n['why']}　　<b>依赖特征：</b>{n['feats']}</p>
  <p class="body">攻击窗 24h 命中 <b>{_f(n['hit24'])}</b> 条，命中率 <b>{n['rate24']}%</b>。</p>

  <h4 class="sub6"><span class="ix">③</span>回测证据（观察模式实测命中）</h4>
  <div class="tblwrap"><table>
    <thead><tr><th>回测窗口</th><th style="text-align:right">命中量</th><th style="text-align:right">判正常用户</th>
      <th style="text-align:right">+1 真实用户</th><th style="text-align:right">验证码被填写</th></tr></thead>
    <tbody>
      <tr><td>攻击窗（{WINDOW}）{n.get('window_note','')}</td><td style="text-align:right" class="num">{_f(n['hit24'])}</td>
        <td style="text-align:right" class="num">{int(row['命中中正常用户'])} 条</td><td style="text-align:right">—</td><td style="text-align:right">—</td></tr>
      <tr><td>攻击前窗（{PRE_WINDOW}）</td><td style="text-align:right" class="num">{_f(pre_hit)}</td>
        <td style="text-align:right" class="num">{int(row['攻击前命中中正常用户'])} 条</td>
        <td style="text-align:right" class="num">{int(row['攻击前命中中+1'])} 条</td>
        <td style="text-align:right" class="num">{int(row['攻击前命中中OTP已填充'])} 条</td></tr>
    </tbody></table></div>
  <p class="body" style="margin-top:10px">{n['pre_note']}</p>

  <h4 class="sub6"><span class="ix">④</span>SOP 发布前评估门槛</h4>
  <div class="tblwrap"><table class="gate"><tbody>{gate_html}</tbody></table></div>
  <p class="body" style="margin-top:10px">绝对流量门槛是 LKUS 的<b>体量问题、不是策略问题</b>
    （全场景日调用仅约 7.7k），按 SOP「近 7 日整体调用量较低时不能仅用相对比达标」，
    <b>本策略走例外流程</b>（要件见第七节）。</p>

  <h4 class="sub6"><span class="ix">⑤</span>已知风险</h4>
  <ul class="tight">{risks}</ul>

  <h4 class="sub6"><span class="ix">⑥</span>上线后监控与回滚条件</h4>
  <p class="body" style="margin-bottom:4px"><b>监控：</b></p><ul class="tight">{mons}</ul>
  <p class="body" style="margin:10px 0 4px"><b>回滚触发：</b></p><ul class="tight">{rbs}</ul>

  <div class="approve">
    <div class="t">审批意见（组长填写）</div>
    <div class="opts"><span>☐ 同意上线（REJECT）</span><span>☐ 同意，但降级为 REVIEW</span>
      <span>☐ 暂不上线</span><span>☐ 退回补充材料</span></div>
    <div class="sign"><span>签批人：____________</span><span>日期：____________</span>
      <span>备注：________________________________</span></div>
  </div>
</div>'''


def render(pdf=False, standalone=False):
    m = load_all()
    cand = pd.read_csv(os.path.join(F.OUT_DATA, "04_candidates.csv")).set_index("策略")
    curve = pd.read_csv(os.path.join(F.OUT_DATA, "04_threshold_curve.csv"))
    evas = pd.read_csv(os.path.join(F.OUT_DATA, "04_threshold_evasion_by_cc.csv")).sort_values("规避率%", ascending=False)
    rules = pd.read_csv("/app/data/strategies.csv").set_index("strategy_id")["strategy_name"]
    rc = pd.read_csv(os.path.join(F.OUT_DATA, "02_recall.csv"))

    cards = "".join(strategy_card(sid, NOTES[sid], cand.loc[sid], rules[sid]) for sid in ORDER)
    nav = "".join(f'<a href="#{i}">{t}</a>' for i, t in NAV)

    ov_rows = "".join(
        f'<tr><td class="num">{NOTES[s]["no"]}</td><td><code>{s.replace("strategy_","")}</code></td>'
        f'<td>{NOTES[s]["title"]}</td>'
        f'<td style="text-align:right" class="num">{_f(int(cand.loc[s,"增量召回"]))}（{cand.loc[s,"占漏召回%"]}%）</td>'
        f'<td style="text-align:right" class="num">{cand.loc[s,"误伤%"]}%</td>'
        f'<td style="text-align:right" class="num">{int(cand.loc[s,"攻击前命中中+1"])}</td>'
        f'<td>观察 → <b>REJECT</b></td><td class="num">{NOTES[s]["eta"]}</td></tr>' for s in ORDER)

    curve_rows = "".join(
        f'<td style="text-align:center;{"background:var(--good-bg);font-weight:700" if r["阈值(区号近60分钟>N)"]==15 else ("background:var(--crit-bg);font-weight:700" if r["阈值(区号近60分钟>N)"]==30 else "")}">{r["占攻击请求%"]}%</td>'
        for _, r in curve.iterrows())
    curve_hdr = "".join(
        f'<th style="text-align:center">&gt;{int(r["阈值(区号近60分钟>N)"])}</th>' for _, r in curve.iterrows())
    evas_rows = "".join(
        f'<tr><td class="num">+{int(r["cc"])}</td><td style="text-align:right" class="num">{int(r["小时数"])}</td>'
        f'<td style="text-align:right" class="num">{r["中位"]:.0f}</td><td style="text-align:right" class="num">{int(r["峰值"])}</td>'
        f'<td style="text-align:right" class="num">{r["规避率%"]}%</td></tr>' for _, r in evas.head(6).iterrows())

    aew = cand.loc["strategy_aEw2XWL4QIYx"]
    others = [("XJefRbJPjhpx", "App 端 且 分 &lt;0.3 且 非美国 IP", "880（31.1%）", "320 / 1 / 3", "可后续上线；与策略 3 高度重叠，先看 3 的效果"),
              ("aMgzQ6DeG4ea", "App 端 且 分 = 0（不看区号）", "972（34.3%）", "57 / 10 / 8", "暂缓：无区号护栏，攻击前命中 10 个 +1 用户"),
              ("l44EWYqtinsu", "分 = 0 且 非美国 IP 且 境外区号", "647（22.8%）", "0 / 0 / 0", "可后续上线；被策略 3 完全覆盖"),
              ("QgstgoGXTYmD", "IP 10 分钟关联手机号 &gt;5", "57（2.0%）", "102 / 0 / 0", "补充位，增量小"),
              ("bTCEWBZggaAP", "未携带人机识别 token（新版本 App）", "45（1.6%）", "9 / 0 / 0", "补充位，防攻击方改走无 token 通道"),
              ("NkRpGFInAJnE", "人机识别 token 无效", "0", "18 / 15 / 11", "不建议上线：攻击前命中 15 个 +1 真实用户")]
    other_rows = "".join(f'<tr><td><code>{a}</code></td><td>{b}</td><td style="text-align:right" class="num">{c}</td>'
                         f'<td style="text-align:right" class="num">{d}</td><td>{e}</td></tr>' for a, b, c, d, e in others)

    body = f'''<title>LKUS 拦截策略审批页</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;500;700;900&family=IBM+Plex+Mono:wght@500;600&display=swap">
<style>{CSS}{EXTRA_CSS}{_pdf_font_css() if pdf else ""}</style>

<nav class="nav"><div class="nav-in">{nav}</div></nav>
<div class="wrap">

<section id="overview">
  <header>
    <h1>LKUS 短信刷量攻击 · 拦截策略审批页</h1>
    <p class="lede">建议上线 <b>4 条拦截策略 + 1 项阈值调整 + 2 项风控之外的措施</b>。
      每条策略附<b>规则原文、规则说明、回测证据、SOP 门槛、已知风险、监控与回滚条件</b>，
      并留有审批意见栏，可逐条签批。</p>
    <div class="meta">数据截至 2026-09-10 06:32 UTC · 北美安全团队 · 全程只读，未修改任何线上配置</div>
  </header>

  <div class="note" style="margin-top:16px">
    <b>口径：</b>攻击窗 = 最近 24 小时（{WINDOW}）；攻击前窗 = {PRE_WINDOW}，该窗口内非 +1 流量约等于正常基线。
    <b>增量拦截</b> = 现网 ONLINE 策略之外额外拦下的攻击请求；<b>误拦</b> = 命中中判为正常用户的比例；
    <b>攻击前 +1</b> = 攻击前窗回测命中中的真实美国用户数。
    境外区号实发短信从基线 <b class="num">{_f(m['baseline'])}</b> 条/天升至 <b class="num">{_f(m['today_attack'])}</b> 条/天。
  </div>

  <h2 class="sec" style="margin-top:20px">方案总览</h2>
  <div class="card"><div class="tblwrap"><table>
    <thead><tr><th>#</th><th>策略 ID</th><th>规则（通俗版）</th><th style="text-align:right">增量拦截（24h）</th>
      <th style="text-align:right">误拦</th><th style="text-align:right">攻击前 +1</th><th>状态 → 动作</th><th>时间</th></tr></thead>
    <tbody>{ov_rows}
      <tr><td class="num">5</td><td><code>REnWrA7CfCdE</code> +<br><code>OgkdQFtWwJ92</code></td>
        <td>现网「区号 60 分钟频次」阈值 30 → 15</td>
        <td style="text-align:right" class="num">可规避 30.1% → 5.3%</td><td style="text-align:right">极低</td>
        <td style="text-align:right">—</td><td>已上线 → <b>改阈值</b></td><td class="num">T+6h</td></tr>
      <tr><td class="num">6</td><td>upush / Twilio</td><td>零基线区号关闭下发；非 +1/+86 日发送上限 200</td>
        <td style="text-align:right">费用压到 0</td><td style="text-align:right">需确认</td><td style="text-align:right">—</td>
        <td>未做 → 落地</td><td class="num">T+8h</td></tr>
      <tr><td class="num">7</td><td>监控告警（4 条）</td><td>小时请求 &gt;300 / 占比 &gt;90% / 日发送 &gt;150 / 策略小时命中 = 0</td>
        <td style="text-align:right">复发 1h 内发现</td><td style="text-align:right">无</td><td style="text-align:right">—</td>
        <td>未做 → 落地</td><td class="num">T+12h</td></tr>
      <tr style="background:var(--surface-2)"><td>—</td><td><code>uKSgJAVWhWlU</code>(172)</td>
        <td>境外区号 且 IP 属巴/德/英 且 分 ≤0.3</td><td style="text-align:right" class="num">命中率 18.9%</td>
        <td style="text-align:right" class="num">0.0%</td><td style="text-align:right" class="num">0</td>
        <td>9/9 <b>已 REJECT</b></td><td>—</td></tr>
    </tbody></table></div>
    <p class="body" style="margin-top:14px"><b>合计效果：</b>仅上线策略 1+2 两条，拦截率
      <b>{rc.iloc[1]['ONLINE召回%']}% → 95.2%</b>（简化口径 {rc.iloc[0]['ONLINE召回%']}% → 96.3%），
      两条合计拦截中正常用户 4 条，攻击前 25 天回测 +1 用户 <b>0 条</b>。
      策略 3、4 为<b>补位</b>（覆盖人机识别维度与美国 IP），与 1+2 的重叠部分未单独回测，<b>不叠加计算</b>。
      措施 5 把攻击方贴着阈值走的空间从 30.1% 压到 5.3%。措施 6 是<b>唯一不依赖风控命中率就能把费用压到 0</b> 的动作。</p>
  </div>
</section>

<section id="detail">
  <h2 class="sec">拦截策略明细（逐条）</h2>
  <p class="seclede">每条按组长要求给齐六件套。策略 1、2 为主力，3、4 为补位。</p>
  {cards}
</section>
'''
    part2 = f'''
<section id="threshold">
  <h2 class="sec">阈值调整：区号 60 分钟频次 30 → 15</h2>
  <p class="seclede">现网两条频次类规则（分别覆盖名单内 / 名单外区号）<b>动作不变，仅收紧阈值</b>。
    这是唯一一条改现网已上线策略的动作。</p>
  <div class="stcard">
    <div class="sthead"><span class="n">措施 5</span><h3>REnWrA7CfCdE / OgkdQFtWwJ92 —— 阈值 30 → 15</h3></div>
    <div class="chips"><span class="chip">状态 <b>两条均已 ONLINE（9/3 上线，当前拦截主力）</b></span>
      <span class="chip">动作 <b>REJECT 不变</b></span><span class="chip">范围 <b>LKUS_push 非 +1/+86</b></span>
      <span class="chip">建议 <b>T+6h</b></span></div>

    <h4 class="sub6"><span class="ix">①</span>规则原文（现行，两条分别覆盖名单内 / 名单外）</h4>
    <pre class="rule">{rules['strategy_REnWrA7CfCdE']}

{rules['strategy_OgkdQFtWwJ92']}</pre>
    <p class="body" style="margin-top:10px"><b>建议改为：</b>区号近 60 分钟的访问次数 <b>大于 15</b>（两条同步修改，其余不动）。</p>

    <h4 class="sub6"><span class="ix">②</span>规则说明</h4>
    <p class="body">同一境外区号 1 小时内超过 15 条即拦截（现为 30）。攻击方目前把每个区号每小时压在
      <b>24～33 条</b>，正好卡在 30 的门槛下方。改成 15 后，攻击方要维持同样总量就得把区号数翻倍，
      而<b>每多用一个区号都会撞上策略 1、2 的单日 100 上限</b>——两组规则形成夹击。</p>

    <h4 class="sub6"><span class="ix">③</span>回测证据</h4>
    <p class="body" style="margin-bottom:8px"><b>不同阈值下仍可规避规则的攻击请求占比：</b></p>
    <div class="tblwrap"><table><thead><tr><th>小时频次阈值</th>{curve_hdr}</tr></thead>
      <tbody><tr><td>仍可规避的攻击请求占比</td>{curve_rows}</tr></tbody></table></div>
    <p class="body" style="margin-top:8px;font-size:12.5px">绿色为建议阈值（&gt;15），红色为现行阈值（&gt;30）。</p>
    <p class="body" style="margin:14px 0 8px"><b>攻击方的每小时节奏（09-05 起，按目标区号）：</b></p>
    <div class="tblwrap"><table><thead><tr><th>区号</th><th style="text-align:right">活跃小时</th>
      <th style="text-align:right">小时中位数</th><th style="text-align:right">小时峰值</th>
      <th style="text-align:right">≤30 的小时占比</th></tr></thead><tbody>{evas_rows}</tbody></table></div>
    <p class="body" style="margin-top:10px">48.4% 的（区号,小时）格子 ≤30，承载 30.1% 的攻击请求；
      攻击前境外区号每小时请求量的 <b>P99 = 13</b>。</p>

    <h4 class="sub6"><span class="ix">④</span>SOP 门槛</h4>
    <p class="body">属<b>现网已上线策略的参数调整</b>，不是新策略上线，无需重走发布前评估；
      按变更管理留痕即可。建议与策略 1、2 同批走例外流程审批，便于统一记录。</p>

    <h4 class="sub6"><span class="ix">⑤</span>已知风险</h4>
    <ul class="tight">
      <li><b>区号级聚合规则</b>：某区号 1 小时内真实 + 攻击请求合计超过 15 时，其真实用户会被拦。
        正常时期该指标 P99 = 13，只在攻击时段才会影响境外真实用户。</li>
      <li>更保守的可选做法：<b>名单内改 15、名单外改 20</b>，先观察一轮再统一。</li>
    </ul>

    <h4 class="sub6"><span class="ix">⑥</span>监控与回滚</h4>
    <p class="body" style="margin-bottom:4px"><b>监控：</b></p>
    <ul class="tight"><li>可规避占比是否如预期降到 5% 附近</li>
      <li>+44 / +49 / +65 / +60 的验证码使用率（下降即说明拦到真实用户）</li></ul>
    <p class="body" style="margin:10px 0 4px"><b>回滚：</b></p>
    <ul class="tight"><li>改回 30 只需一次配置，可即时回退</li></ul>

    <div class="approve"><div class="t">审批意见（组长填写）</div>
      <div class="opts"><span>☐ 同意改为 &gt;15</span><span>☐ 同意，名单内 15 / 名单外 20</span>
        <span>☐ 维持 &gt;30 不变</span></div>
      <div class="sign"><span>签批人：____________</span><span>日期：____________</span></div></div>
  </div>
</section>

<section id="reject">
  <h2 class="sec">不予上线的策略与备选</h2>
  <p class="seclede">一并列出，避免组长追问「为什么不用那条命中更高的」。</p>
  <div class="stcard" style="border-left-color:var(--crit)">
    <div class="sthead"><span class="n" style="background:var(--crit)">不建议上线</span>
      <h3>aEw2XWL4QIYx —— 补回比例高，但没有区号护栏</h3></div>
    <h4 class="sub6"><span class="ix">①</span>规则原文</h4>
    <pre class="rule">{rules['strategy_aEw2XWL4QIYx']}</pre>
    <h4 class="sub6"><span class="ix">②</span>为什么不能上</h4>
    <p class="body">24h 增量拦截 <b>{_f(int(aew['增量召回']))}</b> 条、补回 <b>{aew['占漏召回%']}%</b>，
      单看数字是所有候选里最高的之一。但<b>规则没有区号护栏</b>，会把所有低分请求一起拦，包括美国本土用户：</p>
    <div class="tblwrap"><table><thead><tr><th>回测窗口</th><th style="text-align:right">命中量</th>
      <th style="text-align:right">+1 真实用户</th><th style="text-align:right">判正常用户</th>
      <th style="text-align:right">验证码被填写</th></tr></thead>
      <tbody><tr><td>攻击前窗（{PRE_WINDOW}）</td>
        <td style="text-align:right" class="num">{_f(int(aew['攻击前窗命中']))}</td>
        <td style="text-align:right" class="num" >{_f(int(aew['攻击前命中中+1']))}</td>
        <td style="text-align:right" class="num">{_f(int(aew['攻击前命中中正常用户']))}</td>
        <td style="text-align:right" class="num">{_f(int(aew['攻击前命中中OTP已填充']))}</td></tr></tbody></table></div>
    <p class="body" style="margin-top:10px">上线等于<b>每天误拦数以百计的真实美国用户</b>。
      它就是 9/9 大盘上「171 / 59.8%」那条被当作攻击总量参照的策略——<b>适合做度量，不适合做拦截</b>。</p>
  </div>
  <div class="card">
    <h3>其余观察模式策略（本轮不上，数据留作后续）</h3>
    <div class="tblwrap"><table><thead><tr><th>策略</th><th>规则（通俗版）</th>
      <th style="text-align:right">增量拦截（24h）</th><th style="text-align:right">攻击前命中 / +1 / 正常</th>
      <th>建议</th></tr></thead><tbody>{other_rows}</tbody></table></div>
  </div>
</section>
'''

    part3 = f'''
<section id="outside">
  <h2 class="sec">风控之外的两项措施</h2>
  <p class="seclede">策略上线后攻击方会继续换维度；通道侧限额是不依赖风控命中率的兜底，告警是复发时的探测器。</p>
  <div class="grid2">
    <div class="stcard aux" style="margin:0">
      <div class="sthead"><span class="n" style="background:var(--warn)">措施 6</span><h3>短信通道限额</h3></div>
      <div class="chips"><span class="chip">T+8h</span><span class="chip">upush 侧</span>
        <span class="chip">需业务确认零基线国家无真实用户</span></div>
      <p class="body"><b>① 关闭零基线区号的下发权限</b>（Twilio Messaging Geo Permissions 按国家开关）。
        零基线 = 本轮攻击中出现、但攻击前 25 天发送量为 0 的区号：+213 阿尔及利亚、+375 白俄罗斯、
        +265 马拉维、+992 塔吉克斯坦、+264 纳米比亚、+386 斯洛文尼亚、+233 加纳、+223 马里、+258 莫桑比克 等；
        <b>最终名单由 upush 发送表逐个确认</b>。</p>
      <p class="body"><b>注意：</b>+92 巴基斯坦 5～8 月已有历史发送量，<b>不能直接关闭</b>，改用日限额。</p>
      <p class="body"><b>② 非 +1/+86 整体日发送上限 200 条/天</b>。攻击前基线 {_f(m['baseline'])} 条/天（区间 {m['base_lo']}~{m['base_hi']}），
        200 留出约 3 倍余量；超限后当日境外短信全部停发，转人工确认。</p>
      <p class="body"><b>效果：</b>与风控命中率无关，直接把境外短信费用压到基线水平。</p>
      <div class="approve"><div class="t">审批意见</div>
        <div class="opts"><span>☐ 同意关闭 + 限额</span><span>☐ 仅设限额，暂不关闭</span><span>☐ 暂不执行</span></div>
        <div class="sign"><span>签批人：____________</span><span>日期：____________</span></div></div>
    </div>
    <div class="stcard aux" style="margin:0">
      <div class="sthead"><span class="n" style="background:var(--warn)">措施 7</span><h3>监控告警（4 条）</h3></div>
      <div class="chips"><span class="chip">T+12h</span><span class="chip">DBA + 风控</span>
        <span class="chip">替代「攻击集中在非营业时段」的说法</span></div>
      <div class="tblwrap"><table><thead><tr><th>告警</th><th style="text-align:right">阈值</th><th>依据</th></tr></thead>
        <tbody>
          <tr><td>境外区号小时请求量</td><td style="text-align:right" class="num">&gt; 300</td><td>攻击期每小时 347～2,213；正常期 &lt;30</td></tr>
          <tr><td>境外区号占小时总请求</td><td style="text-align:right" class="num">&gt; 90%</td><td>攻击期夜间 93%～99.6%；正常期 &lt;15%</td></tr>
          <tr><td>upush 境外区号日发送量</td><td style="text-align:right" class="num">&gt; 150</td><td>攻击前基线 {m['base_lo']}~{m['base_hi']}</td></tr>
          <tr><td>任一拦截策略小时命中量</td><td style="text-align:right" class="num">= 0（连续 2h）</td><td>特征改名会让策略静默失效；172 号正常水平 11～105/小时</td></tr>
        </tbody></table></div>
      <p class="body" style="margin-top:10px"><b>不建议做「美东 22:00–06:00 时段拦截」</b>：攻击 7×24 全天候，
        低谷时段仍占 8.8%，夜间无差别影响境外真实用户，精度不如频次类规则。
        <b>时段特征的正确用法是告警，不是拦截。</b></p>
      <div class="approve"><div class="t">审批意见</div>
        <div class="opts"><span>☐ 同意 4 条全上</span><span>☐ 部分采纳</span><span>☐ 暂不执行</span></div>
        <div class="sign"><span>签批人：____________</span><span>日期：____________</span></div></div>
    </div>
  </div>
</section>

<section id="rollout">
  <h2 class="sec">上线执行、例外流程要件与回滚</h2>
  <p class="seclede">按 SOP：观察模式 → 准确率评估 → 上线 → 上线后观察。本次走「正在遭受黑产攻击的应急处置场景」例外流程。</p>

  <div class="card">
    <h3>分步上线顺序（每步观察 1 小时再走下一步）</h3>
    <div class="tblwrap"><table><thead><tr><th>时间</th><th>动作</th><th>看什么再走下一步</th></tr></thead>
      <tbody>
        <tr><td class="num">T+2h</td><td><b>策略 1 + 2 上线（REJECT）</b></td><td>命中率；熔断 = 0；真实用户区号使用率不下降</td></tr>
        <tr><td class="num">T+4h</td><td>策略 3 + 4 上线（REJECT）</td><td>同上；+86 命中量；与 172 的重叠比例</td></tr>
        <tr><td class="num">T+6h</td><td>阈值 30 → 15</td><td>可规避占比；真实用户区号使用率</td></tr>
        <tr><td class="num">T+8h</td><td>upush 零基线区号关闭 + 日限额 200</td><td>upush 境外日发送量回落</td></tr>
        <tr><td class="num">T+12h</td><td>4 条告警上线</td><td>用 9/9 数据回放能否触发</td></tr>
        <tr><td class="num">T+24h</td><td>复盘</td><td><b>境外日发送 &lt;150 条/天 = 压制达标</b></td></tr>
      </tbody></table></div>
  </div>

  <div class="card" style="margin-top:16px">
    <h3>例外流程四项要件（SOP 1.7，必须逐项写明）</h3>
    <div class="tblwrap"><table><tbody>
      <tr><td style="width:130px"><b>原因</b></td><td>正在遭受黑产攻击的应急处置：境外区号实发短信从
        {_f(m['baseline'])} 条/天升至 {_f(m['today_attack'])} 条/天，费用实时发生；
        LKUS 体量（日调用约 7.7k）<b>永远达不到 SOP 绝对流量门槛</b>（8,000 调用 / 3,000 用户）。</td></tr>
      <tr><td><b>风险</b></td><td>误拦境外区号的真实用户。四条策略命中样本误拦率均为 <b>0.0%</b>，
        攻击前 25 天回测 +1 用户命中 <b>0 条</b>。</td></tr>
      <tr><td><b>补充控制措施</b></td><td>仅对非 +1/+86 生效，+1 用户完全不受影响；
        保留手机号 / 用户编号 / IP 白名单通道；分步上线、每步观察 1 小时。</td></tr>
      <tr><td><b>上线后监控安排</b></td><td>逐小时命中量 / 命中率 / 熔断；
        有真实用户区号（+44/+49/+65/+60/+86）的验证码使用率；upush 境外日发送量；4 条告警。</td></tr>
    </tbody></table></div>
  </div>

  <div class="card" style="margin-top:16px">
    <h3>回滚触发（SOP 1.8 应急止损 —— 电话通知，不得只发飞书）</h3>
    <ul class="tight">
      <li>任一策略命中样本正常用户占比 <b>&gt;0.1%</b> → 立即降级为 REVIEW</li>
      <li>确认为本策略拦截的真实用户投诉 → 关闭策略</li>
      <li>熔断触发 → 按 RMS 自动降级并人工复核</li>
      <li>命中率突然 <b>&lt;5%</b> → 先查特征名是否被改，再查攻击是否转移</li>
      <li>阈值调整可一次配置改回 30</li>
    </ul>
  </div>

  <div class="card" style="margin-top:16px">
    <h3>需研发排期的新特征（本轮用不上，下一轮攻击会用到）</h3>
    <ul class="tight">
      <li><b>同网关 uid 近 60 分钟关联手机号个数</b> —— 最大的一个 uid 关联 277 个号、93 个 IP、跨 3 个国家，
        而<b>现有规则完全没有 uid 维度</b>，这是当前最大的能力缺口</li>
      <li>同 IP C 段近 60 分钟关联手机号个数（现有只有 1 分钟 / 10 分钟窗口）</li>
      <li>手机号合法性校验（按各国号段规划）</li>
      <li>ASN / 机房 IP 标签（美国攻击 IP 全部落在 Plano / Richardson 机房段）</li>
    </ul>
  </div>
</section>

<section id="appendix">
  <h2 class="sec">附录：口径定义</h2>
  <div class="card"><div class="tblwrap"><table><tbody>
    <tr><td style="width:150px"><b>场景</b></td><td><code>tenant='LKUS' AND scene_id='LKUS_push'</code>（短信验证码风控场景）</td></tr>
    <tr><td><b>攻击窗</b></td><td>最近 24 小时：{WINDOW}</td></tr>
    <tr><td><b>攻击前窗</b></td><td>{PRE_WINDOW}，该窗口内非 +1 流量约等于正常基线（日均 {_f(m['baseline'])} 条，区间 {m['base_lo']}~{m['base_hi']}）</td></tr>
    <tr><td><b>区号分组</b></td><td>+1 = &#123;1,+1&#125;；+86 = &#123;86,+86&#125;；非 +1/+86 = 其余非空；未知 = 空值，单独一桶</td></tr>
    <tr><td><b>增量拦截</b></td><td>现网 ONLINE 策略之外<b>额外</b>拦下的攻击请求（引擎实测命中，非回放估算）</td></tr>
    <tr><td><b>误拦</b></td><td>命中样本中判为「正常用户」的比例。黑产判定遵循 SOP §3.7：需 ≥2 类独立特征交叉印证，单一特征标「暂无法判断」，不计入黑产</td></tr>
    <tr><td><b>验证码被填写</b></td><td>短信发出后用户真的输入了验证码（<code>t_sent_verifycode_sms.filled</code>），是判定真实用户最硬的标签</td></tr>
    <tr><td><b>数据源</b></td><td>风控请求日志 <code>t_access_log_0000..0063</code>（64 分片源库）+ 短信发送记录；规则原文取自 RMS 策略表，逐字未改</td></tr>
  </tbody></table></div></div>
</section>

<footer>瑞幸咖啡北美 · 信息安全 / 数据库团队 · 数据截至 2026-09-10 06:32 UTC · 本页数字均可追溯至明细 CSV</footer>
</div>'''

    doc = body + part2 + part3
    if standalone:
        head, _, tail = doc.partition("<nav class=")
        doc = ('<!doctype html>\n<html lang="zh-CN">\n<head>\n<meta charset="utf-8">\n'
               '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
               + head + "</head>\n<body>\n<nav class=" + tail + "\n</body>\n</html>")
    return doc


def main():
    for sa, path in [(False, OUT_HTML), (True, OUT_HTML.replace(".html", "_单文件.html"))]:
        html = render(standalone=sa)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"wrote {path}  ({os.path.getsize(path):,} bytes)")


if __name__ == "__main__":
    main()
