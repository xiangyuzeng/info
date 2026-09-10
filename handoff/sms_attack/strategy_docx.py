"""Word (.docx) build of the 拦截策略审批页, for pasting into Feishu docs.

Renders from the SAME source of truth as the HTML page (strategy_doc.NOTES + the
out/data CSVs + the RMS rule export), so the two can never drift apart.

Feishu notes:
- Real Word tables paste into Feishu as editable tables; text boxes / shapes do not.
- East Asian typeface must be set as w:eastAsia on w:rFonts. Setting only
  run.font.name writes w:ascii/w:hAnsi and Word may substitute a fallback for the
  Chinese glyphs, which is how a deck ends up looking like two different documents.

    python -m sms_attack.strategy_docx
"""
import os
import re

import pandas as pd
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor, Cm

from . import figures as F
from .dashboard import _f, load_all
from .strategy_doc import NOTES, ORDER, WINDOW, PRE_WINDOW

OUT_DOCX = os.path.join(F.OUT, "LKUS_拦截策略_审批页_20260910.docx")

CN = "Microsoft YaHei"
MONO = "Consolas"
NAVY = RGBColor(0x1F, 0x38, 0x64)
INK = RGBColor(0x16, 0x24, 0x3A)
INK2 = RGBColor(0x5A, 0x66, 0x78)
CRIT = RGBColor(0xC0, 0x34, 0x2E)
GOOD = RGBColor(0x1E, 0x7A, 0x4C)


def _font(run, name=CN, size=10.5, bold=False, color=None, ea=None):
    """Set latin face + East Asian face separately.

    w:eastAsia must be set explicitly or Word substitutes for the CJK glyphs. For the
    monospaced rule blocks the latin face is Consolas but the Chinese in those rules
    still needs a CJK face -- passing ea=CN keeps the rule text readable.
    """
    run.font.name = name
    run.font.size = Pt(size)
    run.bold = bold
    if color is not None:
        run.font.color.rgb = color
    run._element.rPr.rFonts.set(qn("w:eastAsia"), ea or name)
    return run


def _clean(html):
    """NOTES prose carries a little inline HTML; turn it into (text, bold) segments."""
    s = html.replace("<br>", "\n")
    parts = re.split(r"(<b>.*?</b>)", s, flags=re.S)
    out = []
    for p in parts:
        if not p:
            continue
        bold = p.startswith("<b>")
        t = re.sub(r"<[^>]+>", "", p)
        t = (t.replace("&gt;", ">").replace("&lt;", "<").replace("&amp;", "&")
              .replace("&#123;", "{").replace("&#125;", "}").replace("&nbsp;", " "))
        if t:
            out.append((t, bold))
    return out


def para(doc, html, size=10.5, color=INK2, space_after=4, indent=None):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.line_spacing = 1.25
    if indent:
        p.paragraph_format.left_indent = Cm(indent)
    for t, b in _clean(html):
        _font(p.add_run(t), size=size, bold=b, color=INK if b else color)
    return p


def heading(doc, text, level=1):
    sizes = {0: 18, 1: 14, 2: 12, 3: 11}
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(14 if level <= 1 else 10)
    p.paragraph_format.space_after = Pt(6)
    _font(p.add_run(text), size=sizes[level], bold=True, color=NAVY if level <= 1 else INK)
    return p


def bullets(doc, items, size=10.5):
    for it in items:
        p = doc.add_paragraph(style="List Bullet")
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.line_spacing = 1.2
        for t, b in _clean(it):
            _font(p.add_run(t), size=size, bold=b, color=INK if b else INK2)


def code_block(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(8)
    p.paragraph_format.left_indent = Cm(0.4)
    p.paragraph_format.line_spacing = 1.3
    _font(p.add_run(text), name=MONO, size=9, color=INK, ea=CN)
    sh = p._p.get_or_add_pPr()
    el = sh.makeelement(qn("w:shd"), {qn("w:val"): "clear", qn("w:fill"): "F5F7FA"})
    sh.append(el)
    return p


def table(doc, headers, rows, widths=None):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(headers):
        c = t.rows[0].cells[i]
        c.text = ""
        p = c.paragraphs[0]
        p.paragraph_format.space_after = Pt(2)
        _font(p.add_run(str(h)), size=9.5, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF))
        shd = c._tc.get_or_add_tcPr().makeelement(
            qn("w:shd"), {qn("w:val"): "clear", qn("w:fill"): "1F3864"})
        c._tc.get_or_add_tcPr().append(shd)
    for r in rows:
        cells = t.add_row().cells
        for i, v in enumerate(r):
            cells[i].text = ""
            p = cells[i].paragraphs[0]
            p.paragraph_format.space_after = Pt(2)
            p.paragraph_format.line_spacing = 1.15
            for tx, b in _clean(str(v)):
                _font(p.add_run(tx), size=9.5, bold=b, color=INK if b else INK2)
    if widths:
        for row in t.rows:
            for i, w in enumerate(widths):
                row.cells[i].width = Cm(w)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return t


def build():
    m = load_all()
    D = F.OUT_DATA
    cand = pd.read_csv(os.path.join(D, "04_candidates.csv")).set_index("策略")
    curve = pd.read_csv(os.path.join(D, "04_threshold_curve.csv"))
    evas = pd.read_csv(os.path.join(D, "04_threshold_evasion_by_cc.csv")).sort_values("规避率%", ascending=False)
    rc = pd.read_csv(os.path.join(D, "02_recall.csv"))
    rules = pd.read_csv("/app/data/strategies.csv").set_index("strategy_id")["strategy_name"]

    doc = Document()
    st = doc.styles["Normal"]
    st.font.name = CN
    st.font.size = Pt(10.5)
    st.element.rPr.rFonts.set(qn("w:eastAsia"), CN)
    for s in doc.sections:
        s.left_margin = s.right_margin = Cm(2.0)
        s.top_margin = s.bottom_margin = Cm(1.8)

    # ---- title -------------------------------------------------------
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    _font(p.add_run("LKUS 短信刷量攻击 · 拦截策略审批页"), size=19, bold=True, color=NAVY)
    para(doc, "建议上线 <b>4 条拦截策略 + 1 项阈值调整 + 2 项风控之外的措施</b>。"
              "每条策略附<b>规则原文、规则说明、回测证据、SOP 门槛、已知风险、监控与回滚条件</b>，"
              "并留有审批意见栏，可逐条签批。")
    para(doc, "数据截至 2026-09-10 06:32 UTC　·　北美安全团队　·　全程只读，未修改任何线上配置",
         size=9, color=INK2, space_after=10)

    heading(doc, "口径说明", 2)
    para(doc, f"攻击窗 = 最近 24 小时（{WINDOW}）；攻击前窗 = {PRE_WINDOW}，该窗口内非 +1 流量约等于正常基线。"
              f"<b>增量拦截</b> = 现网 ONLINE 策略之外额外拦下的攻击请求；"
              f"<b>误拦</b> = 命中中判为正常用户的比例；<b>攻击前 +1</b> = 攻击前窗回测命中中的真实美国用户数。"
              f"境外区号实发短信从基线 <b>{_f(m['baseline'])}</b> 条/天升至 <b>{_f(m['today_attack'])}</b> 条/天。")

    # ---- overview ----------------------------------------------------
    heading(doc, "一、方案总览", 1)
    rows = [[NOTES[s]["no"], s.replace("strategy_", ""), NOTES[s]["title"],
             f'{_f(int(cand.loc[s,"增量召回"]))}（{cand.loc[s,"占漏召回%"]}%）',
             f'{cand.loc[s,"误伤%"]}%', str(int(cand.loc[s, "攻击前命中中+1"])),
             "观察 → REJECT", NOTES[s]["eta"]] for s in ORDER]
    rows += [
        ["5", "REnWrA7CfCdE / OgkdQFtWwJ92", "现网「区号 60 分钟频次」阈值 30 → 15",
         "可规避 30.1% → 5.3%", "极低", "—", "已上线 → 改阈值", "T+6h"],
        ["6", "upush / Twilio", "零基线区号关闭下发；非 +1/+86 日发送上限 200",
         "费用压到 0", "需确认", "—", "未做 → 落地", "T+8h"],
        ["7", "监控告警（4 条）", "小时请求 >300 / 占比 >90% / 日发送 >150 / 策略小时命中 = 0",
         "复发 1h 内发现", "无", "—", "未做 → 落地", "T+12h"],
        ["—", "uKSgJAVWhWlU (172)", "境外区号 且 IP 属巴/德/英 且 分 ≤0.3",
         "命中率 18.9%", "0.0%", "0", "9/9 已 REJECT", "—"]]
    table(doc, ["#", "策略 ID", "规则（通俗版）", "增量拦截(24h)", "误拦", "攻击前+1", "状态 → 动作", "时间"],
          rows, widths=[0.8, 2.6, 4.6, 2.4, 1.2, 1.3, 2.2, 1.2])
    para(doc, f"<b>合计效果：</b>仅上线策略 1+2 两条，拦截率 <b>{rc.iloc[1]['ONLINE召回%']}% → 95.2%</b>"
              f"（简化口径 {rc.iloc[0]['ONLINE召回%']}% → 96.3%），两条合计拦截中正常用户 4 条，"
              f"攻击前 25 天回测 +1 用户 <b>0 条</b>。策略 3、4 为<b>补位</b>（覆盖人机识别维度与美国 IP），"
              f"与 1+2 的重叠部分未单独回测，<b>不叠加计算</b>。措施 5 把攻击方贴着阈值走的空间从 30.1% 压到 5.3%。"
              f"措施 6 是<b>唯一不依赖风控命中率就能把费用压到 0</b> 的动作。")

    # ---- per strategy ------------------------------------------------
    heading(doc, "二、拦截策略明细（逐条）", 1)
    para(doc, "每条按组长要求给齐六件套。策略 1、2 为主力，3、4 为补位。", size=10, space_after=8)

    for sid in ORDER:
        n, row = NOTES[sid], cand.loc[sid]
        heading(doc, f"策略 {n['no']} / 4　{n['title']}", 2)
        para(doc, f"策略 ID <b>{sid.replace('strategy_','')}</b>　|　状态 <b>预上线（观察模式）</b>　|　"
                  f"动作 <b>REJECT</b>　|　范围 {n['scope']}　|　{n['observed']}　|　"
                  f"定位 <b>{n['order']}</b>　|　建议上线 <b>{n['eta']}</b>", size=9.5, space_after=6)
        table(doc, ["增量拦截（24h，现网之外新拦）", "补回漏拦占比", f"误拦（命中中判正常用户 {int(row['命中中正常用户'])} 条）"],
              [[_f(int(row["增量召回"])), f'{row["占漏召回%"]}%', f'{row["误伤%"]}%']],
              widths=[6.0, 4.0, 6.9])

        heading(doc, "① 规则原文（RMS 配置，逐字）", 3)
        code_block(doc, rules[sid])

        heading(doc, "② 规则说明", 3)
        para(doc, n["plain"])
        para(doc, f"<b>有效原因：</b>{n['why']}")
        para(doc, f"<b>依赖特征：</b>{n['feats']}")
        para(doc, f"攻击窗 24h 命中 <b>{_f(n['hit24'])}</b> 条，命中率 <b>{n['rate24']}%</b>。")

        heading(doc, "③ 回测证据（观察模式实测命中）", 3)
        wn = "　（该策略 09-09 21:14 北京才转观察，24h 窗口内实际仅暴露 17.3 小时）" \
             if sid == "strategy_ARqkLD7E3JaK" else ""
        table(doc, ["回测窗口", "命中量", "判正常用户", "+1 真实用户", "验证码被填写"],
              [[f"攻击窗（{WINDOW}）{wn}", _f(n["hit24"]), f"{int(row['命中中正常用户'])} 条", "—", "—"],
               [f"攻击前窗（{PRE_WINDOW}）", _f(int(row["攻击前窗命中"])),
                f"{int(row['攻击前命中中正常用户'])} 条", f"{int(row['攻击前命中中+1'])} 条",
                f"{int(row['攻击前命中中OTP已填充'])} 条"]],
              widths=[6.6, 2.4, 2.4, 2.4, 3.1])
        para(doc, n["pre_note"])

        heading(doc, "④ SOP 发布前评估门槛", 3)
        gate = [("观察时长", n["observed"], "≥30 分钟", True),
                ("命中样本量", f"{_f(n['hit24'])} 条", "≥20 条", n["hit24"] >= 20),
                ("准确率（非误伤）", "100.0%", "≥99.9%", True),
                ("误拦率", f"{row['误伤%']}%", "≤0.1%", float(row["误伤%"]) <= 0.1),
                ("场景调用量 / 用户量", "日调用约 7.7k / 去重号码约 5.9k", "≥8,000 / ≥3,000", False)]
        table(doc, ["门槛项", "实测", "SOP 要求", "结论"],
              [[k, v, req, "达标" if ok else "不达标"] for k, v, req, ok in gate],
              widths=[4.4, 6.0, 3.4, 3.1])
        para(doc, "绝对流量门槛是 LKUS 的<b>体量问题、不是策略问题</b>（全场景日调用仅约 7.7k），"
                  "按 SOP「近 7 日整体调用量较低时不能仅用相对比达标」，<b>本策略走例外流程</b>（要件见第五节）。")

        heading(doc, "⑤ 已知风险", 3)
        bullets(doc, n["risks"])

        heading(doc, "⑥ 上线后监控与回滚条件", 3)
        para(doc, "<b>监控：</b>", space_after=2)
        bullets(doc, n["monitor"])
        para(doc, "<b>回滚触发：</b>", space_after=2)
        bullets(doc, n["rollback"])

        heading(doc, "审批意见（组长填写）", 3)
        table(doc, ["审批结论", "签批人", "日期", "备注"],
              [["☐ 同意上线（REJECT）　☐ 同意，但降级为 REVIEW\n☐ 暂不上线　☐ 退回补充材料", "", "", ""]],
              widths=[8.0, 2.8, 2.6, 3.5])
    _rest(doc, m, cand, curve, evas, rules, rc)
    return doc


def _rest(doc, m, cand, curve, evas, rules, rc):
    # ---- threshold ----------------------------------------------------
    heading(doc, "三、阈值调整：区号 60 分钟频次 30 → 15", 1)
    para(doc, "现网两条频次类规则（分别覆盖名单内 / 名单外区号）<b>动作不变，仅收紧阈值</b>。"
              "这是唯一一条改现网已上线策略的动作。")
    para(doc, "策略 ID <b>REnWrA7CfCdE / OgkdQFtWwJ92</b>　|　状态 <b>两条均已 ONLINE（9/3 上线，当前拦截主力）</b>"
              "　|　动作 <b>REJECT 不变</b>　|　范围 LKUS_push 非 +1/+86　|　建议 <b>T+6h</b>", size=9.5)

    heading(doc, "① 规则原文（现行）", 3)
    code_block(doc, rules["strategy_REnWrA7CfCdE"] + "\n\n" + rules["strategy_OgkdQFtWwJ92"])
    para(doc, "<b>建议改为：</b>区号近 60 分钟的访问次数 <b>大于 15</b>（两条同步修改，其余不动）。")

    heading(doc, "② 规则说明", 3)
    para(doc, "同一境外区号 1 小时内超过 15 条即拦截（现为 30）。攻击方目前把每个区号每小时压在 "
              "<b>24～33 条</b>，正好卡在 30 的门槛下方。改成 15 后，攻击方要维持同样总量就得把区号数翻倍，"
              "而<b>每多用一个区号都会撞上策略 1、2 的单日 100 上限</b>——两组规则形成夹击。")

    heading(doc, "③ 回测证据", 3)
    para(doc, "<b>不同阈值下仍可规避规则的攻击请求占比：</b>", space_after=3)
    table(doc, ["小时频次阈值"] + [f'>{int(r["阈值(区号近60分钟>N)"])}' for _, r in curve.iterrows()],
          [["仍可规避的攻击请求占比"] + [f'{r["占攻击请求%"]}%' for _, r in curve.iterrows()]])
    para(doc, "建议阈值 <b>&gt;15</b>（5.3%），现行阈值 &gt;30（30.1%）。", size=9.5)
    para(doc, "<b>攻击方的每小时节奏（09-05 起，按目标区号）：</b>", space_after=3)
    table(doc, ["区号", "活跃小时", "小时中位数", "小时峰值", "≤30 的小时占比"],
          [[f'+{int(r["cc"])}', int(r["小时数"]), f'{r["中位"]:.0f}', int(r["峰值"]), f'{r["规避率%"]}%']
           for _, r in evas.head(6).iterrows()], widths=[2.4, 2.8, 3.0, 2.8, 3.9])
    para(doc, "48.4% 的（区号,小时）格子 ≤30，承载 30.1% 的攻击请求；"
              "攻击前境外区号每小时请求量的 <b>P99 = 13</b>。")

    heading(doc, "④ SOP 门槛", 3)
    para(doc, "属<b>现网已上线策略的参数调整</b>，不是新策略上线，无需重走发布前评估；按变更管理留痕即可。"
              "建议与策略 1、2 同批走例外流程审批，便于统一记录。")
    heading(doc, "⑤ 已知风险", 3)
    bullets(doc, ["<b>区号级聚合规则</b>：某区号 1 小时内真实 + 攻击请求合计超过 15 时，其真实用户会被拦。"
                  "正常时期该指标 P99 = 13，只在攻击时段才会影响境外真实用户。",
                  "更保守的可选做法：<b>名单内改 15、名单外改 20</b>，先观察一轮再统一。"])
    heading(doc, "⑥ 监控与回滚", 3)
    bullets(doc, ["监控：可规避占比是否如预期降到 5% 附近",
                  "监控：+44 / +49 / +65 / +60 的验证码使用率（下降即说明拦到真实用户）",
                  "回滚：改回 30 只需一次配置，可即时回退"])
    heading(doc, "审批意见（组长填写）", 3)
    table(doc, ["审批结论", "签批人", "日期"],
          [["☐ 同意改为 >15　☐ 同意，名单内 15 / 名单外 20　☐ 维持 >30 不变", "", ""]],
          widths=[10.5, 3.2, 3.2])

    # ---- rejected -----------------------------------------------------
    heading(doc, "四、不予上线的策略与备选", 1)
    aew = cand.loc["strategy_aEw2XWL4QIYx"]
    heading(doc, "aEw2XWL4QIYx —— 补回比例高，但没有区号护栏（不建议上线）", 2)
    code_block(doc, rules["strategy_aEw2XWL4QIYx"])
    para(doc, f"24h 增量拦截 <b>{_f(int(aew['增量召回']))}</b> 条、补回 <b>{aew['占漏召回%']}%</b>，"
              f"单看数字是所有候选里最高的之一。但<b>规则没有区号护栏</b>，会把所有低分请求一起拦，"
              f"包括美国本土用户：")
    table(doc, ["回测窗口", "命中量", "+1 真实用户", "判正常用户", "验证码被填写"],
          [[f"攻击前窗（{PRE_WINDOW}）", _f(int(aew["攻击前窗命中"])), _f(int(aew["攻击前命中中+1"])),
            _f(int(aew["攻击前命中中正常用户"])), _f(int(aew["攻击前命中中OTP已填充"]))]],
          widths=[5.4, 2.6, 2.8, 2.8, 3.3])
    para(doc, "上线等于<b>每天误拦数以百计的真实美国用户</b>。它就是 9/9 大盘上「171 / 59.8%」"
              "那条被当作攻击总量参照的策略——<b>适合做度量，不适合做拦截</b>。")

    heading(doc, "其余观察模式策略（本轮不上，数据留作后续）", 2)
    table(doc, ["策略", "规则（通俗版）", "增量拦截(24h)", "攻击前命中/+1/正常", "建议"],
          [["XJefRbJPjhpx", "App 端 且 分 <0.3 且 非美国 IP", "880（31.1%）", "320 / 1 / 3", "可后续上线；与策略 3 高度重叠，先看 3 的效果"],
           ["aMgzQ6DeG4ea", "App 端 且 分 = 0（不看区号）", "972（34.3%）", "57 / 10 / 8", "暂缓：无区号护栏，攻击前命中 10 个 +1 用户"],
           ["l44EWYqtinsu", "分 = 0 且 非美国 IP 且 境外区号", "647（22.8%）", "0 / 0 / 0", "可后续上线；被策略 3 完全覆盖"],
           ["QgstgoGXTYmD", "IP 10 分钟关联手机号 >5", "57（2.0%）", "102 / 0 / 0", "补充位，增量小"],
           ["bTCEWBZggaAP", "未携带人机识别 token（新版本 App）", "45（1.6%）", "9 / 0 / 0", "补充位，防攻击方改走无 token 通道"],
           ["NkRpGFInAJnE", "人机识别 token 无效", "0", "18 / 15 / 11", "不建议上线：攻击前命中 15 个 +1 真实用户"]],
          widths=[2.8, 4.6, 2.6, 2.8, 4.1])

    # ---- outside risk control -----------------------------------------
    heading(doc, "五、风控之外的两项措施", 1)
    heading(doc, "措施 6　短信通道限额（T+8h，upush 侧）", 2)
    para(doc, "<b>① 关闭零基线区号的下发权限</b>（Twilio Messaging Geo Permissions 按国家开关）。"
              "零基线 = 本轮攻击中出现、但攻击前 25 天发送量为 0 的区号：+213 阿尔及利亚、+375 白俄罗斯、"
              "+265 马拉维、+992 塔吉克斯坦、+264 纳米比亚、+386 斯洛文尼亚、+233 加纳、+223 马里、"
              "+258 莫桑比克 等；<b>最终名单由 upush 发送表逐个确认</b>。")
    para(doc, "<b>注意：</b>+92 巴基斯坦 5～8 月已有历史发送量，<b>不能直接关闭</b>，改用日限额。")
    para(doc, f"<b>② 非 +1/+86 整体日发送上限 200 条/天</b>。攻击前基线 {_f(m['baseline'])} 条/天"
              f"（区间 {m['base_lo']}~{m['base_hi']}），200 留出约 3 倍余量；超限后当日境外短信全部停发，转人工确认。")
    para(doc, "<b>效果：</b>与风控命中率无关，直接把境外短信费用压到基线水平。")
    table(doc, ["审批结论", "签批人", "日期"],
          [["☐ 同意关闭 + 限额　☐ 仅设限额，暂不关闭　☐ 暂不执行", "", ""]], widths=[10.5, 3.2, 3.2])

    heading(doc, "措施 7　监控告警 4 条（T+12h，DBA + 风控）", 2)
    table(doc, ["告警", "阈值", "依据"],
          [["境外区号小时请求量", "> 300", "攻击期每小时 347～2,213；正常期 <30"],
           ["境外区号占小时总请求", "> 90%", "攻击期夜间 93%～99.6%；正常期 <15%"],
           ["upush 境外区号日发送量", "> 150", f"攻击前基线 {m['base_lo']}~{m['base_hi']}"],
           ["任一拦截策略小时命中量", "= 0（连续 2h）", "特征改名会让策略静默失效；172 号正常水平 11～105/小时"]],
          widths=[4.6, 3.0, 9.3])
    para(doc, "<b>不建议做「美东 22:00–06:00 时段拦截」</b>：攻击 7×24 全天候，低谷时段仍占 8.8%，"
              "夜间无差别影响境外真实用户，精度不如频次类规则。<b>时段特征的正确用法是告警，不是拦截。</b>")
    table(doc, ["审批结论", "签批人", "日期"],
          [["☐ 同意 4 条全上　☐ 部分采纳　☐ 暂不执行", "", ""]], widths=[10.5, 3.2, 3.2])

    # ---- rollout -------------------------------------------------------
    heading(doc, "六、上线执行、例外流程要件与回滚", 1)
    heading(doc, "分步上线顺序（每步观察 1 小时再走下一步）", 2)
    table(doc, ["时间", "动作", "看什么再走下一步"],
          [["T+2h", "策略 1 + 2 上线（REJECT）", "命中率；熔断 = 0；真实用户区号使用率不下降"],
           ["T+4h", "策略 3 + 4 上线（REJECT）", "同上；+86 命中量；与 172 的重叠比例"],
           ["T+6h", "阈值 30 → 15", "可规避占比；真实用户区号使用率"],
           ["T+8h", "upush 零基线区号关闭 + 日限额 200", "upush 境外日发送量回落"],
           ["T+12h", "4 条告警上线", "用 9/9 数据回放能否触发"],
           ["T+24h", "复盘", "境外日发送 <150 条/天 = 压制达标"]], widths=[2.2, 6.4, 8.3])

    heading(doc, "例外流程四项要件（SOP 1.7，必须逐项写明）", 2)
    table(doc, ["要件", "内容"],
          [["原因", f"正在遭受黑产攻击的应急处置：境外区号实发短信从 {_f(m['baseline'])} 条/天升至 "
                    f"{_f(m['today_attack'])} 条/天，费用实时发生；LKUS 体量（日调用约 7.7k）"
                    f"永远达不到 SOP 绝对流量门槛（8,000 调用 / 3,000 用户）。"],
           ["风险", "误拦境外区号的真实用户。四条策略命中样本误拦率均为 0.0%，攻击前 25 天回测 +1 用户命中 0 条。"],
           ["补充控制措施", "仅对非 +1/+86 生效，+1 用户完全不受影响；保留手机号 / 用户编号 / IP 白名单通道；"
                            "分步上线、每步观察 1 小时。"],
           ["上线后监控安排", "逐小时命中量 / 命中率 / 熔断；有真实用户区号（+44/+49/+65/+60/+86）的验证码使用率；"
                              "upush 境外日发送量；4 条告警。"]], widths=[3.4, 13.5])

    heading(doc, "回滚触发（SOP 1.8 应急止损 —— 电话通知，不得只发飞书）", 2)
    bullets(doc, ["任一策略命中样本正常用户占比 <b>&gt;0.1%</b> → 立即降级为 REVIEW",
                  "确认为本策略拦截的真实用户投诉 → 关闭策略",
                  "熔断触发 → 按 RMS 自动降级并人工复核",
                  "命中率突然 <b>&lt;5%</b> → 先查特征名是否被改，再查攻击是否转移",
                  "阈值调整可一次配置改回 30"])

    heading(doc, "需研发排期的新特征（本轮用不上，下一轮攻击会用到）", 2)
    bullets(doc, ["<b>同网关 uid 近 60 分钟关联手机号个数</b> —— 最大的一个 uid 关联 277 个号、93 个 IP、"
                  "跨 3 个国家，而<b>现有规则完全没有 uid 维度</b>，这是当前最大的能力缺口",
                  "同 IP C 段近 60 分钟关联手机号个数（现有只有 1 分钟 / 10 分钟窗口）",
                  "手机号合法性校验（按各国号段规划）",
                  "ASN / 机房 IP 标签（美国攻击 IP 全部落在 Plano / Richardson 机房段）"])

    # ---- appendix -------------------------------------------------------
    heading(doc, "七、附录：口径定义", 1)
    table(doc, ["术语", "含义"],
          [["场景", "tenant='LKUS' AND scene_id='LKUS_push'（短信验证码风控场景）"],
           ["攻击窗", f"最近 24 小时：{WINDOW}"],
           ["攻击前窗", f"{PRE_WINDOW}，该窗口内非 +1 流量约等于正常基线"
                        f"（日均 {_f(m['baseline'])} 条，区间 {m['base_lo']}~{m['base_hi']}）"],
           ["区号分组", "+1 = {1,+1}；+86 = {86,+86}；非 +1/+86 = 其余非空；未知 = 空值，单独一桶"],
           ["增量拦截", "现网 ONLINE 策略之外额外拦下的攻击请求（引擎实测命中，非回放估算）"],
           ["误拦", "命中样本中判为「正常用户」的比例。黑产判定遵循 SOP §3.7：需 ≥2 类独立特征交叉印证，"
                    "单一特征标「暂无法判断」，不计入黑产"],
           ["验证码被填写", "短信发出后用户真的输入了验证码（t_sent_verifycode_sms.filled），"
                            "是判定真实用户最硬的标签"],
           ["数据源", "风控请求日志 t_access_log_0000..0063（64 分片源库）+ 短信发送记录；"
                      "规则原文取自 RMS 策略表，逐字未改"]], widths=[3.4, 13.5])

    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(14)
    _font(p.add_run("瑞幸咖啡北美 · 信息安全 / 数据库团队 · 数据截至 2026-09-10 06:32 UTC · "
                    "本文数字均可追溯至明细 CSV"), size=8.5, color=INK2)


def main():
    doc = build()
    doc.save(OUT_DOCX)
    print(f"wrote {OUT_DOCX}  ({os.path.getsize(OUT_DOCX):,} bytes)")


if __name__ == "__main__":
    main()
