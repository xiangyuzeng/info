"""Render the SOP approval form for one strategy.

The two tables' first three columns (字段名 / 字段类型 / 必填) are NOT written by hand --
they are loaded from sop_form_skeleton.json, extracted from the team's own demo
(docs/07) and verified row-for-row against the template (docs/06); the only difference
is a stray '<br>' in the template's 黑产评估依据说明 field name, which the demo drops.
Only the fourth column is ever filled. Rows are never added, removed, renamed or
reordered -- that is what the reviewer checks first.

House style quirks reproduced deliberately (identical in both source documents, so they
are convention rather than typo):
  * heading 一 is fully bold  **一、配置前评估表（建议建为多维表格）**
  * heading 二 has the numeral OUTSIDE the bold  二、**发布前评估表（建议建为多维表格）**
  * field name uses a half-width '(' and a full-width '）'
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SKELETON = json.load(open(os.path.join(HERE, "sop_form_skeleton.json"), encoding="utf-8"))

H1 = "**一、配置前评估表（建议建为多维表格）**"
H2 = "二、**发布前评估表（建议建为多维表格）**"
U1 = "用途：用于判断策略是否可以进入配置阶段，重点防止规则本身设计错误、对象理解错误和误伤风险未识别。"
U2 = ("用途：用于判断策略是否可以正式上线，重点防止"
      "“样本不足、观察不足、误伤未识别、未经审批扩范围”等问题。")

# Fields that must stay blank: they belong to the approver, not the analyst.
# A plausible invention here is a review failure, not a convenience.
ALWAYS_BLANK = {"leader审批人", "leader审批结论", "leader审批意见",
                "发布前评估结论", "上线后监控责任人"}


def _cell(v):
    """Escape a value for a Markdown table cell.

    The rule engine's OR operator is '||', which inside a table row reads as a column
    break and silently splits the row -- the template (docs/06) escapes pipes as '\\|'
    for exactly this reason. Newlines become <br>, as both source documents do.
    """
    return str(v).replace("|", "\\|").replace("\n", "<br>")


def _table(rows, values):
    out = ["|**字段名**|**字段类型**|**必填**|**填写说明 / 示例**|", "|---|---|---|---|"]
    for name, typ, req in rows:
        v = "" if name in ALWAYS_BLANK else _cell(values.get(name, ""))
        out.append(f"|{name}|{typ}|{req}|{v}|")
    return "\n".join(out)


def render(strategy_id, t1_values, t2_values, date="20260912"):
    t1_rows, t2_rows = SKELETON[0], SKELETON[1]
    missing = ([n for n, _, r in t1_rows if r == "是" and n not in ALWAYS_BLANK
                and not str(t1_values.get(n, "")).strip()]
               + [n for n, _, r in t2_rows if r == "是" and n not in ALWAYS_BLANK
                  and not str(t2_values.get(n, "")).strip()])
    body = f"""# {date}_审批_北美push场景策略上线审批_{strategy_id}

关联策略编号 {strategy_id}

{H1}

{U1}

{_table(t1_rows, t1_values)}

{H2}

{U2}

{_table(t2_rows, t2_values)}
"""
    return body, missing


def write(strategy_id, t1_values, t2_values, outdir, date="20260912"):
    body, missing = render(strategy_id, t1_values, t2_values, date)
    path = os.path.join(outdir, f"审批_北美push场景策略上线审批_{strategy_id}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    return path, missing
