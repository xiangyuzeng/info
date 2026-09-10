# LKUS 短信攻击分析 —— 任务包文档

本仓库存放 LKUS 短信（OTP）黑产攻击分析任务的随附文档，供 Claude Code 或其他分析工具直接读取。

所有文件均为 Markdown，可在 GitHub 上直接阅读。

## 文档索引

| # | 文件 | 内容 |
|---|---|---|
| 00 | [附件清单 README](docs/00_附件清单_README.md) | 任务包总说明：目录结构、各文件用途、已知截断、Phase 0 待补材料 |
| 01 | [090926 短信分析 strategy_ARqkLD7E3JaK](docs/01_090926短信分析_strategy_ARqkLD7E3JaK.md) | 待评估策略的 6 小时评估原文，九项口径 |
| 02 | [风控策略运营 SOP（执行版 0729）](docs/02_风控策略运营SOP-执行版0729.md) | 上线门槛与黑产评估的制度依据，发布前评估分级标准 |
| 03 | [090426 短信黑产攻击行为初步分析与结论](docs/03_090426短信黑产攻击行为初步分析与结论.md) | 120 天历史基线 + 已有 SQL，国家对分布 |
| 04 | [last24hr 数据字典与基线](docs/04_last24hr_数据字典与基线.md) | 对账基准与词汇表，九项指标 24h 重算值，策略/特征全集 |
| 05 | [监控与运营证据（数值转录）](docs/05_监控与运营证据_数值转录.md) | Grafana 总量、upush 日发送量等数据库中查不到的数字 |

## 使用说明

- 建议将本仓库内容放入分析工作目录的 `docs/` 下，与任务书 `TASK.md` 并列。
- 原始数据集 `last24hr.xlsx`（约 103 MB）**不在本仓库内**，需自行放入 `data/`。
- 上述 `.md` 由 Feishu 纯截图 PDF 经 OCR + 人工核对得出，数字已逐个对照原图校验；如需引用原文措辞或补齐截断部分，请回 Feishu 原文。

## 注意事项

- `04` 与 `05` 中的数字全部来自 24 小时快照或大盘截图，**不能当作长期结论**；正式报告的每个数字都应从数据库重算。
- 对外报告中手机号需脱敏（保留区号 + 前 3 位），IP 不写全段。

## 分析产出（2026-09-10）

| 目录 | 内容 |
|---|---|
| [`out/`](out/) | 9 份报告 + `summary.md` 一页纸 |
| [`out/charts/`](out/charts/) | 7 张图 |
| [`out/data/`](out/data/) | 每个数字背后的表（CSV），报告里的数都能在这里追溯 |
| [`sms_attack/`](sms_attack/) | 可复跑管道：`python -m sms_attack.evaluate --strategy <id> --window 5h` |

先看 [`out/summary.md`](out/summary.md)，再看 [`out/07_群消息.md`](out/07_群消息.md)（可直接粘贴到群里）。

> 报告中手机号已脱敏（保留区号+前 3 位），IP 不写全段；原始数据不在本仓库。

## 公开摘要（可对外分享）

脱敏后可对外分享的摘要统一放在 [`public-summaries/`](public-summaries/)：

| 文件 | 内容 |
|---|---|
| [LKUS 拦截策略公开摘要 2026-09-10](public-summaries/LKUS-blocking-strategies-public-summary-20260910.md) | 4 条拦截策略 + 1 项阈值调整 + 2 项风控之外措施的评估结果、回测证据、上线流程与回滚原则 |
| [北美 push 场景策略上线审批公开摘要 2026-08-31](public-summaries/NA-push-rollout-approval-public-summary-20260831.md) | 28 条策略的上线审批台账：评估表字段体系、审批结论分布、评审中反复出现的质量问题 |

> 这两份是内部受控文档的**脱敏公开摘要**。规则原文、阈值数值、特征字段名、
> 区号名单、告警阈值、已知绕过路径、上线时间点与人员姓名等均未公开。
> 脱敏口径见 [`public-summaries/README.md`](public-summaries/README.md)。
