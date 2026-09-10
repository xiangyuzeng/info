# sms_attack — LKUS 短信（OTP）黑产攻击分析管道

可复跑的取数 → 打标 → 评估 → 出报告管道。田志鲔每配一条新策略，跑一条命令就能出同口径评估。

## 快速开始

```bash
pip install --break-system-packages pandas pyarrow matplotlib phonenumbers tabulate

# 网关地址不硬编码在代码里，运行前先设置（内网地址找 DBA 要）
export MCP_DB_GATEWAY_SSE="http://<mcp-db-gateway-host>:8080/sse"

# 1. 取数（64 分片全量拉取，约 11 分钟，输出 data/risk_log.parquet）
python -m sms_attack.extract --from 2026-08-09 --to 2026-09-11

# 2. 打标（SOP §3.7 黑产分级，输出 data/risk_labeled.parquet）
python -c "from sms_attack.common import load_risk; from sms_attack.label import add_evidence; \
import pandas as pd; \
add_evidence(load_risk(), otp=pd.read_csv('data/otp_filled.csv'), \
             uid_scenes=pd.read_csv('data/uid_scenes.csv')).to_parquet('data/risk_labeled.parquet')"

# 3. 评估任意一条策略（这是最常用的一条命令）
python -m sms_attack.evaluate --strategy strategy_ARqkLD7E3JaK --window 5h
python -m sms_attack.evaluate --strategy strategy_MGj5bfGOijOi --window 24h

# 4. 生成全部报告与图表
python -m sms_attack.report
python -m sms_attack.charts
```

`--window` 接受 `5h` / `24h` / `7d`；`--end` 可指定窗口右端（UTC ISO），默认取数据最新时间。

## 模块

| 文件 | 职责 |
|---|---|
| `mcp_client.py` | MCP-over-SSE 客户端，直连 `mcp-db-gateway`。长 SQL 从文件读、结果直接落盘，绕开工具调用的结果体积限制 |
| `extract.py` | 64 分片 `t_access_log_0000..0063` 全量拉取，JSON 在服务端摊平 |
| `common.py` | **所有口径定义的唯一来源**（区号分组/IP国家分组/token 分桶/特征映射）。改口径只改这里 |
| `countries.py` | 区号 → 中文国家名（region code 取自 `phonenumbers`，非手写猜测） |
| `label.py` | SOP §3.7 黑产分级，≥2 类独立特征交叉印证 |
| `evaluate.py` | David 九项模板 + SOP 发布前评估门槛 |
| `figures.py` | 所有对外数字在此计算一次，同时落 `out/data/*.csv`，保证报告与群消息数字一致 |
| `report.py` | 渲染 `out/*.md` |
| `charts.py` | 渲染 `out/charts/*.png` |
| `sql/` | 全部 SQL 模板 |

## 取数设计要点

- **风控日志按 Sharding-JDBC 分成 64 张表**，一个窗口 = 64 次查询。全量约 7.7k 行/天，直接全拉不抽样。
- **JSON 在服务端摊平**：`response_strategy_engine` 单行约 24KB，全量拉原文是 GB 级。
  用 `JSON_TABLE` 在服务端提取需要的字段，只把标量传回来。
- **`request_strategy_engine.para` 是双重编码的 JSON 字符串**，要 `CAST(JSON_UNQUOTE(JSON_EXTRACT(...)) AS JSON)`。
- **召回/漏召回不需要重实现规则**：预上线策略的命中被引擎逐条写进 `hitPreOnlineStrategy`，
  直接读即可得到"它本可以拦下多少"。

## 三个必须知道的坑

1. **特征名会变。** `reCAPTCHA V3 token是否有效` 在 2026-08-27 ~ 09-05 期间被改名为 `reCAPTCHA V3风险分`
   （09-06/07 两个名字并存，09-08 改回）。同期 `一分钟请求量`↔`一小时请求量`、
   `同IP近5分钟的访问次数`↔`同IP近10分钟的访问次数` 也发生了替换。
   **按字面名字取特征会静默丢掉整段数据，且长得和"reCAPTCHA 故障"一模一样。**
   本管道按"结构"取分（apiResp 能解析成含 `riskAnalysis.score` 的 JSON 对象），不按名字取。
2. **网关会把含 `REPLACE(` 的 SELECT 判成写操作**并拒绝（`Permission denied for operation`）。
   用 `TRIM(LEADING '+' FROM ...)` 之类替代。
3. **`t_sent_verifycode_sms.sent_time` 全为 NULL**，要用 `create_time`；`mobile` 是密文，
   关联手机号只能靠 `mask_no`（区号+首位+`*****`+后4位）+ ±2 分钟时间窗。

## 安全

- 全程只读。不修改任何 RMS 策略、名单或配置——只提建议，不落配置。
- `data/` 含未脱敏手机号与完整 IP，已在 `.gitignore` 中，**不进仓库**。
- `out/` 中手机号一律脱敏（区号+前3位），IP 不写全段。
