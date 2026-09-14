# CAST-SecOC 最小披露材料

本目录用于支持论文中 Python 参考原型的功能实验来源核验。

## 证据边界

- 被测对象：CAST-SecOC Python 参考原型。
- 可支持的结论：所披露功能记录来自 Python 程序的实际执行；配置、输入摘要、响应、判定和运行环境可以关联核验。
- 不支持的结论：这些记录不是嵌入式 C 实现、AUTOSAR 商业栈或 TC397 开发板的实测结果。
- `HostElapsedNs` 是运行 Python 原型时观察到的主机墙钟时间，只用于记录本次执行，不用于评价目标 ECU 实时性。
- 本包不包含仓库中已有的 TC397 参数化合成时延文件。

## 目录内容

- `generate_observed_records.py`：固定输入并执行代表性测试的生成程序。
- `config/config_snapshot.json`：本次披露使用的匿名化消息和 SecOC 配置。
- `code/selected_core_excerpts.txt`：从实际执行版本导出的关键函数原文及原文件哈希。
- `data/selected_execution_records.csv`：逐条直接执行记录。
- `data/scenario_summary.csv`：由逐条记录计算的场景汇总。
- `metadata/run_metadata.json`：运行时间、解释器、平台、种子和数据性质。
- `MANIFEST.sha256`：除自身外所有披露文件的 SHA-256。

## 数据规模

材料覆盖 5 类匿名化消息，每类消息执行以下 5 个场景，每个组合重复 5 次，共 125 条：

1. 合法基准通信；
2. 受认证区域内载荷篡改；
3. 全零认证器伪造；
4. 已接收报文重放；
5. 严格策略下的 FV 回绕候选。

该数据是代表性披露子集，不应替代论文对完整实验总体、抽样规则和样本数量的说明。

## 重新生成

在仓库根目录执行：

```bash
.venv/bin/python supplementary_disclosure_A/generate_observed_records.py
```

脚本会覆盖本目录内的配置快照、代码摘录、数据、元数据和哈希清单。重新执行会获得新的
`RunId` 和主机耗时；固定测试输入、协议响应和判定应保持一致。

## 脱敏说明

PDU-A 至 PDU-E、CAN ID、DataID、ECU 名称和测试密钥均属于公开原型中的匿名化测试值，
不得解释为量产车型资产或生产密钥。测试密钥只记录其指纹，不写入逐条数据。
