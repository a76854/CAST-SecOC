# CAST-SecOC 公开补充数据

本目录提供由 Python 参考实现直接运行得到的、可复现的代表性功能记录。

## 数据边界

- 记录来自 Python 参考实现的直接执行。
- `HostElapsedNs` 和 `ReceiverTauNs` 描述生成记录时的主机运行耗时，不能作为目标 ECU 的实时性保证。
- 等价类消减只针对本目录披露的 125 条候选记录，不代表论文完整实验总体的消减日志。

## 目录内容

- `generate_observed_records.py`：使用固定输入生成并执行代表性场景。
- `config/config_snapshot.json`：匿名化消息和本次执行采用的 SecOC 配置。
- `data/selected_execution_records.csv`：逐条直接执行记录。
- `data/scenario_summary.csv`：由逐条记录计算得到的场景汇总。
- `data/equivalence_classes.csv`：候选向量、等价类和代表向量之间的逐条映射。
- `data/fixed_regression_set.csv`：每个等价类保留一条的确定性回归输入及预期响应。
- `data/mutants.csv`：三个受控配置变异的基准/变异对照和杀死判定。
- `metadata/run_metadata.json`：运行标识、执行环境、随机种子和源码哈希。

数据集包含 5 个匿名化消息和 5 类场景，每个“消息—场景”组合重复执行 5 次，共 125 条记录。

## 等价类消减

等价签名包含消息、场景、接收端状态、向量类型、扰动类型、配置哈希、需求编号和覆盖义务。
载荷内容、重复序号和输入种子不参与签名，因为这些字段在当前披露子集中不改变协议语义和
需求覆盖。每类保留最小 `VectorId`，125 条候选记录最终形成 25 个等价类和 25 条固定回归向量。

`equivalence_classes.csv` 中每行对应一条候选向量：

- `CandidateVectorId`：候选向量编号；
- `EquivalenceClassId`：所属等价类；
- `RepresentativeVectorId`：该类保留的代表；
- `Retained`：该候选是否被保留；
- `EquivalenceSignature`：可审查的等价条件；
- `CoverageObligations`：消息、状态、扰动和需求覆盖标签；
- `ReductionReason`：保留或消减原因。

## 固定回归集

`fixed_regression_set.csv` 保存 25 个代表向量。除状态、配置和扰动外，还保存：

- `PayloadHex`：确定性原始载荷；
- `WirePduHex`：施加扰动后送入接收端的完整线上 PDU；
- `Setup`、`FvLastBefore`：状态准备及接收端前置新鲜度值；
- `ExpectedAuth`、`ExpectedFreshness`、`ExpectedDelivery`：预期多维响应；
- `ExpectedResync`、`ExpectedStateUpdate`、`ExpectedError`：重同步、状态更新和错误预期；
- `ExpectedVerdict`：需求级最终判定。

## Mutant set

`mutants.csv` 包含：M1 回绕门控缺失、M2 认证器长度策略不符合、M3 密码上下文隔离不足。
每行记录变异目标、基准值、变异值、见证输入、基准和变异响应、是否等价以及是否被杀死。
M1、M3采用相同见证输入执行基准/变异对照；M2属于配置加载策略检查。

## 重新生成

在公开目录根目录执行：

```bash
python supplementary_disclosure/generate_observed_records.py
```

重新生成后，运行标识和主机耗时会发生变化；固定输入、等价类映射、回归集、协议响应和
mutant 判定应保持一致。
