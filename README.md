# CAST-SecOC 公开参考实现

本目录包含 CAST-SecOC 的纯 Python SecOC 参考实现、可重复执行的功能与安全测试场景，以及一组由参考实现直接生成的运行记录。

## 内容边界

- 本实现演示报文认证、截断新鲜度值处理、接收窗口检查、回绕门控、重放拒绝和密码上下文隔离。
- 消息标识、ECU 名称、配置值和密钥均为匿名化测试值。
- `cast_secoc.main` 生成的 TC397 时延数据来自参数化合成模型，不是嵌入式硬件实测数据。
- 功能场景的时限判定采用固定 1 ms 处理时间与带固定种子的 CAN FD 排队模型，因此场景判定可以跨主机复现。
- CAN FD 排队模型是简化的随机模型，不等同于完整的 CAN 仲裁过程或 AUTOSAR 协议栈。

## 运行环境

需要 Python 3.10 或更高版本，无第三方运行时依赖。

## 运行完整场景集

在本目录执行：

```bash
python -m cast_secoc.main --output-dir results
```

该命令执行 2,000 条测试向量，并在指定输出目录中生成 `results.json`、`timing.json` 和 `timing.csv`。

如需查看命令行选项而不启动实验，请执行：

```bash
python -m cast_secoc.main --help
```

## 重新生成直接观测记录

```bash
python supplementary_disclosure/generate_observed_records.py
```

该命令会重新生成直接执行记录、等价类映射、固定回归集、mutant set、配置快照和运行元数据。
固定输入和协议判定结果可以复现；运行标识和主机墙钟耗时会随执行时间与环境变化。

## 目录结构

- `cast_secoc/`：协议模型、场景生成、需求判定和命令行入口。
- `supplementary_disclosure/`：直接观测记录、配置快照、运行元数据及生成程序。
