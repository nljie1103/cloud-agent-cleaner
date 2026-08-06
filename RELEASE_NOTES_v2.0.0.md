# cloud-agent-cleaner v2.0.0

> **Superseded:** This release is retained for historical reference. Use `2.0.1-alpha.1` or later; it corrects platform-specific removal claims and behavior.

首个跨云版本。

## 亮点

- 6 个云平台、17 类 Linux Agent
- 单文件 Python 核心工具，零第三方依赖
- 默认只审计
- 精确禁用或卸载
- 核心 Guest Agent 双重保护
- `--dry-run`、TSV 报告、日志、变更前清单和事后复查
- 不使用远程管道执行

## 升级说明

旧版 `aliyun-agent-remover` 用户请不要覆盖执行。将本版本作为新项目下载，先运行：

```bash
python3 cloud_agent_cleaner.py --audit
python3 cloud_agent_cleaner.py --all --dry-run
```

生产服务器应先创建快照并保留独立控制台入口。
