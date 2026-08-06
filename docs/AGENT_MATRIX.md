# Agent 支持矩阵

| Agent ID | 平台 | 类别 | 风险 | 检测 | 禁用 | 卸载 | 主要注意事项 |
|---|---|---:|---:|---:|---:|---:|---|
| `aliyun.assistant` | 阿里云 | 远程运维 | 可选 | 是 | 是 | 是 | 会影响云助手、会话管理、Workbench/OOS 等能力 |
| `aliyun.monitor` | 阿里云 | 监控 | 可选 | 是 | 是 | 是 | 兼容 C++、旧版 Java，并按官方顺序处理 Go 版 `CmsGoAgent.linux-*` |
| `aliyun.security` | 阿里云 | 安全 | 可选 | 是 | 部分 | 官方脚本 | 必须先在控制台关闭自保护与恶意主机行为防御 |
| `tencent.tat` | 腾讯云 | 远程运维 | 可选 | 是 | 是 | 本地/官方脚本 | 默认不下载厂商脚本 |
| `tencent.monitor` | 腾讯云 | 监控 | 可选 | 是 | 是 | 是 | 同时处理 Sgagent 与 BaradAgent，避免自动拉起 |
| `tencent.security` | 腾讯云 | 安全 | 可选 | 是 | 是 | 本地脚本 | 找不到官方本地卸载器时拒绝直接删目录 |
| `aws.ssm` | AWS | 远程运维 | 可选 | 是 | 是 | 是 | 兼容软件包与 Snap |
| `aws.cloudwatch` | AWS | 监控/日志 | 可选 | 是 | 是 | 是 | 停止 CloudWatch guest metrics/logs |
| `aws.codedeploy` | AWS | 部署 | 可选 | 是 | 是 | 是 | 后续 CodeDeploy 部署会失败 |
| `aws.inspector-classic` | AWS | 安全 | 可选 | 是 | 是 | 是 | 只覆盖旧版 Inspector Classic Agent |
| `oracle.cloud-agent` | OCI | 核心插件宿主 | 核心 | 是 | 是 | 是 | 默认保护；插件、监控、OS 管理、Bastion 等可能失效 |
| `oracle.management-agent` | OCI | 管理/监控 | 可选 | 是 | 是 | 是 | 优先使用官方本地 `uninstaller.sh` 完成云端注销 |
| `oracle.workload-protection` | OCI | 安全 | 可选 | 是 | 是 | 是 | Cloud Guard 工作负载保护可能停止 |
| `azure.linux-agent` | Azure | 预配/扩展 | 核心 | 是 | 是 | 是 | 默认保护；先移除扩展并在控制面禁用扩展操作 |
| `azure.monitor-agent` | Azure | 监控/日志 | 可选 | 是 | 是 | 有条件 | 独立软件包可本地卸载；VM 扩展必须在 Azure 控制面删除，工具会返回未完成 |
| `gcp.guest-agent` | GCP | 账号/SSH/网络 | 核心 | 是 | 是 | 是 | 默认保护；兼容旧服务及 2025+ manager/compat manager/core plugin 架构 |
| `gcp.ops-agent` | GCP | 监控/日志 | 可选 | 是 | 是 | 是 | 停止 Cloud Monitoring/Logging 客机数据 |

## “可选”和“核心”的含义

- **可选**：一般不会影响虚拟机本身开机和基础网络，但会影响对应云服务能力。
- **核心**：可能参与预配、SSH、账号、网络、扩展或插件机制。错误处理可能导致失联或难以恢复。

风险标签不是厂商安全评级，也不表示组件是否可信；它只描述本项目执行卸载时的运维风险。

## 验证等级

“卸载：是”表示代码会调用厂商本地卸载器或系统包管理器执行真实删除，不表示已覆盖每个发行版和所有历史版本。`有条件` 表示完整卸载依赖云控制面、厂商自保护开关或本地卸载器是否存在。当前发布等级为 alpha。
