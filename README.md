<div align="center">

# ☁️ Cloud Agent Cleaner

### 自动检测并清理云服务器预装 Agent

支持阿里云、腾讯云、AWS、Oracle Cloud、Microsoft Azure 与 Google Cloud

[![Version](https://img.shields.io/badge/version-2.0.1--alpha.1-orange)](CHANGELOG.md)
[![Tests](https://github.com/nljie1103/cloud-agent-cleaner/actions/workflows/test.yml/badge.svg)](https://github.com/nljie1103/cloud-agent-cleaner/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[中文](README.md) · [English](README_EN.md) · [支持矩阵](docs/AGENT_MATRIX.md) · [安全政策](SECURITY.md)

</div>

## 一键使用

复制到 Linux 服务器执行：

```bash
curl -fsSLo /tmp/cloud-agent-cleaner.sh https://raw.githubusercontent.com/nljie1103/cloud-agent-cleaner/main/quick-run.sh && sudo bash /tmp/cloud-agent-cleaner.sh
```

程序会自动：

1. 判断当前服务器环境；
2. 检测已安装的云厂商 Agent；
3. 显示组件名称、用途和清除影响；
4. 提示阿里云安全中心、Azure 扩展等控制台前置条件；
5. 自动保护核心 Guest Agent；
6. 等待输入 `y`，然后清除检测到的可选组件；
7. 完成后再次检查残留并输出日志。

## 支持范围

| 云平台 | 当前支持的组件 |
|---|---|
| 阿里云 | 云助手、云监控、云安全中心 |
| 腾讯云 | TAT、BaradAgent/Sgagent、YunJing |
| AWS | SSM、CloudWatch、CodeDeploy、Inspector Classic |
| Oracle Cloud | Cloud Agent、Management Agent、Workload Protection |
| Microsoft Azure | Linux Agent、Azure Monitor Agent |
| Google Cloud | Guest Agent、Ops Agent |

## 自动保护

以下核心组件可能参与 SSH、账号、网络、扩展、初始化或故障恢复，一键模式只提示，不会删除：

```text
oracle.cloud-agent
azure.linux-agent
gcp.guest-agent
```

`cloud-init`、`qemu-guest-agent`、VirtIO、ENA、NVMe 驱动和未知软件也不会处理。

## 控制台前置条件

检测到相关组件时，程序会在确认前直接提示：

- **阿里云安全中心**：先在控制台关闭“客户端自保护”和“恶意主机行为防御”；输入 `y` 后会下载阿里云官方 HTTPS 卸载脚本，并在日志中记录来源与 SHA-256。
- **腾讯云 TAT**：本机没有卸载脚本时，输入 `y` 后会从腾讯官方 GitHub 下载卸载脚本，并记录来源与 SHA-256。
- **Azure Monitor Agent**：若由 VM、VMSS 或 Arc 扩展管理，还需从 Azure Portal 或 Azure CLI 删除 `AzureMonitorLinuxAgent` 扩展。
- **自动重装策略**：云控制台策略、扩展、初始化脚本或镜像规则可能重新安装已删除的 Agent。

## 高级命令

```bash
python3 cloud_agent_cleaner.py --audit                  # 只检测，不修改
sudo python3 cloud_agent_cleaner.py --all --dry-run    # 预演全部可选组件
sudo python3 cloud_agent_cleaner.py --provider aliyun  # 清除指定平台
sudo python3 cloud_agent_cleaner.py --agent aws.ssm    # 清除指定组件
python3 cloud_agent_cleaner.py --list-agents           # 查看完整支持清单
```

直接运行入口文件也会进入一键交互模式：

```bash
sudo python3 cloud_agent_cleaner.py
```

## 执行前建议

生产服务器至少保留系统盘快照，以及 VNC、串口控制台或其他独立救援入口。删除安全 Agent 可能降低主机防护能力；删除 Guest OS 内的 Agent 也不能改变云厂商对宿主机、网络、云盘和控制面的管理权限。

## 项目文档

- [Agent 支持矩阵](docs/AGENT_MATRIX.md)
- [官方资料来源](docs/SOURCES.md)
- [验证状态](docs/VALIDATION.md)
- [威胁模型与能力边界](docs/THREAT_MODEL.md)
- [更新日志](CHANGELOG.md)
- [安全政策](SECURITY.md)

## 许可证与声明

本项目使用 [MIT License](LICENSE)，是独立社区项目，与各云服务商不存在隶属、赞助、认证或背书关系。产品名称与商标仅用于说明兼容性，权利归各自所有者。
