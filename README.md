<div align="center">

# ☁️ Cloud Agent Cleaner

### 看见、理解并自主控制云服务器中的高权限 Agent

跨云 Linux Agent 审计、解释、禁用与卸载工具  
支持阿里云、腾讯云、AWS、Oracle Cloud、Microsoft Azure 与 Google Cloud

[![Version](https://img.shields.io/badge/version-2.0.1--alpha.1-orange)](CHANGELOG.md)
[![Tests](https://github.com/nljie1103/cloud-agent-cleaner/actions/workflows/test.yml/badge.svg)](https://github.com/nljie1103/cloud-agent-cleaner/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platforms](https://img.shields.io/badge/clouds-6-blue)](#支持范围)
[![Agents](https://img.shields.io/badge/agents-17-blueviolet)](docs/AGENT_MATRIX.md)

[中文](README.md) · [English](README_EN.md) · [支持矩阵](docs/AGENT_MATRIX.md) · [验证状态](docs/VALIDATION.md) · [安全政策](SECURITY.md)

> **主机内的软件应当可见、可解释、可选择。**

</div>

---

## 为什么需要它？

很多云服务器镜像会预装云助手、监控、安全防护、部署与 Guest Agent。它们通常承担远程命令、指标采集、补丁管理、故障诊断、账号配置或扩展管理等合法功能，但也可能以高权限长期运行，并持续连接云厂商服务。

`cloud-agent-cleaner` 帮助管理员回答四个问题：

1. 服务器里安装了哪些云 Agent？
2. 它们属于监控、安全、远程运维还是核心 Guest Agent？
3. 停用或卸载后会失去哪些能力？
4. 哪些可以在本机完整卸载，哪些还必须从云控制面移除？

本项目不会把所有云 Agent 一概描述为“后门”，也不会承诺让云厂商失去对宿主机、虚拟网络、云盘或控制面的管理能力。

## 核心特性

| 能力 | 说明 |
|---|---|
| 🔎 默认只审计 | 不带修改参数时不会更改系统 |
| 🧭 跨云识别 | 覆盖 6 个平台、17 类 Agent |
| 🎯 精确操作 | 可按平台、类别或 Agent ID 选择 |
| 🧪 安全预演 | `--dry-run` 展示将执行的操作 |
| 🛡️ 核心保护 | 核心 Guest Agent 默认不可被 `--all` 修改 |
| 📦 正规卸载 | 优先调用厂商卸载器或系统包管理器 |
| 🔐 下载防护 | 禁止 `curl \| bash`，远程脚本需显式许可和哈希确认 |
| 🧾 可追溯 | 生成日志、主机清单和卸载后复查结果 |
| 🐍 零第三方依赖 | 单文件 Python 工具，仅使用标准库 |

## 支持范围

| 云平台 | 当前支持的 Agent |
|---|---|
| 阿里云 | 云助手、云监控、云安全中心 |
| 腾讯云 | 自动化助手 TAT、BaradAgent/Sgagent、主机安全 YunJing |
| AWS | SSM Agent、CloudWatch Agent、CodeDeploy Agent、Inspector Classic Agent |
| Oracle Cloud | Oracle Cloud Agent、Management Agent、Workload Protection Agent |
| Microsoft Azure | Azure Linux Agent、Azure Monitor Agent |
| Google Cloud | Guest Agent、Ops Agent |

> 当前版本为 **Alpha 测试版**。脚本包含真实卸载实现，但尚未覆盖所有 Linux 发行版、镜像年代和历史 Agent 版本。完整状态见 [验证状态](docs/VALIDATION.md)。

## 快速开始

### 1. 获取项目

```bash
git clone https://github.com/nljie1103/cloud-agent-cleaner.git
cd cloud-agent-cleaner
```

### 2. 查看支持清单

```bash
python3 cloud_agent_cleaner.py --list-agents
```

### 3. 审计当前服务器

```bash
python3 cloud_agent_cleaner.py --audit
```

生成 TSV 报告：

```bash
python3 cloud_agent_cleaner.py \
  --audit \
  --report ./cloud-agent-audit.tsv
```

### 4. 预演卸载

```bash
sudo python3 cloud_agent_cleaner.py --all --dry-run
```

### 5. 执行精确卸载

卸载指定 Agent：

```bash
sudo python3 cloud_agent_cleaner.py \
  --remove \
  --agent aws.ssm,aws.cloudwatch
```

卸载指定平台中检测到的可选 Agent：

```bash
sudo python3 cloud_agent_cleaner.py \
  --remove \
  --provider aliyun
```

卸载所有检测到的**可选 Agent**：

```bash
sudo python3 cloud_agent_cleaner.py --all
```

仅停止并禁用，不卸载：

```bash
sudo python3 cloud_agent_cleaner.py \
  --disable \
  --category monitoring
```

## ⚠️ 生产环境执行前

至少完成以下准备：

- 创建最新系统盘快照；
- 确认普通 SSH 之外还有 VNC、串口控制台或其他救援入口；
- 先运行 `--audit` 和 `--dry-run`；
- 阅读目标 Agent 的影响说明；
- 确认云控制面不会自动重新安装该 Agent；
- 不要在尚未验证的关键生产机器上直接运行 `--all --yes`。

## 核心 Guest Agent 保护

以下组件可能参与账号、SSH、网络、扩展、插件、初始化或故障恢复：

```text
oracle.cloud-agent
azure.linux-agent
gcp.guest-agent
```

它们不会被普通 `--all` 操作处理。确实需要修改时，必须精确指定并添加 `--include-core`：

```bash
sudo python3 cloud_agent_cleaner.py \
  --remove \
  --agent azure.linux-agent \
  --include-core
```

工具还会要求输入：

```text
APPLY-CORE
```

## 本机卸载与云控制面边界

并非所有组件都能只在虚拟机内部完成完整卸载。例如 Azure Monitor Agent 常由 `AzureMonitorLinuxAgent` VM 扩展管理。此时工具会：

- 停止本地服务；
- 识别扩展状态；
- 输出对应 Azure VM、VMSS 或 Arc 控制面命令；
- 将结果标记为“未完整卸载”；
- 不用删除本地目录冒充成功。

GCP Guest Agent 从 `20250901.00` 起逐步采用插件化架构。本项目同时识别旧版单体服务与 manager、compat manager、core plugin 架构，但仍将其视为核心组件并默认保护。

## 厂商脚本安全策略

部分厂商官方流程依赖动态下载卸载脚本，例如阿里云安全中心和腾讯云 TAT。项目默认拒绝下载和执行远程脚本。

显式允许 HTTPS 厂商脚本：

```bash
sudo python3 cloud_agent_cleaner.py \
  --remove \
  --agent tencent.tat \
  --allow-vendor-downloads
```

工具会先保存文件、检查内容、限制大小并输出 SHA-256。无人值守模式还必须固定预期哈希：

```bash
sudo python3 cloud_agent_cleaner.py \
  --remove \
  --agent tencent.tat \
  --allow-vendor-downloads \
  --vendor-sha256 tencent.tat=<64位SHA256> \
  --yes
```

阿里云安全中心卸载前，还必须先在控制台关闭“客户端自保护”和“恶意主机行为防御”；本项目不会尝试绕过自保护。

## 日志与修改前清单

| 内容 | 默认位置 |
|---|---|
| Root 执行日志 | `/var/log/cloud-agent-cleaner-*.log` |
| 普通用户审计日志 | 系统临时目录 |
| 修改前清单 | `/var/backups/cloud-agent-cleaner/<时间>/manifest.txt` |

修改前清单不是完整备份，不能替代云盘快照。

## 有意不处理的组件

为避免误伤系统启动、网络和磁盘能力，本项目有意排除：

- `cloud-init`
- `qemu-guest-agent`
- VirtIO、ENA、NVMe 等驱动
- 云厂商软件源
- 无法准确识别的未知软件
- 未列入支持矩阵的日志、数据库或应用性能 Agent

## 能力边界

卸载 Guest OS 内的 Agent，只能减少这些程序在虚拟机内部的常驻运行、远程管理入口和遥测。它不能改变：

- 云厂商对物理主机和虚拟化层的控制；
- 实例启停、网络、安全组、磁盘和快照的控制面能力；
- 宿主机侧基础资源指标采集；
- 镜像初始化、扩展策略或自动化规则重新部署 Agent 的可能性。

删除安全 Agent 也可能降低主机防护能力，并不等于自动提高整体安全性。详见 [威胁模型与能力边界](docs/THREAT_MODEL.md)。

## 文档导航

- [Agent 支持矩阵](docs/AGENT_MATRIX.md)
- [官方资料来源](docs/SOURCES.md)
- [验证状态](docs/VALIDATION.md)
- [威胁模型与能力边界](docs/THREAT_MODEL.md)
- [更新日志](CHANGELOG.md)
- [安全政策](SECURITY.md)
- [参与贡献](CONTRIBUTING.md)
- [独立项目与商标声明](NOTICE.md)

## 项目状态

当前版本：**`2.0.1-alpha.1`**

本项目处于公开 Alpha 测试阶段。欢迎提交不同云平台、Linux 发行版和 Agent 版本的审计结果、脱敏日志、问题报告与修复建议。

## 许可证与声明

本项目使用 [MIT License](LICENSE)。

`cloud-agent-cleaner` 是独立社区项目，与阿里云、腾讯云、Amazon Web Services、Oracle、Microsoft、Google 或其他云服务商不存在隶属、赞助、认证或背书关系。产品名称与商标仅用于说明兼容性，权利归各自所有者。详见 [NOTICE.md](NOTICE.md)。

---

<div align="center">

**在删除之前，先看见；在执行之前，先理解。**

</div>
