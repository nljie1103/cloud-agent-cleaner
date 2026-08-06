# cloud-agent-cleaner


> This is an independent community project. It is not affiliated with or endorsed by any cloud provider. See [`NOTICE.md`](NOTICE.md).
A Linux tool to audit, explain, disable, and remove selected cloud-provider agents.

> Software inside a server should be visible, explainable, and optional whenever the platform permits it.

The project does **not** label every cloud agent as a backdoor. These agents often provide legitimate remote management, monitoring, security, deployment, provisioning, and recovery features. The goal is informed control: identify what is installed, explain its impact, and let the administrator choose what to keep.

## Supported providers

- Alibaba Cloud: Cloud Assistant, CloudMonitor, Security Center
- Tencent Cloud: TAT, BaradAgent/Sgagent, YunJing
- AWS: SSM, CloudWatch, CodeDeploy, Inspector Classic
- Oracle Cloud: Oracle Cloud Agent, Management Agent, Workload Protection
- Azure: Linux Agent, Azure Monitor Agent
- Google Cloud: Guest Agent, Ops Agent

The registry currently covers **17 agent classes across 6 providers**.

## Safety properties

- Audit-only by default.
- Exact package, service, process, and path identifiers.
- No `curl | bash`, `wget | sh`, `shell=True`, or broad cloud-name deletion.
- Vendor downloads are disabled by default and limited to HTTPS, a 5 MiB maximum, basic text validation, and SHA-256 reporting.
- Core guest agents require `--include-core` and an additional confirmation token.
- `cloud-init`, `qemu-guest-agent`, device drivers, repositories, and unknown software are intentionally excluded.
- Python standard library only.

## Quick start

```bash
python3 cloud_agent_cleaner.py --list-agents
python3 cloud_agent_cleaner.py --audit
python3 cloud_agent_cleaner.py --all --dry-run
sudo python3 cloud_agent_cleaner.py --all
```

Select exact agents:

```bash
sudo python3 cloud_agent_cleaner.py \
  --remove \
  --agent aws.ssm,aws.cloudwatch
```

Core agents are protected:

```bash
sudo python3 cloud_agent_cleaner.py \
  --remove \
  --agent gcp.guest-agent \
  --include-core
```

## Scope boundary

Removing software from the guest OS does not remove the cloud provider's control of the hypervisor, virtual networking, storage, snapshots, or instance lifecycle. It also does not prove that a provider was maliciously monitoring the server. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## License

MIT License.
