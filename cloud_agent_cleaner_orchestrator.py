from cloud_agent_cleaner_common import *
from cloud_agent_cleaner_detection import *
from cloud_agent_cleaner_change import *
from cloud_agent_cleaner_actions_cloud1 import *
from cloud_agent_cleaner_actions_cloud2 import *

ACTIONS: Dict[str, Callable[[Context], None]] = {
    "aliyun.assistant": act_aliyun_assistant,
    "aliyun.monitor": act_aliyun_monitor,
    "aliyun.security": act_aliyun_security,
    "tencent.tat": act_tencent_tat,
    "tencent.monitor": act_tencent_monitor,
    "tencent.security": act_tencent_security,
    "aws.ssm": act_aws_ssm,
    "aws.cloudwatch": act_aws_cloudwatch,
    "aws.codedeploy": act_aws_codedeploy,
    "aws.inspector-classic": act_aws_inspector,
    "oracle.cloud-agent": act_oracle_cloud_agent,
    "oracle.management-agent": act_oracle_management,
    "oracle.workload-protection": act_oracle_workload,
    "azure.linux-agent": act_azure_linux_agent,
    "azure.monitor-agent": act_azure_monitor,
    "gcp.guest-agent": act_gcp_guest_agent,
    "gcp.ops-agent": act_gcp_ops_agent,
}

CONTROL_PLANE_NOTICES: Dict[str, str] = {
    "aliyun.security": (
        "阿里云安全中心：请先在控制台关闭“客户端自保护”和“恶意主机行为防御”；"
        "否则本机卸载可能被拦截。输入 y 后程序会下载阿里云官方 HTTPS 卸载脚本并记录 SHA-256。"
    ),
    "tencent.tat": (
        "腾讯云 TAT：若服务器内没有本地卸载脚本，输入 y 后程序会从腾讯官方 GitHub 下载卸载脚本并记录 SHA-256。"
    ),
    "azure.monitor-agent": (
        "Azure Monitor Agent：若由 AzureMonitorLinuxAgent VM/VMSS/Arc 扩展管理，"
        "还需在 Azure Portal 或 Azure CLI 删除对应扩展，本机操作会标记为未完整卸载。"
    ),
}


def reload_systemd(ctx: Context) -> None:
    if command_exists("systemctl"):
        ctx.runner.run(["systemctl", "daemon-reload"], check=False)
        ctx.runner.run(["systemctl", "reset-failed"], check=False)


AEGIS_PROCESS_PATTERN = (
    r"\b(AliYunDun|AliYunDunMonitor|AliYunDunUpdate|AliSecGuard|"
    r"AlibabaSecurityAegis|AliSecCheck|AliSecureCheckAdvanced|AliDetect|"
    r"AliNet|AliHips|AliWebGuard)\b"
)


def cleanup_inactive_aegis_residuals(ctx: Context) -> None:
    """Remove the exact Aegis home only after all known Aegis activity is gone."""
    home = Path("/usr/local/aegis")
    if not home.exists():
        return

    active = active_agent_evidence("aliyun.security")
    if process_matches(AEGIS_PROCESS_PATTERN):
        active.append("matching-current-aegis-process")

    if active:
        ctx.reporter.log(
            "WARN",
            "aliyun.security still has active service/process evidence; "
            "refusing residual directory cleanup: " + "; ".join(sorted(set(active))),
        )
        return

    if home.is_symlink() or not home.is_dir():
        ctx.reporter.log(
            "ERROR",
            f"Refusing to recursively remove unexpected Aegis path type: {home}",
        )
        return

    try:
        shutil.rmtree(home)
    except OSError as exc:
        ctx.reporter.log("ERROR", f"Could not remove inactive Aegis residual directory {home}: {exc}")
        return

    ctx.reporter.log("OK", f"Removed inactive Aegis residual directory: {home}")


def execute_changes(ctx: Context, findings: Dict[str, List[str]]) -> None:
    candidates = [agent for agent in selected_agents(ctx.args, for_change=True) if findings.get(agent.agent_id)]
    if not candidates:
        ctx.reporter.log("INFO", "No detected optional agents match the change selectors.")
        protected = [agent for agent in AGENTS if agent.risk == "core" and findings.get(agent.agent_id)]
        if protected:
            print("\n检测到以下核心 Guest Agent，已自动保护并跳过：")
            for agent in protected:
                print(f"  - {agent.agent_id}  {agent.name}")
        return

    print("\n将清除以下检测到的可选组件：")
    for agent in candidates:
        print(f"  - {agent.agent_id}  {agent.name}")
        print(f"    影响：{agent.impact}")

    protected = [agent for agent in AGENTS if agent.risk == "core" and findings.get(agent.agent_id)]
    if protected:
        print("\n以下核心 Guest Agent 已自动保护，不会清除：")
        for agent in protected:
            print(f"  - {agent.agent_id}  {agent.name}")

    notices = [CONTROL_PLANE_NOTICES[agent.agent_id] for agent in candidates if agent.agent_id in CONTROL_PLANE_NOTICES]
    if notices:
        print("\n清除前需要处理：")
        for notice in notices:
            print(f"  ! {notice}")
    print("\n提示：云控制台策略、扩展或初始化规则可能重新安装这些组件。")

    create_backup_manifest(ctx, candidates)

    if not ctx.args.yes and not ctx.args.dry_run:
        if getattr(ctx.args, "quick", False):
            answer = input("\n确认清除以上可选组件？输入 y 继续 [y/N]: ").strip().lower()
            if answer not in {"y", "yes"}:
                ctx.reporter.log("INFO", "Cancelled.")
                return
        else:
            token = "APPLY-CORE" if any(agent.risk == "core" for agent in candidates) else "APPLY"
            print("\nWARNING: Keep independent SSH/VNC/serial-console access and a current snapshot.")
            answer = input(f"Type {token} to continue: ").strip()
            if answer != token:
                ctx.reporter.log("INFO", "Cancelled.")
                return

    for agent in candidates:
        ctx.reporter.log("INFO", f"{ctx.args.action}: {agent.agent_id}")
        action = ACTIONS.get(agent.agent_id)
        if action is None:
            ctx.reporter.log("ERROR", f"No action implementation for {agent.agent_id}.")
            continue
        try:
            action(ctx)
        except CleanerError as exc:
            ctx.reporter.log("ERROR", f"{agent.agent_id}: {exc}")
        reload_systemd(ctx)

    if ctx.args.dry_run:
        ctx.reporter.log("OK", "Dry-run completed; post-action verification was skipped because no changes were made.")
        return

    print("\nPost-action verification")
    for agent in candidates:
        if agent.agent_id in ctx.incomplete:
            ctx.reporter.log(
                "ERROR",
                f"{agent.agent_id}: uninstall incomplete: {ctx.incomplete[agent.agent_id]}",
            )
            continue
        if ctx.args.action == "disable":
            active = active_agent_evidence(agent.agent_id)
            if active:
                ctx.reporter.log(
                    "WARN",
                    f"{agent.agent_id} still has active evidence: {'; '.join(active)}",
                )
            else:
                ctx.reporter.log(
                    "OK",
                    f"{agent.agent_id}: no active service/process evidence; files remain installed by design.",
                )
            continue

        if agent.agent_id == "aliyun.security":
            cleanup_inactive_aegis_residuals(ctx)

        evidence = detect_agent(agent.agent_id)
        if evidence:
            ctx.reporter.log("ERROR", f"{agent.agent_id} residuals detected: {'; '.join(evidence)}")
        else:
            ctx.reporter.log("OK", f"{agent.agent_id}: not detected.")
