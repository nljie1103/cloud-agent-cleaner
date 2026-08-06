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


def reload_systemd(ctx: Context) -> None:
    if command_exists("systemctl"):
        ctx.runner.run(["systemctl", "daemon-reload"], check=False)
        ctx.runner.run(["systemctl", "reset-failed"], check=False)


def execute_changes(ctx: Context, findings: Dict[str, List[str]]) -> None:
    candidates = [agent for agent in selected_agents(ctx.args, for_change=True) if findings.get(agent.agent_id)]
    if not candidates:
        ctx.reporter.log("INFO", "No detected agents match the change selectors.")
        return

    print(f"\nPlanned action: {ctx.args.action}")
    for agent in candidates:
        print(f"  - {agent.agent_id} [{agent.risk}] {agent.name}")
        print(f"    Impact: {agent.impact}")

    create_backup_manifest(ctx, candidates)

    if not ctx.args.yes and not ctx.args.dry_run:
        token = "APPLY-CORE" if any(agent.risk == "core" for agent in candidates) else "APPLY"
        print("\nWARNING: Keep independent SSH/VNC/serial-console access and a current snapshot.")
        print("Cloud-side policies or VM extensions may reinstall agents after local removal.")
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

        evidence = detect_agent(agent.agent_id)
        if evidence:
            ctx.reporter.log("ERROR", f"{agent.agent_id} residuals detected: {'; '.join(evidence)}")
        else:
            ctx.reporter.log("OK", f"{agent.agent_id}: not detected.")
