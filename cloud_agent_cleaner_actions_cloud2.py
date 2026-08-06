from cloud_agent_cleaner_common import *
from cloud_agent_cleaner_detection import *
from cloud_agent_cleaner_change import *


def act_oracle_cloud_agent(ctx: Context) -> None:
    for unit in (
        "oracle-cloud-agent.service",
        "oracle-cloud-agent-updater.service",
        "snap.oracle-cloud-agent.oracle-cloud-agent.service",
        "snap.oracle-cloud-agent.oracle-cloud-agent-updater.service",
    ):
        stop_disable_unit(ctx, unit)
    if snap_installed("oracle-cloud-agent") and ctx.args.action == "disable":
        ctx.runner.run(["snap", "stop", "--disable", "oracle-cloud-agent"], check=False)
    if ctx.args.action == "remove":
        remove_package(ctx, "oracle-cloud-agent")


def act_oracle_management(ctx: Context) -> None:
    stop_disable_unit(ctx, "mgmt_agent.service")
    if ctx.args.action == "remove":
        uninstaller = Path("/opt/oracle/mgmt_agent/agent_inst/bin/uninstaller.sh")
        if run_local_script(ctx, uninstaller):
            return
        ctx.reporter.log(
            "WARN",
            "OCI Management Agent local uninstaller was not found; falling back to exact package removal.",
        )
        remove_package(ctx, "oracle.mgmt_agent")
        remove_package(ctx, "oracle-mgmt-agent")


def act_oracle_workload(ctx: Context) -> None:
    stop_disable_unit(ctx, "wlp-agent.service")
    if ctx.args.action == "remove":
        remove_package(ctx, "wlp-agent")


def act_azure_linux_agent(ctx: Context) -> None:
    stop_disable_unit(ctx, "walinuxagent.service")
    if ctx.args.action == "remove":
        remove_package(ctx, "walinuxagent")
        remove_package(ctx, "WALinuxAgent")
        remove_package(ctx, "python-azure-agent")
        ctx.reporter.log("WARN", "Preserved /var/lib/waagent for recovery; review it manually after confirming the VM is healthy.")


def act_azure_monitor(ctx: Context) -> None:
    extension_paths = azure_monitor_extension_paths()
    stop_disable_unit(ctx, "azuremonitoragent.service")

    if ctx.args.action == "disable":
        if extension_paths:
            ctx.reporter.log(
                "WARN",
                "AzureMonitorLinuxAgent is extension-managed and can be restarted or redeployed by Azure. "
                "Disable its DCR/policy or remove the VM extension in the Azure control plane.",
            )
        return

    if extension_paths:
        paths = ", ".join(str(path) for path in extension_paths)
        mark_incomplete(
            ctx,
            "azure.monitor-agent",
            "Azure Monitor Agent is managed as the AzureMonitorLinuxAgent VM extension. "
            "A guest-only script cannot complete the supported uninstall. Remove the extension "
            "from Azure Portal, or use the supported Azure CLI command for the resource type: "
            "VM: az vm extension delete --resource-group <RESOURCE_GROUP> --vm-name <VM_NAME> "
            "--name AzureMonitorLinuxAgent; VMSS: az vmss extension delete --resource-group "
            "<RESOURCE_GROUP> --vmss-name <VMSS_NAME> --name AzureMonitorLinuxAgent; "
            "Arc: az connectedmachine extension delete --resource-group <RESOURCE_GROUP> "
            "--machine-name <ARC_MACHINE> --name AzureMonitorLinuxAgent. "
            f"Detected extension state: {paths}",
        )
        return

    if package_installed("azuremonitoragent"):
        remove_package(ctx, "azuremonitoragent")
        return

    mark_incomplete(
        ctx,
        "azure.monitor-agent",
        "Azure Monitor Agent evidence was detected, but neither an extension directory nor the "
        "standalone azuremonitoragent package could be safely identified.",
    )


def act_gcp_guest_agent(ctx: Context) -> None:
    # Covers the legacy monolithic service and the 2025+ plugin architecture.
    # The compatibility manager may switch between the legacy service and core
    # plugin, so all manager units must be stopped before package removal.
    stop_disable_unit(ctx, "google-guest-compat-manager.service")
    stop_disable_unit(ctx, "google-guest-agent-manager.service")
    stop_disable_unit(ctx, "google-guest-agent.service")
    if ctx.args.action == "remove":
        remove_package(ctx, "google-guest-agent")
        if package_installed("google-compute-engine"):
            ctx.reporter.log(
                "INFO",
                "Preserved google-compute-engine: it is a broader guest-environment/meta package and is not treated as residual guest-agent evidence.",
            )


def act_gcp_ops_agent(ctx: Context) -> None:
    for unit in (
        "google-cloud-ops-agent.target",
        "google-cloud-ops-agent.service",
        "google-cloud-ops-agent-fluent-bit.service",
        "google-cloud-ops-agent-opentelemetry-collector.service",
    ):
        stop_disable_unit(ctx, unit)
    if ctx.args.action == "remove":
        remove_package(ctx, "google-cloud-ops-agent")
