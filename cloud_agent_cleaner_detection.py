from cloud_agent_cleaner_common import *

# ---------- Agent detection ----------


def detect_agent(agent_id: str) -> List[str]:
    evidence: List[str] = []

    def add_paths(*paths: str) -> None:
        evidence.extend(existing_paths(paths))

    def add_unit(*units: str) -> None:
        for unit in units:
            if unit_exists(unit):
                evidence.append(f"unit:{unit}")

    def add_package(*packages: str) -> None:
        for package in packages:
            if package_installed(package):
                evidence.append(f"package:{package}")
            if snap_installed(package):
                evidence.append(f"snap:{package}")

    if agent_id == "aliyun.assistant":
        add_paths("/usr/local/share/aliyun-assist", "/usr/local/share/assist-daemon/assist_daemon")
        add_unit("aliyun.service", "aliyun-service.service")
        add_package("aliyun-assist")
        if process_matches(r"(?m)^\S*\s+.*\b(aliyun-service|aliyun_assist|assist_daemon)\b"):
            evidence.append("process:aliyun-assist")

    elif agent_id == "aliyun.monitor":
        add_paths("/usr/local/cloudmonitor", "/opt/cloudmonitor")
        add_unit("argusagent.service", "cloudmonitor.service")
        if process_matches(r"(?m)^\S*\s+.*\b(argusagent|CmsGoAgent|cloudmonitor)\b"):
            evidence.append("process:cloudmonitor")

    elif agent_id == "aliyun.security":
        add_paths("/usr/local/aegis")
        if process_matches(r"(?m)^\S*\s+.*\b(AliYunDun|AliSecGuard|AlibabaSecurityAegis|YunDunMonitor|YunDunUpdate)\b"):
            evidence.append("process:aegis")

    elif agent_id == "tencent.tat":
        add_paths("/usr/local/qcloud/tat_agent", "/usr/local/qcloud/tat")
        add_unit("tat_agent.service")
        if process_matches(r"(?m)^\S*\s+.*\b(tat_agent|tat_agent_daemon)\b"):
            evidence.append("process:tat_agent")

    elif agent_id == "tencent.monitor":
        add_paths("/usr/local/qcloud/monitor/barad", "/usr/local/qcloud/stargate")
        if process_matches(r"(?m)^\S*\s+.*\b(barad_agent|sgagent|stargate)\b"):
            evidence.append("process:tencent-monitor")

    elif agent_id == "tencent.security":
        add_paths("/usr/local/qcloud/YunJing", "/var/lib/qcloud/YunJing")
        if process_matches(r"(?m)^\S*\s+.*\b(YDService|YDLive|YDEyes)\b"):
            evidence.append("process:YunJing")

    elif agent_id == "aws.ssm":
        add_package("amazon-ssm-agent")
        add_unit("amazon-ssm-agent.service", "snap.amazon-ssm-agent.amazon-ssm-agent.service")
        if process_matches(r"(?m)^\S*\s+.*\bamazon-ssm-agent\b"):
            evidence.append("process:amazon-ssm-agent")

    elif agent_id == "aws.cloudwatch":
        add_package("amazon-cloudwatch-agent")
        add_paths("/opt/aws/amazon-cloudwatch-agent")
        add_unit("amazon-cloudwatch-agent.service")
        if process_matches(r"(?m)^\S*\s+.*\bamazon-cloudwatch-agent\b"):
            evidence.append("process:amazon-cloudwatch-agent")

    elif agent_id == "aws.codedeploy":
        add_package("codedeploy-agent")
        add_paths("/opt/codedeploy-agent")
        add_unit("codedeploy-agent.service")
        if process_matches(r"(?m)^\S*\s+.*\bcodedeploy-agent\b"):
            evidence.append("process:codedeploy-agent")

    elif agent_id == "aws.inspector-classic":
        matching = [pkg for pkg in installed_packages() if re.match(r"(?i)^(AwsAgent|awsagent)", pkg)]
        evidence.extend(f"package:{pkg}" for pkg in matching)
        add_paths("/opt/aws/awsagent")
        if process_matches(r"(?m)^\S*\s+.*\b(AwsAgent|awsagent)\b"):
            evidence.append("process:awsagent")

    elif agent_id == "oracle.cloud-agent":
        add_package("oracle-cloud-agent")
        add_paths("/var/lib/oracle-cloud-agent")
        add_unit(
            "oracle-cloud-agent.service",
            "oracle-cloud-agent-updater.service",
            "snap.oracle-cloud-agent.oracle-cloud-agent.service",
        )

    elif agent_id == "oracle.management-agent":
        add_package("oracle.mgmt_agent", "oracle-mgmt-agent")
        add_paths("/opt/oracle/mgmt_agent")
        add_unit("mgmt_agent.service")
        if process_matches(r"(?m)^\S*\s+.*\bagentcore\b"):
            evidence.append("process:agentcore")

    elif agent_id == "oracle.workload-protection":
        add_package("wlp-agent")
        add_paths("/opt/oracle/wlp-agent")
        add_unit("wlp-agent.service")

    elif agent_id == "azure.linux-agent":
        add_package("walinuxagent", "WALinuxAgent", "python-azure-agent")
        add_paths("/var/lib/waagent")
        add_unit("walinuxagent.service")

    elif agent_id == "azure.monitor-agent":
        add_package("azuremonitoragent")
        add_unit("azuremonitoragent.service")
        root = Path("/var/lib/waagent")
        if root.is_dir():
            evidence.extend(str(path) for path in root.glob("Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-*") if path.is_dir())

    elif agent_id == "gcp.guest-agent":
        # Current and legacy architectures use the google-guest-agent package.
        # google-compute-engine is a broader guest-environment/meta package and
        # is deliberately not treated as proof that the agent itself remains.
        add_package("google-guest-agent")
        add_unit(
            "google-guest-agent.service",
            "google-guest-agent-manager.service",
            "google-guest-compat-manager.service",
        )
        add_paths(
            "/var/lib/google-guest-agent",
            "/usr/lib/google/guest_agent/core_plugin",
            "/usr/bin/ggactl_plugin",
        )
        if process_matches(r"(?m)^\S*\s+.*\b(google_guest_agent|google-guest-agent|google_guest_agent_manager|google_guest_compat_manager|core_plugin)\b"):
            evidence.append("process:google-guest-agent")

    elif agent_id == "gcp.ops-agent":
        add_package("google-cloud-ops-agent")
        add_paths("/opt/google-cloud-ops-agent")
        add_unit("google-cloud-ops-agent.target", "google-cloud-ops-agent.service")

    return sorted(set(evidence))


RUNNING_UNITS: Dict[str, Tuple[str, ...]] = {
    "aliyun.assistant": ("aliyun.service", "aliyun-service.service"),
    "aliyun.monitor": ("argusagent.service", "cloudmonitor.service"),
    "aliyun.security": ("aegis.service", "AliYunDun.service"),
    "tencent.tat": ("tat_agent.service",),
    "aws.ssm": ("amazon-ssm-agent.service", "snap.amazon-ssm-agent.amazon-ssm-agent.service"),
    "aws.cloudwatch": ("amazon-cloudwatch-agent.service",),
    "aws.codedeploy": ("codedeploy-agent.service",),
    "aws.inspector-classic": ("awsagent.service",),
    "oracle.cloud-agent": (
        "oracle-cloud-agent.service",
        "oracle-cloud-agent-updater.service",
        "snap.oracle-cloud-agent.oracle-cloud-agent.service",
    ),
    "oracle.management-agent": ("mgmt_agent.service",),
    "oracle.workload-protection": ("wlp-agent.service",),
    "azure.linux-agent": ("walinuxagent.service",),
    "azure.monitor-agent": ("azuremonitoragent.service",),
    "gcp.guest-agent": (
        "google-guest-agent.service",
        "google-guest-agent-manager.service",
        "google-guest-compat-manager.service",
    ),
    "gcp.ops-agent": (
        "google-cloud-ops-agent.target",
        "google-cloud-ops-agent.service",
        "google-cloud-ops-agent-fluent-bit.service",
        "google-cloud-ops-agent-opentelemetry-collector.service",
    ),
}

RUNNING_PATTERNS: Dict[str, str] = {
    "aliyun.assistant": r"\b(aliyun-service|aliyun_assist|assist_daemon)\b",
    "aliyun.monitor": r"\b(argusagent|CmsGoAgent|cloudmonitor)\b",
    "aliyun.security": r"\b(AliYunDun|AliSecGuard|AlibabaSecurityAegis|YunDunMonitor|YunDunUpdate)\b",
    "tencent.tat": r"\b(tat_agent|tat_agent_daemon)\b",
    "tencent.monitor": r"\b(barad_agent|sgagent|stargate)\b",
    "tencent.security": r"\b(YDService|YDLive|YDEyes)\b",
    "aws.ssm": r"\bamazon-ssm-agent\b",
    "aws.cloudwatch": r"\bamazon-cloudwatch-agent\b",
    "aws.codedeploy": r"\bcodedeploy-agent\b",
    "aws.inspector-classic": r"\b(AwsAgent|awsagent)\b",
    "oracle.cloud-agent": r"\boracle-cloud-agent\b",
    "oracle.management-agent": r"\bagentcore\b",
    "oracle.workload-protection": r"\bwlp-agent\b",
    "azure.linux-agent": r"\b(waagent|WALinuxAgent)\b",
    "azure.monitor-agent": r"\bazuremonitoragent\b",
    "gcp.guest-agent": r"\b(google_guest_agent|google-guest-agent|google_guest_agent_manager|google_guest_compat_manager|core_plugin)\b",
    "gcp.ops-agent": r"\bgoogle-cloud-ops-agent\b",
}


def unit_active(unit: str) -> bool:
    if not command_exists("systemctl"):
        return False
    return subprocess.run(
        ["systemctl", "is-active", "--quiet", unit],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def active_agent_evidence(agent_id: str) -> List[str]:
    evidence = [f"active-unit:{unit}" for unit in RUNNING_UNITS.get(agent_id, ()) if unit_active(unit)]
    pattern = RUNNING_PATTERNS.get(agent_id)
    if pattern and process_matches(pattern):
        evidence.append("matching-process")
    return sorted(set(evidence))


# ---------- Selection and output ----------


def split_values(values: Optional[List[str]], *, provider: bool = False) -> List[str]:
    output: List[str] = []
    for raw in values or []:
        for item in raw.split(","):
            item = item.strip().lower()
            if not item:
                continue
            if provider:
                item = PROVIDER_ALIASES.get(item, item)
            if item not in output:
                output.append(item)
    return output


def matches_filters(agent: Agent, providers: List[str], categories: List[str], ids: List[str]) -> bool:
    if ids and agent.agent_id not in ids and "all" not in ids:
        return False
    if providers and agent.provider not in providers and "all" not in providers:
        return False
    if categories and agent.category not in categories and "all" not in categories:
        return False
    return True


def selected_agents(args: argparse.Namespace, *, for_change: bool) -> List[Agent]:
    result = []
    for agent in AGENTS:
        if not matches_filters(agent, args.providers, args.categories, args.agent_ids):
            continue
        if for_change and agent.risk == "core" and not args.include_core:
            continue
        result.append(agent)
    return result


def print_registry() -> None:
    print(f"{'AGENT ID':28} {'PROVIDER':10} {'CATEGORY':12} {'RISK':9} NAME")
    print(f"{'-' * 28} {'-' * 10} {'-' * 12} {'-' * 9} {'-' * 30}")
    for agent in AGENTS:
        print(f"{agent.agent_id:28} {agent.provider:10} {agent.category:12} {agent.risk:9} {agent.name}")


def audit(ctx: Context) -> Dict[str, List[str]]:
    agents = selected_agents(ctx.args, for_change=False)
    findings: Dict[str, List[str]] = {}
    print("\nCross-cloud agent audit")
    print(f"Host hint: {detect_host_hint()}")
    print(f"{'AGENT ID':28} {'PROVIDER':10} {'CATEGORY':12} {'RISK':9} {'STATUS':10} EVIDENCE")
    print(f"{'-' * 28} {'-' * 10} {'-' * 12} {'-' * 9} {'-' * 10} {'-' * 30}")
    rows: List[Tuple[str, str, str, str, str, str]] = []
    for agent in agents:
        evidence = detect_agent(agent.agent_id)
        findings[agent.agent_id] = evidence
        status = "DETECTED" if evidence else "not-found"
        evidence_text = "; ".join(evidence) if evidence else "-"
        print(
            f"{agent.agent_id:28} {agent.provider:10} {agent.category:12} "
            f"{agent.risk:9} {status:10} {evidence_text}"
        )
        rows.append((agent.agent_id, agent.provider, agent.category, agent.risk, status, evidence_text))

    if ctx.args.report:
        report_path = Path(ctx.args.report).expanduser().resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle, delimiter="\t")
            writer.writerow(("agent_id", "provider", "category", "risk", "status", "evidence"))
            writer.writerows(rows)
        ctx.reporter.log("OK", f"Audit report written to {report_path}.")

    ctx.reporter.log("INFO", "Detection means management software is installed; it is not proof of malicious surveillance.")
    ctx.reporter.log("INFO", "cloud-init, qemu-guest-agent, drivers and unknown software are intentionally excluded.")
    return findings
