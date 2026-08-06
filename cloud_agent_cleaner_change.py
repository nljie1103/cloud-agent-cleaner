from cloud_agent_cleaner_common import *
from cloud_agent_cleaner_detection import *

# ---------- Change helpers ----------


def stop_disable_unit(ctx: Context, unit: str) -> None:
    if not unit_exists(unit):
        return
    for command in (["systemctl", "stop", unit], ["systemctl", "disable", unit]):
        try:
            ctx.runner.run(command)
        except CleanerError as exc:
            ctx.reporter.log("WARN", str(exc))


def remove_package(ctx: Context, package: str) -> None:
    if snap_installed(package):
        try:
            ctx.runner.run(["snap", "remove", package])
        except CleanerError as exc:
            ctx.reporter.log("ERROR", str(exc))
        return

    if command_exists("dpkg-query") and package_installed(package):
        command = ["apt-get", "purge", "-y", package] if command_exists("apt-get") else ["dpkg", "--purge", package]
        try:
            ctx.runner.run(command)
        except CleanerError as exc:
            ctx.reporter.log("ERROR", str(exc))
        return

    if command_exists("rpm") and package_installed(package):
        if command_exists("dnf"):
            command = ["dnf", "remove", "-y", package]
        elif command_exists("yum"):
            command = ["yum", "remove", "-y", package]
        elif command_exists("zypper"):
            command = ["zypper", "--non-interactive", "remove", package]
        else:
            command = ["rpm", "-e", package]
        try:
            ctx.runner.run(command)
        except CleanerError as exc:
            ctx.reporter.log("ERROR", str(exc))


def remove_matching_packages(ctx: Context, pattern: str) -> None:
    regex = re.compile(pattern, flags=re.IGNORECASE)
    for package in installed_packages():
        if regex.match(package):
            remove_package(ctx, package)


def safe_unlink(ctx: Context, *paths: str) -> None:
    for raw in paths:
        path = Path(raw)
        if ctx.runner.dry_run:
            ctx.reporter.log("INFO", f"DRY-RUN remove file {path}")
            continue
        try:
            if path.is_symlink() or path.is_file():
                path.unlink()
        except OSError as exc:
            ctx.reporter.log("WARN", f"Could not remove {path}: {exc}")


def safe_rmtree(ctx: Context, *paths: str) -> None:
    allowlist = {
        "/usr/local/share/aliyun-assist",
        "/usr/local/share/assist-daemon",
        "/usr/local/cloudmonitor",
        "/opt/cloudmonitor",
    }
    for raw in paths:
        if raw not in allowlist:
            raise CleanerError(f"Refusing to recursively remove non-allowlisted path: {raw}")
        path = Path(raw)
        if ctx.runner.dry_run:
            ctx.reporter.log("INFO", f"DRY-RUN remove directory {path}")
            continue
        if path.exists():
            shutil.rmtree(path)


def run_local_script(ctx: Context, script: Path, *arguments: str) -> bool:
    if not script.is_file():
        return False
    try:
        ctx.runner.run(["bash", f"./{script.name}", *arguments], cwd=script.parent)
        return True
    except CleanerError as exc:
        ctx.reporter.log("ERROR", str(exc))
        return False


def download_vendor_script(
    ctx: Context, url: str, label: str, agent_id: str
) -> Optional[Path]:
    if not ctx.args.allow_vendor_downloads:
        ctx.reporter.log("WARN", f"{label} requires a vendor script not stored locally.")
        ctx.reporter.log("INFO", f"Review the HTTPS URL and re-run with --allow-vendor-downloads: {url}")
        return None
    if not url.lower().startswith("https://"):
        ctx.reporter.log("ERROR", f"Refusing non-HTTPS vendor URL: {url}")
        return None

    destination = ctx.temp_dir / f"vendor-{hashlib.sha256(url.encode()).hexdigest()[:12]}.sh"
    if ctx.runner.dry_run:
        ctx.reporter.log("INFO", f"DRY-RUN download {label} from {url} to {destination}")
        return destination

    request = urllib.request.Request(url, headers={"User-Agent": f"{PROJECT}/{VERSION}"})
    ssl_context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=120, context=ssl_context) as response:
            data = response.read(5 * 1024 * 1024 + 1)
    except Exception as exc:
        ctx.reporter.log("ERROR", f"Could not download {label}: {exc}")
        return None

    if not data or len(data) > 5 * 1024 * 1024 or b"\x00" in data:
        ctx.reporter.log("ERROR", f"Downloaded {label} is empty, too large, or not a text script.")
        return None
    destination.write_bytes(data)
    destination.chmod(0o600)
    digest = hashlib.sha256(data).hexdigest()
    ctx.reporter.log("INFO", f"{label} SHA-256: {digest}")

    expected = ctx.args.vendor_hashes.get(agent_id)
    if expected:
        if expected != digest:
            ctx.reporter.log(
                "ERROR",
                f"{label} SHA-256 mismatch: expected {expected}, received {digest}.",
            )
            return None
        ctx.reporter.log("OK", f"{label} matches the supplied SHA-256 pin.")
        return destination

    if ctx.args.yes:
        ctx.reporter.log(
            "ERROR",
            f"Refusing unattended execution of unpinned {label}. Re-run with "
            f"--vendor-sha256 {agent_id}={digest} after reviewing the downloaded script.",
        )
        return None

    print(f"\nDownloaded vendor script: {destination}")
    print(f"SHA-256: {digest}")
    answer = input("Review the file, then type the full SHA-256 to authorize execution: ").strip().lower()
    if answer != digest:
        ctx.reporter.log("INFO", f"Execution of {label} was not authorized.")
        return None
    return destination


def create_backup_manifest(ctx: Context, agents: Sequence[Agent]) -> None:
    if ctx.args.no_backup or ctx.args.dry_run:
        return
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = Path("/var/backups/cloud-agent-cleaner") / timestamp
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_dir.chmod(0o700)
    ctx.backup_dir = backup_dir

    selected_ids = {agent.agent_id for agent in agents}
    manifest = backup_dir / "manifest.txt"
    with manifest.open("w", encoding="utf-8") as handle:
        handle.write(f"{PROJECT} {VERSION}\n")
        handle.write(f"created={dt.datetime.now().astimezone().isoformat()}\n")
        handle.write(f"host_hint={detect_host_hint()}\n")
        handle.write(f"selected={','.join(sorted(selected_ids))}\n\n")
        handle.write("=== OS ===\n")
        handle.write(read_text(Path("/etc/os-release")))
        handle.write("\n=== findings ===\n")
        for agent in agents:
            handle.write(f"{agent.agent_id}: {detect_agent(agent.agent_id)}\n")
        handle.write("\n=== matching processes ===\n")
        for line in process_table().splitlines():
            if re.search(r"aliyun|aegis|qcloud|tat_agent|barad|stargate|YDService|amazon-ssm|cloudwatch|codedeploy|AwsAgent|oracle-cloud-agent|mgmt_agent|wlp-agent|waagent|AzureMonitor|google.*agent|ops-agent", line, re.I):
                handle.write(line + "\n")
        handle.write("\n=== matching packages ===\n")
        for package in installed_packages():
            if re.search(r"aliyun|aegis|amazon-(ssm|cloudwatch)|codedeploy|awsagent|oracle.*agent|walinux|azuremonitor|google.*agent|ops-agent", package, re.I):
                handle.write(package + "\n")
    manifest.chmod(0o600)

    service_paths = (
        "/etc/systemd/system/aliyun.service",
        "/etc/systemd/system/aliyun-service.service",
        "/etc/systemd/system/tat_agent.service",
        "/etc/systemd/system/amazon-ssm-agent.service",
        "/etc/systemd/system/amazon-cloudwatch-agent.service",
        "/etc/systemd/system/codedeploy-agent.service",
        "/etc/systemd/system/oracle-cloud-agent.service",
        "/etc/systemd/system/mgmt_agent.service",
        "/etc/systemd/system/wlp-agent.service",
        "/etc/systemd/system/walinuxagent.service",
        "/etc/systemd/system/google-guest-agent.service",
        "/etc/systemd/system/google-guest-agent-manager.service",
        "/etc/systemd/system/google-cloud-ops-agent.service",
    )
    for raw in service_paths:
        path = Path(raw)
        if path.is_file():
            shutil.copy2(path, backup_dir / path.name)
    ctx.reporter.log("OK", f"Pre-change manifest saved to {backup_dir}.")


# ---------- Agent actions ----------


def aliyun_go_agent_binaries(home: Path = Path("/usr/local/cloudmonitor")) -> List[Path]:
    """Return exact legacy Go CloudMonitor binaries under the documented home."""
    if not home.is_dir():
        return []
    return sorted(
        path
        for path in home.glob("CmsGoAgent.linux-*")
        if path.is_file() and not path.is_symlink()
    )


def azure_monitor_extension_paths(root: Path = Path("/var/lib/waagent")) -> List[Path]:
    """Return Azure Monitor Linux Agent extension directories managed by Azure."""
    if not root.is_dir():
        return []
    return sorted(
        path
        for path in root.glob("Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-*")
        if path.is_dir()
    )


def mark_incomplete(ctx: Context, agent_id: str, reason: str) -> None:
    ctx.incomplete[agent_id] = reason
    ctx.reporter.log("WARN", reason)
