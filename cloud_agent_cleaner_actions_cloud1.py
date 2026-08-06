from cloud_agent_cleaner_common import *
from cloud_agent_cleaner_detection import *
from cloud_agent_cleaner_change import *

import signal
import time


AEGIS_SERVICE_UNITS: Tuple[str, ...] = (
    "aegis.service",
    "AliYunDun.service",
    "AliYunDunMonitor.service",
    "agentwatch.service",
)

AEGIS_EXACT_PROCESS_NAMES = {
    "AliYunDun",
    "AliYunDunMonitor",
    "AliYunDunUpdate",
    "AliSecGuard",
    "AliSecCheck",
    "AliSecureCheck",
    "AliSecureCheckAdvanced",
    "AlibabaSecurityAegis",
    "AliDetect",
    "AliNet",
    "AliHids",
    "AliHips",
    "AliWebGuard",
    "YunDunMonitor",
    "YunDunUpdate",
    "aegis_cli",
    "aegis_update",
    "aegis_quartz",
    "agentwatch",
    # Linux comm names can be truncated to 15 characters.
    "AliYunDunMonit",
    "AliYunDunUpdat",
    "AliSecureCheckA",
    "AlibabaSecurity",
}


def aegis_process_pids() -> List[int]:
    """Return only processes identified by exact Aegis names or executable path."""
    pids: List[int] = []
    root = Path("/proc")
    if not root.is_dir():
        return pids

    current_pid = os.getpid()
    for proc in root.iterdir():
        if not proc.name.isdigit():
            continue
        pid = int(proc.name)
        if pid == current_pid:
            continue

        comm = read_text(proc / "comm").strip()
        try:
            executable = os.path.realpath(proc / "exe")
        except OSError:
            executable = ""

        if comm in AEGIS_EXACT_PROCESS_NAMES or executable == "/usr/local/aegis" or executable.startswith("/usr/local/aegis/"):
            pids.append(pid)

    return sorted(set(pids))


def terminate_aegis_processes(ctx: Context) -> List[int]:
    """Terminate exact Aegis processes, escalating to SIGKILL only if needed."""
    initial = aegis_process_pids()
    if not initial:
        return []

    if ctx.runner.dry_run:
        ctx.reporter.log("INFO", f"DRY-RUN terminate Aegis process IDs: {', '.join(map(str, initial))}")
        return initial

    for sig, wait_seconds in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 1.0)):
        targets = aegis_process_pids()
        if not targets:
            return []
        for pid in targets:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
            except OSError as exc:
                ctx.reporter.log("WARN", f"Could not signal Aegis process {pid}: {exc}")

        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            remaining = aegis_process_pids()
            if not remaining:
                return []
            time.sleep(0.2)

    return aegis_process_pids()


def remove_aegis_local_artifacts(ctx: Context) -> bool:
    """Local fallback after the official uninstaller fails or leaves processes."""
    for unit in AEGIS_SERVICE_UNITS:
        stop_disable_unit(ctx, unit)

    for init_script in (Path("/etc/init.d/aegis"), Path("/etc/init.d/agentwatch")):
        if init_script.is_file():
            ctx.runner.run(["bash", f"./{init_script.name}", "stop"], cwd=init_script.parent, check=False)

    remaining = terminate_aegis_processes(ctx)

    safe_unlink(
        ctx,
        "/etc/init.d/aegis",
        "/etc/init.d/agentwatch",
        "/etc/systemd/system/aegis.service",
        "/etc/systemd/system/AliYunDun.service",
        "/etc/systemd/system/AliYunDunMonitor.service",
        "/etc/systemd/system/agentwatch.service",
        "/usr/lib/systemd/system/aegis.service",
        "/usr/lib/systemd/system/AliYunDun.service",
        "/usr/lib/systemd/system/AliYunDunMonitor.service",
        "/usr/lib/systemd/system/agentwatch.service",
        "/lib/systemd/system/aegis.service",
        "/lib/systemd/system/AliYunDun.service",
        "/lib/systemd/system/AliYunDunMonitor.service",
        "/lib/systemd/system/agentwatch.service",
        "/etc/systemd/system/multi-user.target.wants/aegis.service",
        "/etc/systemd/system/multi-user.target.wants/AliYunDun.service",
        "/etc/systemd/system/multi-user.target.wants/AliYunDunMonitor.service",
        "/etc/systemd/system/multi-user.target.wants/agentwatch.service",
        "/etc/rc2.d/S80aegis",
        "/etc/rc3.d/S80aegis",
        "/etc/rc4.d/S80aegis",
        "/etc/rc5.d/S80aegis",
        "/etc/rc.d/rc2.d/S80aegis",
        "/etc/rc.d/rc3.d/S80aegis",
        "/etc/rc.d/rc4.d/S80aegis",
        "/etc/rc.d/rc5.d/S80aegis",
    )

    if remaining and not ctx.runner.dry_run:
        reason = (
            "Alibaba Aegis processes remain after TERM/KILL attempts: "
            + ", ".join(map(str, remaining))
            + ". Confirm Security Center self-protection is disabled."
        )
        mark_incomplete(ctx, "aliyun.security", reason)
        return False

    home = Path("/usr/local/aegis")
    if home.exists():
        if home.is_symlink() or not home.is_dir():
            reason = f"Refusing to recursively remove unexpected Aegis path type: {home}"
            mark_incomplete(ctx, "aliyun.security", reason)
            return False
        if ctx.runner.dry_run:
            ctx.reporter.log("INFO", f"DRY-RUN remove directory {home}")
        else:
            try:
                shutil.rmtree(home)
            except OSError as exc:
                mark_incomplete(ctx, "aliyun.security", f"Could not remove {home}: {exc}")
                return False

    return True


def run_aegis_vendor_uninstaller(ctx: Context, script: Path) -> bool:
    """Run the downloaded script without turning a recoverable failure into a hard error."""
    if ctx.runner.dry_run:
        ctx.reporter.log("INFO", f"DRY-RUN bash ./{script.name}")
        return True

    result = ctx.runner.run(
        ["bash", f"./{script.name}"],
        cwd=script.parent,
        check=False,
        capture=True,
    )
    if result.returncode == 0:
        return True

    output = "\n".join(part for part in ((result.stdout or "").strip(), (result.stderr or "").strip()) if part)
    summary = " | ".join(line.strip() for line in output.splitlines()[-4:] if line.strip())
    message = f"Alibaba Aegis official uninstaller exited with code {result.returncode}; using local fallback."
    if result.returncode == 6:
        message += " Exit code 6 commonly indicates a DNS/host-resolution failure in a command used by the vendor script."
    ctx.reporter.log("WARN", message)
    if summary:
        ctx.reporter.log("WARN", f"Alibaba Aegis uninstaller output: {summary[:800]}")
    return False


def act_aliyun_assistant(ctx: Context) -> None:
    daemon = Path("/usr/local/share/assist-daemon/assist_daemon")
    if daemon.is_file():
        try:
            ctx.runner.run([str(daemon), "--stop"])
        except CleanerError as exc:
            ctx.reporter.log("WARN", str(exc))
    stop_disable_unit(ctx, "aliyun.service")
    stop_disable_unit(ctx, "aliyun-service.service")
    if ctx.args.action == "disable":
        return
    if daemon.is_file():
        try:
            ctx.runner.run([str(daemon), "--delete"])
        except CleanerError as exc:
            ctx.reporter.log("WARN", str(exc))
    remove_package(ctx, "aliyun-assist")
    remove_matching_packages(ctx, r"^aliyun[_-]assist")
    safe_rmtree(ctx, "/usr/local/share/aliyun-assist", "/usr/local/share/assist-daemon")
    safe_unlink(
        ctx,
        "/etc/systemd/system/aliyun.service",
        "/etc/systemd/system/aliyun-service.service",
        "/usr/lib/systemd/system/aliyun.service",
        "/lib/systemd/system/aliyun.service",
        "/etc/init.d/aliyun-service",
    )


def act_aliyun_monitor(ctx: Context) -> None:
    stop_disable_unit(ctx, "argusagent.service")
    stop_disable_unit(ctx, "cloudmonitor.service")

    for home in (Path("/usr/local/cloudmonitor"), Path("/opt/cloudmonitor")):
        control = home / "cloudmonitorCtl.sh"
        legacy = home / "wrapper/bin/cloudmonitor.sh"
        if ctx.args.action == "disable":
            run_local_script(ctx, control, "stop")
            run_local_script(ctx, legacy, "stop")
        else:
            run_local_script(ctx, control, "stop")
            run_local_script(ctx, control, "uninstall")
            run_local_script(ctx, legacy, "stop")
            run_local_script(ctx, legacy, "remove")

    for binary in aliyun_go_agent_binaries():
        try:
            ctx.runner.run([str(binary), "stop"], check=False)
            if ctx.args.action == "remove":
                ctx.runner.run([str(binary), "uninstall"], check=False)
        except CleanerError as exc:
            ctx.reporter.log("WARN", str(exc))

    if ctx.args.action == "remove":
        safe_rmtree(ctx, "/usr/local/cloudmonitor", "/opt/cloudmonitor")
        safe_unlink(
            ctx,
            "/etc/systemd/system/argusagent.service",
            "/etc/systemd/system/cloudmonitor.service",
            "/usr/lib/systemd/system/argusagent.service",
            "/usr/lib/systemd/system/cloudmonitor.service",
            "/lib/systemd/system/argusagent.service",
            "/lib/systemd/system/cloudmonitor.service",
            "/etc/systemd/system/multi-user.target.wants/argusagent.service",
            "/etc/systemd/system/multi-user.target.wants/cloudmonitor.service",
            "/etc/init.d/argusagent",
            "/etc/init.d/cloudmonitor",
        )


def act_aliyun_security(ctx: Context) -> None:
    ctx.reporter.log("WARN", "Disable Security Center client self-protection and malicious-host defense in the console first.")
    if ctx.args.action == "disable":
        for unit in AEGIS_SERVICE_UNITS:
            stop_disable_unit(ctx, unit)
        terminate_aegis_processes(ctx)
        return

    script = download_vendor_script(
        ctx,
        "https://update2.aegis.aliyun.com/download/uninstall.sh",
        "Alibaba Aegis uninstaller",
        "aliyun.security",
    )
    if script:
        run_aegis_vendor_uninstaller(ctx, script)

    # The official script may fail because of a transient DNS lookup or may
    # leave active processes/static files. Finish with an exact local cleanup.
    remove_aegis_local_artifacts(ctx)


def act_tencent_tat(ctx: Context) -> None:
    stop_disable_unit(ctx, "tat_agent.service")
    if ctx.args.action == "disable":
        if command_exists("pkill") and process_matches(r"\btat_agent\b"):
            try:
                ctx.runner.run(["pkill", "-TERM", "-x", "tat_agent"], check=False)
            except CleanerError:
                pass
        return
    for path in (
        Path("/usr/local/qcloud/tat_agent/uninstall.sh"),
        Path("/usr/local/qcloud/tat/uninstall.sh"),
    ):
        if run_local_script(ctx, path):
            return
    script = download_vendor_script(
        ctx,
        "https://raw.githubusercontent.com/Tencent/tat-agent/main/install/uninstall.sh",
        "Tencent TAT uninstaller",
        "tencent.tat",
    )
    if script and not ctx.args.dry_run:
        run_local_script(ctx, script)


def act_tencent_monitor(ctx: Context) -> None:
    barad = Path("/usr/local/qcloud/monitor/barad/admin")
    stargate = Path("/usr/local/qcloud/stargate/admin")
    safe_unlink(ctx, "/etc/cron.d/sgagenttask")
    if ctx.args.action == "disable":
        run_local_script(ctx, stargate / "stop.sh")
        run_local_script(ctx, barad / "stop.sh")
    else:
        run_local_script(ctx, stargate / "uninstall.sh")
        run_local_script(ctx, barad / "uninstall.sh")


def act_tencent_security(ctx: Context) -> None:
    if ctx.args.action == "disable":
        run_local_script(ctx, Path("/usr/local/qcloud/YunJing/stopYD.sh"))
        if command_exists("pkill"):
            ctx.runner.run(["pkill", "-TERM", "-f", "/(YDService|YDLive|YDEyes)( |$)"], check=False)
        return
    for script in (
        Path("/usr/local/qcloud/YunJing/uninst.sh"),
        Path("/var/lib/qcloud/YunJing/uninst.sh"),
    ):
        if run_local_script(ctx, script):
            return
    ctx.reporter.log("ERROR", "YunJing was detected but no documented local uninst.sh was found; refusing manual directory deletion.")


def act_aws_ssm(ctx: Context) -> None:
    stop_disable_unit(ctx, "amazon-ssm-agent.service")
    stop_disable_unit(ctx, "snap.amazon-ssm-agent.amazon-ssm-agent.service")
    if snap_installed("amazon-ssm-agent") and ctx.args.action == "disable":
        try:
            ctx.runner.run(["snap", "stop", "--disable", "amazon-ssm-agent"])
        except CleanerError as exc:
            ctx.reporter.log("WARN", str(exc))
    if ctx.args.action == "remove":
        remove_package(ctx, "amazon-ssm-agent")


def act_aws_cloudwatch(ctx: Context) -> None:
    control = Path("/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl")
    if control.is_file():
        ctx.runner.run([str(control), "-a", "stop", "-m", "ec2"], check=False)
    stop_disable_unit(ctx, "amazon-cloudwatch-agent.service")
    if ctx.args.action == "remove":
        remove_package(ctx, "amazon-cloudwatch-agent")


def act_aws_codedeploy(ctx: Context) -> None:
    stop_disable_unit(ctx, "codedeploy-agent.service")
    if ctx.args.action == "remove":
        remove_package(ctx, "codedeploy-agent")


def act_aws_inspector(ctx: Context) -> None:
    stop_disable_unit(ctx, "awsagent.service")
    if ctx.args.action == "remove":
        remove_matching_packages(ctx, r"^(AwsAgent|awsagent)")
