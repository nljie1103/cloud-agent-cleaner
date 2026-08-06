from cloud_agent_cleaner_common import *
from cloud_agent_cleaner_detection import *
from cloud_agent_cleaner_change import *


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
        stop_disable_unit(ctx, "aegis.service")
        stop_disable_unit(ctx, "AliYunDun.service")
        return
    script = download_vendor_script(
        ctx,
        "https://update2.aegis.aliyun.com/download/uninstall.sh",
        "Alibaba Aegis uninstaller",
        "aliyun.security",
    )
    if script and not ctx.args.dry_run:
        run_local_script(ctx, script)


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
