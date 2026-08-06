#!/usr/bin/env python3
"""Cross-cloud Linux agent audit and control CLI."""

from cloud_agent_cleaner_common import *
from cloud_agent_cleaner_detection import *
from cloud_agent_cleaner_change import *
from cloud_agent_cleaner_actions_cloud1 import *
from cloud_agent_cleaner_actions_cloud2 import *
from cloud_agent_cleaner_orchestrator import *

# ---------- CLI ----------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud_agent_cleaner.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Audit, explain, disable, and remove selected cloud-provider agents on Linux.",
        epilog=textwrap.dedent(
            """
            Examples:
              sudo python3 cloud_agent_cleaner.py --audit
              sudo python3 cloud_agent_cleaner.py --audit --provider aws,oracle
              sudo python3 cloud_agent_cleaner.py --all --dry-run
              sudo python3 cloud_agent_cleaner.py --remove --agent aws.ssm,aws.cloudwatch
              sudo python3 cloud_agent_cleaner.py --remove --agent oracle.cloud-agent --include-core
            """
        ),
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--audit", action="store_const", dest="action", const="audit", help="Detect and explain agents; make no changes")
    action.add_argument("--disable", action="store_const", dest="action", const="disable", help="Stop and disable selected agents")
    action.add_argument("--remove", action="store_const", dest="action", const="remove", help="Uninstall selected agents")
    action.add_argument("--all", action="store_true", help="Remove all detected optional agents; core agents remain protected")
    action.add_argument("--list-agents", action="store_true", help="Show the built-in agent registry")

    parser.add_argument("--provider", action="append", help="Comma-separated providers: aliyun,tencent,aws,oracle,azure,gcp,all")
    parser.add_argument("--category", action="append", help="Comma-separated categories: remote,monitoring,security,deployment,core,all")
    parser.add_argument("--agent", action="append", help="Comma-separated exact agent IDs from --list-agents")
    parser.add_argument("--include-core", action="store_true", help="Permit actions on protected core guest agents")
    parser.add_argument("--allow-vendor-downloads", action="store_true", help="Permit reviewed HTTPS vendor uninstall-script downloads")
    parser.add_argument(
        "--vendor-sha256",
        action="append",
        metavar="AGENT_ID=SHA256",
        help="Pin a downloaded vendor uninstaller; required with --yes",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print planned commands without executing them")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip interactive confirmation")
    parser.add_argument("--no-backup", action="store_true", help="Do not create a pre-change manifest")
    parser.add_argument("--report", help="Write audit results as a TSV file")
    parser.add_argument("-V", "--version", action="version", version=VERSION)
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    args.providers = split_values(args.provider, provider=True)
    args.categories = split_values(args.category)
    args.agent_ids = split_values(args.agent)
    args.vendor_hashes = {}
    for raw in args.vendor_sha256 or []:
        for item in raw.split(","):
            agent_id, separator, digest = item.strip().partition("=")
            agent_id = agent_id.strip().lower()
            digest = digest.strip().lower()
            if not separator or agent_id not in AGENT_BY_ID or not re.fullmatch(r"[0-9a-f]{64}", digest):
                parser.error(
                    "--vendor-sha256 requires AGENT_ID followed by a 64-character hexadecimal SHA-256"
                )
            args.vendor_hashes[agent_id] = digest

    unknown_providers = sorted(set(args.providers) - VALID_PROVIDERS)
    unknown_categories = sorted(set(args.categories) - VALID_CATEGORIES)
    unknown_agents = sorted(set(args.agent_ids) - (set(AGENT_BY_ID) | {"all"}))
    if unknown_providers:
        parser.error(f"unknown provider(s): {', '.join(unknown_providers)}")
    if unknown_categories:
        parser.error(f"unknown category/categories: {', '.join(unknown_categories)}")
    if unknown_agents:
        parser.error(f"unknown agent ID(s): {', '.join(unknown_agents)}")

    if args.list_agents:
        return
    if args.all:
        args.action = "remove"
        args.providers = ["all"]
        args.categories = ["all"]
    if not args.action:
        parser.error("choose --audit, --disable, --remove, --all, or --list-agents")

    if args.action in ("disable", "remove"):
        if not args.providers and not args.categories and not args.agent_ids:
            parser.error("a change action requires --provider, --category, --agent, or --all")
        if not args.include_core:
            exact_core = [agent_id for agent_id in args.agent_ids if agent_id in AGENT_BY_ID and AGENT_BY_ID[agent_id].risk == "core"]
            if exact_core:
                parser.error(f"protected core agent(s) require --include-core: {', '.join(exact_core)}")
            if "core" in args.categories:
                parser.error("the core category requires --include-core")


def create_runtime(args: argparse.Namespace) -> Context:
    if args.action in ("disable", "remove") and not args.dry_run and os.geteuid() != 0:
        raise CleanerError("disable/remove actions require root; run with sudo")
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_base = Path("/var/log") if os.geteuid() == 0 else Path(tempfile.gettempdir())
    log_path = log_base / f"cloud-agent-cleaner-{stamp}-{os.getpid()}.log"
    try:
        log_path.touch(mode=0o600, exist_ok=False)
    except OSError:
        log_path = Path(tempfile.gettempdir()) / f"cloud-agent-cleaner-{stamp}-{os.getpid()}.log"
        log_path.touch(mode=0o600, exist_ok=True)
    reporter = Reporter(log_path)
    runner = Runner(reporter, args.dry_run)
    temp_dir = Path(tempfile.mkdtemp(prefix="cloud-agent-cleaner."))
    reporter.log("INFO", f"Log file: {log_path}")
    return Context(args=args, reporter=reporter, runner=runner, temp_dir=temp_dir)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    if args.list_agents:
        print_registry()
        return 0

    try:
        ctx = create_runtime(args)
    except CleanerError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    try:
        ctx.reporter.log("INFO", f"{PROJECT} v{VERSION}")
        findings = audit(ctx)
        if args.action == "audit":
            ctx.reporter.log("OK", "Audit completed; no changes were made.")
        else:
            execute_changes(ctx, findings)
        if ctx.reporter.failures:
            print(f"[ERROR] Completed with {ctx.reporter.failures} error(s) and {ctx.reporter.warnings} warning(s).")
            return 2
        ctx.reporter.log("OK", f"Completed with {ctx.reporter.warnings} warning(s).")
        return 0
    except KeyboardInterrupt:
        ctx.reporter.log("WARN", "Interrupted by user.")
        return 130
    except Exception as exc:
        ctx.reporter.log("ERROR", f"Unexpected failure: {exc}")
        return 2
    finally:
        shutil.rmtree(ctx.temp_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
