#!/usr/bin/env python3
"""cloud-agent-cleaner

Audit, explain, disable, and remove selected cloud-provider agents on Linux.

This file intentionally uses only the Python standard library. It never pipes
remote content directly into a shell, protects core guest agents behind an
explicit flag, and uses exact package/service/path identifiers.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import textwrap
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "2.0.1-alpha.1"
PROJECT = "cloud-agent-cleaner"

ANSI = {
    "reset": "\033[0m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "bold": "\033[1m",
}


@dataclass(frozen=True)
class Agent:
    agent_id: str
    provider: str
    category: str
    risk: str
    name: str
    impact: str


AGENTS: Tuple[Agent, ...] = (
    Agent("aliyun.assistant", "aliyun", "remote", "optional", "Alibaba Cloud Assistant", "Console commands, sessions, Workbench/OOS and diagnostics may stop."),
    Agent("aliyun.monitor", "aliyun", "monitoring", "optional", "Alibaba CloudMonitor", "Guest OS metrics such as memory and filesystem usage may stop."),
    Agent("aliyun.security", "aliyun", "security", "optional", "Alibaba Cloud Security Center (Aegis)", "Host security inspection and protection may stop."),
    Agent("tencent.tat", "tencent", "remote", "optional", "Tencent Cloud TAT Agent", "Automation Tools commands and managed sessions may stop."),
    Agent("tencent.monitor", "tencent", "monitoring", "optional", "Tencent Cloud BaradAgent and Sgagent", "Tencent guest metrics may stop reporting."),
    Agent("tencent.security", "tencent", "security", "optional", "Tencent Cloud Host Security (YunJing)", "Host security inspection and protection may stop."),
    Agent("aws.ssm", "aws", "remote", "optional", "AWS Systems Manager SSM Agent", "Systems Manager Run Command and Session Manager may stop."),
    Agent("aws.cloudwatch", "aws", "monitoring", "optional", "Amazon CloudWatch Agent", "CloudWatch guest metrics and logs may stop."),
    Agent("aws.codedeploy", "aws", "deployment", "optional", "AWS CodeDeploy Agent", "CodeDeploy deployments to this host may stop."),
    Agent("aws.inspector-classic", "aws", "security", "optional", "Amazon Inspector Classic Agent", "Legacy Inspector Classic host assessments may stop."),
    Agent("oracle.cloud-agent", "oracle", "core", "core", "Oracle Cloud Agent", "OCI plugins such as monitoring, run command, OS management, bastion and updates may stop."),
    Agent("oracle.management-agent", "oracle", "monitoring", "optional", "OCI Management Agent", "OCI Management Agent telemetry and integrations may stop."),
    Agent("oracle.workload-protection", "oracle", "security", "optional", "OCI Workload Protection Agent", "Cloud Guard workload protection may stop."),
    Agent("azure.linux-agent", "azure", "core", "core", "Azure Linux Agent", "Azure provisioning and VM extension handling may stop; recovery can be difficult."),
    Agent("azure.monitor-agent", "azure", "monitoring", "optional", "Azure Monitor Agent extension", "Azure guest metrics and logs may stop."),
    Agent("gcp.guest-agent", "gcp", "core", "core", "Google Compute Engine Guest Agent", "GCE SSH/account, metadata-driven network and extension functions may stop."),
    Agent("gcp.ops-agent", "gcp", "monitoring", "optional", "Google Cloud Ops Agent", "Google Cloud guest metrics and logs may stop."),
)
AGENT_BY_ID: Dict[str, Agent] = {agent.agent_id: agent for agent in AGENTS}

PROVIDER_ALIASES = {
    "alibaba": "aliyun",
    "alibabacloud": "aliyun",
    "tencentcloud": "tencent",
    "amazon": "aws",
    "oci": "oracle",
    "microsoft": "azure",
    "google": "gcp",
    "googlecloud": "gcp",
}
VALID_PROVIDERS = {agent.provider for agent in AGENTS} | {"all"}
VALID_CATEGORIES = {agent.category for agent in AGENTS} | {"all"}


class CleanerError(RuntimeError):
    """Expected operational error."""


class Reporter:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.failures = 0
        self.warnings = 0
        self.use_color = sys.stdout.isatty()

    def _color(self, name: str, text: str) -> str:
        if not self.use_color:
            return text
        return f"{ANSI[name]}{text}{ANSI['reset']}"

    def log(self, level: str, message: str) -> None:
        if level == "WARN":
            self.warnings += 1
            color = "yellow"
        elif level == "ERROR":
            self.failures += 1
            color = "red"
        elif level == "OK":
            color = "green"
        else:
            color = "blue"
        print(f"{self._color(color, f'[{level}]')} {message}")
        try:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"[{level}] {message}\n")
        except OSError:
            pass


class Runner:
    def __init__(self, reporter: Reporter, dry_run: bool) -> None:
        self.reporter = reporter
        self.dry_run = dry_run

    @staticmethod
    def format_command(command: Sequence[str]) -> str:
        return " ".join(subprocess.list2cmdline([part]) for part in command)

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Optional[Path] = None,
        check: bool = True,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = [str(part) for part in command]
        prefix = f"(cd {cwd} && " if cwd else ""
        suffix = ")" if cwd else ""
        if self.dry_run:
            self.reporter.log("INFO", f"DRY-RUN {prefix}{self.format_command(command)}{suffix}")
            return subprocess.CompletedProcess(command, 0, "", "")

        try:
            result = subprocess.run(
                command,
                cwd=str(cwd) if cwd else None,
                text=True,
                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
            )
        except OSError as exc:
            raise CleanerError(
                f"Could not execute {self.format_command(command)}: {exc}"
            ) from exc
        if result.stdout:
            with self.reporter.log_path.open("a", encoding="utf-8") as handle:
                handle.write(result.stdout)
        if result.stderr:
            with self.reporter.log_path.open("a", encoding="utf-8") as handle:
                handle.write(result.stderr)
        if check and result.returncode != 0:
            raise CleanerError(
                f"Command failed ({result.returncode}): {self.format_command(command)}"
            )
        return result


@dataclass
class Context:
    args: argparse.Namespace
    reporter: Reporter
    runner: Runner
    temp_dir: Path
    backup_dir: Optional[Path] = None
    incomplete: Dict[str, str] = field(default_factory=dict)


# ---------- Generic inspection helpers ----------


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def process_table() -> str:
    if not command_exists("ps"):
        return ""
    # Do not inspect arbitrary command-line arguments: they can contain agent
    # names in an audit command or test and cause false positives. `comm` plus
    # the executable path is sufficient for the exact agent binaries we track.
    result = subprocess.run(
        ["ps", "-eo", "comm=,exe="],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.stdout or ""


def process_matches(pattern: str) -> bool:
    return re.search(pattern, process_table(), flags=re.MULTILINE) is not None


def unit_exists(unit: str) -> bool:
    if not command_exists("systemctl"):
        return False
    result = subprocess.run(
        ["systemctl", "list-unit-files", unit, "--no-legend"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.stdout.strip():
        return True
    return subprocess.run(
        ["systemctl", "status", unit],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode in (0, 3)


def package_installed(package: str) -> bool:
    if command_exists("dpkg-query"):
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", package],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if "install ok installed" in (result.stdout or ""):
            return True
    if command_exists("rpm"):
        if subprocess.run(
            ["rpm", "-q", package],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0:
            return True
    return False


def snap_installed(package: str) -> bool:
    return command_exists("snap") and subprocess.run(
        ["snap", "list", package],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def installed_packages() -> List[str]:
    packages: List[str] = []
    if command_exists("dpkg-query"):
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${binary:Package}\n"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        packages.extend(line.strip() for line in result.stdout.splitlines() if line.strip())
    if command_exists("rpm"):
        result = subprocess.run(
            ["rpm", "-qa"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        packages.extend(line.strip() for line in result.stdout.splitlines() if line.strip())
    return packages


def existing_paths(paths: Iterable[str]) -> List[str]:
    return [path for path in paths if Path(path).exists()]


def detect_host_hint() -> str:
    values = []
    for path in (
        Path("/sys/class/dmi/id/sys_vendor"),
        Path("/sys/class/dmi/id/product_name"),
        Path("/sys/class/dmi/id/board_vendor"),
    ):
        value = read_text(path).strip()
        if value and value not in values:
            values.append(value)
    joined = " / ".join(values)
    lowered = joined.lower()
    hints = (
        ("alibaba", "Alibaba Cloud"),
        ("tencent", "Tencent Cloud"),
        ("amazon", "AWS"),
        ("oracle", "Oracle Cloud"),
        ("microsoft", "Microsoft Azure or Hyper-V"),
        ("google", "Google Cloud"),
    )
    for needle, label in hints:
        if needle in lowered:
            return f"{label} ({joined})"
    return joined or "unknown"
