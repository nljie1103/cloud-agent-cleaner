from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "cloud_agent_cleaner.py"

spec = importlib.util.spec_from_file_location("cloud_agent_cleaner", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class RegistryTests(unittest.TestCase):
    def test_registry_is_unique_and_action_complete(self) -> None:
        ids = [agent.agent_id for agent in module.AGENTS]
        self.assertEqual(len(ids), 17)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), set(module.ACTIONS))

    def test_expected_providers(self) -> None:
        self.assertEqual(
            {agent.provider for agent in module.AGENTS},
            {"aliyun", "tencent", "aws", "oracle", "azure", "gcp"},
        )

    def test_recursive_delete_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reporter = module.Reporter(Path(tmp) / "test.log")
            ctx = SimpleNamespace(runner=module.Runner(reporter, True))
            with self.assertRaises(module.CleanerError):
                module.safe_rmtree(ctx, "/etc")


class PlatformRegressionTests(unittest.TestCase):
    def make_ctx(self, tmp: str, action: str = "remove") -> module.Context:
        reporter = module.Reporter(Path(tmp) / "test.log")
        args = SimpleNamespace(
            action=action,
            allow_vendor_downloads=False,
            dry_run=False,
            no_backup=True,
        )
        return module.Context(
            args=args,
            reporter=reporter,
            runner=module.Runner(reporter, False),
            temp_dir=Path(tmp),
        )

    def test_aliyun_go_binary_discovery_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            good_a = home / "CmsGoAgent.linux-amd64"
            good_b = home / "CmsGoAgent.linux-arm64"
            unrelated = home / "CmsGoAgent.windows-amd64.exe"
            for path in (good_a, good_b, unrelated):
                path.write_text("test", encoding="utf-8")
            (home / "CmsGoAgent.linux-link").symlink_to(good_a)
            self.assertEqual(
                module.aliyun_go_agent_binaries(home),
                [good_a, good_b],
            )

    def test_aliyun_go_remove_calls_stop_and_uninstall(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self.make_ctx(tmp)
            binary = Path(tmp) / "CmsGoAgent.linux-amd64"
            binary.write_text("fake", encoding="utf-8")
            with mock.patch.object(module, "aliyun_go_agent_binaries", return_value=[binary]), \
                 mock.patch.object(module, "stop_disable_unit"), \
                 mock.patch.object(module, "run_local_script", return_value=False), \
                 mock.patch.object(module, "safe_rmtree"), \
                 mock.patch.object(ctx.runner, "run", return_value=subprocess.CompletedProcess([], 0)) as run_mock:
                module.act_aliyun_monitor(ctx)
            commands = [call.args[0] for call in run_mock.call_args_list]
            self.assertIn([str(binary), "stop"], commands)
            self.assertIn([str(binary), "uninstall"], commands)

    def test_tencent_tat_uses_documented_github_url(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            "https://raw.githubusercontent.com/Tencent/tat-agent/main/install/uninstall.sh",
            source,
        )
        self.assertNotIn("tat-1258344699.cos.accelerate.myqcloud.com", source)

    def test_azure_extension_is_marked_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self.make_ctx(tmp)
            extension = Path(tmp) / "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.0"
            extension.mkdir()
            with mock.patch.object(module, "azure_monitor_extension_paths", return_value=[extension]), \
                 mock.patch.object(module, "stop_disable_unit"), \
                 mock.patch.object(module, "remove_package") as remove_package:
                module.act_azure_monitor(ctx)
            self.assertIn("azure.monitor-agent", ctx.incomplete)
            remove_package.assert_not_called()

    def test_gcp_plugin_architecture_units_are_covered(self) -> None:
        expected = {
            "google-guest-agent.service",
            "google-guest-agent-manager.service",
            "google-guest-compat-manager.service",
        }
        self.assertTrue(expected.issubset(set(module.RUNNING_UNITS["gcp.guest-agent"])))
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("/usr/bin/ggactl_plugin", source)


class CLITests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def test_version(self) -> None:
        result = self.run_cli("--version")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout.strip(), "2.0.1-alpha.1")

    def test_list_agents(self) -> None:
        result = self.run_cli("--list-agents")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("aliyun.assistant", result.stdout)
        self.assertIn("gcp.ops-agent", result.stdout)

    def test_audit_is_non_destructive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "audit.tsv"
            result = self.run_cli("--audit", "--provider", "aws", "--report", str(report))
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertTrue(report.is_file())
            self.assertIn("aws.ssm", report.read_text(encoding="utf-8"))

    def test_unknown_agent_is_rejected(self) -> None:
        result = self.run_cli("--audit", "--agent", "unknown.agent")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown agent", result.stdout)

    def test_invalid_vendor_hash_is_rejected(self) -> None:
        result = self.run_cli(
            "--audit", "--vendor-sha256", "tencent.tat=not-a-sha256"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("64-character hexadecimal", result.stdout)

    def test_core_agent_needs_explicit_flag(self) -> None:
        result = self.run_cli(
            "--remove", "--agent", "azure.linux-agent", "--dry-run", "--yes"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--include-core", result.stdout)

    def test_dry_run_change_does_not_require_root(self) -> None:
        result = self.run_cli(
            "--remove", "--agent", "aws.ssm", "--dry-run", "--yes"
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_source_has_no_unsafe_shell_execution(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        forbidden = ("shell=True", "os.system(", "eval(", "exec(", "http://")
        for text in forbidden:
            self.assertNotIn(text, source)


if __name__ == "__main__":
    unittest.main()
