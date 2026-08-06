# Changelog

## 2.0.1-alpha.1 - 2026-08-06

- Corrected Alibaba CloudMonitor Go-agent stop and uninstall handling.
- Replaced the Tencent TAT fallback with the currently documented HTTPS uninstaller location.
- Distinguished local Azure Monitor package removal from Azure extension removal.
- Added detection for the newer GCE guest-agent manager, compatibility manager, and core plugin architecture.
- Required SHA-256 pinning for unattended vendor-script execution.
- Added explicit independent-project, trademark, and authorization notices.

## 2.0.0 - 2026-08-06

- Renamed and redesigned the project as `cloud-agent-cleaner`.
- Replaced the Alibaba-only script with a standard-library Python implementation.
- Added six-provider, seventeen-Agent detection registry.
- Added audit, disable, remove, provider/category/exact-Agent selection, dry-run, TSV report, logging, backup manifest, and post-action verification.
- Added protected core Guest Agents requiring `--include-core`.
- Added opt-in, HTTPS-only bounded vendor script downloads with SHA-256 output.
- Added Chinese/English documentation, threat model, source matrix, tests, and GitHub Actions.
