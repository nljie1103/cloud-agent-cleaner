# cloud-agent-cleaner 2.0.1-alpha.1

This alpha release corrects overstatements in 2.0.0 and tightens platform-specific removal behavior.

## Fixed

- Alibaba CloudMonitor Go binaries are stopped and unregistered before the installation directory is removed.
- Tencent TAT uses the uninstall URL documented by Tencent Cloud.
- Azure Monitor VM extensions are no longer represented as fully removable from inside the guest. The tool returns an incomplete status and prints the supported Azure CLI command.
- GCE guest-agent detection covers the 2025+ plugin architecture and no longer treats the broader `google-compute-engine` package as residual agent evidence.
- Unattended vendor-script execution now requires an explicit SHA-256 pin.

## Release status

Alpha. Run `--audit` and `--dry-run` first. Keep a current snapshot and an independent recovery channel.
