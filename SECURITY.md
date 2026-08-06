# Security Policy

## Supported version

Only the latest tagged release is actively maintained.

## Reporting a vulnerability

Please do not publish a working destructive bypass, path traversal, unsafe package match, command injection, or privilege-escalation issue before maintainers have had a reasonable opportunity to fix it.

Open a private GitHub Security Advisory and include:

- affected version and Linux distribution;
- exact command and output;
- whether `--dry-run` was used;
- the detected Agent and installation method;
- a minimal reproduction;
- the expected safe behavior.

Do not include cloud credentials, access tokens, server addresses, tenant IDs, or private logs.

## Design requirements for patches

Changes must preserve these rules:

- no shell interpolation of untrusted values;
- no `curl | sh` or equivalent;
- no recursive deletion outside a reviewed allowlist;
- no broad process/package match based only on a provider name;
- core Agent modification must remain opt-in;
- external downloads must remain opt-in, HTTPS-only, bounded, and hashed;
- audit must remain usable without root.
