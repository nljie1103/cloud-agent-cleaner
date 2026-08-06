#!/usr/bin/env bash
set -Eeuo pipefail

REPO="nljie1103/cloud-agent-cleaner"
ARCHIVE="https://github.com/${REPO}/archive/refs/heads/main.tar.gz"
WORKDIR="$(mktemp -d -t cloud-agent-cleaner.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[ERROR] 仅支持 Linux。" >&2
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] 请使用 sudo 执行此命令。" >&2
  exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "[ERROR] 未找到 python3。" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "[ERROR] 未找到 tar。" >&2; exit 1; }

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$ARCHIVE" -o "$WORKDIR/source.tar.gz"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$WORKDIR/source.tar.gz" "$ARCHIVE"
else
  echo "[ERROR] 需要 curl 或 wget。" >&2
  exit 1
fi

tar -xzf "$WORKDIR/source.tar.gz" -C "$WORKDIR"
PROJECT_DIR="$(find "$WORKDIR" -mindepth 1 -maxdepth 1 -type d -name 'cloud-agent-cleaner-*' | head -n 1)"
if [[ -z "$PROJECT_DIR" || ! -f "$PROJECT_DIR/cloud_agent_cleaner.py" ]]; then
  echo "[ERROR] 下载内容不完整。" >&2
  exit 1
fi

cd "$PROJECT_DIR"
python3 cloud_agent_cleaner.py --quick
