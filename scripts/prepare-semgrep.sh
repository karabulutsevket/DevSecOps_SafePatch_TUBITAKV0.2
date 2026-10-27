#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p .runtime/uv .runtime/uv-cache .runtime/python-linux
tar -xzf .runtime/uv.tar.gz -C .runtime/uv --strip-components=1
export UV_CACHE_DIR="$PWD/.runtime/uv-cache"
export UV_PYTHON_INSTALL_DIR="$PWD/.runtime/python-linux"
.runtime/uv/uv venv --python 3.12 .runtime/semgrep-venv
.runtime/uv/uv pip install --python .runtime/semgrep-venv/bin/python semgrep==1.136.0 setuptools==80.9.0
.runtime/semgrep-venv/bin/semgrep --version
