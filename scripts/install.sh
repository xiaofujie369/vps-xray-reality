#!/bin/sh
set -eu

umask 077

REPOSITORY="https://github.com/xiaofujie369/vps-xray-reality.git"
INSTALL_ROOT="${ASN_REALITY_INSTALL_ROOT:-${HOME}/.local/share/asn-reality-audit}"
BIN_DIR="${ASN_REALITY_BIN_DIR:-${HOME}/.local/bin}"

find_python() {
    if [ -n "${PYTHON:-}" ]; then
        candidates="${PYTHON}"
    else
        candidates="python3.13 python3.12 python3.11 python3"
    fi
    for candidate in ${candidates}; do
        if command -v "${candidate}" >/dev/null 2>&1 && \
            "${candidate}" -c 'import sys, venv; raise SystemExit(sys.version_info < (3, 11))' >/dev/null 2>&1; then
            command -v "${candidate}"
            return 0
        fi
    done
    return 1
}

PYTHON_BIN="$(find_python || true)"
if [ -z "${PYTHON_BIN}" ]; then
    echo "ERROR: Python 3.11+ with the venv module is required." >&2
    echo "Debian/Ubuntu package hint: install python3.11 and python3.11-venv (or a newer version)." >&2
    exit 1
fi

PYTHON_VERSION="$("${PYTHON_BIN}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if ! "${PYTHON_BIN}" -c 'import ensurepip' >/dev/null 2>&1; then
    echo "ERROR: ${PYTHON_BIN} cannot bootstrap pip because ensurepip is missing." >&2
    if command -v apt-get >/dev/null 2>&1; then
        echo "Install it, then rerun this script:" >&2
        echo "  apt-get update && apt-get install -y python${PYTHON_VERSION}-venv" >&2
    else
        echo "Install the venv/ensurepip package for Python ${PYTHON_VERSION}, then rerun this script." >&2
    fi
    exit 1
fi

if [ "${1:-}" = "--local" ]; then
    SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
    SOURCE="$(dirname -- "${SCRIPT_DIR}")"
else
    if ! command -v git >/dev/null 2>&1; then
        echo "ERROR: git is required for installation from GitHub." >&2
        exit 1
    fi
    SOURCE="git+${REPOSITORY}"
fi

mkdir -p "${INSTALL_ROOT}" "${BIN_DIR}"
if ! "${PYTHON_BIN}" -m venv "${INSTALL_ROOT}/venv"; then
    echo "ERROR: Failed to create the virtual environment with ${PYTHON_BIN}." >&2
    echo "Install the venv package for Python ${PYTHON_VERSION}, then rerun this script." >&2
    exit 1
fi
"${INSTALL_ROOT}/venv/bin/python" -m pip install --upgrade pip
"${INSTALL_ROOT}/venv/bin/python" -m pip install --upgrade "${SOURCE}"
ln -sfn "${INSTALL_ROOT}/venv/bin/asn-reality-audit" "${BIN_DIR}/asn-reality-audit"

echo "Installed: ${BIN_DIR}/asn-reality-audit"
if ! printf '%s' ":${PATH}:" | grep -F ":${BIN_DIR}:" >/dev/null 2>&1; then
    echo "Add ${BIN_DIR} to PATH, then run: asn-reality-audit --version"
fi
