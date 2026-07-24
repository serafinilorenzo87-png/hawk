#!/usr/bin/env bash
# HAWK — setup raw-socket capabilities for nmap/masscan
#
# Run this ONCE after installing HAWK (or after `apt upgrade` replaces
# the nmap/masscan binary — capabilities do not survive package upgrades).
#
# What it does:
#   - Grants nmap & masscan the capabilities they need for SYN scans
#     (cap_net_raw, cap_net_admin, cap_net_bind_service) without requiring
#     `sudo`.
#   - HAWK auto-detects these caps and drops the `sudo` prefix, which
#     fixes the real-time progress bar (sudo's pty relay otherwise
#     buffers nmap's --stats-every output until the scan ends).
#
# Reversing:
#   sudo setcap -r $(which nmap)
#   sudo setcap -r $(which masscan)

set -e

GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

info()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
error() { echo -e "${RED}[✗]${RESET} $*" >&2; }

if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
    info "This script needs sudo to call setcap. Asking for your password…"
fi

CAPS="cap_net_raw,cap_net_admin,cap_net_bind_service+eip"
TARGETS=(nmap masscan)
FAILED=0

for bin in "${TARGETS[@]}"; do
    path=$(command -v "$bin" || true)
    if [[ -z $path ]]; then
        warn "$bin not found on PATH — skipping (install with \`apt install $bin\` if you use it)."
        continue
    fi

    # Resolve symlinks — setcap must be applied to the real file
    real=$(readlink -f "$path")

    if sudo setcap "$CAPS" "$real"; then
        info "$bin   ($real)  →  $CAPS"
    else
        error "Failed to set caps on $real"
        FAILED=1
    fi
done

echo ""
if [[ $FAILED -eq 0 ]]; then
    info "Done. HAWK will now run nmap/masscan without sudo — progress bars"
    info "will update in real time. No action needed on restart."
else
    error "One or more binaries could not be configured. Re-run with sudo or check that the filesystem supports capabilities (ext4/xfs do; some tmpfs mounts don't)."
    exit 1
fi
