#!/usr/bin/env bash
# Phase 0 item 0.4 — Create the fixed Drive folder skeleton (PDS Vol. 4 §5.1)
# in one or more continuity-plane Google accounts via rclone.
#
# SAFE BY DESIGN:
#   - Creates folders and one marker file only. Never deletes, moves, or
#     overwrites existing content (mkdir is a no-op on existing folders).
#   - Idempotent: re-running is harmless.
#
# PREREQUISITES (run on the operator's own machine, NOT in CI):
#   1. Install rclone: https://rclone.org/install/
#   2. For each account, create a Drive remote (browser OAuth):
#        rclone config create gdrive-control  drive scope=drive   # iambivash.bn
#        rclone config create gdrive-vault1   drive scope=drive   # bivashnayak.ai007
#        rclone config create gdrive-vault2   drive scope=drive   # cyberdudebivashpro
#        rclone config create gdrive-vault3   drive scope=drive   # bivashnayak.ai07
#        rclone config create gdrive-vault4   drive scope=drive   # bivashkumar521
#        rclone config create gdrive-vault5   drive scope=drive   # bivashan127001
#        rclone config create gdrive-cold     drive scope=drive   # bivash.kmr007
#      (each `config create` opens a browser to authorize that account)
#
# USAGE:
#   ./setup-google-drive-skeleton.sh gdrive-vault1            # one remote
#   ./setup-google-drive-skeleton.sh --all                    # all seven
#
set -euo pipefail

ROOT="CyberDudeBivash"
ALL_REMOTES=(gdrive-control gdrive-vault1 gdrive-vault2 gdrive-vault3 gdrive-vault4 gdrive-vault5 gdrive-cold)

# Fixed skeleton — identical in every account (PDS Vol. 4 §5.1).
# Each vault actively uses only the folders matching its role, but the
# identical skeleton lets any vault absorb another's role in DR (RB-5).
FOLDERS=(
  "_CATALOG"
  "Sentinel APEX/Threat Reports"
  "Sentinel APEX/IOC"
  "Sentinel APEX/Malware"
  "Sentinel APEX/CVE"
  "Sentinel APEX/YARA"
  "Sentinel APEX/Sigma"
  "Sentinel APEX/ATTACK"
  "AI Security Hub"
  "Products"
  "MSSP"
  "Marketing"
  "Research"
  "GitHub Backup"
  "Executive/Finance"
  "Executive/Legal"
  "Executive/HR"
  "Executive/Board"
  "Archive"
)

usage() { echo "usage: $0 <rclone-remote-name> | --all"; exit 1; }
[ $# -eq 1 ] || usage

if [ "$1" = "--all" ]; then
  REMOTES=("${ALL_REMOTES[@]}")
else
  REMOTES=("$1")
fi

command -v rclone >/dev/null || { echo "ERROR: rclone not installed"; exit 1; }

for REMOTE in "${REMOTES[@]}"; do
  echo "==> ${REMOTE}: creating skeleton under ${ROOT}/"
  rclone listremotes | grep -qx "${REMOTE}:" || { echo "ERROR: remote '${REMOTE}' not configured — see prerequisites"; exit 1; }

  for f in "${FOLDERS[@]}"; do
    rclone mkdir "${REMOTE}:${ROOT}/${f}"
    echo "    ok  ${ROOT}/${f}"
  done

  # Verification marker (Phase 0 tracker evidence, item 0.4)
  MARKER=$(mktemp)
  printf '{"skeleton_version":"pds-v1.0","created_by":"setup-google-drive-skeleton.sh","created_at":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${MARKER}"
  rclone copyto "${MARKER}" "${REMOTE}:${ROOT}/_CATALOG/skeleton-created.json"
  rm -f "${MARKER}"
  echo "    ok  ${ROOT}/_CATALOG/skeleton-created.json (marker)"
done

echo "DONE. Record completion in PHASE-0-EXECUTION-PLAN.md item 0.4."
