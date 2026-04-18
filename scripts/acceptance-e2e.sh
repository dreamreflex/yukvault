#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="${BIN_PATH:-$ROOT_DIR/yukvault}"
VAULT_PATH="${VAULT_PATH:-$ROOT_DIR/secrets.vault}"
CRED_PATH="${CRED_PATH:-${VAULT_PATH}.credid}"
MOUNT_PATH="${MOUNT_PATH:-$ROOT_DIR/test-mount}"
TEST_FILE_REL="${TEST_FILE_REL:-hello.txt}"
TEST_FILE_CONTENT="${TEST_FILE_CONTENT:-yukvault acceptance $(date -u +%Y%m%dT%H%M%SZ)}"
SIZE="${SIZE:-256M}"
FS_TYPE="${FS_TYPE:-ext4}"
WITH_RECOVERY="${WITH_RECOVERY:-0}"
RECOVERY_KEY="${RECOVERY_KEY:-}"
KEEP_ARTIFACTS="${KEEP_ARTIFACTS:-0}"
NEED_CLEANUP=0

log() {
  printf '[acceptance] %s\n' "$*"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  }
}

is_mounted() {
  mountpoint -q "${MOUNT_PATH}"
}

unmount_mount_path() {
  if ! is_mounted; then
    return 0
  fi
  log "existing mount detected at ${MOUNT_PATH}, attempting to unmount it"
  if command -v fusermount >/dev/null 2>&1; then
    if fusermount -u "${MOUNT_PATH}"; then
      return 0
    fi
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo umount "${MOUNT_PATH}"
    return 0
  fi
  printf 'failed to unmount busy mount path: %s\n' "${MOUNT_PATH}" >&2
  return 1
}

remove_path_if_possible() {
  local path="$1"
  if [[ ! -e "${path}" ]]; then
    return 0
  fi
  rm -rf "${path}"
}

cleanup() {
  local status=$?
  if [[ "${NEED_CLEANUP}" != "1" ]]; then
    return "${status}"
  fi
  if [[ "${KEEP_ARTIFACTS}" == "1" ]]; then
    log "KEEP_ARTIFACTS=1, skipping artifact cleanup"
    return "${status}"
  fi
  unmount_mount_path || true
  remove_path_if_possible "${MOUNT_PATH}" || true
  remove_path_if_possible "${VAULT_PATH}" || true
  remove_path_if_possible "${CRED_PATH}" || true
  return "${status}"
}

run_cmd() {
  log "$*"
  "$@"
}

main() {
  require_cmd go
  require_cmd stat
  if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'this acceptance script currently supports Linux only\n' >&2
    exit 1
  fi

  log "repository root: ${ROOT_DIR}"
  log "binary path: ${BIN_PATH}"
  log "vault path: ${VAULT_PATH}"
  log "mount path: ${MOUNT_PATH}"

  if [[ -n "${YUKVAULT_FAKE_FIDO2:-}" ]]; then
    printf 'YUKVAULT_FAKE_FIDO2 is set, but the project no longer supports fake FIDO2 mode\n' >&2
    exit 1
  fi

  NEED_CLEANUP=1
  trap cleanup EXIT

  if command -v fuse2fs >/dev/null 2>&1; then
    log "mount strategy: fuse2fs"
  else
    require_cmd sudo
    log "mount strategy: sudo mount -o loop"
  fi

  unmount_mount_path
  remove_path_if_possible "${MOUNT_PATH}"
  remove_path_if_possible "${VAULT_PATH}"
  remove_path_if_possible "${CRED_PATH}"
  mkdir -p "${MOUNT_PATH}"

  pushd "${ROOT_DIR}" >/dev/null
  run_cmd /usr/local/go/bin/go test ./...
  run_cmd /usr/local/go/bin/go build -o "${BIN_PATH}" ./main.go

  init_args=("${BIN_PATH}" "init" "--vault" "${VAULT_PATH}" "--size" "${SIZE}" "--fs" "${FS_TYPE}")
  if [[ "${WITH_RECOVERY}" == "1" ]]; then
    init_args+=("--recover")
  fi
  log "initializing vault; interactive PIN/touch is expected"
  "${init_args[@]}"

  [[ -f "${VAULT_PATH}" ]] || { printf 'vault file was not created\n' >&2; exit 1; }
  [[ -f "${CRED_PATH}" ]] || { printf 'credential sidecar was not created\n' >&2; exit 1; }

  vault_mode="$(stat -c '%a' "${VAULT_PATH}")"
  cred_mode="$(stat -c '%a' "${CRED_PATH}")"
  [[ "${vault_mode}" == "600" ]] || { printf 'unexpected vault mode: %s\n' "${vault_mode}" >&2; exit 1; }
  [[ "${cred_mode}" == "600" ]] || { printf 'unexpected credid mode: %s\n' "${cred_mode}" >&2; exit 1; }

  log "opening vault; interactive PIN/touch is expected"
  "${BIN_PATH}" open --vault "${VAULT_PATH}" --mount "${MOUNT_PATH}"

  [[ -d "${MOUNT_PATH}" ]] || { printf 'mount path does not exist after open\n' >&2; exit 1; }
  printf '%s\n' "${TEST_FILE_CONTENT}" > "${MOUNT_PATH}/${TEST_FILE_REL}"
  sync

  log "closing vault; interactive PIN/touch may be expected"
  "${BIN_PATH}" close --vault "${VAULT_PATH}" --mount "${MOUNT_PATH}"

  log "re-opening vault to verify persisted content"
  "${BIN_PATH}" open --vault "${VAULT_PATH}" --mount "${MOUNT_PATH}"
  diff -u <(printf '%s\n' "${TEST_FILE_CONTENT}") "${MOUNT_PATH}/${TEST_FILE_REL}"
  "${BIN_PATH}" close --vault "${VAULT_PATH}" --mount "${MOUNT_PATH}"

  if [[ "${WITH_RECOVERY}" == "1" ]]; then
    if [[ -z "${RECOVERY_KEY}" ]]; then
      printf 'WITH_RECOVERY=1 requires RECOVERY_KEY to be provided explicitly\n' >&2
      exit 1
    fi
    log "opening vault through recovery flow"
    "${BIN_PATH}" recover --vault "${VAULT_PATH}" --mount "${MOUNT_PATH}" --key "${RECOVERY_KEY}"
    diff -u <(printf '%s\n' "${TEST_FILE_CONTENT}") "${MOUNT_PATH}/${TEST_FILE_REL}"
    "${BIN_PATH}" close --vault "${VAULT_PATH}" --mount "${MOUNT_PATH}"
  fi

  popd >/dev/null
  NEED_CLEANUP=0
  cleanup
  log "acceptance flow completed successfully"
}

main "$@"
