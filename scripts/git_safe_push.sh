#!/usr/bin/env bash
# =============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX v101 — SAFE GIT PUSH UTILITY
# Purpose: Permanent elimination of non-fast-forward push failures
# Strategy: fetch → rebase → push with 4-attempt exponential backoff
# Usage:    source scripts/git_safe_push.sh && safe_git_push [commit_msg] [files...]
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# safe_git_push <commit_message> [file_patterns...]
# Stages specified file patterns, commits if changes exist, then push safely.
# ---------------------------------------------------------------------------
safe_git_push() {
  local commit_msg="${1:-"[sentinel] Auto-commit [skip ci]"}"
  shift || true
  local files=("$@")

  # ── 1. Abort any lingering rebase/merge state ───────────────────────────
  git rebase --abort 2>/dev/null || true
  git merge  --abort 2>/dev/null || true
  rm -f .git/MERGE_HEAD .git/CHERRY_PICK_HEAD .git/REVERT_HEAD 2>/dev/null || true

  # ── 2. Stage requested files (force-add to bypass .gitignore on data/) ──
  if [ "${#files[@]}" -gt 0 ]; then
    for pattern in "${files[@]}"; do
      git add -f "$pattern" 2>/dev/null || true
    done
  fi

  # ── 3. Only proceed if staged changes exist ─────────────────────────────
  if git diff --staged --quiet; then
    echo "[safe_push] No staged changes — nothing to commit."
    return 0
  fi

  # ── 4. Commit ────────────────────────────────────────────────────────────
  git commit -m "$commit_msg"

  # ── 5. Push with 4-attempt fetch+rebase backoff ─────────────────────────
  local max_attempts=4
  local attempt=0
  local pushed=false

  while [ $attempt -lt $max_attempts ]; do
    attempt=$((attempt + 1))

    # Fetch latest state
    git fetch origin main --quiet

    # Rebase our commit(s) on top of origin/main
    if git rebase origin/main --quiet; then
      : # rebase OK
    else
      echo "[safe_push] Rebase conflict on attempt $attempt — using ours strategy"
      git rebase --abort 2>/dev/null || true
      # Fallback: merge with ours preference
      git merge origin/main -X ours --no-edit --quiet 2>/dev/null || true
    fi

    # Attempt push
    if git push origin main --quiet; then
      echo "[safe_push] Push succeeded (attempt $attempt/$max_attempts)"
      pushed=true
      break
    fi

    local backoff=$((attempt * 15))
    echo "[safe_push] Push attempt $attempt/$max_attempts failed — retrying in ${backoff}s..."
    sleep "$backoff"
  done

  if [ "$pushed" = false ]; then
    echo "[safe_push] WARN: All $max_attempts push attempts failed — state committed locally."
    return 1
  fi
}

# ---------------------------------------------------------------------------
# safe_git_configure <name> <email> <token> <repo>
# One-shot git config + remote URL setup for CI environments.
# ---------------------------------------------------------------------------
safe_git_configure() {
  local bot_name="${1:-CDB-Sentinel-Bot}"
  local bot_email="${2:-sentinel@cyberdudebivash.com}"
  local gh_token="${3:-}"
  local repository="${4:-}"

  git config --local user.name  "$bot_name"
  git config --local user.email "$bot_email"

  if [ -n "$gh_token" ] && [ -n "$repository" ]; then
    git remote set-url origin "https://x-access-token:${gh_token}@github.com/${repository}"
  fi
}

# ---------------------------------------------------------------------------
# abort_rebase_state
# Emergency cleanup of any interrupted git operation.
# ---------------------------------------------------------------------------
abort_rebase_state() {
  git rebase --abort      2>/dev/null || true
  git merge  --abort      2>/dev/null || true
  rm -rf .git/rebase-merge  2>/dev/null || true
  rm -rf .git/rebase-apply  2>/dev/null || true
  rm -f  .git/MERGE_HEAD    2>/dev/null || true
  rm -f  .git/CHERRY_PICK_HEAD 2>/dev/null || true
  rm -f  .git/REVERT_HEAD   2>/dev/null || true
  echo "[abort_rebase] Git state cleaned."
}
