#!/usr/bin/env bash
#
# so-set-extract-limit.sh
#
# Sets Zeek's FileExtract::default_limit in Security Onion by overriding
# extract.zeek in the local Salt tree. This governs how many bytes Zeek WRITES
# to disk per extracted file — it is a truncation limit on the artifact, not a
# scan limit. Strelka scans whatever lands on disk, so a payload past the limit
# is never carved and never seen.
#
# Usage:
#   sudo ./so-set-extract-limit.sh 100M          # set limit, prompt to confirm
#   sudo ./so-set-extract-limit.sh 100M -y       # no prompt
#   sudo ./so-set-extract-limit.sh --dry-run 100M
#   sudo ./so-set-extract-limit.sh --show        # report current state only
#   sudo ./so-set-extract-limit.sh --verify      # look for truncated artifacts
#
# Never edits the default Salt tree. Backs up the local copy before each change.
#
set -euo pipefail

DEFAULT_ROOT="/opt/so/saltstack/default/salt/zeek/policy"
LOCAL_ROOT="/opt/so/saltstack/local/salt/zeek/policy"
EXTRACT_DIR="/nsm/zeek/extracted/complete"
STRELKA_BACKEND="/opt/so/conf/strelka/backend/backend.yaml"
STOCK_LIMIT=9000000

RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; DIM=$'\033[2m'; RST=$'\033[0m'

die()  { printf '%serror:%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
warn() { printf '%swarn:%s  %s\n' "$YEL" "$RST" "$*" >&2; }
ok()   { printf '%s ok:%s   %s\n' "$GRN" "$RST" "$*"; }
info() { printf '        %s\n' "$*"; }

# ---------------------------------------------------------------- size parsing

parse_size() {
    local in num unit
    in="$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
    if [[ "$in" =~ ^([0-9]+)(K|M|G)?B?$ ]]; then
        num="${BASH_REMATCH[1]}"; unit="${BASH_REMATCH[2]:-}"
        case "$unit" in
            K) echo $(( num * 1024 )) ;;
            M) echo $(( num * 1024 * 1024 )) ;;
            G) echo $(( num * 1024 * 1024 * 1024 )) ;;
            *) echo "$num" ;;
        esac
    else
        return 1
    fi
}

human() {
    local b=$1
    if   (( b >= 1073741824 )); then printf '%s (~%s GB)' "$b" "$(( b / 1073741824 ))"
    elif (( b >= 1048576 ));    then printf '%s (~%s MB)' "$b" "$(( b / 1048576 ))"
    elif (( b >= 1024 ));       then printf '%s (~%s KB)' "$b" "$(( b / 1024 ))"
    else printf '%s bytes' "$b"; fi
}

# ------------------------------------------------------------- file discovery

find_default_script() {
    local f
    f="$(find "$DEFAULT_ROOT" -type f -name 'extract.zeek' -path '*file-extraction*' 2>/dev/null | head -n1)"
    [[ -z "$f" ]] && f="$(find "$DEFAULT_ROOT" -type f -name 'extract.zeek' 2>/dev/null | head -n1)"
    [[ -z "$f" ]] && die "could not locate extract.zeek under $DEFAULT_ROOT (path may differ on this release)"
    printf '%s' "$f"
}

# Mirror the default path into the local tree, preserving the relative layout.
local_path_for() {
    local default_file="$1" rel
    rel="${default_file#$DEFAULT_ROOT/}"
    printf '%s/%s' "$LOCAL_ROOT" "$rel"
}

current_limit_in() {
    local f="$1"
    [[ -r "$f" ]] || return 1
    grep -oP 'FileExtract::default_limit\s*=\s*\K[0-9]+' "$f" 2>/dev/null | head -n1
}

# --------------------------------------------------- preflight: is redef live?

# default_limit only applies when the extract analyzer is attached WITHOUT an
# explicit per-file $extract_limit. If the script passes one, the argument wins
# and editing the redef changes nothing.
check_per_file_override() {
    local f="$1"
    if grep -q 'extract_limit' "$f"; then
        warn "extract.zeek references \$extract_limit:"
        grep -n 'extract_limit' "$f" | sed 's/^/          /' >&2
        warn "a per-file limit overrides default_limit — editing the redef may have no effect."
        warn "inspect the Files::add_analyzer call before relying on this script."
        return 1
    fi
    return 0
}

# ------------------------------------------------------------------- reporting

show_state() {
    local dflt local_f dv lv
    dflt="$(find_default_script)"
    local_f="$(local_path_for "$dflt")"

    printf '\nZeek extraction limit\n%s\n' "${DIM}---------------------${RST}"
    dv="$(current_limit_in "$dflt" || true)"
    info "default tree : $dflt"
    info "               ${dv:-<no redef found>}${dv:+  $(human "$dv" | sed 's/^[0-9]*//')}"

    if [[ -f "$local_f" ]]; then
        lv="$(current_limit_in "$local_f" || true)"
        info "local  tree : $local_f"
        info "               ${lv:-<no redef found>}${lv:+  $(human "$lv" | sed 's/^[0-9]*//')}"
        printf '\n'
        if [[ -n "${lv:-}" ]]; then
            ok "effective limit: $(human "$lv")  (local override active)"
        fi
    else
        printf '\n'
        info "local  tree : (no override — stock default in effect)"
        [[ -n "${dv:-}" ]] && ok "effective limit: $(human "$dv")"
    fi

    printf '\nStrelka scan limits %s\n' "${DIM}(second, independent ceiling)${RST}"
    printf '%s\n' "${DIM}-------------------${RST}"
    if [[ -r "$STRELKA_BACKEND" ]]; then
        info "$STRELKA_BACKEND"
        grep -nE 'limits|timeout|max_|size' "$STRELKA_BACKEND" 2>/dev/null \
            | sed 's/^/          /' || info "(no limit keys matched)"
    else
        info "$STRELKA_BACKEND not readable from here — check on the manager,"
        info "or via Administration -> Configuration -> strelka"
    fi
    printf '\n'
}

# Files sitting exactly at the cap are almost certainly truncated, not complete.
verify_artifacts() {
    local dflt local_f limit n=0 sz
    dflt="$(find_default_script)"
    local_f="$(local_path_for "$dflt")"
    limit="$(current_limit_in "$local_f" 2>/dev/null || current_limit_in "$dflt" || echo "$STOCK_LIMIT")"

    printf '\nChecking %s against a limit of %s\n\n' "$EXTRACT_DIR" "$(human "$limit")"
    [[ -d "$EXTRACT_DIR" ]] || die "$EXTRACT_DIR not found — wrong host, or nothing extracted yet"

    while IFS= read -r -d '' f; do
        sz="$(stat -c %s "$f")"
        if (( sz >= limit )); then
            printf '  %sTRUNCATED%s  %10s  %s\n' "$RED" "$RST" "$sz" "$f"
            n=$(( n + 1 ))
        fi
    done < <(find "$EXTRACT_DIR" -maxdepth 1 -type f -print0 2>/dev/null)

    if (( n == 0 )); then
        ok "no artifacts are sitting at the cap"
    else
        warn "$n artifact(s) at or above the limit — these were cut short before Strelka saw them"
    fi
    printf '\n'
    info "note: files failing Zeek validation never reach complete/ at all,"
    info "so an absent artifact and a truncated one are different failures."
    printf '\n'
}

# ----------------------------------------------------------------------- apply

apply_limit() {
    local new="$1" assume_yes="$2" dry="$3"
    local dflt local_f local_dir cur backup

    dflt="$(find_default_script)"
    local_f="$(local_path_for "$dflt")"
    local_dir="$(dirname "$local_f")"

    grep -q 'FileExtract::default_limit' "$dflt" \
        || die "no FileExtract::default_limit redef in $dflt — this script does not apply to your release"

    check_per_file_override "$dflt" || {
        [[ "$assume_yes" == "yes" ]] || die "aborting; re-run with -y to override this check"
        warn "continuing anyway (-y given)"
    }

    cur="$(current_limit_in "$local_f" 2>/dev/null || current_limit_in "$dflt")"

    printf '\n  source   : %s\n' "$dflt"
    printf '  override : %s\n' "$local_f"
    printf '  current  : %s\n' "$(human "$cur")"
    printf '  new      : %s\n\n' "$(human "$new")"

    if [[ "$cur" == "$new" && -f "$local_f" ]]; then
        ok "already set to $(human "$new") — nothing to do"
        return 0
    fi

    (( new > 1073741824 )) && warn "limit exceeds 1 GB; this applies to EVERY extracted file"
    (( new < 65536 ))      && warn "limit is very small; most files will be truncated"

    if [[ "$dry" == "yes" ]]; then
        info "${DIM}dry run — no changes written${RST}"
        return 0
    fi

    if [[ "$assume_yes" != "yes" ]]; then
        read -r -p "  Apply? [y/N] " reply
        [[ "$reply" =~ ^[Yy]$ ]] || { info "aborted"; return 1; }
    fi

    mkdir -p "$local_dir"

    if [[ -f "$local_f" ]]; then
        backup="${local_f}.bak.$(date +%Y%m%d-%H%M%S)"
        cp -p "$local_f" "$backup"
        info "backup: $backup"
    else
        cp -p "$dflt" "$local_f"
        info "seeded local override from default"
    fi

    sed -i -E "s/(FileExtract::default_limit[[:space:]]*=[[:space:]]*)[0-9]+/\1${new}/" "$local_f"

    local verify
    verify="$(current_limit_in "$local_f" || true)"
    [[ "$verify" == "$new" ]] || die "edit did not take — check $local_f by hand"

    ok "local override now reads $(human "$new")"
    printf '\n  Next:\n'
    info "1. SOC -> Administration -> Configuration -> Options -> Synchronize Grid"
    info "   (or: sudo salt-call state.apply zeek  on the affected node)"
    info "2. Re-send the test file"
    info "3. sudo $0 --verify"
    printf '\n'
    warn "raising this ceiling increases disk use in /nsm/zeek/extracted/ and"
    warn "hands Strelka larger files — watch for scanner timeouts on heavy YARA rules."
    printf '\n'
}

# ------------------------------------------------------------------------ main

usage() {
    awk 'NR>2 { if ($0 !~ /^#/) exit; sub(/^# ?/,""); print }' "$0"
    exit "${1:-0}"
}

for a in "$@"; do
    [[ "$a" == "-h" || "$a" == "--help" ]] && usage 0
done

[[ $EUID -eq 0 ]] || die "must run as root (needs the Salt tree)"

SIZE=""; ASSUME_YES="no"; DRY="no"; MODE="apply"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes)     ASSUME_YES="yes" ;;
        -n|--dry-run) DRY="yes" ;;
        --show)       MODE="show" ;;
        --verify)     MODE="verify" ;;
        -h|--help)    usage 0 ;;
        -*)           die "unknown option: $1" ;;
        *)            SIZE="$1" ;;
    esac
    shift
done

case "$MODE" in
    show)   show_state ;;
    verify) verify_artifacts ;;
    apply)
        [[ -n "$SIZE" ]] || { warn "no size given"; usage 1; }
        NEW="$(parse_size "$SIZE")" || die "bad size '$SIZE' (use bytes, or 100K / 100M / 1G)"
        apply_limit "$NEW" "$ASSUME_YES" "$DRY"
        ;;
esac
