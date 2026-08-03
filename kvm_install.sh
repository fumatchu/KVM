#!/usr/bin/env bash
#
# Rocky Linux KVM Host Builder
# Standalone replacement for fumatchu/KVM kvm_install.sh
#
# Key networking behavior:
#   - Native/untagged management network is placed on br<NATIVE_VLAN>
#   - Cockpit and SSH use the management IP on that native bridge
#   - Tagged VLAN interfaces use explicit names such as enp86s0.10
#   - Every tagged VLAN is attached directly to a matching bridge such as br10
#   - Cockpit therefore displays br10, br18, br20, etc., not nm-bridge1
#   - No orphan bridge-slave-vlanXX profiles are created
#
# Run only from a local console or with out-of-band access available.
# The final network cutover will interrupt an SSH session.

set -Eeuo pipefail

readonly SCRIPT_VERSION="2.4.0"
readonly LOG_FILE="/var/log/kvm_builder.log"
readonly NETWORK_LOG="/var/log/kvm_vlan_setup.log"

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
RESET="\033[0m"

TMP_FILES=()

cleanup() {
    local file
    for file in "${TMP_FILES[@]:-}"; do
        [[ -n "$file" ]] && rm -f "$file"
    done
}
trap cleanup EXIT

log() {
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG_FILE" >/dev/null
}

die() {
    local message="$1"
    log "ERROR: $message"
    if command -v dialog >/dev/null 2>&1; then
        dialog --title "Error" --msgbox "$message\n\nLog: $LOG_FILE" 10 72
    else
        printf 'ERROR: %s\n' "$message" >&2
    fi
    exit 1
}

run() {
    log "RUN: $*"
    "$@" >>"$LOG_FILE" 2>&1
}

require_root() {
    (( EUID == 0 )) || die "This installer must be run as root."
}

require_rocky() {
    [[ -r /etc/os-release ]] || die "Unable to read /etc/os-release."
    # shellcheck disable=SC1091
    source /etc/os-release

    [[ "${ID:-}" == "rocky" ]] || die "This installer supports Rocky Linux only."

    local major="${VERSION_ID%%.*}"
    [[ "$major" =~ ^[0-9]+$ ]] || die "Unable to determine Rocky Linux version."
    (( major >= 9 )) || die "Rocky Linux 9 or newer is required."

    log "Detected Rocky Linux ${VERSION_ID}."
}

install_dialog_early() {
    if ! command -v dialog >/dev/null 2>&1; then
        dnf -y install dialog >>"$LOG_FILE" 2>&1 || {
            printf 'Unable to install dialog. See %s\n' "$LOG_FILE" >&2
            exit 1
        }
    fi
}

validate_ipv4() {
    local ip="$1" IFS=. octet
    read -r -a octets <<<"$ip"
    [[ ${#octets[@]} -eq 4 ]] || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( octet >= 0 && octet <= 255 )) || return 1
    done
}

validate_cidr() {
    local cidr="$1" ip prefix
    [[ "$cidr" == */* ]] || return 1
    ip="${cidr%/*}"
    prefix="${cidr#*/}"
    validate_ipv4 "$ip" || return 1
    [[ "$prefix" =~ ^[0-9]+$ ]] || return 1
    (( prefix >= 0 && prefix <= 32 ))
}

validate_vlan() {
    local vlan="$1"
    [[ "$vlan" =~ ^[0-9]+$ ]] || return 1
    (( 10#$vlan >= 1 && 10#$vlan <= 4094 ))
}

validate_fqdn() {
    local name="$1"
    [[ "$name" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] &&
        [[ "$name" == *.* ]]
}

show_welcome() {
    dialog --title "Rocky KVM Builder ${SCRIPT_VERSION}" --msgbox \
"Rocky Linux KVM Host Builder

This installer configures:

 • KVM, libvirt, Cockpit and supporting packages
 • Chrony NTP
 • Fail2Ban
 • A native/untagged management bridge
 • Explicit VLAN bridges named br10, br20, br30, and so on

IMPORTANT:
The final network cutover interrupts connectivity.
Use a local console or ensure out-of-band access is available." 18 78
}

detect_active_management() {
    MGMT_DEVICE=$(ip -4 route show default | awk 'NR==1 {print $5}')
    MGMT_GATEWAY=$(ip -4 route show default | awk 'NR==1 {print $3}')

    [[ -n "${MGMT_DEVICE:-}" ]] || die "No IPv4 default-route interface was found."

    MGMT_CONNECTION=$(nmcli -t -f NAME,DEVICE connection show --active |
        awk -F: -v dev="$MGMT_DEVICE" '$2 == dev {print $1; exit}')

    [[ -n "${MGMT_CONNECTION:-}" ]] ||
        die "No active NetworkManager profile was found for $MGMT_DEVICE."

    MGMT_ADDRESS=$(nmcli -g ipv4.addresses connection show "$MGMT_CONNECTION" |
        sed '/^$/d' | head -n1)

    [[ -n "$MGMT_ADDRESS" ]] ||
        MGMT_ADDRESS=$(ip -4 -o addr show dev "$MGMT_DEVICE" scope global |
            awk '{print $4; exit}')

    MGMT_DNS=$(nmcli -g ipv4.dns connection show "$MGMT_CONNECTION" |
        sed '/^$/d' | paste -sd, -)

    MGMT_SEARCH=$(nmcli -g ipv4.dns-search connection show "$MGMT_CONNECTION" |
        sed '/^$/d' | paste -sd, -)

    MGMT_METHOD=$(nmcli -g ipv4.method connection show "$MGMT_CONNECTION" |
        tr -d '[:space:]')

    log "Management device: $MGMT_DEVICE"
    log "Management profile: $MGMT_CONNECTION"
    log "Management address: ${MGMT_ADDRESS:-none}"
    log "Management gateway: ${MGMT_GATEWAY:-none}"
}

configure_static_ip_if_needed() {
    if [[ "$MGMT_METHOD" == "manual" && -n "$MGMT_ADDRESS" && -n "$MGMT_GATEWAY" ]]; then
        dialog --title "Static Management Address" --infobox \
            "Using existing static address:\n\n$MGMT_ADDRESS via $MGMT_GATEWAY" 8 60
        sleep 2
        return
    fi

    local tmp
    tmp=$(mktemp)
    TMP_FILES+=("$tmp")

    while true; do
        dialog --title "Static Management Address" --inputbox \
            "Enter the static host address in CIDR format:" 8 62 \
            "${MGMT_ADDRESS:-}" 2>"$tmp" || exit 1
        MGMT_ADDRESS=$(<"$tmp")
        validate_cidr "$MGMT_ADDRESS" && break
        dialog --msgbox "Invalid IPv4 CIDR address." 6 45
    done

    while true; do
        dialog --title "Default Gateway" --inputbox \
            "Enter the IPv4 default gateway:" 8 62 \
            "${MGMT_GATEWAY:-}" 2>"$tmp" || exit 1
        MGMT_GATEWAY=$(<"$tmp")
        validate_ipv4 "$MGMT_GATEWAY" && break
        dialog --msgbox "Invalid IPv4 address." 6 45
    done

    dialog --title "DNS Servers" --inputbox \
        "Enter comma-separated DNS servers:" 8 62 \
        "${MGMT_DNS:-1.1.1.1,8.8.8.8}" 2>"$tmp" || exit 1
    MGMT_DNS=$(<"$tmp")

    dialog --title "DNS Search Domain" --inputbox \
        "Enter the DNS search suffix, or leave blank:" 8 62 \
        "${MGMT_SEARCH:-}" 2>"$tmp" || exit 1
    MGMT_SEARCH=$(<"$tmp")

    run nmcli connection modify "$MGMT_CONNECTION" \
        ipv4.method manual \
        ipv4.addresses "$MGMT_ADDRESS" \
        ipv4.gateway "$MGMT_GATEWAY"

    [[ -n "$MGMT_DNS" ]] &&
        run nmcli connection modify "$MGMT_CONNECTION" ipv4.dns "$MGMT_DNS"
    [[ -n "$MGMT_SEARCH" ]] &&
        run nmcli connection modify "$MGMT_CONNECTION" ipv4.dns-search "$MGMT_SEARCH"

    run nmcli connection modify "$MGMT_CONNECTION" ipv4.ignore-auto-dns yes
}

configure_hostname() {
    local current tmp proposed
    current=$(hostnamectl --static 2>/dev/null || hostname)

    if [[ "$current" != "localhost" && "$current" != "localhost.localdomain" && "$current" == *.* ]]; then
        dialog --title "Hostname" --infobox "Using hostname: $current" 6 60
        sleep 2
        return
    fi

    tmp=$(mktemp)
    TMP_FILES+=("$tmp")

    while true; do
        dialog --title "Hostname" --inputbox \
            "Enter the host FQDN, for example kvm01.home.int:" 8 65 \
            "$current" 2>"$tmp" || exit 1
        proposed=$(<"$tmp")
        validate_fqdn "$proposed" && break
        dialog --msgbox "Enter a valid fully qualified hostname." 6 52
    done

    run hostnamectl set-hostname "$proposed"
}

configure_selinux() {
    local status
    status=$(getenforce 2>/dev/null || true)

    case "$status" in
        Enforcing)
            log "SELinux is enforcing."
            ;;
        Permissive)
            sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
            run setenforce 1
            ;;
        Disabled)
            sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
            dialog --title "SELinux" --msgbox \
                "SELinux was disabled. It has been set to enforcing for the next boot." 7 68
            ;;
        *)
            log "Unable to determine SELinux status."
            ;;
    esac
}

install_packages() {
    # Original repository progress behavior preserved.
    dialog --title "Repository Setup" --gauge "Enabling EPEL and CRB repositories..." 10 60 0 < <(
        (
            (
                dnf install -y epel-release >/dev/null 2>&1
                dnf config-manager --set-enabled crb >/dev/null 2>&1
            ) &
            PID=$!
            PROGRESS=0
            while kill -0 "$PID" 2>/dev/null; do
                echo "$PROGRESS"
                echo "XXX"
                echo "Enabling EPEL and CRB..."
                echo "XXX"
                ((PROGRESS += 5))
                if [[ $PROGRESS -ge 95 ]]; then
                    PROGRESS=5
                fi
                sleep 0.5
            done
            echo "100"
            echo "XXX"
            echo "Repositories enabled."
            echo "XXX"
        )
    )

    # System update: tailing dnf's own transcript for a single combined
    # "dnf -y upgrade" transaction (the previous approach) ties the gauge to
    # dnf/rpm's own stdout timing, which can lag or batch for reasons
    # entirely outside our control - the gauge label ends up several
    # packages behind reality, looks "frozen," then catches up all at once.
    # Confirmed on this hardware with two different packages landing at the
    # same ~52% mark, which rules out a single slow package and points at
    # the tailing approach itself.
    #
    # Instead, use the same pattern proven working in fumatchu/RADS_WEB:
    # precompute the exact list of packages that need upgrading with
    # `dnf repoquery --upgrades`, then upgrade them one at a time, printing
    # the gauge line for each package BEFORE calling dnf on it. The
    # displayed package/percentage is then always in lockstep with what is
    # about to run, not dependent on dnf's own output reappearing in time.
    local update_pipe update_gauge_pid pkg upd_count upd_total upd_pct
    local -a UPDATE_LIST

    printf 'Checking for available updates...\n' | tee -a "$LOG_FILE" >/dev/null
    dnf -q makecache >>"$LOG_FILE" 2>&1 || true

    # fwupd/fwupd-efi are excluded: a KVM hypervisor host has no real need
    # for firmware-update tooling, and it removes any chance of its
    # UEFI-NVRAM-touching scriptlet adding a genuinely long single-package
    # step to this list.
    mapfile -t UPDATE_LIST < <(dnf -q repoquery --upgrades --qf '%{name}' 2>/dev/null | grep -v '^fwupd' | sort -u)
    upd_total=${#UPDATE_LIST[@]}

    if (( upd_total == 0 )); then
        log "No packages require updating."
    else
        update_pipe=$(mktemp -u)
        mkfifo "$update_pipe"

        dialog --title "System Update" \
            --gauge "Starting system update..." 10 74 0 <"$update_pipe" &
        update_gauge_pid=$!

        exec 3>"$update_pipe"
        upd_count=0
        for pkg in "${UPDATE_LIST[@]}"; do
            upd_count=$((upd_count + 1))
            upd_pct=$(( upd_count * 100 / upd_total ))
            printf '%s\nXXX\nUpgrading: %s (%s of %s)\nXXX\n' \
                "$upd_pct" "$pkg" "$upd_count" "$upd_total" >&3
            log "dnf: Upgrading $pkg ($upd_count/$upd_total)"
            dnf -y -q upgrade --best --allowerasing "$pkg" >>"$LOG_FILE" 2>&1 || true
        done
        printf '100\nXXX\nSystem update complete.\nXXX\n' >&3
        exec 3>&-

        wait "$update_gauge_pid" 2>/dev/null || true
        rm -f "$update_pipe"
    fi

    dialog --title "Package Installation" --infobox \
        "Installing Required Packages..." 5 50
    sleep 2

    PACKAGE_LIST=(
        "lsof"
        "ntsysv"
        "rsync"
        "fail2ban"
        "tuned"
        "qemu-kvm"
        "libvirt"
        "virt-install"
        "virt-manager"
        "virt-viewer"
        "cockpit"
        "cockpit-storaged"
        "cockpit-machines"
        "cockpit-files"
        "net-tools"
        "dmidecode"
        "ipcalc"
        "bind-utils"
        "zip"
        "dnf-plugins-core"
        "curl"
        "wget"
        "dnf-automatic"
        "chrony"
        "smartmontools"
        "nvme-cli"
    )

    TOTAL_PACKAGES=${#PACKAGE_LIST[@]}
    PIPE=$(mktemp -u)
    mkfifo "$PIPE"

    dialog --title "Installing Required Packages" \
        --gauge "Preparing to install packages..." 10 70 0 < "$PIPE" &

    exec 3>"$PIPE"
    COUNT=0

    for PACKAGE in "${PACKAGE_LIST[@]}"; do
        COUNT=$((COUNT + 1))

        PERCENT=$(( (COUNT * 100) / TOTAL_PACKAGES ))

        echo "$PERCENT" >&3
        echo "XXX" >&3
        echo "Installing: $PACKAGE" >&3
        echo "XXX" >&3

        if ! dnf -y install "$PACKAGE" >>"$LOG_FILE" 2>&1; then
            exec 3>&-
            rm -f "$PIPE"
            die "Package installation failed for '$PACKAGE'. Review $LOG_FILE."
        fi
    done

    exec 3>&-
    rm -f "$PIPE"

    dialog --title "Installation Complete" --infobox \
        "All packages installed successfully!" 6 50
    sleep 3
}

configure_ntp() {
    local tmp input server
    tmp=$(mktemp)
    TMP_FILES+=("$tmp")

    dialog --title "Chrony NTP" --inputbox \
        "Enter up to three comma-separated NTP servers:" 9 70 \
        "pool.ntp.org" 2>"$tmp" || return 0
    input=$(<"$tmp")

    [[ -n "$input" ]] || return 0

    cp -a /etc/chrony.conf "/etc/chrony.conf.bak.$(date +%Y%m%d-%H%M%S)"
    sed -i '/^[[:space:]]*\(server\|pool\)[[:space:]]/d' /etc/chrony.conf

    IFS=',' read -r -a servers <<<"$input"
    for server in "${servers[@]}"; do
        server=$(echo "$server" | xargs)
        [[ -n "$server" ]] && printf 'server %s iburst\n' "$server" >>/etc/chrony.conf
    done

    run systemctl enable --now chronyd
    run systemctl restart chronyd
}

configure_fail2ban() {
    mkdir -p /etc/fail2ban/jail.d

    cat >/etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
maxretry = 5
findtime = 300
bantime = 3600
bantime.increment = true
bantime.factor = 2
EOF

    restorecon -RFv /etc/fail2ban >>"$LOG_FILE" 2>&1 || true
    run systemctl enable --now fail2ban
}

enable_services() {
    run systemctl enable --now libvirtd
    run systemctl enable --now cockpit.socket
    run systemctl enable --now tuned
    run tuned-adm profile virtual-host
}

offer_home_reclaim() {
    local home_source home_lv root_source root_lv root_fs
    local backup fstab_backup fstab_tmp timestamp vg_free_before
    local home_uuid=""

    home_source=$(findmnt -n -o SOURCE --target /home 2>/dev/null || true)
    [[ -n "$home_source" ]] || return 0

    # Resolve UUID=/LABEL=/mapper aliases to the canonical block device.
    home_lv=$(findmnt -n -o SOURCE --evaluate --target /home 2>/dev/null || true)
    [[ -n "$home_lv" ]] || home_lv="$home_source"
    home_lv=$(readlink -f "$home_lv" 2>/dev/null || printf '%s' "$home_lv")

    # Determine whether the canonical /home device belongs to LVM.
    local matched_home_lv=""
    while IFS= read -r candidate; do
        candidate=$(echo "$candidate" | xargs)
        [[ -n "$candidate" ]] || continue
        if [[ "$(readlink -f "$candidate" 2>/dev/null || printf '%s' "$candidate")" == "$home_lv" ]]; then
            matched_home_lv="$candidate"
            break
        fi
    done < <(lvs --noheadings -o lv_path 2>/dev/null)

    if [[ -z "$matched_home_lv" ]]; then
        log "/home is not on an LVM logical volume ($home_source -> $home_lv); skipping reclaim."
        dialog --title "Home Reclaim Skipped" --msgbox \
"/home is mounted from:
  $home_source

This is not an LVM logical volume, so the automatic /home reclaim
feature does not apply here. No changes were made." 11 72
        return 0
    fi
    home_lv="$matched_home_lv"

    root_source=$(findmnt -n -o SOURCE --target /)
    root_lv=$(findmnt -n -o SOURCE --evaluate --target / 2>/dev/null || true)
    [[ -n "$root_lv" ]] || root_lv="$root_source"
    root_lv=$(readlink -f "$root_lv" 2>/dev/null || printf '%s' "$root_lv")
    root_fs=$(findmnt -n -o FSTYPE --target /)

    local matched_root_lv=""
    while IFS= read -r candidate; do
        candidate=$(echo "$candidate" | xargs)
        [[ -n "$candidate" ]] || continue
        if [[ "$(readlink -f "$candidate" 2>/dev/null || printf '%s' "$candidate")" == "$root_lv" ]]; then
            matched_root_lv="$candidate"
            break
        fi
    done < <(lvs --noheadings -o lv_path 2>/dev/null)

    if [[ -z "$matched_root_lv" ]]; then
        log "Root filesystem is not on LVM ($root_source -> $root_lv); skipping /home reclaim."
        dialog --title "Home Reclaim Skipped" --msgbox \
"Root filesystem is mounted from:
  $root_source

This is not an LVM logical volume, so /home cannot be reclaimed into
it automatically. No changes were made." 11 72
        return 0
    fi
    root_lv="$matched_root_lv"

    if [[ "$home_lv" == "$root_lv" ]]; then
        log "/home and / are already on the same logical volume; nothing to reclaim."
        dialog --title "Home Reclaim Skipped" --msgbox \
"/home and / already share the same logical volume:
  $home_lv

There is nothing separate to reclaim. No changes were made." 10 72
        return 0
    fi

    dialog --title "Optional LVM Reclaim" --yesno \
"/home is mounted from a separate LVM logical volume:

  Source: $home_source
  Device: $home_lv
  Root:   $root_lv

This operation will:

  1. Back up all /home data
  2. Remove the /home entry from /etc/fstab
  3. Unmount /home
  4. Remove the /home logical volume
  5. Extend the root logical volume
  6. Restore /home as a directory on root

Continue?" 20 78 || return 0

    timestamp=$(date +%Y%m%d-%H%M%S)
    backup="/root/home-backup-${timestamp}"
    fstab_backup="/etc/fstab.pre-home-reclaim-${timestamp}"
    fstab_tmp=$(mktemp)
    TMP_FILES+=("$fstab_tmp")

    mkdir -p "$backup"

    # Every recovery path below relies on this backup being valid, so treat
    # its failure as fatal before anything about /home is touched.
    if ! cp -a /etc/fstab "$fstab_backup"; then
        die "Failed to back up /etc/fstab to $fstab_backup. Nothing was changed; aborting."
    fi

    log "Backing up /home to $backup"
    if ! run rsync -aHAXS --numeric-ids /home/ "$backup/"; then
        die "Backup of /home to $backup failed. Nothing was changed; review $LOG_FILE."
    fi

    # Verify the backup before touching the mount or LV.
    if ! run rsync -aHAXSn --delete --numeric-ids /home/ "$backup/"; then
        die "Backup verification of /home against $backup failed. Nothing was changed; review $LOG_FILE."
    fi

    # Remove every active /home mount record by parsing fstab fields.
    # This works whether the source is UUID=, LABEL=, /dev/mapper/*, or /dev/*.
    awk '
        /^[[:space:]]*#/ || NF == 0 { print; next }
        $2 == "/home" { next }
        { print }
    ' /etc/fstab >"$fstab_tmp"

    if ! install -m 0644 "$fstab_tmp" /etc/fstab; then
        die "Failed to write the updated /etc/fstab from $fstab_tmp. Original fstab is still at $fstab_backup; /home was not touched."
    fi
    systemctl daemon-reload || true

    if findmnt --fstab --target /home >/dev/null 2>&1; then
        cp -a "$fstab_backup" /etc/fstab
        systemctl daemon-reload
        die "The /home entry could not be removed from /etc/fstab. Original fstab restored."
    fi

    # Refuse to continue when another mount exists beneath /home.
    if findmnt -R -n -o TARGET /home | tail -n +2 | grep -q .; then
        cp -a "$fstab_backup" /etc/fstab
        systemctl daemon-reload
        die "Nested mounts exist below /home. Original fstab restored; reclaim aborted."
    fi

    # Processes with their working directory or open files in /home can block unmount.
    if command -v fuser >/dev/null 2>&1 && fuser -m /home >/dev/null 2>&1; then
        cp -a "$fstab_backup" /etc/fstab
        systemctl daemon-reload
        die "Processes are using /home. Log users out and rerun. Original fstab restored."
    fi

    # Let any in-flight writeback/allocation work on /home settle before we
    # try to detach it. Backing up /home with rsync (backup pass, then the
    # -n --delete verify pass) touches every single file in the tree twice,
    # which on XFS spawns a large number of short-lived kernel worker
    # threads to do delayed-allocation conversion (xfs-conv/<dev>) and
    # per-inode writeback-cgroup reassignment (inode_switch_wbs). On a
    # /home with many files this backlog can run into the thousands of
    # queued work items and take well more than a couple of seconds to
    # drain - during which umount legitimately returns "device busy" even
    # though fuser/lsof show no real open handle, because the block device
    # itself is still active underneath. Poll for that backlog to actually
    # drain (or stop shrinking) instead of guessing a fixed delay.
    local home_devnode home_devname wb_pattern wb_count wb_prev=-1 wb_stable=0 wb_waited=0

    home_devnode=$(readlink -f "$home_lv" 2>/dev/null || true)
    home_devname="${home_devnode##*/}"

    if [[ -n "$home_devname" ]]; then
        wb_pattern="inode_switch_wbs|xfs-conv/${home_devname}"
        log "Waiting for XFS writeback/inode-switch backlog on $home_devname to settle before unmounting /home..."
        while (( wb_waited < 180 )); do
            wb_count=$(ps -eo comm= 2>/dev/null | grep -Ec -- "$wb_pattern" || true)
            log "  ...$wb_count matching kernel worker threads still running (${wb_waited}s elapsed)."
            (( wb_count == 0 )) && break
            if (( wb_count == wb_prev )); then
                (( wb_stable += 1 ))
                # No further progress for three consecutive checks in a row -
                # assume this is steady-state noise, not an active drain.
                (( wb_stable >= 3 )) && break
            else
                wb_stable=0
            fi
            wb_prev=$wb_count
            sleep 3
            wb_waited=$(( wb_waited + 3 ))
        done
    fi

    sync
    sleep 2

    # Do not let a failing umount kill the whole script here - under
    # set -e an unguarded failure would exit before the recovery check
    # below ever runs, silently skipping the fstab restore and leaving
    # every later step (including VLAN configuration) unreached. Let the
    # findmnt check below decide success or failure instead.
    #
    # Even after the backlog wait above, retry a handful of times with a
    # short pause instead of giving up on the very first EBUSY.
    local umount_attempt umount_ok=0
    for umount_attempt in 1 2 3 4 5; do
        if run umount /home; then
            umount_ok=1
            break
        fi
        log "umount /home attempt $umount_attempt failed (likely transient); retrying after a short pause."
        sync
        sleep 3
    done
    (( umount_ok )) || log "umount /home did not succeed after $umount_attempt attempts."

    # NOTE: this deliberately uses `mountpoint -q /home`, not
    # `findmnt --target /home`. findmnt --target resolves a path to
    # whatever filesystem currently backs it - once /home is successfully
    # unmounted it's just an empty directory on root, and findmnt happily
    # matches root and reports "mounted" anyway. That false positive was
    # the actual cause of every "still busy" failure seen so far: dmesg
    # confirmed XFS completed the unmount (its "Unmounting Filesystem" log
    # line only appears once the kernel has fully torn the mount down), and
    # there was exactly one umount attempt logged with no retries, meaning
    # it succeeded on the first try - the very next check just asked the
    # wrong question. mountpoint -q tests specifically "is this path its
    # own separate mount point right now," which is what we actually want.
    if mountpoint -q /home; then
        # Capture what's actually holding /home open right now, since
        # whatever is busy may clear up by the time anyone looks manually.
        # Every line here is individually guarded so a missing tool can
        # never again abort the script before the recovery/die below runs.
        {
            echo "===== /home still busy after umount - diagnostic capture ====="
            echo "--- fuser -mv /home ---"
            if command -v fuser >/dev/null 2>&1; then
                fuser -mv /home 2>&1 || true
            else
                echo "(fuser not installed)"
            fi
            echo "--- lsof +D /home ---"
            if command -v lsof >/dev/null 2>&1; then
                lsof +D /home 2>&1 || true
            else
                echo "(lsof not installed)"
            fi
            echo "--- logged in sessions (who) ---"
            who 2>&1 || true
            echo "--- recent kernel messages ---"
            dmesg 2>&1 | tail -50 || true
            echo "================================================================"
        } >>"$LOG_FILE" 2>&1 || true
        cp -a "$fstab_backup" /etc/fstab
        systemctl daemon-reload
        die "/home remained mounted after umount. Diagnostic details (fuser/lsof/who/dmesg) were written to $LOG_FILE - check the '/home still busy' section there for the actual process holding it open. Original fstab restored; /home was left mounted and untouched."
    fi

    home_uuid=$(blkid -s UUID -o value "$home_lv" 2>/dev/null || true)
    log "Removing /home LV $home_lv (UUID ${home_uuid:-unknown})."

    if ! run lvremove -y "$home_lv"; then
        cp -a "$fstab_backup" /etc/fstab
        systemctl daemon-reload
        mkdir -p /home
        mount /home >>"$LOG_FILE" 2>&1 || true
        die "Failed to remove logical volume $home_lv. Original fstab restored and /home remount attempted. Review $LOG_FILE."
    fi

    vg_free_before=$(vgs --noheadings --units b --nosuffix -o vg_free         "$(lvs --noheadings -o vg_name "$root_lv" | xargs)" 2>/dev/null |
        xargs || true)
    log "VG free bytes before extending root: ${vg_free_before:-unknown}"

    if ! run lvextend -l +100%FREE "$root_lv"; then
        die "The /home logical volume was already removed, but extending $root_lv failed. Free space remains in the volume group. Your data is safely backed up at $backup - review $LOG_FILE and extend $root_lv manually."
    fi

    case "$root_fs" in
        xfs)
            if ! run xfs_growfs /; then
                die "Root LV was extended, but xfs_growfs failed. Your data is backed up at $backup. Review $LOG_FILE and grow the filesystem manually."
            fi
            ;;
        ext4)
            if ! run resize2fs "$root_lv"; then
                die "Root LV was extended, but resize2fs failed. Your data is backed up at $backup. Review $LOG_FILE and grow the filesystem manually."
            fi
            ;;
        *)
            die "Root LV was extended, but filesystem type '$root_fs' is unsupported. Grow it manually. Your data is backed up at $backup."
            ;;
    esac

    mkdir -p /home
    if ! run rsync -aHAXS --numeric-ids "$backup/" /home/; then
        die "Failed to restore /home data from $backup onto the new root filesystem. Your original data remains intact in the backup directory. Review $LOG_FILE and restore manually."
    fi
    restorecon -RFv /home >>"$LOG_FILE" 2>&1 || true

    # Keep the backup until the next successful reboot; do not delete it automatically.
    cat >"/root/README-home-backup-${timestamp}.txt" <<EOF
/home was moved onto the root filesystem by kvm_install.sh.

Backup directory:
  $backup

Original fstab:
  $fstab_backup

After rebooting and confirming all user data is present, these backup files
may be removed manually.
EOF

    log "/home reclaim completed. Backup retained at $backup."

    dialog --title "Home Reclaim Successful" --msgbox \
"/home was successfully merged into the root filesystem.

  Removed LV:   $home_lv
  Extended LV:  $root_lv
  Backup:       $backup
  Fstab backup: $fstab_backup

/home is now a regular directory on root with your data restored.
The backup above is kept until you confirm everything looks right
after a reboot; it is not deleted automatically." 16 78
}

profile_exists() {
    nmcli -t -f NAME connection show | grep -Fxq "$1"
}

delete_profile_if_exists() {
    local profile="$1"
    if profile_exists "$profile"; then
        log "Deleting existing profile: $profile"
        nmcli connection delete "$profile" >>"$NETWORK_LOG" 2>&1
    fi
}

set_bridge_autoconnect_ports() {
    local bridge="$1"
    nmcli connection modify "$bridge" connection.autoconnect yes >>"$NETWORK_LOG" 2>&1
    nmcli connection modify "$bridge" connection.autoconnect-ports 1 >>"$NETWORK_LOG" 2>&1 ||
        nmcli connection modify "$bridge" connection.autoconnect-slaves 1 >>"$NETWORK_LOG" 2>&1 ||
        true
}

configure_vlans() {
    local tmp interface_list selected all_vlans native_vlan native_bridge
    local original_profile native_port vlan vlan_if vlan_bridge
    local backup_dir timestamp
    local -a vlan_array unique_vlans
    declare -A seen=()

    tmp=$(mktemp)
    TMP_FILES+=("$tmp")
    : >"$NETWORK_LOG"

    interface_list=""
    while IFS=: read -r dev type state; do
        [[ "$type" == "ethernet" && "$state" == "connected" ]] || continue
        interface_list+="$dev ${dev} "
    done < <(nmcli -t -f DEVICE,TYPE,STATE device status)

    [[ -n "$interface_list" ]] || die "No connected Ethernet device was found."

    selected=$(dialog --title "Trunk Interface" --menu \
        "Select the physical interface connected to the switch trunk:" \
        16 72 8 $interface_list 2>&1 >/dev/tty) || exit 1

    original_profile=$(nmcli -t -f NAME,DEVICE connection show --active |
        awk -F: -v dev="$selected" '$2 == dev {print $1; exit}')

    [[ -n "$original_profile" ]] ||
        die "No active NetworkManager profile was found for $selected."

    dialog --title "Tagged VLANs" --inputbox \
        "Enter comma-separated tagged VLAN IDs for VM networks.\n\nExample: 10,18,20,30,45,46,47" \
        10 72 2>"$tmp" || exit 1
    all_vlans=$(tr -d '[:space:]' <"$tmp")

    [[ -n "$all_vlans" ]] || die "At least one tagged VLAN is required."

    IFS=',' read -r -a vlan_array <<<"$all_vlans"
    unique_vlans=()

    for vlan in "${vlan_array[@]}"; do
        validate_vlan "$vlan" || die "Invalid VLAN ID: $vlan"
        if [[ -z "${seen[$vlan]:-}" ]]; then
            unique_vlans+=("$vlan")
            seen["$vlan"]=1
        fi
    done

    while true; do
        dialog --title "Native Management VLAN" --inputbox \
"The current host management address is:

  Address: $MGMT_ADDRESS
  Gateway: $MGMT_GATEWAY
  Device:  $selected

Enter the switchport native/untagged VLAN ID.
The management IP will be placed on br<VLAN>." 14 72 2>"$tmp" || exit 1
        native_vlan=$(tr -d '[:space:]' <"$tmp")
        validate_vlan "$native_vlan" && break
        dialog --msgbox "Invalid native VLAN ID." 6 45
    done

    native_bridge="br${native_vlan}"

    dialog --title "Review Network Configuration" --yesno \
"Physical trunk: $selected
Native VLAN:     $native_vlan
Management:      $MGMT_ADDRESS via $MGMT_GATEWAY
Native bridge:   $native_bridge
Tagged VLANs:    $(IFS=,; echo "${unique_vlans[*]}")

Cockpit will display bridges by VLAN:
br10, br18, br20, br30, and so forth.

The network cutover will interrupt SSH.
Continue?" 18 78 || exit 1

    timestamp=$(date +%Y%m%d-%H%M%S)
    backup_dir="/root/NetworkManager-backup-${timestamp}"
    mkdir -p "$backup_dir"
    cp -a /etc/NetworkManager/system-connections/. "$backup_dir/" 2>/dev/null || true
    log "NetworkManager profile backup: $backup_dir"

    # Remove stale profiles from earlier versions of the script.
    for vlan in "${unique_vlans[@]}"; do
        delete_profile_if_exists "bridge-slave-vlan${vlan}"
        delete_profile_if_exists "vlan${vlan}"
        delete_profile_if_exists "br${vlan}"
    done
    delete_profile_if_exists "bridge-slave-${selected}"
    delete_profile_if_exists "port-${selected}-to-${native_bridge}"
    delete_profile_if_exists "$native_bridge"

    # Native/untagged bridge owns the host management IP.
    nmcli connection add \
        type bridge \
        con-name "$native_bridge" \
        ifname "$native_bridge" \
        bridge.stp no \
        ipv4.method manual \
        ipv4.addresses "$MGMT_ADDRESS" \
        ipv4.gateway "$MGMT_GATEWAY" \
        ipv6.method disabled \
        connection.autoconnect yes >>"$NETWORK_LOG" 2>&1

    [[ -n "$MGMT_DNS" ]] &&
        nmcli connection modify "$native_bridge" \
            ipv4.dns "$MGMT_DNS" \
            ipv4.ignore-auto-dns yes >>"$NETWORK_LOG" 2>&1

    [[ -n "$MGMT_SEARCH" ]] &&
        nmcli connection modify "$native_bridge" \
            ipv4.dns-search "$MGMT_SEARCH" >>"$NETWORK_LOG" 2>&1

    set_bridge_autoconnect_ports "$native_bridge"

    native_port="port-${selected}-to-${native_bridge}"
    nmcli connection add \
        type ethernet \
        con-name "$native_port" \
        ifname "$selected" \
        controller "$native_bridge" \
        port-type bridge \
        connection.autoconnect yes >>"$NETWORK_LOG" 2>&1

    # Tagged VLAN bridges. The VLAN profile itself is the bridge port.
    for vlan in "${unique_vlans[@]}"; do
        [[ "$vlan" == "$native_vlan" ]] && continue

        vlan_if="${selected}.${vlan}"
        vlan_bridge="br${vlan}"

        nmcli connection add \
            type bridge \
            con-name "$vlan_bridge" \
            ifname "$vlan_bridge" \
            bridge.stp no \
            ipv4.method disabled \
            ipv6.method disabled \
            connection.autoconnect yes >>"$NETWORK_LOG" 2>&1

        set_bridge_autoconnect_ports "$vlan_bridge"

        nmcli connection add \
            type vlan \
            con-name "vlan${vlan}" \
            ifname "$vlan_if" \
            dev "$selected" \
            id "$vlan" \
            ipv4.method disabled \
            ipv6.method disabled \
            connection.autoconnect yes >>"$NETWORK_LOG" 2>&1

        nmcli connection modify "vlan${vlan}" \
            connection.controller "$vlan_bridge" \
            connection.port-type bridge >>"$NETWORK_LOG" 2>&1
    done

    # Prevent the original standalone NIC profile from returning with the old IP.
    nmcli connection modify "$original_profile" connection.autoconnect no >>"$NETWORK_LOG" 2>&1

    nmcli connection reload >>"$NETWORK_LOG" 2>&1

    # Activate in dependency order.
    nmcli connection up "$native_bridge" >>"$NETWORK_LOG" 2>&1 || true
    nmcli connection up "$native_port" >>"$NETWORK_LOG" 2>&1 || true

    for vlan in "${unique_vlans[@]}"; do
        [[ "$vlan" == "$native_vlan" ]] && continue
        nmcli connection up "br${vlan}" >>"$NETWORK_LOG" 2>&1 || true
        nmcli connection up "vlan${vlan}" >>"$NETWORK_LOG" 2>&1 || true
    done

    # The old profile must be deactivated last because this interrupts management.
    nmcli connection down "$original_profile" >>"$NETWORK_LOG" 2>&1 || true
    nmcli connection up "$native_bridge" >>"$NETWORK_LOG" 2>&1 || true
    nmcli connection up "$native_port" >>"$NETWORK_LOG" 2>&1 || true

    sleep 5

    {
        echo
        echo "===== nmcli active connections ====="
        nmcli connection show --active
        echo
        echo "===== bridge links ====="
        bridge link
        echo
        echo "===== addresses ====="
        ip -br address
        echo
        echo "===== routes ====="
        ip route
    } >>"$NETWORK_LOG" 2>&1

    if ! ip link show "$native_bridge" >/dev/null 2>&1; then
        die "Native bridge $native_bridge was not created. Restore profiles from $backup_dir."
    fi

    for vlan in "${unique_vlans[@]}"; do
        [[ "$vlan" == "$native_vlan" ]] && continue
        if ! ip link show "br${vlan}" >/dev/null 2>&1; then
            die "Bridge br${vlan} was not created. Restore profiles from $backup_dir."
        fi
    done

    sed -i '/^## Run KVM installer/,/^fi$/d' /root/.bash_profile 2>/dev/null || true

    dialog --title "Configuration Complete" --msgbox \
"Installation and network configuration are complete.

Management bridge: $native_bridge
Management address: $MGMT_ADDRESS
Cockpit URL: https://${MGMT_ADDRESS%/*}:9090

Tagged VM bridges:
$(printf 'br%s ' "${unique_vlans[@]}")

Network backup:
$backup_dir

Network log:
$NETWORK_LOG

Reboot from the local console if this session does not survive." 20 80
}

main() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"

    require_root
    require_rocky
    install_dialog_early
    show_welcome
    detect_active_management
    configure_static_ip_if_needed
    configure_hostname
    configure_selinux
    install_packages
    configure_ntp
    configure_fail2ban
    enable_services
    offer_home_reclaim
    configure_vlans

    dialog --title "Reboot" --yesno \
        "Reboot now to verify that all bridge and VLAN profiles return correctly?" \
        8 70 && reboot
}

main "$@"
