#!/usr/bin/env bash
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
CYAN="\e[36m"
RESET="\e[0m"
USER=$(whoami)
MAJOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')
clear
echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rocky ${CYAN}KVM${TEXTRESET} Builder ${YELLOW}Installation${TEXTRESET}"

# Checking for user permissions
if [ "$USER" = "root" ]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Running as root user."
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] This program must be run as root."
  echo "Exiting..."
  exit 1
fi

# Checking for version information
if [ "$MAJOROS" -ge 9 ]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Detected compatible OS version: Rocky 9.x or greater"
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] Sorry, but this installer only works on Rocky 9.X or greater"
  echo -e "Please upgrade to ${GREEN}Rocky 9.x${TEXTRESET} or later"
  echo "Exiting the installer..."
  exit 1
fi

# ========= VALIDATION HELPERS =========
validate_cidr() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; }
validate_ip()   { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
validate_fqdn() { [[ "$1" =~ ^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$ ]]; }

is_host_ip() {
  local cidr="$1"
  local ip_part="${cidr%/*}"
  local mask="${cidr#*/}"

  IFS='.' read -r o1 o2 o3 o4 <<< "$ip_part"
  ip_dec=$(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))

  netmask=$(( 0xFFFFFFFF << (32 - mask) & 0xFFFFFFFF ))
  network=$(( ip_dec & netmask ))
  broadcast=$(( network | ~netmask & 0xFFFFFFFF ))

  [[ "$ip_dec" -eq "$network" || "$ip_dec" -eq "$broadcast" ]] && return 1 || return 0
}

check_hostname_in_domain() {
  local fqdn="$1"
  local hostname="${fqdn%%.*}"
  local domain="${fqdn#*.}"
  [[ ! "$domain" =~ (^|\.)"$hostname"(\.|$) ]]
}

# ========= SYSTEM CHECKS =========
check_root_and_os() {
  if [[ "$EUID" -ne 0 ]]; then
    dialog --aspect 9 --title "Permission Denied" --msgbox "This script must be run as root." 7 50
    clear; exit 1
  fi

  if [[ -f /etc/redhat-release ]]; then
    MAJOROS=$(grep -oP '\d+' /etc/redhat-release | head -1)
  else
    dialog --title "OS Check Failed" --msgbox "/etc/redhat-release not found. Cannot detect OS." 7 50
    exit 1
  fi

  if [[ "$MAJOROS" -lt 9 ]]; then
    dialog --title "Unsupported OS" --msgbox "This installer requires Rocky Linux 9.x or later." 7 50
    exit 1
  fi
}

# ========= SELINUX CHECK =========
check_and_enable_selinux() {
  local current_status=$(getenforce)

  if [[ "$current_status" == "Enforcing" ]]; then
    dialog --title "SELinux Status" --infobox "SELinux is already enabled and enforcing." 6 50
    sleep 4
  else
    dialog --title "SELinux Disabled" --msgbox "SELinux is not enabled. Enabling SELinux now..." 6 50
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
    setenforce 1

    if [[ "$(getenforce)" == "Enforcing" ]]; then
      dialog --title "SELinux Enabled" --msgbox "SELinux has been successfully enabled and is now enforcing." 6 50
    else
      dialog --title "SELinux Error" --msgbox "Failed to enable SELinux. Please check the configuration manually." 6 50
      exit 1
    fi
  fi
}

# ========= NETWORK DETECTION =========
detect_active_interface() {
  dialog --title "Interface Check" --infobox "Checking active network interface..." 5 50
  sleep 3

  # Attempt 1: Use nmcli to find connected Ethernet
  INTERFACE=$(nmcli -t -f DEVICE,TYPE,STATE device | grep "ethernet:connected" | cut -d: -f1 | head -n1)

  # Attempt 2: Fallback to any interface with an IP if nmcli fails
  if [[ -z "$INTERFACE" ]]; then
    INTERFACE=$(ip -o -4 addr show up | grep -v ' lo ' | awk '{print $2}' | head -n1)
  fi

  # Get the matching connection profile name
  if [[ -n "$INTERFACE" ]]; then
    CONNECTION=$(nmcli -t -f NAME,DEVICE connection show | grep ":$INTERFACE" | cut -d: -f1)
  fi

  # Log to /tmp in case of failure
  echo "DEBUG: INTERFACE=$INTERFACE" >> /tmp/kvm_debug.log
  echo "DEBUG: CONNECTION=$CONNECTION" >> /tmp/kvm_debug.log

  if [[ -z "$INTERFACE" || -z "$CONNECTION" ]]; then
    dialog --clear  --no-ok --title "Interface Error" --aspect 9 --msgbox "No active network interface with IP found. Check /tmp/kvm_debug.log for d
etails." 5 70
    exit 1
  fi

  export INTERFACE CONNECTION
}

# ========= STATIC IP CONFIG =========
prompt_static_ip_if_dhcp() {
  IP_METHOD=$(nmcli -g ipv4.method connection show "$CONNECTION" | tr -d '' | xargs)

  if [[ "$IP_METHOD" == "manual" ]]; then
  dialog --clear --title "Static IP Detected" --infobox "Interface '$INTERFACE' is already using a static IP.\nNo changes needed." 6 70
  sleep 3
  return
elif [[ "$IP_METHOD" == "auto" ]]; then
    while true; do
      while true; do
        IPADDR=$(dialog --title "Static IP" --inputbox "Enter static IP in CIDR format (e.g., 192.168.1.100/24):" 8 60 3>&1 1>&2 2>&3)
        validate_cidr "$IPADDR" && break || dialog --msgbox "Invalid CIDR format. Try again." 6 40
      done

      while true; do
        GW=$(dialog --title "Gateway" --inputbox "Enter default gateway:" 8 60 3>&1 1>&2 2>&3)
        validate_ip "$GW" && break || dialog --msgbox "Invalid IP address. Try again." 6 40
      done

      while true; do
        DNSSERVER=$(dialog --title "DNS Server" --inputbox "Enter Upstream DNS server IP:" 8 60 3>&1 1>&2 2>&3)
        validate_ip "$DNSSERVER" && break || dialog --msgbox "Invalid IP address. Try again." 6 40
      done

      while true; do
        HOSTNAME=$(dialog --title "FQDN" --inputbox "Enter FQDN (e.g., host.domain.com):" 8 60 3>&1 1>&2 2>&3)
        if validate_fqdn "$HOSTNAME" && check_hostname_in_domain "$HOSTNAME"; then break
        else dialog --msgbox "Invalid FQDN or hostname repeated in domain. Try again." 7 60
        fi
      done

      while true; do
        DNSSEARCH=$(dialog --title "DNS Search" --inputbox "Enter domain search suffix (e.g., localdomain):" 8 60 3>&1 1>&2 2>&3)
        [[ -n "$DNSSEARCH" ]] && break || dialog --msgbox "Search domain cannot be blank." 6 40
      done

      dialog --title "Confirm Settings" --yesno "Apply these settings?\n\nInterface: $INTERFACE\nIP: $IPADDR\nGW: $GW\nFQDN: $HOSTNAME\nDNS: $DNSSERVER\nSearch: $DNSSEARCH" 12 60

      if [[ $? -eq 0 ]]; then
        nmcli con mod "$CONNECTION" ipv4.address "$IPADDR"
        nmcli con mod "$CONNECTION" ipv4.gateway "$GW"
        nmcli con mod "$CONNECTION" ipv4.method manual
        nmcli con mod "$CONNECTION" ipv4.dns "$DNSSERVER"
        nmcli con mod "$CONNECTION" ipv4.dns-search "$DNSSEARCH"
        hostnamectl set-hostname "$HOSTNAME"


        dialog --clear --no-shadow --no-ok --title "Reboot Required" --aspect 9 --msgbox "Network stack set. The System will reboot. Reconnect at: ${IPADDR%%/*}" 5 95
        reboot
      fi
    done
  fi
}

# ========= UI SCREENS =========
show_welcome_screen() {
  clear
  echo -e "${GREEN}
                               .*((((((((((((((((*
                         .(((((((((((((((((((((((((((/
                      ,((((((((((((((((((((((((((((((((((.
                    (((((((((((((((((((((((((((((((((((((((/
                  (((((((((((((((((((((((((((((((((((((((((((/
                .(((((((((((((((((((((((((((((((((((((((((((((
               ,((((((((((((((((((((((((((((((((((((((((((((((((.
               ((((((((((((((((((((((((((((((/   ,(((((((((((((((
              /((((((((((((((((((((((((((((.        /((((((((((((*
              ((((((((((((((((((((((((((/              ((((((((((
              ((((((((((((((((((((((((                   *((((((/
              /((((((((((((((((((((*                        (((((*
               ((((((((((((((((((             (((*            ,((
               .((((((((((((((.            /(((((((
                 ((((((((((/             (((((((((((((/
                  *((((((.            /((((((((((((((((((.
                    *(*)            ,(((((((((((((((((((((((,
                                 (((((((((((((((((((((((/
                              /((((((((((((((((((((((.
                                ,((((((((((((((,
${RESET}"
  echo -e "                         ${GREEN}Rocky Linux${RESET} ${CYAN}KVM${RESET} ${YELLOW}Builder${RESET}"

  sleep 2
}

# ========= INTERNET CONNECTIVITY CHECK =========
check_internet_connectivity() {
  dialog --title "Network Test" --infobox "Checking internet connectivity..." 5 50
  sleep 2

  local dns_test="FAILED"
  local ip_test="FAILED"

  if ping -c 1 -W 2 google.com &>/dev/null; then
    dns_test="SUCCESS"
  fi

  if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
    ip_test="SUCCESS"
  fi

  dialog --title "Connectivity Test Results" --infobox "DNS Resolution: $dns_test
Direct IP (8.8.8.8): $ip_test " 7 50
  sleep 4

  if [[ "$dns_test" == "FAILED" || "$ip_test" == "FAILED" ]]; then
    dialog --title "Network Warning" --yesno "Internet connectivity issues detected. Do you want to continue?" 7 50
    if [[ $? -ne 0 ]]; then
      exit 1
    fi
  fi
}

# ========= HOSTNAME VALIDATION =========
validate_and_set_hostname() {
  local current_hostname
  current_hostname=$(hostname)

  if [[ "$current_hostname" == "localhost.localdomain" ]]; then
    while true; do
      NEW_HOSTNAME=$(dialog --title "Hostname Configuration" --inputbox \
        "Current hostname is '$current_hostname'. Please enter a new FQDN (e.g., server.example.com):" \
        8 60 3>&1 1>&2 2>&3)

      if validate_fqdn "$NEW_HOSTNAME" && check_hostname_in_domain "$NEW_HOSTNAME"; then
        hostnamectl set-hostname "$NEW_HOSTNAME"
        dialog --title "Hostname Set" --msgbox "Hostname updated to: $NEW_HOSTNAME" 6 50
        break
      else
        dialog --title "Invalid Hostname" --msgbox "Invalid hostname. Please try again." 6 50
      fi
    done
  else
    # Show a temporary info box with current hostname, no OK button
    dialog --title "Hostname Check" --infobox \
      "Hostname set to: $current_hostname" 6 60
    sleep 3
  fi
}

# ========= SYSTEM UPDATE & PACKAGE INSTALL =========
update_and_install_packages() {
  # Simulate progress while enabling EPEL and CRB
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

  dialog --title "System Update" --infobox "Checking for updates. This may take a few moments..." 5 70
  sleep 2

  dnf check-update -y &>/dev/null

  TEMP_FILE=$(mktemp)
  dnf check-update | awk '{print $1}' | grep -vE '^$|Obsoleting|Last' | awk -F'.' '{print $1}' | sort -u > "$TEMP_FILE"

  PACKAGE_LIST=($(cat "$TEMP_FILE"))
  TOTAL_PACKAGES=${#PACKAGE_LIST[@]}

  if [[ "$TOTAL_PACKAGES" -eq 0 ]]; then
    dialog --title "System Update" --msgbox "No updates available!" 6 50
    rm -f "$TEMP_FILE"
  else
    PIPE=$(mktemp -u)
    mkfifo "$PIPE"
    dialog --title "System Update" --gauge "Installing updates..." 10 70 0 < "$PIPE" &
    exec 3>"$PIPE"
    COUNT=0
    for PACKAGE in "${PACKAGE_LIST[@]}"; do
      ((COUNT++))
      PERCENT=$(( (COUNT * 100) / TOTAL_PACKAGES ))
      echo "$PERCENT" > "$PIPE"
      echo "XXX" > "$PIPE"
      echo "Updating: $PACKAGE" > "$PIPE"
      echo "XXX" > "$PIPE"
      dnf -y install "$PACKAGE" >/dev/null 2>&1
    done
    exec 3>&-
    rm -f "$PIPE" "$TEMP_FILE"
  fi

  dialog --title "Package Installation" --infobox "Installing Required Packages..." 5 50
  sleep 2
  PACKAGE_LIST=("ntsysv" "iptraf" "fail2ban" "tuned" "qemu-kvm" "libvirt" "virt-install" "virt-manager" "virt-viewer" "cockpit" "cockpit-storaged" "
cockpit-machines" "cockpit-files" "net-tools" "dmidecode" "ipcalc" "bind-utils"  "iotop" "zip" "yum-utils" "nano" "curl" "wget" "dnf-automatic")
  TOTAL_PACKAGES=${#PACKAGE_LIST[@]}

  PIPE=$(mktemp -u)
  mkfifo "$PIPE"
  dialog --title "Installing Required Packages" --gauge "Preparing to install packages..." 10 70 0 < "$PIPE" &
  exec 3>"$PIPE"
  COUNT=0
  for PACKAGE in "${PACKAGE_LIST[@]}"; do
    ((COUNT++))
    PERCENT=$(( (COUNT * 100) / TOTAL_PACKAGES ))
    echo "$PERCENT" > "$PIPE"
    echo "XXX" > "$PIPE"
    echo "Installing: $PACKAGE" > "$PIPE"
    echo "XXX" > "$PIPE"
    dnf -y install "$PACKAGE" >/dev/null 2>&1
  done
  exec 3>&-
  rm -f "$PIPE"
  dialog --title "Installation Complete" --infobox "All packages installed successfully!" 6 50
  sleep 3
}
#===========DETECT VIRT and INSTALL GUEST=============
# Function to show a dialog infobox
vm_detection() {
show_info() {
    dialog --title "$1" --infobox "$2" 5 60
    sleep 2
}

# Function to show a progress bar during installation
show_progress() {
    (
        echo "10"; sleep 1
        echo "40"; sleep 1
        echo "70"; sleep 1
        echo "100"
    ) | dialog --title "$1" --gauge "$2" 7 60 0
}

# Detect virtualization platform
HWKVM=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep KVM | cut -c16-)
HWVMWARE=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep Manufacturer | grep "VMware, Inc." | cut -c16- | cut -d , -f1)

show_info "Virtualization Check" "Checking for virtualization platform..."

# Install guest agent for KVM
if [ "$HWKVM" = "KVM" ]; then
    show_info "Platform Detected" "KVM platform detected.\nInstalling qemu-guest-agent..."
    show_progress "Installing qemu-guest-agent" "Installing guest tools for KVM..."
    dnf -y install qemu-guest-agent &>/dev/null
fi

# Install guest agent for VMware
if [ "$HWVMWARE" = "VMware" ]; then
    show_info "Platform Detected" "VMware platform detected.\nInstalling open-vm-tools..."
    show_progress "Installing open-vm-tools" "Installing guest tools for VMware..."
    dnf -y install open-vm-tools &>/dev/null
fi
}

# ========= CONFIGURE FAIL2BAN =========
configure_fail2ban() {

    LOG_FILE="/tmp/fail2ban_configure.log"
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"

    log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$LOG_FILE"
}

    dialog --title "Fail2Ban Configuration" --infobox "Configuring Fail2Ban service..." 4 50
    log "Configuring Fail2Ban service..."

    ORIGINAL_FILE="/etc/fail2ban/jail.conf"
    JAIL_LOCAL_FILE="/etc/fail2ban/jail.local"
    SSHD_LOCAL_FILE="/etc/fail2ban/jail.d/sshd.local"

    if cp -v "$ORIGINAL_FILE" "$JAIL_LOCAL_FILE" >> "$LOG_FILE" 2>&1; then
        log "Copied jail.conf to jail.local"
    else
        log "Failed to copy jail.conf"
        dialog --title "Fail2Ban Configuration" --msgbox "ERROR: Failed to copy jail.conf to jail.local" 6 50
        return 1
    fi

    if sed -i '/^\[sshd\]/,/^$/ s/#mode.*normal/&\nenabled = true/' "$JAIL_LOCAL_FILE" >> "$LOG_FILE" 2>&1; then
        log "Modified jail.local to enable SSHD"
    else
        log "Failed to modify jail.local"
        dialog --title "Fail2Ban Configuration" --msgbox "ERROR: Failed to modify jail.local to enable SSHD" 6 50
        return 1
    fi

    cat <<EOL > "$SSHD_LOCAL_FILE"
[sshd]
enabled = true
maxretry = 5
findtime = 300
bantime = 3600
bantime.increment = true
bantime.factor = 2
EOL
    log "Created $SSHD_LOCAL_FILE"

    dialog --title "Fail2Ban Configuration" --infobox "Starting and enabling Fail2Ban..." 4 50
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl start fail2ban >> "$LOG_FILE" 2>&1
    sleep 2

    if systemctl is-active --quiet fail2ban; then
        log "Fail2Ban is running."
    else
        log "Fail2Ban failed to start. Checking SELinux..."

        selinux_status=$(sestatus | grep "SELinux status" | awk '{print $3}')
        if [ "$selinux_status" == "enabled" ]; then
            restorecon -v /etc/fail2ban/jail.local >> "$LOG_FILE" 2>&1
            denials=$(ausearch -m avc -ts recent | grep "fail2ban-server" | wc -l)
            if [ "$denials" -gt 0 ]; then
                dialog --title "Fail2Ban Configuration" --infobox "Applying SELinux policy for Fail2Ban..." 4 50
                ausearch -c 'fail2ban-server' --raw | audit2allow -M my-fail2banserver >> "$LOG_FILE" 2>&1
                semodule -X 300 -i my-fail2banserver.pp >> "$LOG_FILE" 2>&1
                log "Custom SELinux policy for Fail2Ban applied."
            fi
        fi

        systemctl restart fail2ban >> "$LOG_FILE" 2>&1
        if systemctl is-active --quiet fail2ban; then
            log "Fail2Ban started after SELinux policy."
        else
            log "Fail2Ban still not running after SELinux fix."
            dialog --title "Fail2Ban Configuration" --msgbox "ERROR: Fail2Ban failed to start even after SELinux fix." 6 60
            return 1
        fi
    fi

    sshd_status=$(fail2ban-client status sshd 2>&1)

    if echo "$sshd_status" | grep -q "ERROR   NOK: ('sshd',)"; then
        log "SSHD jail failed to start."
        dialog --title "Fail2Ban Configuration" --msgbox "ERROR: SSHD jail failed to start. Check configuration." 6 60
    elif echo "$sshd_status" | grep -E "Banned IP list:"; then
        log "SSHD jail is active."
    else
        log "SSHD jail may not be working correctly."
        dialog --title "Fail2Ban Configuration" --msgbox "WARNING: SSHD jail may not be functional. Please check." 6 60
    fi

    dialog --infobox "Fail2Ban configured successfully!" 4 50
    sleep 3

    log "Fail2Ban configuration complete."
}

# ========= CONFIGURE CHRONY =========
declare -a ADDR
LOG_NTP="/tmp/chrony_ntp_configure.log"
touch "$LOG_NTP"

log_ntp() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$LOG_NTP"
}

prompt_ntp_servers() {
    while true; do
        NTP_SERVERS=$(dialog --title "Chrony NTP Configuration" \
            --inputbox "Enter up to 3 comma-separated NTP server IPs or FQDNs:" 8 60 \
            3>&1 1>&2 2>&3)
        exit_status=$?
        if [ $exit_status -eq 1 ] || [ $exit_status -eq 255 ]; then
            return 1
        fi

        if [[ -n "$NTP_SERVERS" ]]; then
            IFS=',' read -ra ADDR <<< "$NTP_SERVERS"
            if (( ${#ADDR[@]} > 3 )); then
                dialog --title "Chrony NTP Configuration" --msgbox "You may only enter up to 3 servers." 6 50
                continue
            fi
            return 0
        else
            dialog --title "Chrony NTP Configuration" --msgbox "The input cannot be blank. Please try again." 6 50
        fi
    done
}

update_chrony_config() {
    cp /etc/chrony.conf /etc/chrony.conf.bak
    sed -i '/^\(server\|pool\)[[:space:]]/d' /etc/chrony.conf

    for srv in "${ADDR[@]}"; do
        echo "server ${srv} iburst" >> /etc/chrony.conf
        log_ntp "Added server ${srv} to chrony.conf"
    done

    systemctl restart chronyd
    sleep 2
}

validate_time_sync() {
    local attempt=1
    local success=0

    while (( attempt <= 3 )); do
        dialog --title "Chrony NTP Configuration" --infobox "Validating time sync... Attempt $attempt/3" 4 50
        sleep 5

        TRACKING=$(chronyc tracking 2>&1)
        echo "$TRACKING" >> "$LOG_NTP"

        if echo "$TRACKING" | grep -q "Leap status[[:space:]]*:[[:space:]]*Normal"; then
            success=1
            break
        fi
        ((attempt++))
    done

    if [[ "$success" -eq 1 ]]; then
        dialog --title "Chrony NTP Configuration" --msgbox "Time synchronized successfully:\n\n$TRACKING" 15 80
    else
        dialog --title "Chrony NTP Configuration" --yesno "Time sync failed after 3 attempts.\nDo you want to proceed anyway?" 8 70
        [[ $? -eq 0 ]] || return 1
    fi
    return 0
}

# ========= START SERVICES  =========
check_and_enable_services() {
    SERVICES=("libvirtd" "cockpit.socket" "fail2ban")
    for svc in "${SERVICES[@]}"; do
        dialog --infobox "Checking and enabling '$svc'..." 5 50
        sleep 1
        if systemctl is-enabled --quiet "$svc"; then
            if systemctl is-active --quiet "$svc"; then
                dialog --infobox "$svc is already enabled and running." 5 50
            else
                systemctl start "$svc"
                dialog --infobox "$svc was enabled but not running. Started now." 5 50
            fi
        else
            systemctl enable --now "$svc"
            if systemctl is-active --quiet "$svc"; then
                dialog --infobox "$svc has been enabled and started successfully." 5 50
            else
                dialog --msgbox "Failed to start or enable $svc.\nPlease check systemctl status $svc manually." 7 60
            fi
        fi
        sleep 2
    done

    dialog --title "Service Check Complete" --msgbox \
    "All required services have been verified:\n\n• libvirtd\n• cockpit.socket\n• fail2ban\n\nIf any were not running, they were started and enabled for boot." 12 60
}



# ========= SHOW INFO on VLANS  =========
show_vlan_warning() {
    dialog --title "VLAN Preparation Notice" --msgbox \
"The next step will configure the system for the VLANs used by Virtual Machines.

Your network switch should already be set to TRUNK mode with an untagged (native) VLAN.

The current static IP will be moved to the Untagged VLAN bridge for management access.
This provides isolation between management traffic and VM traffic.

STP (Spanning Tree Protocol) will be disabled on all interfaces created by this script.
Ensure STP is configured appropriately on your switch.

Please verify your switch configuration before continuing.

AFTER YOU SET THESE OPTIONS THE INTERFACES WILL RESET AND THE SERVER WILL REBOOT" 30 100
}


# ========= SET BRIDGE and VLANS  =========
configure_vlans() {
    local TMP_FILE
    TMP_FILE=$(mktemp)
    local LOG_FILE="/var/log/kvm_vlan_setup.log"

    # Get interfaces
    interfaces=$(nmcli device status | awk '$2 == "ethernet" && $3 == "connected" {print $1}')
    interface_list=""
    for iface in $interfaces; do
        interface_list+="$iface '' "
    done

    # Prompt for trunk interface
    chosen_iface=$(dialog --clear --title "Select Trunk Interface" --menu \
        "Choose the interface to act as trunk:" 15 50 5 $interface_list 2>&1 >/dev/tty)
    if [ -z "$chosen_iface" ]; then
        dialog --msgbox "No interface selected. Exiting." 6 40
        clear; return 1
    fi

    # Prompt for VLANs to create
    dialog --inputbox "Enter comma-separated VLAN IDs to create (e.g., 10,20,30):" 8 60 2>$TMP_FILE
    VLAN_IDS=$(<"$TMP_FILE")

    # Detect static IP and gateway
    mgmt_iface=$(ip route | grep default | awk '{print $5}' | head -n1)
    mgmt_ip=$(ip -4 addr show dev "$mgmt_iface" | awk '/inet / {print $2}' | head -n1)
    mgmt_gw=$(ip route | grep default | awk '{print $3}' | head -n1)

    if [ -z "$mgmt_ip" ] || [ -z "$mgmt_gw" ]; then
        dialog --msgbox "Unable to detect the current static IP or gateway. Please configure networking first." 7 60
        return 1
    fi

    # Prompt for native VLAN, showing current IP/gateway
    dialog --inputbox "The system is currently using:\n\n  IP Address: $mgmt_ip\n  Gateway: $mgmt_gw\n\nPlease enter the native (untagged)
VLAN ID for this management IP:" 12 60 2>$TMP_FILE
    NATIVE_VLAN=$(<"$TMP_FILE")

    HOST_IP="$mgmt_ip"
    GATEWAY="$mgmt_gw"

    # Confirm all settings
    dialog --title "Review Configuration" --yesno "Management IP: $HOST_IP\nGateway: $GATEWAY\nNative VLAN: $NATIVE_VLAN\nTagged VLANs: $VLAN_IDS\nTrunk Interface: $chosen_iface\n\nProceed with configuration?" 15 60
    [ $? -ne 0 ] && { dialog --msgbox "Operation cancelled." 6 40; return 1; }

    # Create native bridge
    native_bridge="br${NATIVE_VLAN}"
    nmcli con add type bridge con-name "$native_bridge"
    nmcli con mod "$native_bridge" bridge.stp no
    nmcli con add type bridge-slave ifname "$chosen_iface" master "$native_bridge"
    nmcli con mod "$native_bridge" ipv4.addresses "$HOST_IP"
    nmcli con mod "$native_bridge" ipv4.gateway "$GATEWAY"
    nmcli con mod "$native_bridge" ipv4.method manual

    # Create VLAN bridges
    IFS=',' read -r -a vlan_array <<< "$VLAN_IDS"
    for vlan in "${vlan_array[@]}"; do
        vlan_id=$(echo "$vlan" | tr -d ' ')
        if [ "$vlan_id" == "$NATIVE_VLAN" ]; then continue; fi

        vlan_con="vlan${vlan_id}"
        bridge_con="br${vlan_id}"
        nmcli con add type vlan con-name "$vlan_con" dev "$chosen_iface" id "$vlan_id"
        nmcli con add type bridge con-name "$bridge_con"
        nmcli con mod "$bridge_con" bridge.stp no
        nmcli con add type bridge-slave ifname "$vlan_con" master "$bridge_con"
        nmcli con mod "$vlan_con" ipv4.method disabled
        nmcli con mod "$vlan_con" ipv6.method disabled
        nmcli con mod "$bridge_con" ipv4.method disabled
        nmcli con mod "$bridge_con" ipv6.method disabled
    done

    # Disable IP on physical trunk interface
    nmcli con mod "$chosen_iface" ipv4.method disabled
    nmcli con down "$chosen_iface"
    nmcli con up "$chosen_iface"

    # Reload all connections
    nmcli connection reload

    dialog --msgbox "VLAN and bridge configuration completed.\n\nUse 'nmcli con show' to review all connections." 8 60
    clear
    rm -f "$TMP_FILE"
    reboot
}


# ========= MAIN =========
show_welcome_screen
detect_active_interface
prompt_static_ip_if_dhcp
check_root_and_os
check_and_enable_selinux
check_internet_connectivity
validate_and_set_hostname
#set_inside_interface
#=== Set Time ===
if ! prompt_ntp_servers; then
    dialog --title "Chrony NTP Configuration" --msgbox "NTP configuration was cancelled." 6 40
    exit 1
fi
update_chrony_config
if ! validate_time_sync; then
    dialog --title "Chrony NTP Configuration" --msgbox "Chrony configuration aborted." 6 40
    exit 1
fi
dialog --title "Chrony NTP Configuration" --infobox "Chrony NTP configuration completed successfully." 4 50
sleep 3
#=== End Set time ===
update_and_install_packages
vm_detection
configure_fail2ban
check_and_enable_services
show_vlan_warning
configure_vlans
