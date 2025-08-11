# KVM & VLAN Setup Installer for Rocky Linux

This project provides a comprehensive, dialog-based Bash installer that automates the setup of a **Rocky Linux 9.x server** as a secure, VLAN-aware KVM virtualization host.

---

## What It Does

Validates and enforces static IP configuration  
Configures Chrony NTP using up to 3 user-defined servers
Updates the system to latest packaging via dnf
Installs all necessary packages for KVM, libvirt, and Cockpit  
Enables and starts `libvirtd`, `fail2ban`, and `cockpit.socket`  
Prompts for trunk interface and VLANs to bind VMs  
Sets up bridges for each VLAN with STP disabled (switch handles STP)  
Migrates your static IP to a native VLAN bridge for management isolation 
If the /home directory has been set as a separate mapper by the OS installation, the script will remap and reclaim space from home into root, and recreate the /home directory  
Removes auto-run installer from `.bash_profile`  
Cleans up installer files. If running from the console will reboot. If from SSH you must manually reboot on the console (due to network changes)

**Result:** 
You get a fully-functional, secure KVM server ready for virtual machine deployment, with VLAN isolation and management separation.

---

## Usage Instructions

### 1. Install Rocky 9 or greater on your system. 
You should only be using (1) physical interface that will be configured for trunking by your network swtich equipment, by deafult. 
You do not have to run any updates on the server, just a simple install from the ISO (Install, reboot). 
The Script/Installer will take care of the rest. 

### 2. After the initial OS install and reboot from installation, SSH or login on the console
Open the EASY_INSTALL File and run the contents inside from the REPO itself 
Or copy this line from here and run in terminal or SSH session:

dnf -y install wget && cd /root && bash <(wget -qO- https://raw.githubusercontent.com/fumatchu/KVM/main/KVMInstall.sh)

This will download and bootstrap the installer 

### 3. After you have run the installer, you need to manually reboot from the physical console if running over SSH (ctrl+alt+del, or login and type reboot). 
Network changes will disconnect your active session at the end of the script if using SSH

### 4. After reboot, the Server will be configured for KVM and you can manage Virtual Machines via cockpit at https://ip_address:9090 
Use the "Virtual machines" navigation option on the left and make sure you are directly attaching the machines to the VLANs you want 


