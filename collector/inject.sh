#!/usr/bin/env bash
# AutoSecure — misconfiguration injector (LAB TARGETS ONLY)
#
# Injects a single, reproducible, REVERSIBLE misconfiguration onto a lab
# machine so the collector can snapshot a labeled "vulnerable" sample.
# Original state is backed up under /var/lib/autosecure/backups/<ID>/.
#
# Usage:
#   sudo ./inject.sh list                 # show the misconfig catalog
#   sudo ./inject.sh apply M07            # inject one misconfig
#   sudo ./inject.sh revert M07           # restore original state
#   sudo ./inject.sh status               # show applied misconfigs
#
# Pair with the collector:
#   sudo ./inject.sh apply M07
#   sudo python3 collect.py --host-id target-b --tag M07 \
#        --label vulnerable --inject M07 --out ../dataset
#   sudo ./inject.sh revert M07

set -u

BACKUP_ROOT="/var/lib/autosecure/backups"
STATE_FILE="/var/lib/autosecure/applied"

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "[-] must run as root (sudo)"; exit 1
    fi
}

reload_ssh() {
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
}

backup_file() {
    # backup_file <ID> <path>
    local id="$1" path="$2"
    mkdir -p "$BACKUP_ROOT/$id"
    if [[ -e "$path" && ! -e "$BACKUP_ROOT/$id/$(basename "$path")" ]]; then
        cp -a "$path" "$BACKUP_ROOT/$id/$(basename "$path")"
        echo "$path" >> "$BACKUP_ROOT/$id/manifest.paths"
        sort -u "$BACKUP_ROOT/$id/manifest.paths" -o "$BACKUP_ROOT/$id/manifest.paths"
    fi
}

restore_files() {
    # restore_files <ID>  — copies every backed-up file back
    local id="$1" f
    [[ -d "$BACKUP_ROOT/$id" ]] || { echo "[-] no backup for $id"; return 1; }
    while read -r f; do
        [[ -n "$f" ]] || continue
        local b="$BACKUP_ROOT/$id/$(basename "$f")"
        if [[ -e "$b" ]]; then
            cp -a "$b" "$f"
            echo "[+] restored $f"
        fi
    done < "$BACKUP_ROOT/$id/manifest.paths"
    return 0
}

mark_applied() { echo "$1" >> "$STATE_FILE"; sort -u "$STATE_FILE" -o "$STATE_FILE"; }
unmark_applied() { [[ -f "$STATE_FILE" ]] && sed -i "/^$1$/d" "$STATE_FILE"; }

# ---------------------------------------------------------------------------
# catalog: apply_<ID> and revert_<ID> functions
# ---------------------------------------------------------------------------

apply_M01() {
    backup_file M01 /etc/ssh/sshd_config
    if grep -qE '^\s*#\?\s*PermitRootLogin' /etc/ssh/sshd_config; then
        sed -i 's/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    else
        echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
    fi
    reload_ssh; echo "[+] M01: PermitRootLogin yes"
}
revert_M01() { restore_files M01 && reload_ssh; }

apply_M02() {
    backup_file M02 /etc/ssh/sshd_config
    if grep -qE '^\s*#\?\s*PasswordAuthentication' /etc/ssh/sshd_config; then
        sed -i 's/^\s*#\?\s*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    else
        echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    fi
    reload_ssh; echo "[+] M02: PasswordAuthentication yes"
}
revert_M02() { restore_files M02 && reload_ssh; }

apply_M03() {
    backup_file M03 /etc/ssh/sshd_config
    if grep -qE '^\s*#\?\s*PermitEmptyPasswords' /etc/ssh/sshd_config; then
        sed -i 's/^\s*#\?\s*PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config
    else
        echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config
    fi
    reload_ssh; echo "[+] M03: PermitEmptyPasswords yes"
}
revert_M03() { restore_files M03 && reload_ssh; }

apply_M04() {
    backup_file M04 /etc/shadow
    stat -c '%a' /etc/shadow > "$BACKUP_ROOT/M04_shadow_mode"
    chmod 0666 /etc/shadow
    echo "[+] M04: /etc/shadow world-writable (was $(cat "$BACKUP_ROOT/M04_shadow_mode"))"
}
revert_M04() {
    chmod "$(cat "$BACKUP_ROOT/M04_shadow_mode" 2>/dev/null || echo 640)" /etc/shadow
    echo "[+] M04 reverted"
}

apply_M05() {
    mkdir -p /var/autosecure-share
    chmod 0777 /var/autosecure-share
    echo "[+] M05: world-writable dir without sticky bit"
}
revert_M05() { rm -rf /var/autosecure-share; echo "[+] M05 reverted"; }

apply_M06() {
    useradd -m victim01 2>/dev/null || true
    usermod -p "" victim01
    echo "[+] M06: user victim01 with EMPTY password"
}
revert_M06() { userdel -r victim01 2>/dev/null; echo "[+] M06 reverted"; }

apply_M07() {
    backup_file M07 /etc/sudoers
    echo "victim01 ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/99-autosecure-test
    chmod 0440 /etc/sudoers.d/99-autosecure-test
    echo "[+] M07: NOPASSWD sudoers entry"
}
revert_M07() { rm -f /etc/sudoers.d/99-autosecure-test; echo "[+] M07 reverted"; }

apply_M08() {
    backup_file M08 /etc/login.defs
    sed -i 's/^\s*PASS_MAX_DAYS.*/PASS_MAX_DAYS\t99999/' /etc/login.defs
    grep -q '^PASS_MIN_LEN' /etc/login.defs \
        && sed -i 's/^\s*PASS_MIN_LEN.*/PASS_MIN_LEN\t0/' /etc/login.defs \
        || echo "PASS_MIN_LEN\t0" >> /etc/login.defs
    echo "[+] M08: weak password aging/length policy"
}
revert_M08() { restore_files M08; }

apply_M09() {
    mkdir -p "$BACKUP_ROOT/M09"
    for svc in ufw nftables firewalld; do
        if systemctl is-active --quiet "$svc"; then
            echo "$svc active" >> "$BACKUP_ROOT/M09/fw_state"
        fi
    done
    ufw disable 2>/dev/null || true
    systemctl stop nftables firewalld 2>/dev/null || true
    iptables -F 2>/dev/null || true
    echo "[+] M09: firewall disabled/flushed"
}
revert_M09() {
    if [[ -f "$BACKUP_ROOT/M09/fw_state" ]]; then
        while read -r _ svc _; do
            [[ "$svc" == "active" ]] && continue
            systemctl start "$svc" 2>/dev/null && ufw enable 2>/dev/null
        done < "$BACKUP_ROOT/M09/fw_state"
    fi
    echo "[+] M09 reverted (restart firewall manually if unsure)"
}

apply_M10() {
    if command -v inetutils-inetd >/dev/null 2>&1 || dpkg -l inetutils-inetd >/dev/null 2>&1; then
        systemctl enable --now inetutils-inetd
        echo "[+] M10: telnet service enabled"
    else
        echo "[~] M10: attempting to install inetutils-inetd (needs network)"
        apt-get install -y inetutils-inetd && systemctl enable --now inetutils-inetd \
            || echo "[-] M10: install failed (offline?) — target already has inetutils-inetd in lab images"
    fi
}
revert_M10() { systemctl disable --now inetutils-inetd 2>/dev/null; echo "[+] M10 reverted"; }

apply_M11() {
    cp /bin/bash /usr/local/bin/.autosecure-helper
    chmod 4755 /usr/local/bin/.autosecure-helper
    echo "[+] M11: unauthorized SUID shell at /usr/local/bin/.autosecure-helper"
}
revert_M11() { rm -f /usr/local/bin/.autosecure-helper; echo "[+] M11 reverted"; }

apply_M12() {
    echo "# autosecure test config" > /etc/autosecure-test.conf
    chmod 0666 /etc/autosecure-test.conf
    echo "[+] M12: world-writable file in /etc"
}
revert_M12() { rm -f /etc/autosecure-test.conf; echo "[+] M12 reverted"; }

apply_M13() {
    useradd -o -u 0 -g 0 -M backdoor01 2>/dev/null || true
    usermod -p '*' backdoor01
    echo "[+] M13: hidden UID-0 user backdoor01"
}
revert_M13() { userdel backdoor01 2>/dev/null; echo "[+] M13 reverted"; }

apply_M14() {
    backup_file M14 /etc/apt/apt.conf.d/20auto-upgrades
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
EOF
    echo "[+] M14: automatic security updates disabled"
}
revert_M14() { restore_files M14; }

apply_M15() {
    if [[ -f /etc/snmp/snmpd.conf ]]; then
        backup_file M15 /etc/snmp/snmpd.conf
        echo "rocommunity public" >> /etc/snmp/snmpd.conf
        systemctl restart snmpd 2>/dev/null || true
        echo "[+] M15: SNMP default public community string"
    else
        echo "[-] M15: no /etc/snmp/snmpd.conf — snmpd not installed"
        return 1
    fi
}
revert_M15() { restore_files M15 && systemctl restart snmpd 2>/dev/null; }

# ---------------------------------------------------------------------------
# catalog listing
# ---------------------------------------------------------------------------

CATALOG="
M01|SSH: PermitRootLogin yes
M02|SSH: PasswordAuthentication yes
M03|SSH: PermitEmptyPasswords yes
M04|FS: /etc/shadow world-writable (0666)
M05|FS: world-writable dir without sticky bit (/var/autosecure-share)
M06|AUTH: user with empty password field (victim01)
M07|AUTH: NOPASSWD sudoers entry
M08|POLICY: weak password aging/length in login.defs
M09|NET: firewall disabled and flushed
M10|NET: telnet service enabled (inetutils-inetd)
M11|FS: unauthorized SUID shell copy
M12|FS: world-writable file in /etc
M13|AUTH: hidden UID-0 backdoor user
M14|UPDATE: unattended-upgrades disabled
M15|NET: SNMP rocommunity public
"

# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

case "${1:-}" in
    list)
        echo "$CATALOG" | column -t -s'|'
        ;;
    status)
        echo "Applied misconfigs:"
        cat "$STATE_FILE" 2>/dev/null || echo "  (none)"
        ;;
    apply)
        require_root
        ID="${2:-}"
        fn="apply_${ID}"
        if declare -f "$fn" >/dev/null; then
            "$fn" && mark_applied "$ID"
        else
            echo "[-] unknown ID '$ID' — try: $0 list"; exit 1
        fi
        ;;
    revert)
        require_root
        ID="${2:-}"
        fn="revert_${ID}"
        if declare -f "$fn" >/dev/null; then
            "$fn" && unmark_applied "$ID"
        else
            echo "[-] unknown ID '$ID' — try: $0 list"; exit 1
        fi
        ;;
    *)
        echo "Usage: sudo $0 {list|status|apply ID|revert ID}"
        exit 1
        ;;
esac

