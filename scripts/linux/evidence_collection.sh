#!/bin/bash

# IRIS Evidence Collection Scripts for Linux
# Defensive security tool for incident response

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="output"

mkdir -p "$OUTPUT_DIR"

collect_processes() {
    echo "Collecting process information..."
    {
        echo "Process List - $(date)"
        echo "================================"
        ps aux
        echo ""
        echo "Process Tree:"
        pstree -p
        echo ""
        echo "Top processes by CPU:"
        top -b -n1 | head -20
    } > "$OUTPUT_DIR/processes_$TIMESTAMP.txt"
    echo "Process information saved to $OUTPUT_DIR/processes_$TIMESTAMP.txt"
}

collect_network() {
    echo "Collecting network information..."
    {
        echo "Network Connections - $(date)"
        echo "================================"
        echo "Active connections:"
        netstat -tuln
        echo ""
        echo "Socket statistics:"
        ss -tuln
        echo ""
        echo "ARP table:"
        arp -a
        echo ""
        echo "Routing table:"
        route -n
    } > "$OUTPUT_DIR/network_$TIMESTAMP.txt"
    echo "Network information saved to $OUTPUT_DIR/network_$TIMESTAMP.txt"
}

collect_system_info() {
    echo "Collecting system information..."
    {
        echo "System Information - $(date)"
        echo "================================"
        echo "Hostname: $(hostname)"
        echo "OS Info: $(uname -a)"
        echo "Uptime: $(uptime)"
        echo ""
        echo "CPU Info:"
        cat /proc/cpuinfo | grep "model name" | head -1
        echo ""
        echo "Memory Info:"
        free -h
        echo ""
        echo "Disk Usage:"
        df -h
        echo ""
        echo "IP Addresses:"
        ip addr show
        echo ""
        echo "Environment Variables:"
        env | sort
    } > "$OUTPUT_DIR/system_info_$TIMESTAMP.txt"
    echo "System information saved to $OUTPUT_DIR/system_info_$TIMESTAMP.txt"
}

collect_users() {
    echo "Collecting user information..."
    {
        echo "User Information - $(date)"
        echo "================================"
        echo "Currently logged in users:"
        who 2>/dev/null || w 2>/dev/null || echo "No user information available"
        echo ""
        echo "Last logins:"
        if command -v last >/dev/null 2>&1; then
            last -10
        elif command -v journalctl >/dev/null 2>&1; then
            journalctl --list-boots -n 5 2>/dev/null || echo "No login history available"
        else
            echo "Login history tools not available"
        fi
        echo ""
        echo "All user accounts:"
        cat /etc/passwd
        echo ""
        echo "Groups:"
        cat /etc/group
        echo ""
        echo "Sudo access:"
        cat /etc/sudoers 2>/dev/null || echo "Cannot read sudoers file"
    } > "$OUTPUT_DIR/users_$TIMESTAMP.txt"
    echo "User information saved to $OUTPUT_DIR/users_$TIMESTAMP.txt"
}

hash_suspicious_files() {
    echo "Generating hashes for suspicious files..."
    {
        echo "File Hashes - $(date)"
        echo "================================"
        
        SUSPICIOUS_DIRS="/tmp /var/tmp /dev/shm $HOME/Downloads"
        
        for dir in $SUSPICIOUS_DIRS; do
            if [ -d "$dir" ]; then
                echo "Hashing files in $dir:"
                find "$dir" -type f -exec md5sum {} \; 2>/dev/null | head -20
                echo ""
            fi
        done
        
        echo "Recently modified files in /etc:"
        find /etc -type f -mtime -7 -exec ls -la {} \; 2>/dev/null | head -10
        
    } > "$OUTPUT_DIR/file_hashes_$TIMESTAMP.txt"
    echo "File hashes saved to $OUTPUT_DIR/file_hashes_$TIMESTAMP.txt"
}

# Main execution
case "$1" in
    processes)
        collect_processes
        ;;
    network)
        collect_network
        ;;
    sysinfo)
        collect_system_info
        ;;
    users)
        collect_users
        ;;
    hash)
        hash_suspicious_files
        ;;
    all)
        collect_processes
        collect_network
        collect_system_info
        collect_users
        hash_suspicious_files
        ;;
    *)
        echo "Usage: $0 {processes|network|sysinfo|users|hash|all}"
        exit 1
        ;;
esac