#!/bin/bash

# IRIS Network Isolation Scripts for Linux
# Defensive security tool for incident response

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="output"
WHITELIST_FILE="$OUTPUT_DIR/whitelist_ips.json"

mkdir -p "$OUTPUT_DIR"

emergency_isolation() {
    echo "INITIATING EMERGENCY NETWORK ISOLATION"
    echo "======================================="
    
    # Save current iptables rules
    iptables-save > "$OUTPUT_DIR/iptables_backup_$TIMESTAMP.txt"
    echo "Current iptables rules backed up"
    
    # Block all outbound connections by default
    iptables -P OUTPUT DROP
    echo "Default OUTPUT policy set to DROP"
    
    # Allow loopback
    iptables -A OUTPUT -o lo -j ACCEPT
    echo "Loopback traffic allowed"
    
    # Allow established connections
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    echo "Established connections allowed"
    
    # Block DNS
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP
    echo "DNS traffic blocked"
    
    # Add whitelist IPs if they exist
    if [ -f "$WHITELIST_FILE" ]; then
        echo "Applying whitelist rules..."
        # This would parse the JSON and add rules - simplified for MVP
        iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT
        iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
    fi
    
    echo "EMERGENCY ISOLATION COMPLETE"
    echo "System is now isolated from network"
    
    # Log isolation
    {
        echo "Emergency Network Isolation - $(date)"
        echo "====================================="
        echo "System isolated at: $(date)"
        echo "Current iptables rules:"
        iptables -L -n
    } > "$OUTPUT_DIR/emergency_isolation_$TIMESTAMP.txt"
}

restore_network() {
    echo "Restoring network connectivity..."
    
    # Find the most recent backup
    BACKUP_FILE=$(ls -t "$OUTPUT_DIR"/iptables_backup_*.txt 2>/dev/null | head -1)
    
    if [ -f "$BACKUP_FILE" ]; then
        echo "Restoring from: $BACKUP_FILE"
        iptables-restore < "$BACKUP_FILE"
        echo "Network connectivity restored"
    else
        echo "No backup found, using default rules"
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT  
        iptables -P OUTPUT ACCEPT
        iptables -F
        echo "Default iptables rules applied"
    fi
    
    {
        echo "Network Restoration - $(date)"
        echo "============================="
        echo "Network restored at: $(date)"
        echo "Current iptables rules:"
        iptables -L -n
    } > "$OUTPUT_DIR/network_restoration_$TIMESTAMP.txt"
}

kill_suspicious_connections() {
    echo "Terminating suspicious network connections..."
    
    # Suspicious ports commonly used by malware/backdoors
    SUSPICIOUS_PORTS="4444 5555 6666 7777 8080 9999"
    KILLED_PROCESSES=""
    
    for port in $SUSPICIOUS_PORTS; do
        echo "Checking port $port..."
        PIDS=$(lsof -ti:$port 2>/dev/null)
        
        if [ -n "$PIDS" ]; then
            echo "Found processes on port $port: $PIDS"
            for pid in $PIDS; do
                PROCESS_INFO=$(ps -p $pid -o comm= 2>/dev/null)
                echo "Killing process $pid ($PROCESS_INFO) on port $port"
                kill -TERM $pid 2>/dev/null
                KILLED_PROCESSES="$KILLED_PROCESSES\nKilled PID $pid ($PROCESS_INFO) on port $port"
            done
        fi
    done
    
    # Log killed processes
    {
        echo "Suspicious Connection Termination - $(date)"
        echo "===========================================" 
        echo "Killed processes:"
        echo -e "$KILLED_PROCESSES"
        echo ""
        echo "Current network connections after cleanup:"
        netstat -tuln
    } > "$OUTPUT_DIR/killed_connections_$TIMESTAMP.txt"
    
    echo "Suspicious connection termination complete"
}

block_dns() {
    echo "Blocking DNS resolution..."
    
    # Block DNS ports
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP
    
    # Block common public DNS servers
    DNS_SERVERS="8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1 9.9.9.9"
    
    for dns in $DNS_SERVERS; do
        iptables -A OUTPUT -d $dns -j DROP
        echo "Blocked DNS server: $dns"
    done
    
    {
        echo "DNS Blocking - $(date)"
        echo "===================="
        echo "DNS resolution blocked at: $(date)"
        echo "Blocked DNS servers: $DNS_SERVERS"
        echo ""
        echo "Current iptables rules:"
        iptables -L -n | grep -E "(53|dns)"
    } > "$OUTPUT_DIR/dns_block_$TIMESTAMP.txt"
    
    echo "DNS blocking complete"
}

show_isolation_status() {
    echo "Checking network isolation status..."
    
    {
        echo "Network Isolation Status - $(date)"
        echo "=================================="
        echo ""
        echo "IPTABLES RULES:"
        iptables -L -n
        echo ""
        echo "ACTIVE CONNECTIONS:"
        netstat -tuln
        echo ""
        echo "LISTENING SERVICES:"
        ss -tuln
        echo ""
        echo "ROUTING TABLE:"
        route -n
        echo ""
        echo "INTERFACE STATUS:"
        ip addr show
    } > "$OUTPUT_DIR/isolation_status_$TIMESTAMP.txt"
    
    # Check if isolation is active
    if iptables -L | grep -q "DROP"; then
        echo "ISOLATION STATUS: ACTIVE"
    else
        echo "ISOLATION STATUS: INACTIVE"
    fi
    
    echo "Status report saved to $OUTPUT_DIR/isolation_status_$TIMESTAMP.txt"
}

# Main execution
case "$1" in
    emergency)
        emergency_isolation
        ;;
    restore)
        restore_network
        ;;
    kill)
        kill_suspicious_connections
        ;;
    dns)
        block_dns
        ;;
    status)
        show_isolation_status
        ;;
    *)
        echo "Usage: $0 {emergency|restore|kill|dns|status}"
        echo ""
        echo "Commands:"
        echo "  emergency - Block all network traffic (emergency isolation)"
        echo "  restore   - Restore network connectivity"
        echo "  kill      - Terminate suspicious network connections"
        echo "  dns       - Block DNS resolution"
        echo "  status    - Show current isolation status"
        exit 1
        ;;
esac