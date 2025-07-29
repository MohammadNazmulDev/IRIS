# IRIS Network Isolation Scripts for Windows PowerShell
# Defensive security tool for incident response

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("emergency","restore","kill","dns","status")]
    [string]$Operation
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "output"

# Create output directory if it doesn't exist
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

function Emergency-Isolation {
    Write-Host "INITIATING EMERGENCY NETWORK ISOLATION"
    Write-Host "======================================="
    
    $outputFile = "$outputDir\emergency_isolation_$timestamp.txt"
    
    @"
Emergency Network Isolation - $(Get-Date)
==========================================
SYSTEM ISOLATED FROM NETWORK
"@ | Out-File -FilePath $outputFile
    
    try {
        # Backup current firewall settings
        Write-Host "Backing up current firewall settings..."
        netsh advfirewall export "$outputDir\firewall_backup_$timestamp.wfw" | Out-File -FilePath $outputFile -Append
        "Firewall settings backed up" | Out-File -FilePath $outputFile -Append
        
        # Set firewall to block all connections
        Write-Host "Setting firewall to block all outbound connections..."
        netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-File -FilePath $outputFile -Append
        "Default policy set to block all connections" | Out-File -FilePath $outputFile -Append
        
        # Allow loopback
        Write-Host "Allowing loopback traffic..."
        netsh advfirewall firewall add rule name="IRIS_ALLOW_LOOPBACK" dir=out action=allow remoteip=127.0.0.1 | Out-File -FilePath $outputFile -Append
        "Loopback traffic allowed" | Out-File -FilePath $outputFile -Append
        
        # Allow local network (for investigation access)
        Write-Host "Allowing local network access..."
        netsh advfirewall firewall add rule name="IRIS_ALLOW_LOCAL_192" dir=out action=allow remoteip=192.168.0.0/16 | Out-File -FilePath $outputFile -Append
        netsh advfirewall firewall add rule name="IRIS_ALLOW_LOCAL_10" dir=out action=allow remoteip=10.0.0.0/8 | Out-File -FilePath $outputFile -Append
        "Local network access allowed for investigation" | Out-File -FilePath $outputFile -Append
        
        # Block DNS
        Write-Host "Blocking DNS traffic..."
        netsh advfirewall firewall add rule name="IRIS_BLOCK_DNS_UDP" dir=out action=block protocol=UDP remoteport=53 | Out-File -FilePath $outputFile -Append
        netsh advfirewall firewall add rule name="IRIS_BLOCK_DNS_TCP" dir=out action=block protocol=TCP remoteport=53 | Out-File -FilePath $outputFile -Append
        "DNS traffic blocked" | Out-File -FilePath $outputFile -Append
        
        Write-Host "EMERGENCY ISOLATION COMPLETE"
        Write-Host "System is now isolated from network"
        "Emergency isolation completed successfully at $(Get-Date)" | Out-File -FilePath $outputFile -Append
        
    }
    catch {
        $errorMsg = "Error during isolation: $($_.Exception.Message)"
        Write-Host $errorMsg -ForegroundColor Red
        $errorMsg | Out-File -FilePath $outputFile -Append
    }
    
    Write-Host "Isolation log saved to $outputFile"
}

function Restore-Network {
    Write-Host "Restoring network connectivity..."
    
    $outputFile = "$outputDir\network_restoration_$timestamp.txt"
    
    @"
Network Restoration - $(Get-Date)
================================
"@ | Out-File -FilePath $outputFile
    
    try {
        # Find the most recent backup
        $backupFiles = Get-ChildItem -Path $outputDir -Filter "firewall_backup_*.wfw" | Sort-Object LastWriteTime -Descending
        
        if ($backupFiles.Count -gt 0) {
            $latestBackup = $backupFiles[0].FullName
            Write-Host "Restoring from: $latestBackup"
            netsh advfirewall import $latestBackup | Out-File -FilePath $outputFile -Append
            "Network connectivity restored from backup: $latestBackup" | Out-File -FilePath $outputFile -Append
        }
        else {
            Write-Host "No backup found, using default settings"
            # Reset to default Windows Defender Firewall settings
            netsh advfirewall reset | Out-File -FilePath $outputFile -Append
            "Default firewall settings applied" | Out-File -FilePath $outputFile -Append
        }
        
        # Remove IRIS-specific rules
        Write-Host "Removing IRIS isolation rules..."
        $irisRules = @(
            "IRIS_ALLOW_LOOPBACK",
            "IRIS_ALLOW_LOCAL_192", 
            "IRIS_ALLOW_LOCAL_10",
            "IRIS_BLOCK_DNS_UDP",
            "IRIS_BLOCK_DNS_TCP"
        )
        
        foreach ($rule in $irisRules) {
            netsh advfirewall firewall delete rule name=$rule 2>$null | Out-File -FilePath $outputFile -Append
        }
        "IRIS isolation rules removed" | Out-File -FilePath $outputFile -Append
        
        Write-Host "Network connectivity restored"
        "Network restoration completed at $(Get-Date)" | Out-File -FilePath $outputFile -Append
    }
    catch {
        $errorMsg = "Error during restoration: $($_.Exception.Message)"
        Write-Host $errorMsg -ForegroundColor Red
        $errorMsg | Out-File -FilePath $outputFile -Append
    }
    
    Write-Host "Restoration log saved to $outputFile"
}

function Kill-SuspiciousConnections {
    Write-Host "Terminating suspicious network connections..."
    
    $outputFile = "$outputDir\killed_connections_$timestamp.txt"
    
    @"
Suspicious Connection Termination - $(Get-Date)
===============================================
"@ | Out-File -FilePath $outputFile
    
    # Suspicious ports commonly used by malware/backdoors
    $suspiciousPorts = @(4444, 5555, 6666, 7777, 8080, 9999)
    $killedProcesses = @()
    
    foreach ($port in $suspiciousPorts) {
        Write-Host "Checking port $port..."
        
        # Get processes using the port
        $connections = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
        
        if ($connections) {
            foreach ($connection in $connections) {
                try {
                    $process = Get-Process -Id $connection.OwningProcess -ErrorAction Stop
                    Write-Host "Found process $($process.Name) (PID: $($process.Id)) on port $port"
                    
                    # Kill the process
                    Stop-Process -Id $process.Id -Force
                    $killedInfo = "Killed process $($process.Name) (PID: $($process.Id)) on port $port"
                    $killedProcesses += $killedInfo
                    Write-Host $killedInfo
                }
                catch {
                    "Error killing process on port $port`: $($_.Exception.Message)" | Out-File -FilePath $outputFile -Append
                }
            }
        }
    }
    
    # Log killed processes
    "Killed processes:" | Out-File -FilePath $outputFile -Append
    if ($killedProcesses.Count -eq 0) {
        "No suspicious processes found on monitored ports" | Out-File -FilePath $outputFile -Append
    }
    else {
        $killedProcesses | Out-File -FilePath $outputFile -Append
    }
    
    # Current network connections after cleanup
    "`nCurrent network connections after cleanup:" | Out-File -FilePath $outputFile -Append
    netstat -an | Out-File -FilePath $outputFile -Append
    
    Write-Host "Suspicious connection termination complete"
    Write-Host "Termination log saved to $outputFile"
}

function Block-DNS {
    Write-Host "Blocking DNS resolution..."
    
    $outputFile = "$outputDir\dns_block_$timestamp.txt"
    
    @"
DNS Blocking - $(Get-Date)
=========================
"@ | Out-File -FilePath $outputFile
    
    try {
        # Block DNS ports
        netsh advfirewall firewall add rule name="IRIS_BLOCK_DNS_UDP" dir=out action=block protocol=UDP remoteport=53 | Out-File -FilePath $outputFile -Append
        netsh advfirewall firewall add rule name="IRIS_BLOCK_DNS_TCP" dir=out action=block protocol=TCP remoteport=53 | Out-File -FilePath $outputFile -Append
        "DNS ports blocked" | Out-File -FilePath $outputFile -Append
        
        # Block common public DNS servers
        $dnsServers = @("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9")
        
        foreach ($dns in $dnsServers) {
            netsh advfirewall firewall add rule name="IRIS_BLOCK_DNS_$dns" dir=out action=block remoteip=$dns | Out-File -FilePath $outputFile -Append
            Write-Host "Blocked DNS server: $dns"
        }
        "Public DNS servers blocked: $($dnsServers -join ', ')" | Out-File -FilePath $outputFile -Append
        
        Write-Host "DNS blocking complete"
        "DNS blocking completed at $(Get-Date)" | Out-File -FilePath $outputFile -Append
    }
    catch {
        $errorMsg = "Error blocking DNS: $($_.Exception.Message)"
        Write-Host $errorMsg -ForegroundColor Red
        $errorMsg | Out-File -FilePath $outputFile -Append
    }
    
    Write-Host "DNS blocking log saved to $outputFile"
}

function Show-IsolationStatus {
    Write-Host "Checking network isolation status..."
    
    $outputFile = "$outputDir\isolation_status_$timestamp.txt"
    
    @"
Network Isolation Status - $(Get-Date)
=====================================
"@ | Out-File -FilePath $outputFile
    
    # Firewall status
    "FIREWALL STATUS:" | Out-File -FilePath $outputFile -Append
    netsh advfirewall show allprofiles | Out-File -FilePath $outputFile -Append
    
    # Current firewall rules
    "`nIRIS FIREWALL RULES:" | Out-File -FilePath $outputFile -Append
    netsh advfirewall firewall show rule name=all | Where-Object {$_ -match "IRIS"} | Out-File -FilePath $outputFile -Append
    
    # Active connections
    "`nACTIVE CONNECTIONS:" | Out-File -FilePath $outputFile -Append
    netstat -an | Out-File -FilePath $outputFile -Append
    
    # Network adapters
    "`nNETWORK ADAPTERS:" | Out-File -FilePath $outputFile -Append
    Get-NetAdapter | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append
    
    # Routing table
    "`nROUTING TABLE:" | Out-File -FilePath $outputFile -Append
    route print | Out-File -FilePath $outputFile -Append
    
    # Check if isolation is active
    $firewallPolicy = netsh advfirewall show allprofiles | Select-String "Outbound connections"
    if ($firewallPolicy -match "Block") {
        Write-Host "ISOLATION STATUS: ACTIVE" -ForegroundColor Yellow
        "ISOLATION STATUS: ACTIVE" | Out-File -FilePath $outputFile -Append
    }
    else {
        Write-Host "ISOLATION STATUS: INACTIVE" -ForegroundColor Green
        "ISOLATION STATUS: INACTIVE" | Out-File -FilePath $outputFile -Append
    }
    
    Write-Host "Status report saved to $outputFile"
}

# Main execution
switch ($Operation) {
    "emergency" { Emergency-Isolation }
    "restore" { Restore-Network }
    "kill" { Kill-SuspiciousConnections }
    "dns" { Block-DNS }
    "status" { Show-IsolationStatus }
    default { 
        Write-Host "Invalid operation. Use: emergency, restore, kill, dns, or status"
        Write-Host ""
        Write-Host "Commands:"
        Write-Host "  emergency - Block all network traffic (emergency isolation)"
        Write-Host "  restore   - Restore network connectivity"
        Write-Host "  kill      - Terminate suspicious network connections"
        Write-Host "  dns       - Block DNS resolution"
        Write-Host "  status    - Show current isolation status"
        exit 1
    }
}