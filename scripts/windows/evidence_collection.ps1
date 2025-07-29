# IRIS Evidence Collection Scripts for Windows PowerShell
# Defensive security tool for incident response

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("processes","network","sysinfo","users","hash","all")]
    [string]$Operation
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "output"

# Create output directory if it doesn't exist
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

function Collect-Processes {
    Write-Host "Collecting process information..."
    
    $outputFile = "$outputDir\processes_$timestamp.txt"
    
    @"
Process List - $(Get-Date)
================================
"@ | Out-File -FilePath $outputFile
    
    # Get detailed process information
    Get-Process | Select-Object Name, Id, CPU, WorkingSet, StartTime, Path | 
        Format-Table -AutoSize | Out-File -FilePath $outputFile -Append
    
    # Get process with command line
    "`nDetailed Process Information:" | Out-File -FilePath $outputFile -Append
    Get-WmiObject -Class Win32_Process | Select-Object Name, ProcessId, CommandLine, CreationDate | 
        Format-List | Out-File -FilePath $outputFile -Append
    
    # Services
    "`nRunning Services:" | Out-File -FilePath $outputFile -Append
    Get-Service | Where-Object {$_.Status -eq "Running"} | 
        Format-Table -AutoSize | Out-File -FilePath $outputFile -Append
    
    Write-Host "Process information saved to $outputFile"
}

function Collect-Network {
    Write-Host "Collecting network information..."
    
    $outputFile = "$outputDir\network_$timestamp.txt"
    
    @"
Network Connections - $(Get-Date)
================================
"@ | Out-File -FilePath $outputFile
    
    # Network connections
    "Active Connections:" | Out-File -FilePath $outputFile -Append
    netstat -an | Out-File -FilePath $outputFile -Append
    
    # Network connections with process info
    "`nConnections with Process Info:" | Out-File -FilePath $outputFile -Append
    netstat -anb | Out-File -FilePath $outputFile -Append
    
    # Network adapters
    "`nNetwork Adapters:" | Out-File -FilePath $outputFile -Append
    Get-NetAdapter | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append
    
    # ARP table
    "`nARP Table:" | Out-File -FilePath $outputFile -Append
    arp -a | Out-File -FilePath $outputFile -Append
    
    # Routing table
    "`nRouting Table:" | Out-File -FilePath $outputFile -Append
    route print | Out-File -FilePath $outputFile -Append
    
    Write-Host "Network information saved to $outputFile"
}

function Collect-SystemInfo {
    Write-Host "Collecting system information..."
    
    $outputFile = "$outputDir\system_info_$timestamp.txt"
    
    @"
System Information - $(Get-Date)
================================
"@ | Out-File -FilePath $outputFile
    
    # System information
    systeminfo | Out-File -FilePath $outputFile -Append
    
    # Environment variables
    "`nEnvironment Variables:" | Out-File -FilePath $outputFile -Append
    Get-ChildItem Env: | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append
    
    # Installed programs
    "`nInstalled Programs:" | Out-File -FilePath $outputFile -Append
    Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | 
        Sort-Object Name | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append
    
    # Windows features
    "`nWindows Features:" | Out-File -FilePath $outputFile -Append
    Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"} | 
        Select-Object FeatureName | Out-File -FilePath $outputFile -Append
    
    Write-Host "System information saved to $outputFile"
}

function Collect-Users {
    Write-Host "Collecting user information..."
    
    $outputFile = "$outputDir\users_$timestamp.txt"
    
    @"
User Information - $(Get-Date)
================================
"@ | Out-File -FilePath $outputFile
    
    # Currently logged in users
    "Currently Logged In Users:" | Out-File -FilePath $outputFile -Append
    query user | Out-File -FilePath $outputFile -Append
    
    # All user accounts
    "`nAll User Accounts:" | Out-File -FilePath $outputFile -Append
    Get-LocalUser | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append
    
    # Local groups
    "`nLocal Groups:" | Out-File -FilePath $outputFile -Append
    Get-LocalGroup | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append
    
    # Group memberships for Administrators
    "`nAdministrators Group Members:" | Out-File -FilePath $outputFile -Append
    Get-LocalGroupMember -Group "Administrators" | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append
    
    # Recent logon events (last 24 hours)
    "`nRecent Logon Events:" | Out-File -FilePath $outputFile -Append
    $yesterday = (Get-Date).AddDays(-1)
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=$yesterday} -MaxEvents 50 | 
        Select-Object TimeCreated, Id, LevelDisplayName, Message | Out-File -FilePath $outputFile -Append
    
    Write-Host "User information saved to $outputFile"
}

function Hash-SuspiciousFiles {
    Write-Host "Generating hashes for suspicious files..."
    
    $outputFile = "$outputDir\file_hashes_$timestamp.txt"
    
    @"
File Hashes - $(Get-Date)
================================
"@ | Out-File -FilePath $outputFile
    
    # Suspicious directories
    $suspiciousDirs = @(
        "C:\Temp",
        "C:\Windows\Temp",
        "$env:USERPROFILE\Downloads",
        "$env:LOCALAPPDATA\Temp"
    )
    
    foreach ($dir in $suspiciousDirs) {
        if (Test-Path $dir) {
            "`nHashing files in $dir:" | Out-File -FilePath $outputFile -Append
            
            Get-ChildItem -Path $dir -File -Recurse -ErrorAction SilentlyContinue | 
                Select-Object -First 20 | ForEach-Object {
                    try {
                        $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256
                        $md5 = Get-FileHash -Path $_.FullName -Algorithm MD5
                        "$($_.Name) - SHA256: $($hash.Hash) - MD5: $($md5.Hash)" | Out-File -FilePath $outputFile -Append
                    }
                    catch {
                        "$($_.Name) - Error calculating hash: $($_.Exception.Message)" | Out-File -FilePath $outputFile -Append
                    }
                }
        }
    }
    
    # Recently modified files in system directories
    "`nRecently modified files in Windows directory:" | Out-File -FilePath $outputFile -Append
    $sevenDaysAgo = (Get-Date).AddDays(-7)
    Get-ChildItem -Path "C:\Windows" -File -Recurse -ErrorAction SilentlyContinue | 
        Where-Object {$_.LastWriteTime -gt $sevenDaysAgo} | 
        Select-Object -First 10 | ForEach-Object {
            "$($_.Name) - Modified: $($_.LastWriteTime)" | Out-File -FilePath $outputFile -Append
        }
    
    Write-Host "File hashes saved to $outputFile"
}

# Main execution
switch ($Operation) {
    "processes" { Collect-Processes }
    "network" { Collect-Network }
    "sysinfo" { Collect-SystemInfo }
    "users" { Collect-Users }
    "hash" { Hash-SuspiciousFiles }
    "all" {
        Collect-Processes
        Collect-Network
        Collect-SystemInfo
        Collect-Users
        Hash-SuspiciousFiles
    }
    default { 
        Write-Host "Invalid operation. Use: processes, network, sysinfo, users, hash, or all"
        exit 1
    }
}