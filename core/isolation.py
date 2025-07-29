import subprocess
import os
import json
from datetime import datetime
from pathlib import Path

class NetworkIsolation:
    def __init__(self, platform, config):
        self.platform = platform
        self.config = config
        self.output_dir = Path(config.get('evidence_collection', {}).get('output_directory', 'output'))
        self.output_dir.mkdir(exist_ok=True)
        self.whitelist_ips = config.get('network_isolation', {}).get('whitelist_ips', [])
        
    def run_operation(self, operation, log_callback):
        operations = {
            'emergency': self.emergency_isolation,
            'whitelist': self.manage_whitelist,
            'kill': self.kill_connections,
            'dns': self.block_dns,
            'status': self.isolation_status
        }
        
        if operation in operations:
            return operations[operation](log_callback)
        else:
            log_callback(f"Unknown isolation operation: {operation}")
            return None
    
    def emergency_isolation(self, log_callback):
        log_callback("INITIATING EMERGENCY NETWORK ISOLATION")
        try:
            if self.platform == 'linux':
                # Block all outbound connections except localhost and whitelist
                commands = [
                    ['iptables', '-P', 'OUTPUT', 'DROP'],
                    ['iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
                    ['iptables', '-A', 'OUTPUT', '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']
                ]
                
                # Add whitelist IPs
                for ip in self.whitelist_ips:
                    commands.append(['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'ACCEPT'])
                
                # Block DNS
                commands.extend([
                    ['iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport', '53', '-j', 'DROP'],
                    ['iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport', '53', '-j', 'DROP']
                ])
                
            else:  # Windows
                commands = [
                    ['netsh', 'advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound,blockoutbound'],
                    ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=IRIS_ALLOW_LOOPBACK', 'dir=out', 'action=allow', 'remoteip=127.0.0.1']
                ]
                
                # Add whitelist IPs
                for i, ip in enumerate(self.whitelist_ips):
                    commands.append(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name=IRIS_WHITELIST_{i}', 'dir=out', 'action=allow', f'remoteip={ip}'])
            
            results = []
            for cmd in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                    results.append(f"SUCCESS: {' '.join(cmd)}")
                    log_callback(f"Executed: {' '.join(cmd)}")
                except subprocess.CalledProcessError as e:
                    results.append(f"FAILED: {' '.join(cmd)} - {e}")
                    log_callback(f"Failed: {' '.join(cmd)} - {e}")
            
            # Save isolation log
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.output_dir / f"isolation_emergency_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"Emergency Isolation - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n")
                f.write("SYSTEM ISOLATED FROM NETWORK\n")
                f.write("Whitelist IPs: " + ", ".join(self.whitelist_ips) + "\n")
                f.write("\nCommands executed:\n")
                for result in results:
                    f.write(result + "\n")
            
            log_callback("EMERGENCY ISOLATION COMPLETE")
            log_callback("WARNING: System is now isolated from network")
            return str(filename)
            
        except Exception as e:
            log_callback(f"Error during emergency isolation: {e}")
            return None
    
    def manage_whitelist(self, log_callback):
        log_callback("Managing IP whitelist...")
        try:
            whitelist_file = self.output_dir / "whitelist_ips.json"
            
            # Default whitelist for investigation access
            default_whitelist = [
                "127.0.0.1",
                "::1",
                "10.0.0.0/8",
                "192.168.0.0/16"
            ]
            
            current_whitelist = self.whitelist_ips + default_whitelist
            
            whitelist_data = {
                "timestamp": datetime.now().isoformat(),
                "whitelist_ips": current_whitelist,
                "description": "IP addresses allowed during isolation"
            }
            
            with open(whitelist_file, 'w') as f:
                json.dump(whitelist_data, f, indent=2)
            
            log_callback(f"Whitelist saved: {len(current_whitelist)} IPs")
            for ip in current_whitelist:
                log_callback(f"  - {ip}")
            
            return str(whitelist_file)
            
        except Exception as e:
            log_callback(f"Error managing whitelist: {e}")
            return None
    
    def kill_connections(self, log_callback):
        log_callback("Terminating suspicious connections...")
        try:
            if self.platform == 'linux':
                # Get current connections
                result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, check=True)
                connections = result.stdout
                
                # Kill processes with suspicious network activity
                suspicious_ports = ['4444', '5555', '6666', '8080', '9999']
                killed_processes = []
                
                for port in suspicious_ports:
                    try:
                        # Find processes using suspicious ports
                        lsof_result = subprocess.run(['lsof', '-i', f':{port}'], capture_output=True, text=True)
                        if lsof_result.stdout:
                            lines = lsof_result.stdout.split('\n')[1:]  # Skip header
                            for line in lines:
                                if line.strip():
                                    parts = line.split()
                                    if len(parts) > 1:
                                        pid = parts[1]
                                        try:
                                            subprocess.run(['kill', '-TERM', pid], check=True)
                                            killed_processes.append(f"Killed PID {pid} using port {port}")
                                            log_callback(f"Terminated process {pid} on port {port}")
                                        except subprocess.CalledProcessError:
                                            pass
                    except subprocess.CalledProcessError:
                        pass
                        
            else:  # Windows
                # Windows equivalent
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, check=True)
                connections = result.stdout
                killed_processes = ["Windows connection termination not implemented in MVP"]
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.output_dir / f"killed_connections_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"Connection Termination - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n")
                f.write("Network connections before termination:\n")
                f.write(connections)
                f.write("\n" + "=" * 40 + "\n")
                f.write("Terminated processes:\n")
                for process in killed_processes:
                    f.write(process + "\n")
            
            log_callback(f"Connection termination complete: {len(killed_processes)} processes")
            return str(filename)
            
        except Exception as e:
            log_callback(f"Error killing connections: {e}")
            return None
    
    def block_dns(self, log_callback):
        log_callback("Blocking DNS resolution...")
        try:
            if self.platform == 'linux':
                commands = [
                    ['iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport', '53', '-j', 'DROP'],
                    ['iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport', '53', '-j', 'DROP'],
                    # Backup DNS servers
                    ['iptables', '-A', 'OUTPUT', '-d', '8.8.8.8', '-j', 'DROP'],
                    ['iptables', '-A', 'OUTPUT', '-d', '8.8.4.4', '-j', 'DROP'],
                    ['iptables', '-A', 'OUTPUT', '-d', '1.1.1.1', '-j', 'DROP']
                ]
            else:  # Windows
                commands = [
                    ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=IRIS_BLOCK_DNS_UDP', 'dir=out', 'action=block', 'protocol=UDP', 'localport=53'],
                    ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=IRIS_BLOCK_DNS_TCP', 'dir=out', 'action=block', 'protocol=TCP', 'localport=53']
                ]
            
            results = []
            for cmd in commands:
                try:
                    subprocess.run(cmd, capture_output=True, text=True, check=True)
                    results.append(f"SUCCESS: {' '.join(cmd)}")
                    log_callback(f"Executed: {' '.join(cmd)}")
                except subprocess.CalledProcessError as e:
                    results.append(f"FAILED: {' '.join(cmd)} - {e}")
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.output_dir / f"dns_block_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"DNS Blocking - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n")
                f.write("DNS resolution has been blocked\n")
                f.write("Commands executed:\n")
                for result in results:
                    f.write(result + "\n")
            
            log_callback("DNS blocking complete")
            return str(filename)
            
        except Exception as e:
            log_callback(f"Error blocking DNS: {e}")
            return None
    
    def isolation_status(self, log_callback):
        log_callback("Checking isolation status...")
        try:
            status_info = {
                'timestamp': datetime.now().isoformat(),
                'platform': self.platform,
                'isolation_active': False,
                'firewall_rules': [],
                'active_connections': []
            }
            
            if self.platform == 'linux':
                # Check iptables rules
                try:
                    iptables_result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, check=True)
                    status_info['firewall_rules'] = iptables_result.stdout.split('\n')
                    status_info['isolation_active'] = 'DROP' in iptables_result.stdout
                except subprocess.CalledProcessError:
                    status_info['firewall_rules'] = ["Could not read iptables rules"]
                
                # Check active connections
                try:
                    netstat_result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, check=True)
                    status_info['active_connections'] = netstat_result.stdout.split('\n')
                except subprocess.CalledProcessError:
                    status_info['active_connections'] = ["Could not read network connections"]
                    
            else:  # Windows
                try:
                    firewall_result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True, check=True)
                    status_info['firewall_rules'] = firewall_result.stdout.split('\n')
                    status_info['isolation_active'] = 'Block' in firewall_result.stdout
                except subprocess.CalledProcessError:
                    status_info['firewall_rules'] = ["Could not read firewall rules"]
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.output_dir / f"isolation_status_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(status_info, f, indent=2)
            
            isolation_text = "ACTIVE" if status_info['isolation_active'] else "INACTIVE"
            log_callback(f"Isolation status: {isolation_text}")
            log_callback(f"Active connections: {len(status_info['active_connections'])} found")
            
            return str(filename)
            
        except Exception as e:
            log_callback(f"Error checking isolation status: {e}")
            return None