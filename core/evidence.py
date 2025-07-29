import subprocess
import os
import hashlib
import json
from datetime import datetime
from pathlib import Path

class EvidenceCollector:
    def __init__(self, platform, config):
        self.platform = platform
        self.config = config
        self.output_dir = Path(config.get('evidence_collection', {}).get('output_directory', 'output'))
        self.output_dir.mkdir(exist_ok=True)
        
    def run_operation(self, operation, log_callback):
        operations = {
            'processes': self.collect_processes,
            'network': self.collect_network,
            'sysinfo': self.collect_system_info,
            'hash': self.hash_files
        }
        
        if operation in operations:
            return operations[operation](log_callback)
        else:
            log_callback(f"Unknown evidence operation: {operation}")
            return None
    
    def collect_processes(self, log_callback):
        log_callback("Collecting running processes...")
        try:
            if self.platform == 'linux':
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, check=True)
            else:  # Windows
                result = subprocess.run(['tasklist', '/fo', 'csv', '/v'], capture_output=True, text=True, check=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.output_dir / f"processes_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"Process List - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n")
                f.write(result.stdout)
            
            log_callback(f"Process list saved to {filename}")
            return str(filename)
        except subprocess.CalledProcessError as e:
            log_callback(f"Error collecting processes: {e}")
            return None
    
    def collect_network(self, log_callback):
        log_callback("Collecting network connections...")
        try:
            if self.platform == 'linux':
                # Get network connections
                netstat_result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, check=True)
                ss_result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, check=True)
            else:  # Windows
                netstat_result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, check=True)
                ss_result = subprocess.run(['netstat', '-anb'], capture_output=True, text=True, check=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.output_dir / f"network_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"Network Connections - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n")
                f.write("NETSTAT OUTPUT:\n")
                f.write(netstat_result.stdout)
                f.write("\n" + "=" * 60 + "\n")
                if self.platform == 'linux':
                    f.write("SS OUTPUT:\n")
                else:
                    f.write("DETAILED NETSTAT OUTPUT:\n")
                f.write(ss_result.stdout)
            
            log_callback(f"Network connections saved to {filename}")
            return str(filename)
        except subprocess.CalledProcessError as e:
            log_callback(f"Error collecting network info: {e}")
            return None
    
    def collect_system_info(self, log_callback):
        log_callback("Collecting system information...")
        try:
            system_info = {}
            
            if self.platform == 'linux':
                # Hostname
                hostname = subprocess.run(['hostname'], capture_output=True, text=True, check=True)
                system_info['hostname'] = hostname.stdout.strip()
                
                # OS Info
                os_info = subprocess.run(['uname', '-a'], capture_output=True, text=True, check=True)
                system_info['os_info'] = os_info.stdout.strip()
                
                # Uptime
                uptime = subprocess.run(['uptime'], capture_output=True, text=True, check=True)
                system_info['uptime'] = uptime.stdout.strip()
                
                # IP addresses
                ip_info = subprocess.run(['ip', 'addr'], capture_output=True, text=True, check=True)
                system_info['ip_addresses'] = ip_info.stdout
                
                # Memory info
                mem_info = subprocess.run(['free', '-h'], capture_output=True, text=True, check=True)
                system_info['memory'] = mem_info.stdout
                
            else:  # Windows
                # System info
                sysinfo = subprocess.run(['systeminfo'], capture_output=True, text=True, check=True)
                system_info['system_info'] = sysinfo.stdout
                
                # IP config
                ipconfig = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, check=True)
                system_info['ip_config'] = ipconfig.stdout
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.output_dir / f"system_info_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"System Information - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n")
                for key, value in system_info.items():
                    f.write(f"{key.upper()}:\n{value}\n")
                    f.write("-" * 40 + "\n")
            
            log_callback(f"System information saved to {filename}")
            return str(filename)
        except subprocess.CalledProcessError as e:
            log_callback(f"Error collecting system info: {e}")
            return None
    
    def collect_users(self, log_callback):
        log_callback("Collecting user account information...")
        try:
            if self.platform == 'linux':
                # Currently logged in users
                who_result = subprocess.run(['who'], capture_output=True, text=True, check=False)
                if who_result.returncode != 0:
                    who_result = subprocess.run(['w'], capture_output=True, text=True, check=False)
                
                # Last logins - try multiple commands
                last_result = None
                for cmd in [['last', '-10'], ['journalctl', '-u', 'ssh', '--since', 'yesterday', '-n', '10'], ['dmesg', '|', 'grep', 'login']]:
                    try:
                        if len(cmd) > 2 and '|' in cmd:
                            # Handle piped commands
                            result = subprocess.run(' '.join(cmd), shell=True, capture_output=True, text=True, check=True)
                        else:
                            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                        last_result = result
                        break
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        continue
                
                if last_result is None:
                    last_result = subprocess.run(['echo', 'Login history not available - system may not have wtmp/journal logs'], capture_output=True, text=True)
                
                # All users
                users_result = subprocess.run(['cat', '/etc/passwd'], capture_output=True, text=True, check=True)
            else:  # Windows
                # Logged in users
                who_result = subprocess.run(['query', 'user'], capture_output=True, text=True, check=True)
                # User accounts
                users_result = subprocess.run(['net', 'user'], capture_output=True, text=True, check=True)
                last_result = subprocess.run(['wevtutil', 'qe', 'Security', '/c:10', '/f:text'], capture_output=True, text=True, check=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.output_dir / f"users_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"User Account Information - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n")
                f.write("CURRENTLY LOGGED IN:\n")
                f.write(who_result.stdout)
                f.write("\n" + "=" * 40 + "\n")
                f.write("RECENT LOGINS:\n")
                f.write(last_result.stdout)
                f.write("\n" + "=" * 40 + "\n")
                f.write("USER ACCOUNTS:\n")
                f.write(users_result.stdout)
            
            log_callback(f"User information saved to {filename}")
            return str(filename)
        except subprocess.CalledProcessError as e:
            log_callback(f"Error collecting user info: {e}")
            return None
    
    def hash_files(self, log_callback):
        log_callback("Generating file hashes for suspicious locations...")
        try:
            suspicious_paths = []
            hashes = []
            
            if self.platform == 'linux':
                suspicious_paths = [
                    '/tmp',
                    '/var/tmp',
                    '/dev/shm',
                    os.path.expanduser('~/Downloads'),
                    '/etc/crontab'
                ]
            else:  # Windows
                suspicious_paths = [
                    'C:\\Temp',
                    'C:\\Windows\\Temp',
                    os.path.expanduser('~\\Downloads'),
                    os.path.expanduser('~\\AppData\\Local\\Temp')
                ]
            
            for path in suspicious_paths:
                if os.path.exists(path):
                    if os.path.isfile(path):
                        file_hash = self.calculate_file_hash(path)
                        if file_hash:
                            hashes.append({
                                'file': path,
                                'md5': file_hash['md5'],
                                'sha256': file_hash['sha256'],
                                'size': os.path.getsize(path),
                                'modified': datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                            })
                    elif os.path.isdir(path):
                        for root, dirs, files in os.walk(path):
                            for file in files[:10]:  # Limit to first 10 files per directory
                                filepath = os.path.join(root, file)
                                file_hash = self.calculate_file_hash(filepath)
                                if file_hash:
                                    hashes.append({
                                        'file': filepath,
                                        'md5': file_hash['md5'],
                                        'sha256': file_hash['sha256'],
                                        'size': os.path.getsize(filepath),
                                        'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                                    })
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.output_dir / f"file_hashes_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'platform': self.platform,
                    'files': hashes
                }, f, indent=2)
            
            log_callback(f"File hashes saved to {filename} ({len(hashes)} files)")
            return str(filename)
        except Exception as e:
            log_callback(f"Error generating file hashes: {e}")
            return None
    
    def calculate_file_hash(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()
                return {'md5': md5_hash, 'sha256': sha256_hash}
        except Exception:
            return None