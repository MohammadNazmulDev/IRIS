import subprocess
import os
import shutil
from datetime import datetime
from pathlib import Path
import tempfile

class ForensicsCollector:
    def __init__(self, platform, config):
        self.platform = platform
        self.config = config
        self.output_dir = Path(config.get('evidence_collection', {}).get('output_directory', 'output'))
        self.output_dir.mkdir(exist_ok=True)
        self.max_log_size = config.get('forensics', {}).get('max_log_size_mb', 100) * 1024 * 1024
        
    def run_operation(self, operation, log_callback):
        operations = {
            'memory': self.capture_memory,
            'logs': self.collect_logs,
            'browser': self.collect_browser_artifacts,
            'files': self.collect_recent_files,
            'screenshot': self.take_screenshot
        }
        
        if operation in operations:
            return operations[operation](log_callback)
        else:
            log_callback(f"Unknown forensics operation: {operation}")
            return None
    
    def capture_memory(self, log_callback):
        log_callback("Capturing memory snapshot...")
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if self.platform == 'linux':
                # Create memory dump using /proc/kcore (limited but available)
                memory_info = {}
                
                # Memory statistics
                try:
                    with open('/proc/meminfo', 'r') as f:
                        memory_info['meminfo'] = f.read()
                except:
                    memory_info['meminfo'] = "Could not read /proc/meminfo"
                
                # Process memory maps
                try:
                    result = subprocess.run(['ps', 'aux', '--sort=-%mem'], capture_output=True, text=True, check=True)
                    memory_info['top_memory_processes'] = result.stdout
                except:
                    memory_info['top_memory_processes'] = "Could not get process memory info"
                
                # Virtual memory stats
                try:
                    result = subprocess.run(['vmstat'], capture_output=True, text=True, check=True)
                    memory_info['vmstat'] = result.stdout
                except:
                    memory_info['vmstat'] = "Could not get vmstat"
                
                # Save memory snapshot info
                filename = self.output_dir / f"memory_snapshot_{timestamp}.txt"
                with open(filename, 'w') as f:
                    f.write(f"Memory Snapshot - {datetime.now().isoformat()}\n")
                    f.write("=" * 60 + "\n")
                    f.write("WARNING: Full memory dump requires specialized tools\n")
                    f.write("This is a summary of memory state and processes\n")
                    f.write("=" * 60 + "\n")
                    for key, value in memory_info.items():
                        f.write(f"\n{key.upper()}:\n")
                        f.write(value)
                        f.write("\n" + "-" * 40 + "\n")
                
            else:  # Windows
                # Windows memory capture would require specialized tools
                filename = self.output_dir / f"memory_snapshot_{timestamp}.txt"
                with open(filename, 'w') as f:
                    f.write(f"Memory Snapshot - {datetime.now().isoformat()}\n")
                    f.write("=" * 60 + "\n")
                    f.write("Windows memory capture requires specialized tools like WinPmem\n")
                    f.write("This MVP version provides process memory information instead\n")
                    f.write("=" * 60 + "\n")
                    
                    try:
                        result = subprocess.run(['tasklist', '/fo', 'csv', '/v'], capture_output=True, text=True, check=True)
                        f.write("PROCESS MEMORY USAGE:\n")
                        f.write(result.stdout)
                    except:
                        f.write("Could not retrieve process information\n")
            
            log_callback(f"Memory snapshot saved to {filename}")
            log_callback("Note: Full memory dumps require specialized tools")
            return str(filename)
            
        except Exception as e:
            log_callback(f"Error capturing memory: {e}")
            return None
    
    def collect_logs(self, log_callback):
        log_callback("Collecting system logs...")
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            logs_dir = self.output_dir / f"logs_{timestamp}"
            logs_dir.mkdir(exist_ok=True)
            
            if self.platform == 'linux':
                log_locations = [
                    '/var/log/syslog',
                    '/var/log/auth.log',
                    '/var/log/kern.log',
                    '/var/log/dmesg',
                    '/var/log/messages',
                    '/var/log/secure'
                ]
                
                # Also collect systemd journal
                try:
                    result = subprocess.run(['journalctl', '--since', '1 hour ago'], capture_output=True, text=True, check=True)
                    with open(logs_dir / 'journalctl_recent.log', 'w') as f:
                        f.write(result.stdout)
                    log_callback("Collected journalctl logs")
                except subprocess.CalledProcessError:
                    log_callback("Could not collect journalctl logs")
                
            else:  # Windows
                log_locations = []
                # Windows Event Log collection
                event_logs = ['System', 'Security', 'Application']
                
                for event_log in event_logs:
                    try:
                        result = subprocess.run(['wevtutil', 'qe', event_log, '/c:100', '/f:text'], 
                                              capture_output=True, text=True, check=True)
                        with open(logs_dir / f'{event_log.lower()}_events.log', 'w') as f:
                            f.write(result.stdout)
                        log_callback(f"Collected {event_log} event log")
                    except subprocess.CalledProcessError:
                        log_callback(f"Could not collect {event_log} event log")
            
            # Copy existing log files
            collected_logs = []
            for log_path in log_locations:
                if os.path.exists(log_path) and os.path.isfile(log_path):
                    try:
                        file_size = os.path.getsize(log_path)
                        if file_size > self.max_log_size:
                            # If log is too large, copy only the last part
                            with open(log_path, 'rb') as source:
                                source.seek(-self.max_log_size, 2)  # Seek to last max_log_size bytes
                                content = source.read()
                            
                            dest_path = logs_dir / f"{Path(log_path).name}_truncated"
                            with open(dest_path, 'wb') as dest:
                                dest.write(content)
                            collected_logs.append(f"{log_path} (truncated to {self.max_log_size} bytes)")
                        else:
                            dest_path = logs_dir / Path(log_path).name
                            shutil.copy2(log_path, dest_path)
                            collected_logs.append(log_path)
                        
                        log_callback(f"Collected: {log_path}")
                    except Exception as e:
                        log_callback(f"Failed to collect {log_path}: {e}")
            
            # Create summary
            summary_file = logs_dir / "log_collection_summary.txt"
            with open(summary_file, 'w') as f:
                f.write(f"Log Collection Summary - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n")
                f.write(f"Platform: {self.platform}\n")
                f.write(f"Collection timestamp: {timestamp}\n")
                f.write(f"Max log size limit: {self.max_log_size} bytes\n")
                f.write("\nCollected logs:\n")
                for log in collected_logs:
                    f.write(f"  - {log}\n")
            
            log_callback(f"Log collection complete: {len(collected_logs)} files")
            return str(logs_dir)
            
        except Exception as e:
            log_callback(f"Error collecting logs: {e}")
            return None
    
    def collect_browser_artifacts(self, log_callback):
        log_callback("Collecting browser artifacts...")
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            browser_dir = self.output_dir / f"browser_artifacts_{timestamp}"
            browser_dir.mkdir(exist_ok=True)
            
            home_dir = Path.home()
            artifacts = []
            
            if self.platform == 'linux':
                browser_paths = {
                    'firefox': home_dir / '.mozilla/firefox',
                    'chrome': home_dir / '.config/google-chrome',
                    'chromium': home_dir / '.config/chromium'
                }
            else:  # Windows
                browser_paths = {
                    'chrome': home_dir / 'AppData/Local/Google/Chrome/User Data',
                    'firefox': home_dir / 'AppData/Roaming/Mozilla/Firefox/Profiles',
                    'edge': home_dir / 'AppData/Local/Microsoft/Edge/User Data'
                }
            
            for browser_name, browser_path in browser_paths.items():
                if browser_path.exists():
                    log_callback(f"Found {browser_name} profile")
                    
                    # Look for specific files
                    target_files = ['history', 'cookies', 'downloads', 'bookmarks']
                    
                    for root, dirs, files in os.walk(browser_path):
                        for file in files:
                            file_lower = file.lower()
                            if any(target in file_lower for target in target_files):
                                source_path = Path(root) / file
                                relative_path = source_path.relative_to(browser_path)
                                dest_path = browser_dir / browser_name / relative_path
                                dest_path.parent.mkdir(parents=True, exist_ok=True)
                                
                                try:
                                    shutil.copy2(source_path, dest_path)
                                    artifacts.append(f"{browser_name}: {relative_path}")
                                    log_callback(f"Copied: {browser_name}/{relative_path}")
                                except Exception as e:
                                    log_callback(f"Failed to copy {source_path}: {e}")
                        
                        # Don't go too deep to avoid collecting too much
                        if len(artifacts) > 50:
                            break
            
            # Create summary
            summary_file = browser_dir / "browser_artifacts_summary.txt"
            with open(summary_file, 'w') as f:
                f.write(f"Browser Artifacts Collection - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n")
                f.write(f"Platform: {self.platform}\n")
                f.write(f"Collection timestamp: {timestamp}\n")
                f.write("\nCollected artifacts:\n")
                for artifact in artifacts:
                    f.write(f"  - {artifact}\n")
            
            log_callback(f"Browser artifacts collection complete: {len(artifacts)} files")
            return str(browser_dir)
            
        except Exception as e:
            log_callback(f"Error collecting browser artifacts: {e}")
            return None
    
    def collect_recent_files(self, log_callback):
        log_callback("Collecting recently accessed files...")
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            recent_files = []
            
            if self.platform == 'linux':
                # Find recently modified files in key directories
                search_paths = [
                    Path.home() / 'Downloads',
                    Path.home() / 'Documents', 
                    Path.home() / 'Desktop',
                    Path('/tmp'),
                    Path('/var/tmp')
                ]
                
                for search_path in search_paths:
                    if search_path.exists():
                        try:
                            # Find files modified in last 24 hours
                            result = subprocess.run(['find', str(search_path), '-type', 'f', '-mtime', '-1'], 
                                                  capture_output=True, text=True, check=True)
                            
                            for file_path in result.stdout.strip().split('\n'):
                                if file_path and os.path.exists(file_path):
                                    try:
                                        stat = os.stat(file_path)
                                        recent_files.append({
                                            'path': file_path,
                                            'size': stat.st_size,
                                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat()
                                        })
                                    except Exception:
                                        pass
                        except subprocess.CalledProcessError:
                            log_callback(f"Could not search {search_path}")
            else:  # Windows
                # Windows recent files
                search_paths = [
                    Path.home() / 'Downloads',
                    Path.home() / 'Documents',
                    Path.home() / 'Desktop',
                    Path('C:/Temp'),
                    Path.home() / 'AppData/Local/Temp'
                ]
                
                for search_path in search_paths:
                    if search_path.exists():
                        try:
                            for file_path in search_path.rglob('*'):
                                if file_path.is_file():
                                    try:
                                        stat = file_path.stat()
                                        # Files modified in last 24 hours
                                        if (datetime.now().timestamp() - stat.st_mtime) < 86400:
                                            recent_files.append({
                                                'path': str(file_path),
                                                'size': stat.st_size,
                                                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat()
                                            })
                                    except Exception:
                                        pass
                                    
                                    # Limit results
                                    if len(recent_files) > 100:
                                        break
                        except Exception:
                            log_callback(f"Could not search {search_path}")
            
            # Sort by modification time
            recent_files.sort(key=lambda x: x['modified'], reverse=True)
            recent_files = recent_files[:50]  # Keep top 50
            
            filename = self.output_dir / f"recent_files_{timestamp}.txt"
            with open(filename, 'w') as f:
                f.write(f"Recently Accessed Files - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n")
                f.write(f"Platform: {self.platform}\n")
                f.write(f"Files modified in last 24 hours (top 50):\n")
                f.write("=" * 60 + "\n")
                
                for file_info in recent_files:
                    f.write(f"Path: {file_info['path']}\n")
                    f.write(f"Size: {file_info['size']} bytes\n")
                    f.write(f"Modified: {file_info['modified']}\n")
                    f.write(f"Accessed: {file_info['accessed']}\n")
                    f.write("-" * 40 + "\n")
            
            log_callback(f"Recent files collection complete: {len(recent_files)} files")
            return str(filename)
            
        except Exception as e:
            log_callback(f"Error collecting recent files: {e}")
            return None
    
    def take_screenshot(self, log_callback):
        log_callback("Taking desktop screenshot...")
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if self.platform == 'linux':
                screenshot_file = self.output_dir / f"screenshot_{timestamp}.png"
                
                # Try different screenshot tools
                screenshot_commands = [
                    ['scrot', str(screenshot_file)],
                    ['gnome-screenshot', '-f', str(screenshot_file)],
                    ['import', '-window', 'root', str(screenshot_file)]
                ]
                
                screenshot_taken = False
                for cmd in screenshot_commands:
                    try:
                        subprocess.run(cmd, check=True, capture_output=True)
                        screenshot_taken = True
                        log_callback(f"Screenshot taken with {cmd[0]}")
                        break
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        continue
                
                if not screenshot_taken:
                    # Create a text file explaining the situation
                    screenshot_file = self.output_dir / f"screenshot_{timestamp}.txt"
                    with open(screenshot_file, 'w') as f:
                        f.write(f"Screenshot Attempt - {datetime.now().isoformat()}\n")
                        f.write("=" * 60 + "\n")
                        f.write("Could not take screenshot - no suitable tool found\n")
                        f.write("Install scrot, gnome-screenshot, or imagemagick for screenshots\n")
                    log_callback("No screenshot tool available")
                
            else:  # Windows
                screenshot_file = self.output_dir / f"screenshot_{timestamp}.png"
                
                # Use PowerShell to take screenshot
                ps_command = f"""
                Add-Type -AssemblyName System.Windows.Forms
                Add-Type -AssemblyName System.Drawing
                $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
                $Width = $Screen.Width
                $Height = $Screen.Height
                $Left = $Screen.Left
                $Top = $Screen.Top
                $bitmap = New-Object System.Drawing.Bitmap $Width, $Height
                $graphic = [System.Drawing.Graphics]::FromImage($bitmap)
                $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)
                $bitmap.Save('{screenshot_file}')
                """
                
                try:
                    subprocess.run(['powershell', '-Command', ps_command], check=True, capture_output=True)
                    log_callback("Screenshot taken with PowerShell")
                except subprocess.CalledProcessError:
                    # Fallback to text file
                    screenshot_file = self.output_dir / f"screenshot_{timestamp}.txt"
                    with open(screenshot_file, 'w') as f:
                        f.write(f"Screenshot Attempt - {datetime.now().isoformat()}\n")
                        f.write("=" * 60 + "\n")
                        f.write("Could not take screenshot with PowerShell\n")
                    log_callback("Screenshot failed")
            
            return str(screenshot_file)
            
        except Exception as e:
            log_callback(f"Error taking screenshot: {e}")
            return None