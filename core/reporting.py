import json
import os
import hashlib
from datetime import datetime
from pathlib import Path
import glob

class ReportGenerator:
    def __init__(self, platform, config):
        self.platform = platform
        self.config = config
        self.output_dir = Path(config.get('evidence_collection', {}).get('output_directory', 'output'))
        self.output_dir.mkdir(exist_ok=True)
        
    def run_operation(self, operation, log_callback):
        operations = {
            'inventory': self.generate_inventory,
            'timeline': self.generate_timeline,
            'summary': self.generate_summary,
            'export_txt': self.export_text_report,
            'export_html': self.export_html_report
        }
        
        if operation in operations:
            return operations[operation](log_callback)
        else:
            log_callback(f"Unknown reporting operation: {operation}")
            return None
    
    def generate_inventory(self, log_callback):
        log_callback("Generating evidence inventory...")
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            inventory = {
                'generation_time': datetime.now().isoformat(),
                'platform': self.platform,
                'evidence_files': [],
                'total_files': 0,
                'total_size_bytes': 0
            }
            
            # Scan output directory for evidence files
            for file_path in self.output_dir.rglob('*'):
                if file_path.is_file() and not file_path.name.startswith('inventory'):
                    try:
                        file_stat = file_path.stat()
                        file_hash = self.calculate_file_hash(file_path)
                        
                        file_info = {
                            'filename': file_path.name,
                            'path': str(file_path.relative_to(self.output_dir)),
                            'size_bytes': file_stat.st_size,
                            'created': datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                            'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                            'md5_hash': file_hash['md5'],
                            'sha256_hash': file_hash['sha256'],
                            'file_type': self.determine_file_type(file_path)
                        }
                        
                        inventory['evidence_files'].append(file_info)
                        inventory['total_size_bytes'] += file_stat.st_size
                        
                    except Exception as e:
                        log_callback(f"Error processing {file_path}: {e}")
            
            inventory['total_files'] = len(inventory['evidence_files'])
            
            # Sort by creation time
            inventory['evidence_files'].sort(key=lambda x: x['created'], reverse=True)
            
            # Save inventory
            inventory_file = self.output_dir / f"evidence_inventory_{timestamp}.json"
            with open(inventory_file, 'w') as f:
                json.dump(inventory, f, indent=2)
            
            log_callback(f"Evidence inventory generated: {inventory['total_files']} files")
            log_callback(f"Total evidence size: {inventory['total_size_bytes']} bytes")
            
            return str(inventory_file)
            
        except Exception as e:
            log_callback(f"Error generating inventory: {e}")
            return None
    
    def generate_timeline(self, log_callback):
        log_callback("Generating investigation timeline...")
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            timeline_events = []
            
            # Collect events from all evidence files
            for file_path in self.output_dir.glob('*'):
                if file_path.is_file():
                    file_stat = file_path.stat()
                    event = {
                        'timestamp': datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                        'event_type': 'evidence_collected',
                        'description': f"Evidence file created: {file_path.name}",
                        'file_path': str(file_path.relative_to(self.output_dir)),
                        'file_size': file_stat.st_size
                    }
                    timeline_events.append(event)
            
            # Parse log files for additional events
            self.parse_log_events(timeline_events, log_callback)
            
            # Sort timeline by timestamp
            timeline_events.sort(key=lambda x: x['timestamp'])
            
            timeline_data = {
                'generation_time': datetime.now().isoformat(),
                'platform': self.platform,
                'total_events': len(timeline_events),
                'timeline': timeline_events
            }
            
            # Save timeline
            timeline_file = self.output_dir / f"investigation_timeline_{timestamp}.json"
            with open(timeline_file, 'w') as f:
                json.dump(timeline_data, f, indent=2)
            
            # Create human-readable timeline
            timeline_txt = self.output_dir / f"investigation_timeline_{timestamp}.txt"
            with open(timeline_txt, 'w') as f:
                f.write(f"Investigation Timeline - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n")
                f.write(f"Platform: {self.platform}\n")
                f.write(f"Total events: {len(timeline_events)}\n")
                f.write("=" * 60 + "\n\n")
                
                for event in timeline_events:
                    f.write(f"[{event['timestamp']}] {event['event_type'].upper()}\n")
                    f.write(f"  {event['description']}\n")
                    if 'file_path' in event:
                        f.write(f"  File: {event['file_path']}\n")
                    f.write("\n")
            
            log_callback(f"Timeline generated: {len(timeline_events)} events")
            return str(timeline_txt)
            
        except Exception as e:
            log_callback(f"Error generating timeline: {e}")
            return None
    
    def generate_summary(self, log_callback):
        log_callback("Generating system summary...")
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Collect summary information
            summary = {
                'generation_time': datetime.now().isoformat(),
                'platform': self.platform,
                'incident_response_summary': {},
                'evidence_summary': {},
                'system_state': {},
                'recommendations': []
            }
            
            # Count evidence files by type
            evidence_counts = {}
            total_evidence_size = 0
            
            for file_path in self.output_dir.glob('*'):
                if file_path.is_file():
                    file_type = self.determine_file_type(file_path)
                    evidence_counts[file_type] = evidence_counts.get(file_type, 0) + 1
                    total_evidence_size += file_path.stat().st_size
            
            summary['evidence_summary'] = {
                'total_files': sum(evidence_counts.values()),
                'total_size_bytes': total_evidence_size,
                'file_types': evidence_counts
            }
            
            # Parse system information if available
            system_info_files = list(self.output_dir.glob('system_info_*.txt'))
            if system_info_files:
                summary['system_state']['system_info_collected'] = True
                summary['system_state']['system_info_files'] = len(system_info_files)
            
            # Check for network isolation evidence
            isolation_files = list(self.output_dir.glob('*isolation*'))
            if isolation_files:
                summary['system_state']['network_isolation_applied'] = True
                summary['system_state']['isolation_files'] = len(isolation_files)
            
            # Generate recommendations
            if evidence_counts.get('process_list', 0) > 0:
                summary['recommendations'].append("Review process list for suspicious processes")
            
            if evidence_counts.get('network_connections', 0) > 0:
                summary['recommendations'].append("Analyze network connections for malicious activity")
            
            if evidence_counts.get('log_files', 0) > 0:
                summary['recommendations'].append("Examine log files for indicators of compromise")
            
            if not isolation_files:
                summary['recommendations'].append("Consider network isolation if threat is active")
            
            # Save summary
            summary_file = self.output_dir / f"incident_summary_{timestamp}.json"
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
            
            # Create human-readable summary
            summary_txt = self.output_dir / f"incident_summary_{timestamp}.txt"
            with open(summary_txt, 'w') as f:
                f.write("INCIDENT RESPONSE SUMMARY REPORT\n")
                f.write("=" * 60 + "\n")
                f.write(f"Generated: {summary['generation_time']}\n")
                f.write(f"Platform: {self.platform.upper()}\n")
                f.write("=" * 60 + "\n\n")
                
                f.write("EVIDENCE COLLECTION SUMMARY:\n")
                f.write("-" * 30 + "\n")
                f.write(f"Total files collected: {summary['evidence_summary']['total_files']}\n")
                f.write(f"Total evidence size: {summary['evidence_summary']['total_size_bytes']} bytes\n")
                f.write("\nFile types collected:\n")
                for file_type, count in summary['evidence_summary']['file_types'].items():
                    f.write(f"  - {file_type}: {count} files\n")
                
                f.write("\nSYSTEM STATE:\n")
                f.write("-" * 15 + "\n")
                for key, value in summary['system_state'].items():
                    f.write(f"  - {key.replace('_', ' ').title()}: {value}\n")
                
                f.write("\nRECOMMENDATIONS:\n")
                f.write("-" * 17 + "\n")
                for i, recommendation in enumerate(summary['recommendations'], 1):
                    f.write(f"{i}. {recommendation}\n")
                
                f.write("\n" + "=" * 60 + "\n")
                f.write("End of Summary Report\n")
            
            log_callback(f"System summary generated: {summary['evidence_summary']['total_files']} evidence files")
            return str(summary_txt)
            
        except Exception as e:
            log_callback(f"Error generating summary: {e}")
            return None
    
    def export_text_report(self, log_callback):
        log_callback("Exporting comprehensive text report...")
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = self.output_dir / f"IRIS_incident_report_{timestamp}.txt"
            
            with open(report_file, 'w') as f:
                # Header
                f.write("IRIS INCIDENT RESPONSE REPORT\n")
                f.write("=" * 60 + "\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f"Platform: {self.platform.upper()}\n")
                f.write(f"IRIS Version: {self.config.get('application', {}).get('version', 'Unknown')}\n")
                f.write("=" * 60 + "\n\n")
                
                # Include all evidence files content
                evidence_files = sorted(self.output_dir.glob('*.txt'))
                
                for evidence_file in evidence_files:
                    if evidence_file.name != report_file.name:
                        f.write(f"EVIDENCE FILE: {evidence_file.name}\n")
                        f.write("-" * 40 + "\n")
                        try:
                            with open(evidence_file, 'r') as ef:
                                content = ef.read()
                                f.write(content)
                        except Exception as e:
                            f.write(f"Error reading file: {e}\n")
                        f.write("\n" + "=" * 60 + "\n\n")
                
                # Footer
                f.write("END OF INCIDENT RESPONSE REPORT\n")
                f.write("Generated by IRIS - Incident Response Integration Suite\n")
                f.write(f"Report hash: {self.calculate_file_hash(report_file)['sha256']}\n")
            
            # Calculate final hash after file is complete
            final_hash = self.calculate_file_hash(report_file)
            with open(report_file, 'a') as f:
                f.write(f"Final report hash: {final_hash['sha256']}\n")
            
            log_callback(f"Text report exported: {report_file.name}")
            return str(report_file)
            
        except Exception as e:
            log_callback(f"Error exporting text report: {e}")
            return None
    
    def export_html_report(self, log_callback):
        log_callback("Exporting HTML report...")
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = self.output_dir / f"IRIS_incident_report_{timestamp}.html"
            
            with open(report_file, 'w') as f:
                # HTML Header
                f.write("""<!DOCTYPE html>
<html>
<head>
    <title>IRIS Incident Response Report</title>
    <style>
        body { font-family: 'Courier New', monospace; margin: 20px; background: white; color: black; }
        .header { border: 3px solid black; padding: 20px; margin-bottom: 20px; }
        .section { border: 2px solid black; padding: 15px; margin-bottom: 15px; }
        .evidence-file { border: 1px solid black; padding: 10px; margin: 10px 0; }
        .timestamp { font-weight: bold; }
        pre { background: #f0f0f0; padding: 10px; border: 1px solid black; overflow-x: auto; }
        h1, h2, h3 { border-bottom: 2px solid black; }
    </style>
</head>
<body>
""")
                
                # Header section
                f.write(f"""
    <div class="header">
        <h1>🛡️ IRIS INCIDENT RESPONSE REPORT</h1>
        <p><strong>Generated:</strong> {datetime.now().isoformat()}</p>
        <p><strong>Platform:</strong> {self.platform.upper()}</p>
        <p><strong>IRIS Version:</strong> {self.config.get('application', {}).get('version', 'Unknown')}</p>
    </div>
""")
                
                # Evidence sections
                evidence_files = sorted(self.output_dir.glob('*.txt'))
                
                for evidence_file in evidence_files:
                    if not evidence_file.name.endswith('.html'):
                        f.write(f"""
    <div class="section">
        <h2>Evidence File: {evidence_file.name}</h2>
        <div class="evidence-file">
""")
                        try:
                            with open(evidence_file, 'r') as ef:
                                content = ef.read()
                                # Escape HTML characters
                                content = content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                                f.write(f"<pre>{content}</pre>")
                        except Exception as e:
                            f.write(f"<p>Error reading file: {e}</p>")
                        
                        f.write("        </div>\n    </div>\n")
                
                # Footer
                f.write(f"""
    <div class="section">
        <h3>Report Information</h3>
        <p>Generated by IRIS - Incident Response Integration Suite</p>
        <p>This report contains evidence collected during incident response.</p>
        <p class="timestamp">Generation completed: {datetime.now().isoformat()}</p>
    </div>
</body>
</html>
""")
            
            log_callback(f"HTML report exported: {report_file.name}")
            return str(report_file)
            
        except Exception as e:
            log_callback(f"Error exporting HTML report: {e}")
            return None
    
    def parse_log_events(self, timeline_events, log_callback):
        """Parse log files to extract timeline events"""
        try:
            # Look for process collection events
            process_files = list(self.output_dir.glob('processes_*.txt'))
            for process_file in process_files:
                file_stat = process_file.stat()
                event = {
                    'timestamp': datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                    'event_type': 'process_enumeration',
                    'description': 'System processes enumerated',
                    'file_path': str(process_file.relative_to(self.output_dir))
                }
                timeline_events.append(event)
            
            # Look for network isolation events
            isolation_files = list(self.output_dir.glob('*isolation*.txt'))
            for isolation_file in isolation_files:
                file_stat = isolation_file.stat()
                event = {
                    'timestamp': datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                    'event_type': 'network_isolation',
                    'description': 'Network isolation applied',
                    'file_path': str(isolation_file.relative_to(self.output_dir))
                }
                timeline_events.append(event)
                
        except Exception as e:
            log_callback(f"Error parsing log events: {e}")
    
    def determine_file_type(self, file_path):
        """Determine evidence file type based on filename"""
        name = file_path.name.lower()
        
        if 'process' in name:
            return 'process_list'
        elif 'network' in name:
            return 'network_connections'
        elif 'system' in name:
            return 'system_information'
        elif 'user' in name:
            return 'user_accounts'
        elif 'hash' in name:
            return 'file_hashes'
        elif 'log' in name:
            return 'log_files'
        elif 'memory' in name:
            return 'memory_snapshot'
        elif 'browser' in name:
            return 'browser_artifacts'
        elif 'screenshot' in name:
            return 'screenshot'
        elif 'isolation' in name:
            return 'network_isolation'
        elif name.endswith('.json'):
            return 'structured_data'
        elif name.endswith('.html'):
            return 'report_html'
        else:
            return 'other'
    
    def calculate_file_hash(self, file_path):
        """Calculate MD5 and SHA256 hashes of a file"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()
                return {'md5': md5_hash, 'sha256': sha256_hash}
        except Exception:
            return {'md5': 'error', 'sha256': 'error'}