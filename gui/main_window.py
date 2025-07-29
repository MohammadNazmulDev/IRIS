import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import subprocess
import sys
import os
from datetime import datetime

from gui.brutalist_theme import BrutalistTheme

class MainWindow:
    def __init__(self, root, config, platform):
        self.root = root
        self.config = config
        self.platform = platform
        self.current_operation = None
        
        BrutalistTheme.configure_root(self.root)
        self.setup_ui()
        
    def setup_ui(self):
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        
        self.create_header()
        self.create_main_content()
        self.create_status_bar()
        
    def create_header(self):
        header_frame = BrutalistTheme.create_frame(self.root)
        header_frame.grid(row=0, column=0, sticky='ew', padx=10, pady=5)
        header_frame.grid_columnconfigure(0, weight=1)
        
        title_label = BrutalistTheme.create_label(
            header_frame, 
            "🛡️ IRIS - INCIDENT RESPONSE INTEGRATION SUITE", 
            'title'
        )
        title_label.grid(row=0, column=0, pady=10)
        
        subtitle_label = BrutalistTheme.create_label(
            header_frame, 
            f"MVP VERSION | PLATFORM: {self.platform.upper()}", 
            'default'
        )
        subtitle_label.grid(row=1, column=0, pady=(0, 10))
        
    def create_main_content(self):
        main_frame = BrutalistTheme.create_frame(self.root)
        main_frame.grid(row=1, column=0, sticky='nsew', padx=10, pady=5)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_rowconfigure(2, weight=2)
        
        self.create_evidence_section(main_frame)
        self.create_isolation_section(main_frame)
        self.create_forensics_section(main_frame)
        self.create_reports_section(main_frame)
        self.create_terminal_section(main_frame)
        
    def create_evidence_section(self, parent):
        evidence_frame = BrutalistTheme.create_frame(parent)
        evidence_frame.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        evidence_frame.grid_columnconfigure(0, weight=1)
        
        title = BrutalistTheme.create_label(evidence_frame, "SYSTEM EVIDENCE COLLECTOR", 'button')
        title.grid(row=0, column=0, pady=10)
        
        btn_processes = BrutalistTheme.create_button(
            evidence_frame, "ENUMERATE PROCESSES", 
            lambda: self.run_operation("evidence", "processes")
        )
        btn_processes.grid(row=1, column=0, pady=2)
        
        btn_network = BrutalistTheme.create_button(
            evidence_frame, "NETWORK CONNECTIONS", 
            lambda: self.run_operation("evidence", "network")
        )
        btn_network.grid(row=2, column=0, pady=2)
        
        btn_sysinfo = BrutalistTheme.create_button(
            evidence_frame, "SYSTEM INFORMATION", 
            lambda: self.run_operation("evidence", "sysinfo")
        )
        btn_sysinfo.grid(row=3, column=0, pady=2)
        
        
        btn_hash = BrutalistTheme.create_button(
            evidence_frame, "FILE HASHING", 
            lambda: self.run_operation("evidence", "hash")
        )
        btn_hash.grid(row=4, column=0, pady=2)
        
    def create_isolation_section(self, parent):
        isolation_frame = BrutalistTheme.create_frame(parent)
        isolation_frame.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)
        isolation_frame.grid_columnconfigure(0, weight=1)
        
        title = BrutalistTheme.create_label(isolation_frame, "NETWORK ISOLATION", 'button')
        title.grid(row=0, column=0, pady=10)
        
        btn_emergency = BrutalistTheme.create_button(
            isolation_frame, "EMERGENCY ISOLATION", 
            lambda: self.run_operation("isolation", "emergency")
        )
        btn_emergency.grid(row=1, column=0, pady=2)
        
        btn_whitelist = BrutalistTheme.create_button(
            isolation_frame, "MANAGE WHITELIST", 
            lambda: self.run_operation("isolation", "whitelist")
        )
        btn_whitelist.grid(row=2, column=0, pady=2)
        
        btn_kill_conn = BrutalistTheme.create_button(
            isolation_frame, "KILL CONNECTIONS", 
            lambda: self.run_operation("isolation", "kill")
        )
        btn_kill_conn.grid(row=3, column=0, pady=2)
        
        btn_dns_block = BrutalistTheme.create_button(
            isolation_frame, "BLOCK DNS", 
            lambda: self.run_operation("isolation", "dns")
        )
        btn_dns_block.grid(row=4, column=0, pady=2)
        
        btn_status = BrutalistTheme.create_button(
            isolation_frame, "ISOLATION STATUS", 
            lambda: self.run_operation("isolation", "status")
        )
        btn_status.grid(row=5, column=0, pady=2)
        
    def create_forensics_section(self, parent):
        forensics_frame = BrutalistTheme.create_frame(parent)
        forensics_frame.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)
        forensics_frame.grid_columnconfigure(0, weight=1)
        
        title = BrutalistTheme.create_label(forensics_frame, "FORENSIC COLLECTION", 'button')
        title.grid(row=0, column=0, pady=10)
        
        btn_memory = BrutalistTheme.create_button(
            forensics_frame, "MEMORY SNAPSHOT", 
            lambda: self.run_operation("forensics", "memory")
        )
        btn_memory.grid(row=1, column=0, pady=2)
        
        btn_logs = BrutalistTheme.create_button(
            forensics_frame, "COLLECT LOGS", 
            lambda: self.run_operation("forensics", "logs")
        )
        btn_logs.grid(row=2, column=0, pady=2)
        
        btn_browser = BrutalistTheme.create_button(
            forensics_frame, "BROWSER ARTIFACTS", 
            lambda: self.run_operation("forensics", "browser")
        )
        btn_browser.grid(row=3, column=0, pady=2)
        
        btn_files = BrutalistTheme.create_button(
            forensics_frame, "RECENT FILES", 
            lambda: self.run_operation("forensics", "files")
        )
        btn_files.grid(row=4, column=0, pady=2)
        
        btn_screenshot = BrutalistTheme.create_button(
            forensics_frame, "TAKE SCREENSHOT", 
            lambda: self.run_operation("forensics", "screenshot")
        )
        btn_screenshot.grid(row=5, column=0, pady=2)
        
    def create_reports_section(self, parent):
        reports_frame = BrutalistTheme.create_frame(parent)
        reports_frame.grid(row=1, column=1, sticky='nsew', padx=5, pady=5)
        reports_frame.grid_columnconfigure(0, weight=1)
        
        title = BrutalistTheme.create_label(reports_frame, "REPORT GENERATOR", 'button')
        title.grid(row=0, column=0, pady=10)
        
        btn_inventory = BrutalistTheme.create_button(
            reports_frame, "EVIDENCE INVENTORY", 
            lambda: self.run_operation("reports", "inventory")
        )
        btn_inventory.grid(row=1, column=0, pady=2)
        
        btn_timeline = BrutalistTheme.create_button(
            reports_frame, "GENERATE TIMELINE", 
            lambda: self.run_operation("reports", "timeline")
        )
        btn_timeline.grid(row=2, column=0, pady=2)
        
        btn_summary = BrutalistTheme.create_button(
            reports_frame, "SYSTEM SUMMARY", 
            lambda: self.run_operation("reports", "summary")
        )
        btn_summary.grid(row=3, column=0, pady=2)
        
        btn_export_txt = BrutalistTheme.create_button(
            reports_frame, "EXPORT TEXT", 
            lambda: self.run_operation("reports", "export_txt")
        )
        btn_export_txt.grid(row=4, column=0, pady=2)
        
        btn_export_html = BrutalistTheme.create_button(
            reports_frame, "EXPORT HTML", 
            lambda: self.run_operation("reports", "export_html")
        )
        btn_export_html.grid(row=5, column=0, pady=2)
        
    def create_terminal_section(self, parent):
        terminal_frame = BrutalistTheme.create_frame(parent)
        terminal_frame.grid(row=2, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)
        terminal_frame.grid_columnconfigure(0, weight=1)
        terminal_frame.grid_rowconfigure(1, weight=1)
        
        title = BrutalistTheme.create_label(terminal_frame, "TERMINAL OUTPUT", 'button')
        title.grid(row=0, column=0, pady=5)
        
        self.terminal_text = BrutalistTheme.create_text_widget(terminal_frame, height=15, width=120)
        self.terminal_text.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)
        
        scrollbar = BrutalistTheme.create_scrollbar(terminal_frame, self.terminal_text)
        scrollbar.grid(row=1, column=1, sticky='ns', pady=5)
        
        self.log_message("IRIS SYSTEM INITIALIZED")
        self.log_message(f"Platform: {self.platform.upper()}")
        self.log_message("Ready for incident response operations...")
        
    def create_status_bar(self):
        status_frame = BrutalistTheme.create_frame(self.root, bd=1)
        status_frame.grid(row=2, column=0, sticky='ew', padx=10, pady=5)
        status_frame.grid_columnconfigure(0, weight=1)
        status_frame.grid_columnconfigure(1, weight=0)
        
        self.status_label = BrutalistTheme.create_label(
            status_frame, "STATUS: READY", 'status'
        )
        self.status_label.grid(row=0, column=0, sticky='w', padx=10, pady=5)
        
        self.time_label = BrutalistTheme.create_label(
            status_frame, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'status'
        )
        self.time_label.grid(row=0, column=1, sticky='e', padx=10, pady=5)
        
        self.update_time()
        
    def update_time(self):
        self.time_label.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.root.after(1000, self.update_time)
        
    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        
        self.terminal_text.config(state='normal')
        self.terminal_text.insert(tk.END, formatted_message)
        self.terminal_text.see(tk.END)
        self.terminal_text.config(state='disabled')
        
    def update_status(self, status):
        self.status_label.config(text=f"STATUS: {status.upper()}")
        
    def run_operation(self, category, operation):
        if self.current_operation:
            messagebox.showwarning("Operation in Progress", "Please wait for current operation to complete.")
            return
            
        self.current_operation = f"{category}_{operation}"
        self.update_status(f"RUNNING {operation.upper()}")
        self.log_message(f"Starting {category.upper()} operation: {operation.upper()}")
        
        thread = threading.Thread(target=self._execute_operation, args=(category, operation))
        thread.daemon = True
        thread.start()
        
    def _execute_operation(self, category, operation):
        try:
            from core.evidence import EvidenceCollector
            from core.isolation import NetworkIsolation
            from core.forensics import ForensicsCollector
            from core.reporting import ReportGenerator
            
            if category == "evidence":
                collector = EvidenceCollector(self.platform, self.config)
                result = collector.run_operation(operation, self.log_message)
            elif category == "isolation":
                isolator = NetworkIsolation(self.platform, self.config)
                result = isolator.run_operation(operation, self.log_message)
            elif category == "forensics":
                forensics = ForensicsCollector(self.platform, self.config)
                result = forensics.run_operation(operation, self.log_message)
            elif category == "reports":
                reporter = ReportGenerator(self.platform, self.config)
                result = reporter.run_operation(operation, self.log_message)
            else:
                result = f"Unknown category: {category}"
                
            self.log_message(f"Operation {operation.upper()} completed")
            self.update_status("READY")
            
        except Exception as e:
            self.log_message(f"ERROR: {str(e)}")
            self.update_status("ERROR")
        finally:
            self.current_operation = None