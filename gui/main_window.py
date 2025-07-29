import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import subprocess
import sys
import os
from datetime import datetime

from gui.brutalist_theme import BrutalistTheme
from tkinter import ttk

class MainWindow:
    def __init__(self, root, config, platform):
        self.root = root
        self.config = config
        self.platform = platform
        self.current_operation = None
        
        BrutalistTheme.configure_root(self.root)
        self.setup_ui()
    
    def create_scrollable_section(self, parent, title_text):
        """Helper function to create a scrollable section with title"""
        frame = BrutalistTheme.create_frame(parent)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)
        
        title = BrutalistTheme.create_label(frame, title_text, 'button')
        title.grid(row=0, column=0, pady=10)
        
        canvas = tk.Canvas(frame, bg='white', bd=2, relief='solid')
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='white')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.grid(row=1, column=0, sticky='nsew')
        scrollbar.grid(row=1, column=1, sticky='ns')
        scrollable_frame.grid_columnconfigure(0, weight=1)
        
        return frame, scrollable_frame
        
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
        main_frame.grid_rowconfigure(0, weight=2)
        main_frame.grid_rowconfigure(1, weight=2)
        main_frame.grid_rowconfigure(2, weight=1)
        
        self.create_evidence_section(main_frame)
        self.create_isolation_section(main_frame)
        self.create_forensics_section(main_frame)
        self.create_reports_section(main_frame)
        self.create_terminal_section(main_frame)
        
    def create_evidence_section(self, parent):
        evidence_frame, scrollable_frame = self.create_scrollable_section(parent, "SYSTEM EVIDENCE COLLECTOR")
        evidence_frame.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        
        buttons = [
            ("ENUMERATE PROCESSES", "processes"),
            ("NETWORK CONNECTIONS", "network"), 
            ("SYSTEM INFORMATION", "sysinfo"),
            ("USER ACCOUNTS", "users"),
            ("FILE HASHING", "hash")
        ]
        
        for i, (text, operation) in enumerate(buttons):
            btn = BrutalistTheme.create_button(
                scrollable_frame, text,
                lambda op=operation: self.run_operation("evidence", op)
            )
            btn.grid(row=i, column=0, pady=2, padx=5, sticky='ew')
        
    def create_isolation_section(self, parent):
        isolation_frame, scrollable_frame = self.create_scrollable_section(parent, "NETWORK ISOLATION")
        isolation_frame.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)
        
        buttons = [
            ("EMERGENCY ISOLATION", "emergency"),
            ("MANAGE WHITELIST", "whitelist"),
            ("KILL CONNECTIONS", "kill"),
            ("BLOCK DNS", "dns"),
            ("ISOLATION STATUS", "status")
        ]
        
        for i, (text, operation) in enumerate(buttons):
            btn = BrutalistTheme.create_button(
                scrollable_frame, text,
                lambda op=operation: self.run_operation("isolation", op)
            )
            btn.grid(row=i, column=0, pady=2, padx=5, sticky='ew')
        
    def create_forensics_section(self, parent):
        forensics_frame, scrollable_frame = self.create_scrollable_section(parent, "FORENSIC COLLECTION")
        forensics_frame.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)
        
        buttons = [
            ("MEMORY SNAPSHOT", "memory"),
            ("COLLECT LOGS", "logs"),
            ("BROWSER ARTIFACTS", "browser"),
            ("RECENT FILES", "files"),
            ("TAKE SCREENSHOT", "screenshot")
        ]
        
        for i, (text, operation) in enumerate(buttons):
            btn = BrutalistTheme.create_button(
                scrollable_frame, text,
                lambda op=operation: self.run_operation("forensics", op)
            )
            btn.grid(row=i, column=0, pady=2, padx=5, sticky='ew')
        
    def create_reports_section(self, parent):
        reports_frame, scrollable_frame = self.create_scrollable_section(parent, "REPORT GENERATOR")
        reports_frame.grid(row=1, column=1, sticky='nsew', padx=5, pady=5)
        
        buttons = [
            ("EVIDENCE INVENTORY", "inventory"),
            ("GENERATE TIMELINE", "timeline"),
            ("SYSTEM SUMMARY", "summary"),
            ("EXPORT TEXT", "export_txt"),
            ("EXPORT HTML", "export_html")
        ]
        
        for i, (text, operation) in enumerate(buttons):
            btn = BrutalistTheme.create_button(
                scrollable_frame, text,
                lambda op=operation: self.run_operation("reports", op)
            )
            btn.grid(row=i, column=0, pady=2, padx=5, sticky='ew')
        
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