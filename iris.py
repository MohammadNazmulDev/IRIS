#!/usr/bin/env python3

import sys
import os
import platform
import json
import tkinter as tk
from pathlib import Path

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from gui.main_window import MainWindow

class IRISApplication:
    def __init__(self):
        self.platform = platform.system().lower()
        self.config = self.load_config()
        self.root = None
        
    def load_config(self):
        config_path = Path(__file__).parent / "config" / "settings.json"
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Configuration file not found: {config_path}")
            return self.get_default_config()
        except json.JSONDecodeError:
            print(f"Invalid JSON in configuration file: {config_path}")
            return self.get_default_config()
    
    def get_default_config(self):
        return {
            "application": {"name": "IRIS", "version": "1.0.0-MVP"},
            "gui": {"window_width": 1200, "window_height": 800}
        }
    
    def check_privileges(self):
        if self.platform == "windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:
            return os.geteuid() == 0
    
    def run(self):
        if not self.check_privileges():
            print("WARNING: IRIS requires administrator/root privileges for full functionality.")
            print("Some features may not work properly without elevated permissions.")
            
        self.root = tk.Tk()
        self.root.title(f"{self.config['application']['name']} v{self.config['application']['version']}")
        self.root.geometry(f"{self.config['gui']['window_width']}x{self.config['gui']['window_height']}")
        
        app = MainWindow(self.root, self.config, self.platform)
        
        self.root.mainloop()

def main():
    print("=" * 60)
    print("🛡️  IRIS - Incident Response Integration Suite")
    print("   MVP Version - Cross-Platform IR Toolkit")
    print("=" * 60)
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version.split()[0]}")
    print("=" * 60)
    
    try:
        app = IRISApplication()
        app.run()
    except KeyboardInterrupt:
        print("\nIRIS application interrupted by user.")
    except Exception as e:
        print(f"Error starting IRIS: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()