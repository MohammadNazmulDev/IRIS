#!/usr/bin/env python3

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    if sys.version_info < (3, 7):
        print("Error: Python 3.7 or higher is required")
        sys.exit(1)

def create_venv():
    venv_path = Path("venv")
    if not venv_path.exists():
        print("Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
        print("Virtual environment created successfully")
    return venv_path

def get_venv_python(venv_path):
    if platform.system() == "Windows":
        return venv_path / "Scripts" / "python.exe"
    else:
        return venv_path / "bin" / "python"

def install_requirements(venv_python):
    requirements = [
        "tkinter",  # Usually built-in, but just in case
    ]
    
    # Check if requirements.txt exists, if not create basic one
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print("Creating requirements.txt...")
        with open(requirements_file, 'w') as f:
            f.write("# IRIS Dependencies\n")
            f.write("# Most dependencies are built-in Python modules\n")
            f.write("# Add additional packages here if needed\n")
    
    print("Installing/upgrading pip...")
    subprocess.run([str(venv_python), "-m", "pip", "install", "--upgrade", "pip"], check=True)
    
    if requirements_file.stat().st_size > 100:  # If requirements.txt has actual content
        print("Installing requirements...")
        subprocess.run([str(venv_python), "-m", "pip", "install", "-r", "requirements.txt"], check=True)

def check_gui_support():
    try:
        import tkinter
        return True
    except ImportError:
        return False

def setup_project():
    print("=" * 60)
    print("🛡️  IRIS - Incident Response Integration Suite")
    print("   Automated Setup and Launch Script")
    print("=" * 60)
    
    # Check Python version
    check_python_version()
    print(f"✓ Python {sys.version.split()[0]} detected")
    
    # Check GUI support
    if not check_gui_support():
        print("Error: tkinter GUI support not available")
        print("On Linux, install with: sudo apt-get install python3-tk")
        sys.exit(1)
    print("✓ GUI support available")
    
    # Create virtual environment
    venv_path = create_venv()
    venv_python = get_venv_python(venv_path)
    
    if not venv_python.exists():
        print(f"Error: Virtual environment Python not found at {venv_python}")
        sys.exit(1)
    print(f"✓ Virtual environment ready at {venv_path}")
    
    # Install requirements
    install_requirements(venv_python)
    print("✓ Dependencies installed")
    
    # Check for admin/root privileges
    if platform.system() == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin = False
    else:
        is_admin = os.geteuid() == 0
    
    if not is_admin:
        print("⚠️  WARNING: Not running with administrator/root privileges")
        print("   Some IRIS features may not work properly")
    else:
        print("✓ Running with elevated privileges")
    
    print("=" * 60)
    print("🚀 Launching IRIS...")
    print("=" * 60)
    
    return venv_python

def main():
    try:
        # Change to script directory
        script_dir = Path(__file__).parent
        os.chdir(script_dir)
        
        # Setup project and get venv python
        venv_python = setup_project()
        
        # Launch IRIS
        subprocess.run([str(venv_python), "iris.py"], check=True)
        
    except KeyboardInterrupt:
        print("\nSetup interrupted by user")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error during setup: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()