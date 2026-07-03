# run.py
import subprocess
import threading
import sys

def run_flask():
    subprocess.run([sys.executable, "app.py"])

def run_scanner():
    subprocess.run([sys.executable, "scanner/scanner.py"])

def run_process_monitor():
    subprocess.run([sys.executable, "monitor/process_monitor.py"])

if __name__ == "__main__":
    threading.Thread(target=run_scanner).start()
    run_flask()
