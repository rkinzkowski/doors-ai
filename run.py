import subprocess
import sys
from pathlib import Path


if __name__ == "__main__":
    app_path = Path(__file__).with_name("app.py")
    raise SystemExit(subprocess.call([sys.executable, str(app_path)]))
