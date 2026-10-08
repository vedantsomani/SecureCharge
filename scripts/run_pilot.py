"""One-command private-CA fault experiment, artifact verification, and dashboard."""

from __future__ import annotations
import argparse
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import uuid


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path)
    parser.add_argument("--no-dashboard", action="store_true")
    args = parser.parse_args()
    out = args.out or Path("artifacts") / (
        "pilot-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    )
    subprocess.run([sys.executable, "-m", "securecharge", "pilot-demo", "--out", str(out)], cwd=root, check=True)
    subprocess.run([sys.executable, "scripts/verify_artifacts.py", str(out)], cwd=root, check=True)
    if not args.no_dashboard:
        return subprocess.call(
            [sys.executable, "-m", "streamlit", "run", "dashboard.py", "--server.address", "127.0.0.1"], cwd=root
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
