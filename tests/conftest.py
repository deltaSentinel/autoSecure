import sys
from pathlib import Path

# make agent/main.py importable as 'main'
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
