"""R16 integration: fire on increase, silent on baseline and decrease (registered sequence)."""
import sqlite3, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def _scan(snapshot, db):
    subprocess.run(
        [sys.executable, str(ROOT / "agent" / "main.py"),
         "--snapshot", str(ROOT / "tests" / "fixtures" / snapshot),
         "--db", str(db)],
        cwd=ROOT, check=True, capture_output=True, text=True)

def _findings(db):
    con = sqlite3.connect(db)
    rows = con.execute(
        "SELECT s.id, f.rule_id FROM findings f "
        "JOIN scans s ON f.scan_id = s.id ORDER BY f.id").fetchall()
    con.close()
    return rows

def test_r16_three_scan_sequence(tmp_path):
    db = tmp_path / "r16.db"
    _scan("scan_clean.json", db)                      # scan 1: baseline
    scan1 = [r for r in _findings(db)]
    assert not any(r[1] == "R16" for r in scan1), "R16 fired on first scan — prev lookup broken"

    _scan("scan_m11.json", db)                        # scan 2: +1 SUID
    scan2 = [r for r in _findings(db) if r[0] == 2]   # findings belonging to scan 2
    assert any(r[1] == "R16" for r in scan2), "R16 silent on increase — raw persistence or delta broken"

    _scan("scan_clean.json", db)                      # scan 3: decrease
    scan3 = [r for r in _findings(db) if r[0] == 3]
    assert not any(r[1] == "R16" for r in scan3), "R16 fired on decrease — comparison inverted"
