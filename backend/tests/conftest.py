from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

os.environ["MG_LOAD_DOTENV"] = "0"  # a developer's backend/.env must never change test results

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT.parent / "samples"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))


@pytest.fixture
def samples_dir() -> Path:
    if not any(SAMPLES.glob("*.eml")):
        subprocess.run([sys.executable, str(SAMPLES / "build_samples.py")], check=True)
    return SAMPLES
