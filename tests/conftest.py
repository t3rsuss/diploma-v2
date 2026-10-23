import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "experiments"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
