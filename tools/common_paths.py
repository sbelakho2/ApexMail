from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
# Single tracked corpus location (data/README.md): the root data/ dir
# is a retired gitignored scratch area whose JSONL corpus was removed.
DATA_DIR = PROJECT_ROOT / "apps/ai/training/data"


def data_path(name: str) -> Path:
    return DATA_DIR / name