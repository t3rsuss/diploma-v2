import pathlib

from src import known
from src.segment import segment
from src.triage.triage import MAX_BYTES, _fragment, analyze


def analyze_full(path, force_regions=False):
    path = pathlib.Path(path)
    rep = analyze(path)
    fmt = rep["format"]
    data = path.read_bytes()[:MAX_BYTES]
    if fmt in ("pe", "elf") and not force_regions:
        rep["branch"] = "виконуваний файл"
        return rep
    if not force_regions and known.available(fmt):
        try:
            rep["structure"] = known.describe(data, fmt)
            rep["branch"] = "відомий формат: опис структури (Kaitai Struct)"
            return rep
        except Exception as e:
            rep["structure_error"] = f"{type(e).__name__}: {e}"
    rep["regions"] = segment(data, _fragment())
    if force_regions:
        rep["branch"] = "карта областей (примусово)"
    elif fmt in ("other", "unknown") or rep["confidence"] < 0.5:
        rep["branch"] = "невідомий формат: карта областей за вмістом"
    else:
        rep["branch"] = "відомий формат без готового опису: карта областей за вмістом"
    return rep