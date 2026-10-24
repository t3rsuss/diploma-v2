import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.triage.fragment import FragmentClassifier

MAX_BYTES = 200_000_000
THETA = 0.7
TEXT_FAMILY = {"txt", "log", "ini", "csv"}
MAP = {
    "png": "png", "jpeg": "jpg", "gif": "gif", "bmp": "bmp", "ico": "ico", "pdf": "pdf",
    "zip": "zip", "gzip": "gz", "sqlite": "sqlite", "wav": "wav", "mp3": "mp3",
    "json": "json", "xml": "xml", "html": "html", "txt": "txt", "ttf": "ttf",
    "pebin": "pe", "elf": "elf", "docx": "docx", "xlsx": "xlsx", "pptx": "pptx",
    "rtf": "rtf", "lnk": "lnk", "msi": "ole2", "doc": "ole2", "xls": "ole2",
    "ppt": "ole2", "ole": "ole2", "ini": "ini", "internetshortcut": "ini",
    "csv": "csv", "tsv": "csv", "pcap": "pcap", "pcapng": "pcap",
}
EXT_CLASS = {
    "png": "png", "jpg": "jpg", "jpeg": "jpg", "gif": "gif", "bmp": "bmp", "ico": "ico",
    "pdf": "pdf", "zip": "zip", "gz": "gz", "sqlite": "sqlite", "db": "sqlite",
    "wav": "wav", "mp3": "mp3", "json": "json", "xml": "xml", "html": "html",
    "htm": "html", "txt": "txt", "pcap": "pcap", "ttf": "ttf", "exe": "pe", "dll": "pe",
    "sys": "pe", "ocx": "pe", "so": "elf", "docx": "docx", "xlsx": "xlsx",
    "pptx": "pptx", "doc": "ole2", "xls": "ole2", "ppt": "ole2", "msi": "ole2",
    "rtf": "rtf", "evtx": "evtx", "lnk": "lnk", "log": "log", "ini": "ini",
    "cfg": "ini", "conf": "ini", "csv": "csv",
}
_cache = {}


def _magika():
    if "mg" not in _cache:
        from magika import Magika
        _cache["mg"] = Magika()
    return _cache["mg"]


def _fragment():
    if "fc" not in _cache:
        _cache["fc"] = FragmentClassifier()
    return _cache["fc"]


def _is_pe(b):
    if b[:2] != b"MZ" or len(b) < 64:
        return False
    e = int.from_bytes(b[0x3C:0x40], "little")
    return e + 4 <= len(b) and b[e:e + 4] == b"PE\x00\x00"


def _v1(path):
    try:
        from src.structure.predict import predict_blocks, table_labels
        from src.detector.verdict import score_file, level
        from src.detector.rules import apply_rules, elf_machine
        res = score_file(path)
        if res is None:
            return {"error": "v1: невідомий тип виконуваного файлу"}
        out = predict_blocks(path)
        pred = truth = None
        agree = None
        if out is not None:
            pred, _, n = out
            _, truth = table_labels(path, n)
            if truth is not None:
                agree = float((pred == truth).mean())
        machine = elf_machine(path) if res["kind"] == "ELF" else None
        lvl, reasons, raised = apply_rules(level(res), res["kind"], pred, truth, machine)
        return {"kind": res["kind"], "model": res["source"], "score": res["score"],
                "level": lvl, "raised_by_rules": bool(raised), "reasons": reasons,
                "agreement_with_section_table": agree}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def analyze(path, run_v1=True):
    path = pathlib.Path(path)
    data = path.read_bytes()[:MAX_BYTES]
    ext = path.suffix.lower().lstrip(".")
    ext_cls = EXT_CLASS.get(ext)
    mg = _magika().identify_bytes(data)
    m_label = str(mg.output.label) if mg.ok else "error"
    m_score = float(mg.score) if mg.ok else 0.0
    m_cls = MAP.get(m_label)
    f_cls, f_conf, probs = _fragment().classify(data)

    if _is_pe(data):
        fmt, src, conf = "pe", "сигнатура", 1.0
    elif data[:4] == b"\x7fELF" and len(data) > 64:
        fmt, src, conf = "elf", "сигнатура", 1.0
    elif m_cls and m_score >= THETA:
        fmt, src, conf = m_cls, "Magika", m_score
    elif (
        m_cls is None
        and m_label not in ("unknown", "error", "other")
        and m_score >= THETA
    ):
        fmt, src, conf = m_label, "Magika (поза словником моделі)", m_score
    else:
        fmt, src, conf = "unknown", "формат не встановлено", 0.0

    format_status = "unrecognized" if fmt == "unknown" else "recognized"
    candidate = (
        {
            "format": f_cls,
            "score": round(f_conf, 3),
            "source": "модель фрагментів",
            "interpretation": "Кандидат, а не встановлений формат.",
        }
        if fmt == "unknown" else None
    )

    flags = []
    if fmt in ("pe", "elf") and ext_cls not in (None, "pe", "elf"):
        flags.append(f"виконуваний файл ({fmt}) під розширенням .{ext}")
    elif fmt != "unknown" and ext_cls and ext_cls != fmt and not (ext_cls == "txt" and fmt in TEXT_FAMILY):
        flags.append(f"розширення .{ext} не відповідає визначеному формату {fmt}")
    if m_cls and m_score >= THETA and f_cls != m_cls and f_conf >= 0.6:
        flags.append(f"Magika ({m_cls}) і модель фрагментів ({f_cls}) розходяться")
    if fmt == "unknown":
        flags.append(
            "Формат не встановлено. Класи моделі фрагментів є "
            "припущеннями про вміст, а не підтвердженою структурою."
        )
    elif conf < 0.5:
        flags.append("низька впевненість визначення")

    branch = (
        "невідомий формат" if fmt == "unknown" else
        "виконуваний файл" if fmt in ("pe", "elf") else
        "відомий формат"
    )
    top = sorted(probs.items(), key=lambda kv: -kv[1])[:3]
    rep = {
        "file": path.name, "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "extension": ext, "extension_class": ext_cls,
        "magika": {"label": m_label, "score": round(m_score, 3), "class": m_cls},
        "fragment_model": {"class": f_cls, "confidence": round(f_conf, 3),
                           "top3": [(k, round(v, 3)) for k, v in top]},
        "format": fmt, "format_source": src, "confidence": round(conf, 3),
        "format_status": format_status,
        "format_candidate": candidate,
        "confidence_kind": (
            "not_applicable" if fmt == "unknown" else "method_score"
        ),
        "branch": branch, "flags": flags,
    }
    if fmt in ("pe", "elf") and run_v1:
        rep["executable_analysis"] = _v1(path)
    return rep


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Використання: python -m src.triage.triage <файл>")
        sys.exit(1)
    print(json.dumps(analyze(sys.argv[1]), ensure_ascii=False, indent=2, default=float))