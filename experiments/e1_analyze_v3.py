import collections
import math
import pathlib

import numpy as np
import pandas as pd

BASE = pathlib.Path(r"C:\Users\vlad\Desktop\diploma-v2")
SRC = BASE / "results" / "e1_v2.csv"
OUT = BASE / "results" / "e1_v3_summary.csv"
REPORT = BASE / "results" / "e1_v3_report.txt"

lines = []


def out(s=""):
    print(s)
    lines.append(str(s))


EXT_CLASS = {
    "png": "png", "jpg": "jpg", "jpeg": "jpg", "gif": "gif", "bmp": "bmp",
    "ico": "ico", "pdf": "pdf", "zip": "zip", "gz": "gz", "tgz": "gz",
    "7z": "7z", "sqlite": "sqlite", "db": "sqlite", "sqlite3": "sqlite",
    "wav": "wav", "mp3": "mp3", "json": "json", "xml": "xml", "html": "html",
    "htm": "html", "txt": "txt", "pcap": "pcap", "pcapng": "pcap",
    "ttf": "ttf", "otf": "ttf", "exe": "pe", "dll": "pe", "sys": "pe",
    "ocx": "pe", "efi": "pe", "so": "elf", "elf": "elf", "o": "elf", "": "elf",
    "docx": "docx", "xlsx": "xlsx", "pptx": "pptx",
    "doc": "ole2", "xls": "ole2", "ppt": "ole2", "msi": "ole2",
    "rtf": "rtf", "evtx": "evtx", "lnk": "lnk", "log": "log",
    "ini": "ini", "cfg": "ini", "conf": "ini", "csv": "csv",
}
OOXML = "application/vnd.openxmlformats-officedocument."
MG_MANUAL = {
    "png": {"png"}, "jpg": {"jpeg"}, "gif": {"gif"}, "bmp": {"bmp"}, "ico": {"ico"},
    "pdf": {"pdf"}, "zip": {"zip"}, "gz": {"gzip"}, "sqlite": {"sqlite"},
    "wav": {"wav"}, "mp3": {"mp3"}, "json": {"json"}, "xml": {"xml"},
    "html": {"html"}, "txt": {"txt"}, "ttf": {"ttf"}, "pe": {"pebin"},
    "elf": {"elf"}, "docx": {"docx"}, "xlsx": {"xlsx"}, "pptx": {"pptx"},
    "rtf": {"rtf"}, "lnk": {"lnk"},
    "ole2": {"msi", "doc", "xls", "ppt", "ole"},
    "ini": {"ini", "internetshortcut"}, "csv": {"csv", "tsv"},
    "pcap": {"pcap", "pcapng"}, "log": {"txt", "log", "syslog"},
}
LM_MANUAL = {
    "png": {"image/png"}, "jpg": {"image/jpeg"}, "gif": {"image/gif"},
    "bmp": {"image/bmp", "image/x-ms-bmp"},
    "ico": {"image/vnd.microsoft.icon", "image/x-icon"},
    "pdf": {"application/pdf"}, "zip": {"application/zip"},
    "gz": {"application/gzip", "application/x-gzip"},
    "sqlite": {"application/vnd.sqlite3", "application/x-sqlite3"},
    "wav": {"audio/x-wav", "audio/wav", "audio/vnd.wave"}, "mp3": {"audio/mpeg"},
    "xml": {"text/xml", "application/xml"}, "html": {"text/html"},
    "txt": {"text/plain"}, "rtf": {"text/rtf", "application/rtf"},
    "ttf": {"font/sfnt", "application/font-sfnt", "application/x-font-ttf", "font/ttf"},
    "pe": {"application/x-dosexec", "application/vnd.microsoft.portable-executable"},
    "elf": {"application/x-executable", "application/x-sharedlib",
            "application/x-pie-executable", "application/x-object"},
    "docx": {OOXML + "wordprocessingml.document"},
    "xlsx": {OOXML + "spreadsheetml.sheet"},
    "pptx": {OOXML + "presentationml.presentation"},
    "ole2": {"application/x-msi", "application/msword", "application/vnd.ms-excel",
             "application/vnd.ms-powerpoint", "application/x-ole-storage",
             "application/CDFV2"},
}
UNSUP_MG = {"evtx"}
UNSUP_LM = {"json", "evtx", "lnk", "pcap", "csv", "ini", "log"}
TEXT_CLASSES = ["csv", "html", "ini", "json", "log", "txt", "xml"]
TEXT_MG = {"txt", "csv", "tsv", "ini", "json", "jsonl", "xml", "html", "log", "syslog",
           "markdown", "yaml", "toml", "winregistry", "internetshortcut", "javascript",
           "vba", "powershell", "twig", "asp", "php", "python", "shell", "batch",
           "css", "svg", "sql", "latex", "rtf"}
CONDS = ["orig", "zero_header", "random_header", "trunc_tail", "fragment",
         "spoof_jpg", "spoof_txt"]
BIG = 20

df = pd.read_csv(SRC, keep_default_na=False, dtype=str)
classes = sorted(df["fmt"].unique())
orig = df[df["condition"] == "orig"]
n_cls = orig.groupby("fmt").size().to_dict()


def build(col, manual, unsup, title):
    acc = {}
    out(f"Мапінг міток: {title}")
    for f in classes:
        if f in unsup:
            acc[f] = None
            top = collections.Counter(orig[orig["fmt"] == f][col]).most_common(1)[0]
            out(f"  {f}: нп (інструмент не має такого типу; найчастіша мітка '{top[0]}')")
        elif f in manual:
            acc[f] = set(manual[f])
            sub = orig[orig["fmt"] == f][col]
            hit = sum(1 for x in sub if x in manual[f]) / len(sub)
            if hit < 0.5:
                top = collections.Counter(sub).most_common(3)
                out(f"  УВАГА {f}: збіг лише {hit:.0%}, мітки {top}")
        else:
            acc[f] = None
            out(f"  {f}: немає мапінгу, виключено")
    out()
    return acc


acc_mg = build("magika", MG_MANUAL, UNSUP_MG, "Magika")
acc_lm = build("libmagic_mime", LM_MANUAL, UNSUP_LM, "libmagic")


def okv(labels, fmts, acc):
    res = []
    for l, f in zip(labels, fmts):
        s = acc.get(f)
        res.append(np.nan if s is None else float(l in s))
    return res


df["ok_ext"] = [float(EXT_CLASS.get(e) == f) for e, f in zip(df["ext_shown"], df["fmt"])]
df["ok_mg"] = okv(df["magika"], df["fmt"], acc_mg)
df["ok_lm"] = okv(df["libmagic_mime"], df["fmt"], acc_lm)
df["txt_mg"] = [float(l in TEXT_MG) for l in df["magika"]]
df["txt_lm"] = [float(m.startswith("text/") or m in ("application/json", "application/xml"))
                for m in df["libmagic_mime"]]
TOOLS = [("ext", "ok_ext", "розширення"), ("libmagic", "ok_lm", "libmagic"),
         ("magika", "ok_mg", "Magika")]


def wilson(k, n):
    if n == 0:
        return float("nan"), float("nan")
    z = 1.96
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


rows = []
for f in classes:
    for c in CONDS:
        sub = df[(df["fmt"] == f) & (df["condition"] == c)]
        if len(sub) == 0:
            continue
        for key, col, _ in TOOLS:
            s = sub[col].dropna()
            if len(s) == 0:
                continue
            k, n = int(s.sum()), len(s)
            lo, hi = wilson(k, n)
            rows.append([f, c, key, n, k, round(k / n, 3), round(lo, 3), round(hi, 3)])
pd.DataFrame(rows, columns=["fmt", "condition", "tool", "n", "k", "acc", "lo", "hi"]
             ).to_csv(OUT, index=False, encoding="utf-8")


def pivot(col, title):
    out(f"Точність, %, {title} (* n < {BIG}; нп = тип не підтримується)")
    out(f"{'клас':8s}{'n':>4s}" + "".join(f"{c[:12]:>14s}" for c in CONDS))
    for f in classes:
        star = "*" if n_cls[f] < BIG else " "
        cells = []
        for c in CONDS:
            part = df[(df["fmt"] == f) & (df["condition"] == c)]
            s = part[col].dropna()
            if part.empty:
                cells.append(f"{'-':>14s}")
            elif len(s) == 0:
                cells.append(f"{'нп':>14s}")
            else:
                cells.append(f"{100 * s.mean():13.0f} ")
        out(f"{f:8s}{n_cls[f]:>3d}{star}" + "".join(cells))
    out()


for _, col, name in TOOLS:
    pivot(col, name)

out("Середня точність (макро: класи з n >= 20 та підтримкою; мікро: усі підтримувані), %")
out(f"{'інструмент':12s}{'':8s}" + "".join(f"{c[:12]:>14s}" for c in CONDS))
big = [f for f in classes if n_cls[f] >= BIG]
for _, col, name in TOOLS:
    macro, micro = [], []
    for c in CONDS:
        sub = df[df["condition"] == c]
        per = []
        for f in big:
            s = sub[sub["fmt"] == f][col].dropna()
            if len(s):
                per.append(s.mean())
        allv = sub[col].dropna()
        macro.append(f"{100 * np.mean(per):.1f}" if per else "-")
        micro.append(f"{100 * allv.mean():.1f}" if len(allv) else "-")
    out(f"{name:12s}{'макро':8s}" + "".join(f"{x:>14s}" for x in macro))
    out(f"{'':12s}{'мікро':8s}" + "".join(f"{x:>14s}" for x in micro))
out()

out("Підміна розширення для виконуваних файлів, %")
for f in ("pe", "elf"):
    for c in ("orig", "spoof_jpg", "spoof_txt"):
        sub = df[(df["fmt"] == f) & (df["condition"] == c)]
        if len(sub):
            out(f"  {f:4s} {c:10s} n={len(sub):3d}  розширення {100 * sub['ok_ext'].mean():5.1f}  "
                f"libmagic {100 * sub['ok_lm'].mean():5.1f}  Magika {100 * sub['ok_mg'].mean():5.1f}")
out()

out("Текстові класи: частка файлів, визнаних текстовими (родина, не формат), %")
out(f"{'інструмент':12s}{'клас':8s}" + "".join(f"{c[:12]:>14s}" for c in CONDS[:5]))
for name, col in (("libmagic", "txt_lm"), ("Magika", "txt_mg")):
    for f in TEXT_CLASSES:
        vals = []
        for c in CONDS[:5]:
            s = df[(df["fmt"] == f) & (df["condition"] == c)][col]
            vals.append(f"{100 * s.mean():13.0f} " if len(s) else f"{'-':>14s}")
        out(f"{name:12s}{f:8s}" + "".join(vals))
out()

out("Частка файлів без розширення у корпусі (стан orig), %")
for f in classes:
    sub = orig[orig["fmt"] == f]
    share = (sub["ext_shown"] == "").mean()
    if share > 0 and f != "elf":
        out(f"  {f:8s} {100 * share:5.1f} (з {len(sub)})")
out()

out("Частка 'unknown' у Magika за станами, %")
for c in CONDS:
    sub = df[df["condition"] == c]
    if len(sub):
        out(f"  {c:14s} {100 * (sub['magika'] == 'unknown').mean():5.1f}")
out()

out("Класи, що залежать від заголовка (orig >= 90 %, zero_header < 50 %)")
for _, col, name in TOOLS[1:]:
    dep = []
    for f in classes:
        a = df[(df["fmt"] == f) & (df["condition"] == "orig")][col].dropna()
        z = df[(df["fmt"] == f) & (df["condition"] == "zero_header")][col].dropna()
        if len(a) and len(z) and a.mean() >= 0.9 and z.mean() < 0.5:
            dep.append(f"{f} ({100 * a.mean():.0f}->{100 * z.mean():.0f})")
    out(f"  {name}: " + (", ".join(dep) if dep else "немає"))
out()

out("Що відповідає Magika на фрагментах (клас: точність, найчастіші мітки)")
for f in classes:
    sub = df[(df["fmt"] == f) & (df["condition"] == "fragment")]
    s = sub["ok_mg"].dropna()
    if len(s) and s.mean() < 0.5:
        top = collections.Counter(sub["magika"]).most_common(4)
        out(f"  {f:7s} {100 * s.mean():5.1f} %  {top}")

REPORT.write_text("\n".join(lines), encoding="utf-8")
out(f"\nЗвіт: {REPORT}")
out(f"Таблиця з інтервалами Вілсона: {OUT}")