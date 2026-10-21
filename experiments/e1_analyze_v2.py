import collections
import math
import pathlib

import pandas as pd

BASE = pathlib.Path(r"C:\Users\vlad\Desktop\diploma-v2")
SRC = BASE / "results" / "e1_v2.csv"
OUT = BASE / "results" / "e1_v2_summary.csv"
REPORT = BASE / "results" / "e1_v2_report.txt"

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
MG_MANUAL = {
    "png": {"png"}, "jpg": {"jpeg"}, "gif": {"gif"}, "bmp": {"bmp"}, "ico": {"ico"},
    "pdf": {"pdf"}, "zip": {"zip"}, "gz": {"gzip"}, "sqlite": {"sqlite"},
    "wav": {"wav"}, "mp3": {"mp3"}, "json": {"json"}, "xml": {"xml"},
    "html": {"html"}, "txt": {"txt"}, "ttf": {"ttf"}, "pe": {"pebin"},
    "elf": {"elf"}, "docx": {"docx"}, "xlsx": {"xlsx"}, "pptx": {"pptx"},
    "rtf": {"rtf"}, "lnk": {"lnk"},
}
LM_MANUAL = {
    "png": {"image/png"}, "jpg": {"image/jpeg"}, "gif": {"image/gif"},
    "bmp": {"image/bmp", "image/x-ms-bmp"},
    "ico": {"image/vnd.microsoft.icon", "image/x-icon"},
    "pdf": {"application/pdf"}, "zip": {"application/zip"},
    "gz": {"application/gzip", "application/x-gzip"},
    "sqlite": {"application/vnd.sqlite3", "application/x-sqlite3"},
    "wav": {"audio/x-wav", "audio/wav", "audio/vnd.wave"}, "mp3": {"audio/mpeg"},
    "json": {"application/json"}, "xml": {"text/xml", "application/xml"},
    "html": {"text/html"}, "txt": {"text/plain"},
    "pe": {"application/x-dosexec", "application/vnd.microsoft.portable-executable"},
    "elf": {"application/x-executable", "application/x-sharedlib",
            "application/x-pie-executable", "application/x-object"},
    "rtf": {"text/rtf", "application/rtf"},
}
CONDS = ["orig", "zero_header", "random_header", "trunc_tail", "fragment",
         "spoof_jpg", "spoof_txt"]
BIG = 20

df = pd.read_csv(SRC, keep_default_na=False, dtype=str)
df["magika_score"] = pd.to_numeric(df["magika_score"], errors="coerce")
classes = sorted(df["fmt"].unique())
orig = df[df["condition"] == "orig"]
n_cls = orig.groupby("fmt").size().to_dict()


def accepted(col, manual, title):
    acc = {}
    out(f"Мапінг міток: {title}")
    for f in classes:
        sub = orig[orig["fmt"] == f][col]
        mode, cnt = collections.Counter(sub).most_common(1)[0]
        share = cnt / len(sub)
        man = manual.get(f)
        if man:
            acc[f] = set(man)
            hit = sum(1 for x in sub if x in man) / len(sub)
            if hit < 0.5:
                out(f"  УВАГА {f}: ручний мапінг {sorted(man)} збігається лише на {hit:.0%}, "
                    f"найчастіша мітка '{mode}' ({share:.0%})")
        else:
            acc[f] = {mode} if share >= 0.5 else set()
            out(f"  {f}: з даних -> '{mode}' ({share:.0%})"
                + ("" if share >= 0.5 else " НЕ ПРИЙНЯТО"))
    out()
    return acc


acc_mg = accepted("magika", MG_MANUAL, "Magika")
acc_lm = accepted("libmagic_mime", LM_MANUAL, "libmagic")

df["ok_ext"] = [EXT_CLASS.get(e) == f for e, f in zip(df["ext_shown"], df["fmt"])]
df["ok_mg"] = [l in acc_mg[f] for l, f in zip(df["magika"], df["fmt"])]
df["ok_lm"] = [l in acc_lm[f] for l, f in zip(df["libmagic_mime"], df["fmt"])]
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
            k, n = int(sub[col].sum()), len(sub)
            lo, hi = wilson(k, n)
            rows.append([f, c, key, n, k, round(k / n, 3), round(lo, 3), round(hi, 3)])
pd.DataFrame(rows, columns=["fmt", "condition", "tool", "n", "k", "acc", "lo", "hi"]
             ).to_csv(OUT, index=False, encoding="utf-8")


def pivot(col, title):
    out(f"Точність, %, {title} (* означає n < {BIG} у стані orig)")
    out(f"{'клас':8s}{'n':>4s}" + "".join(f"{c[:12]:>14s}" for c in CONDS))
    for f in classes:
        star = "*" if n_cls[f] < BIG else " "
        cells = []
        for c in CONDS:
            sub = df[(df["fmt"] == f) & (df["condition"] == c)]
            cells.append(f"{100 * sub[col].mean():13.0f} " if len(sub) else f"{'-':>14s}")
        out(f"{f:8s}{n_cls[f]:>3d}{star}" + "".join(cells))
    out()


for _, col, name in TOOLS:
    pivot(col, name)

out("Середня точність за станами (макро: лише класи з n >= 20; мікро: усі файли), %")
out(f"{'інструмент':12s}{'':8s}" + "".join(f"{c[:12]:>14s}" for c in CONDS))
big = [f for f in classes if n_cls[f] >= BIG]
for _, col, name in TOOLS:
    macro, micro = [], []
    for c in CONDS:
        sub = df[df["condition"] == c]
        if len(sub) == 0:
            macro.append("-")
            micro.append("-")
            continue
        per = [sub[sub["fmt"] == f][col].mean() for f in big if (sub["fmt"] == f).any()]
        macro.append(f"{100 * sum(per) / len(per):.1f}" if per else "-")
        micro.append(f"{100 * sub[col].mean():.1f}")
    out(f"{name:12s}{'макро':8s}" + "".join(f"{x:>14s}" for x in macro))
    out(f"{'':12s}{'мікро':8s}" + "".join(f"{x:>14s}" for x in micro))
out()

out("Підміна розширення для виконуваних файлів (частка правильно названих), %")
for f in ("pe", "elf"):
    for c in ("orig", "spoof_jpg", "spoof_txt"):
        sub = df[(df["fmt"] == f) & (df["condition"] == c)]
        if len(sub):
            out(f"  {f:4s} {c:10s} n={len(sub):3d}  розширення {100 * sub['ok_ext'].mean():5.1f}  "
                f"libmagic {100 * sub['ok_lm'].mean():5.1f}  Magika {100 * sub['ok_mg'].mean():5.1f}")
out()

out("Частка 'unknown' у Magika за станами, %")
for c in CONDS:
    sub = df[df["condition"] == c]
    if len(sub):
        out(f"  {c:14s} {100 * (sub['magika'] == 'unknown').mean():5.1f}")
out()

out("Класи, що залежать від заголовка (orig >= 90 %, zero_header < 50 %)")
for key, col, name in TOOLS[1:]:
    dep = []
    for f in classes:
        a = df[(df["fmt"] == f) & (df["condition"] == "orig")][col].mean()
        z = df[(df["fmt"] == f) & (df["condition"] == "zero_header")][col].mean()
        if a >= 0.9 and z < 0.5:
            dep.append(f"{f} ({100 * a:.0f}->{100 * z:.0f})")
    out(f"  {name}: " + (", ".join(dep) if dep else "немає"))
out()

out("Помилки Magika у стані orig (точність < 90 %): найчастіші мітки")
for f in classes:
    sub = orig[orig["fmt"] == f]
    a = (df[(df["fmt"] == f) & (df["condition"] == "orig")]["ok_mg"]).mean()
    if a < 0.9:
        top = collections.Counter(sub["magika"]).most_common(4)
        out(f"  {f:7s} {100 * a:5.1f} %  {top}")

REPORT.write_text("\n".join(lines), encoding="utf-8")
out(f"\nЗвіт: {REPORT}")
out(f"Таблиця з інтервалами Вілсона: {OUT}")