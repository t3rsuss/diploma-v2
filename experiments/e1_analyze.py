import sys
import pathlib

import pandas as pd

SRC = pathlib.Path(sys.argv[1])
OUT = pathlib.Path(sys.argv[2])

MAGIKA_STRICT = {
    "png": {"png"}, "jpg": {"jpeg"}, "gif": {"gif"}, "bmp": {"bmp"},
    "ico": {"ico"}, "pdf": {"pdf"}, "zip": {"zip"}, "gz": {"gzip"},
    "7z": {"sevenzip", "7z"}, "sqlite": {"sqlite"}, "db": {"sqlite"},
    "wav": {"wav"}, "mp3": {"mp3"}, "json": {"json"}, "xml": {"xml"},
    "html": {"html"}, "txt": {"txt"}, "pcap": {"pcap"}, "ttf": {"ttf"},
    "pe": {"pebin"}, "elf": {"elf"},
}
TEXT_LIKE = {"txt", "tsv", "csv", "ini", "markdown", "yaml", "toml", "json",
             "jsonl", "javascript", "xml", "html", "winregistry", "log"}
MAGIKA_LENIENT = dict(MAGIKA_STRICT)
MAGIKA_LENIENT["txt"] = TEXT_LIKE
MAGIKA_LENIENT["json"] = {"json", "jsonl", "javascript"}
MAGIKA_LENIENT["zip"] = {"zip", "jar", "docx", "xlsx", "pptx", "odt", "apk", "epub"}

MIME = {
    "png": {"image/png"}, "jpg": {"image/jpeg"}, "gif": {"image/gif"},
    "bmp": {"image/bmp", "image/x-ms-bmp"},
    "ico": {"image/vnd.microsoft.icon", "image/x-icon"},
    "pdf": {"application/pdf"}, "zip": {"application/zip"},
    "gz": {"application/gzip", "application/x-gzip"},
    "sqlite": {"application/vnd.sqlite3", "application/x-sqlite3"},
    "db": {"application/vnd.sqlite3", "application/x-sqlite3"},
    "wav": {"audio/x-wav", "audio/wav"}, "mp3": {"audio/mpeg"},
    "json": {"application/json"}, "xml": {"text/xml", "application/xml"},
    "html": {"text/html"}, "txt": {"text/plain"},
    "ttf": {"font/sfnt", "application/x-font-ttf", "font/ttf"},
    "pe": {"application/x-dosexec"},
    "elf": {"application/x-executable", "application/x-sharedlib",
            "application/x-pie-executable"},
}

df = pd.read_csv(SRC)
df["m_strict"] = [m in MAGIKA_STRICT.get(t, {t}) for t, m in zip(df["true"], df["magika"])]
df["m_lenient"] = [m in MAGIKA_LENIENT.get(t, {t}) for t, m in zip(df["true"], df["magika"])]
df["lm_ok"] = [mm in MIME.get(t, {mm}) for t, mm in zip(df["true"], df["libmagic_mime"])]

rows = []
for (cls, cond), g in df.groupby(["true", "condition"]):
    rows.append(dict(
        true=cls, condition=cond, n=len(g),
        magika_strict=round(g["m_strict"].mean(), 3),
        magika_lenient=round(g["m_lenient"].mean(), 3),
        libmagic=round(g["lm_ok"].mean(), 3),
        mean_score=round(g["magika_score"].mean(), 3),
    ))
res = pd.DataFrame(rows)
OUT.parent.mkdir(parents=True, exist_ok=True)
res.to_csv(OUT, index=False, encoding="utf-8")

print(res.pivot(index="true", columns="condition", values="magika_lenient").to_string())
print("\nЗагалом за станами:")
print(df.groupby("condition")[["m_strict", "m_lenient", "lm_ok"]].mean().round(3).to_string())

spoof = df[df["condition"] == "spoof_jpg"]
print("\nЗамасковані виконувані файли, виявлено:")
print("Magika:", round(spoof["m_strict"].mean(), 3), " libmagic:", round(spoof["lm_ok"].mean(), 3))

bad = df[(df["condition"] == "orig") & (~df["m_lenient"])]
print("\nПомилки у стані orig після м'якої нормалізації (перевірити вручну):")
print(bad.groupby(["true", "magika"]).size().sort_values(ascending=False).head(15).to_string())