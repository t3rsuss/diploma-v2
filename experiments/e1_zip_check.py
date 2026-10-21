import glob
import zipfile

from magika import Magika

m = Magika()
files = sorted(glob.glob(r"C:\Windows\System32\SEAPODAT.*.zip"))
print("Знайдено ZIP:", len(files))

for p in files:
    data = open(p, "rb").read()
    size = len(data)
    eocd = data.rfind(b"PK\x05\x06")
    try:
        z = zipfile.ZipFile(p)
        names = z.namelist()
        bad = z.testzip()
        zinfo = f"відкрито, елементів {len(names)}, testzip={bad}"
        first = names[:3]
    except Exception as e:
        zinfo = f"помилка zipfile: {type(e).__name__}: {e}"
        first = []
    r = m.identify_bytes(data)
    r2 = m.identify_bytes(data[:4096])
    print(p.split("\\")[-1])
    print(f"   розмір {size}, EOCD на зсуві {eocd} (від кінця {size - eocd if eocd >= 0 else 'нема'})")
    print(f"   {zinfo}; перші елементи {first}")
    print(f"   Magika повний файл: {r.output.label} {r.score:.2f}; перші 4096 Б: {r2.output.label} {r2.score:.2f}")
    print(f"   хвіст: {data[-60:]!r}")