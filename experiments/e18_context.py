import collections
import gzip
import io
import pathlib
import random
import sys
import wave
import zipfile

from PIL import Image

GENERIC = {"read", "read1", "readinto", "readline", "_read", "_read1", "_safe_read", "peek", "<module>"}
SELF = pathlib.Path(__file__).name if "__file__" in globals() else "e18"
MAX_BYTES, PER_CLASS, SEED, TOP = 150_000, 30, 42, 14


class CtxIO(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.log = []

    def _ctx(self):
        f = sys._getframe(2)
        while f is not None:
            name = f.f_code.co_name
            fn = pathlib.Path(f.f_code.co_filename).name
            if name not in GENERIC and fn != SELF:
                return f"{fn[:-3] if fn.endswith('.py') else fn}.{name}:{f.f_lineno}"
            f = f.f_back
        return "(тіло потоку)"

    def _rec(self, pos, n):
        if n > 0:
            self.log.append((pos, n, self._ctx()))
        if len(self.log) > 100_000:
            raise RuntimeError("надто багато читань")

    def read(self, size=-1):
        pos = self.tell()
        out = super().read(size)
        self._rec(pos, len(out))
        return out

    def read1(self, size=-1):
        return self.read(size)

    def readline(self, size=-1):
        pos = self.tell()
        out = super().readline(size)
        self._rec(pos, len(out))
        return out

    def readinto(self, b):
        pos = self.tell()
        n = super().readinto(b) or 0
        self._rec(pos, n)
        return n


def run_ctx(fmt, data):
    f = CtxIO(data)
    if fmt in ("png", "gif", "ico"):
        im = Image.open(f)
        im.load()
    elif fmt == "wav":
        w = wave.open(f, "rb")
        w.readframes(w.getnframes())
    elif fmt == "gz":
        with gzip.GzipFile(fileobj=f) as g:
            while g.read(1 << 16):
                pass
    elif fmt == "docx":
        with zipfile.ZipFile(f) as z:
            for n in z.namelist():
                z.read(n)
    return f.log


def profile(logs):
    n = len(logs)
    by = collections.defaultdict(list)
    for i, log in enumerate(logs):
        for pos, ln, c in log:
            by[c].append((i, pos, ln))
    rows = []
    for c, items in by.items():
        files = {i for i, _, _ in items}
        lens = collections.Counter(l for _, _, l in items)
        offs = collections.Counter(p for _, p, _ in items)
        per_file = len(items) / len(files)
        (ml, mlc), (mo, moc) = lens.most_common(1)[0], offs.most_common(1)[0]
        share = len(files) / n
        if len(lens) == 1 and moc / len(items) >= 0.9 and per_file <= 1.01:
            role = "поле на фіксованій позиції"
        elif len(lens) == 1 or mlc / len(items) >= 0.8:
            role = "повторюване поле запису"
        else:
            role = "блок змінної довжини"
        rows.append((c, share, per_file, ml, mlc / len(items), mo if role.startswith("поле на") else None, role,
                     sum(l for _, _, l in items) / n))
    rows.sort(key=lambda r: (-r[1], -r[2], r[0]))
    return rows


def annotate(log, limit=16):
    merged = []
    for pos, ln, c in log:
        if merged and merged[-1][2] == c and merged[-1][0] + merged[-1][1] == pos:
            merged[-1] = (merged[-1][0], merged[-1][1] + ln, c)
        else:
            merged.append((pos, ln, c))
    return merged[:limit], len(merged)


def main(fmts):
    import trace_lib as T
    files = T.collect_files()
    rng = random.Random(SEED)
    for c in fmts:
        if c not in T.FORMATS:
            continue
        lst = sorted(files[c])
        rng.shuffle(lst)
        logs = []
        for p in lst:
            if len(logs) >= PER_CLASS:
                break
            try:
                if not (1024 <= p.stat().st_size <= MAX_BYTES):
                    continue
                log = run_ctx(c, p.read_bytes())
            except Exception:
                continue
            if log:
                logs.append(log)
        if len(logs) < 5:
            print(f"{c}: замало файлів")
            continue
        rows = profile(logs)
        stable = sum(1 for r in rows if r[1] >= 0.9)
        print(f"\n{c}: файлів {len(logs)}, різних точок читання {len(rows)}, із них у 90 % файлів і більше: {stable}")
        print(f"  {'точка читання (модуль.функція:рядок)':46s}{'файлів':>8s}{'на файл':>9s}{'довж.':>7s}{'частка':>8s}  роль")
        for r in rows[:TOP]:
            print(f"  {r[0]:46s}{100 * r[1]:7.0f}%{r[2]:9.1f}{r[3]:7d}{100 * r[4]:7.0f}%  {r[6]}")
        m, tot = annotate(logs[0])
        print(f"  перший файл: {tot} зведених читань, перші {len(m)}:")
        for pos, ln, ctx in m:
            print(f"    {pos:7d}..{pos + ln:<7d} {ln:7d} Б  {ctx}")


if __name__ == "__main__":
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    main(sys.argv[1:] or ["png", "gif", "ico", "wav", "gz", "docx"])
