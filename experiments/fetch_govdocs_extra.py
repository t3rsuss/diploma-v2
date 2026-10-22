import collections
import pathlib
import random

from remotezip import RemoteZip

BASE = pathlib.Path(__file__).resolve().parents[1]
GD = BASE / "data" / "govdocs"
URL = "https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/{:03d}.zip"
USED = {0, 1, 2, 500}
EXT = {"jpg": "jpg", "jpeg": "jpg", "gif": "gif", "gz": "gz", "xml": "xml",
       "txt": "txt", "log": "log", "csv": "csv", "rtf": "rtf"}
DEV_Q = {"gif": 60, "jpg": 60, "gz": 40, "xml": 50, "txt": 50, "log": 40, "csv": 40, "rtf": 40}
TEST_Q = {"gif": 40, "jpg": 40, "gz": 30, "xml": 40, "txt": 40, "log": 30, "csv": 30, "rtf": 30}
N_THREADS, PER_THREAD, MAX_MEMBER, RESERVE = 36, 8, 10_000_000, 1.3
rng = random.Random(42)

cand = rng.sample([n for n in range(1000) if n not in USED], N_THREADS)
split = N_THREADS * 2 // 3
SIDES = {"dev": (cand[:split], DEV_Q), "test": (cand[split:], TEST_Q)}


def run(side, threads, quota):
    got = collections.Counter()
    for n in threads:
        try:
            with RemoteZip(URL.format(n)) as z:
                by = collections.defaultdict(list)
                for i in z.infolist():
                    if i.is_dir() or "." not in i.filename:
                        continue
                    cls = EXT.get(i.filename.rsplit(".", 1)[-1].lower())
                    if cls and 512 <= i.file_size <= MAX_MEMBER:
                        by[cls].append(i.filename)
                pick = []
                for cls, q in quota.items():
                    names = by.get(cls, [])
                    rng.shuffle(names)
                    k = min(PER_THREAD, max(0, int(q * RESERVE) - got[cls]), len(names))
                    pick += [(cls, x) for x in names[:k]]
                    got[cls] += k
                if not pick:
                    continue
                out = GD / f"{side}_extra" / f"{n:03d}"
                out.mkdir(parents=True, exist_ok=True)
                for cls, name in pick:
                    (out / pathlib.Path(name).name).write_bytes(z.read(name))
            print(f"{side} {n:03d}: {len(pick)} файлів", flush=True)
        except Exception as e:
            print(f"{side} {n:03d}: пропущено ({type(e).__name__}: {e})", flush=True)
    print(f"\n{side}: набрано", dict(got), "\n")


for side, (threads, quota) in SIDES.items():
    print(f"{side}: каталоги {sorted(threads)}")
    run(side, threads, quota)