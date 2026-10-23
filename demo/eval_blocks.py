import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

RANK = {"низький": 1, "середній": 2, "високий": 3}


def level(findings):
    best = max((RANK[f["severity"]] for f in findings), default=0)
    return {0: "немає", 1: "низький", 2: "середній", 3: "високий"}[best]


def detected(findings, minimum):
    return any(RANK[f["severity"]] >= RANK[minimum] for f in findings)


def main():
    from rebin import analyze
    from demo import cfg1
    from block_scan import scan_block, scan_file

    folder, labels = cfg1.generate()
    report = analyze([str(folder)], reader="demo.cfg1:parse_file", limit=60, min_size=16)

    rows = []
    for item in report["all_fields"]:
        name = item["file"]
        data = (folder / name).read_bytes()
        fields = [tuple(x) for x in item["fields"]]
        with_structure = scan_file(data, fields)
        whole_file = scan_block(data)
        rows.append((name, labels[name], with_structure, whole_file))

    def rate(flag, minimum, which):
        subset = [r for r in rows if r[1]["malicious"] == flag]
        return sum(detected(r[which], minimum) for r in subset), len(subset)

    lines = [f"Проаналізовано файлів: {len(rows)} з {len(labels)}", ""]
    for title, which in (("за відновленою структурою (лише блоки даних)", 2),
                         ("без структури (весь файл одним блоком)", 3)):
        lines.append(title)
        for minimum in ("високий", "середній"):
            tp, nm = rate(True, minimum, which)
            fp, nb = rate(False, minimum, which)
            lines.append(f"  рівень не нижче «{minimum}»: виявлено {tp} з {nm} шкідливих, "
                         f"хибних спрацювань {fp} з {nb} безпечних")
        lines.append("")

    lines.append("Шкідливі зразки за типом вкладення (за структурою):")
    for kind in ("pe", "xor_pe", "encrypted"):
        subset = [r for r in rows if r[1]["malicious"] and r[1]["kind"] == kind]
        counts = {}
        for r in subset:
            counts[level(r[2])] = counts.get(level(r[2]), 0) + 1
        lines.append(f"  {kind}: {len(subset)} файлів, рівні: {counts}")

    located = total = 0
    for name, lab, found, _ in rows:
        if lab["malicious"]:
            total += 1
            a, b = lab["block"]
            located += any(a <= f["offset"] < b and RANK[f["severity"]] >= 2 for f in found)
    lines.append(f"\nЛокалізовано в істинному блоці: {located} з {total}")

    by_kind = {}
    for r in rows:
        if not r[1]["malicious"]:
            row = by_kind.setdefault(r[1]["kind"], [0, 0])
            row[1] += 1
            row[0] += detected(r[2], "середній")
    lines.append(f"Безпечні файли, спрацювання «середнього» рівня за типом: {by_kind}")

    text = "\n".join(lines)
    print(text)
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "eval_blocks.txt").write_text(text + "\n", encoding="utf-8")
    (out / "eval_blocks.json").write_text(
        json.dumps([{"file": n, "label": l, "findings": f} for n, l, f, _ in rows],
                   ensure_ascii=False, indent=2, default=list),
        encoding="utf-8",
    )
    print("\nSaved: results/eval_blocks.txt, results/eval_blocks.json")


if __name__ == "__main__":
    main()
