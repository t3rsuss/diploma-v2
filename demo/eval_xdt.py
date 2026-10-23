import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def truth_fields(data):
    count = struct.unpack_from("<H", data, 6)[0]
    fields = [
        (0, 4, "константа"),
        (4, 6, "константа"),
        (6, 8, "лічильник"),
        (8, 12, "змінне поле"),
    ]
    pos = 12
    for _ in range(count):
        length = struct.unpack_from("<H", data, pos + 1)[0]
        fields += [
            (pos, pos + 1, "тип запису"),
            (pos + 1, pos + 3, "довжина"),
            (pos + 3, pos + 3 + length, "дані (блок)"),
        ]
        pos += 3 + length
    fields.append((pos, pos + 4, "CRC-32"))
    if pos + 4 != len(data):
        raise ValueError("Unexpected XDT1 layout")
    return fields


def edge_set(fields, size):
    return {x for a, b, _ in fields for x in (a, b)} - {0, size}


def role_array(fields, size):
    arr = [None] * size
    for a, b, role in fields:
        for i in range(max(0, a), min(size, b)):
            arr[i] = role
    return arr


def classify(truth, pred):
    pred_set = {(a, b): r for a, b, r in pred}
    out = []
    for a, b, role in truth:
        if (a, b) in pred_set:
            out.append((role, "exact_correct" if pred_set[(a, b)] == role else "exact_wrong_role"))
            continue
        if any(pa <= a and pb >= b for pa, pb, _ in pred):
            out.append((role, "merged"))
            continue
        inside = [1 for pa, pb, _ in pred if pa >= a and pb <= b]
        out.append((role, "split" if len(inside) >= 2 else "other"))
    return out


def evaluate_file(pred, truth, size):
    te, pe = edge_set(truth, size), edge_set(pred, size)
    tr, pr = role_array(truth, size), role_array(pred, size)
    return {
        "edge_tp": len(te & pe),
        "edge_pred": len(pe),
        "edge_true": len(te),
        "bytes": size,
        "correct_role_bytes": sum(1 for x, y in zip(tr, pr) if x == y),
        "fields": classify(truth, pred),
    }


def aggregate(results):
    tp = sum(r["edge_tp"] for r in results)
    npred = sum(r["edge_pred"] for r in results)
    ntrue = sum(r["edge_true"] for r in results)
    precision = tp / npred if npred else 0.0
    recall = tp / ntrue if ntrue else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    by_role = {}
    for r in results:
        for role, status in r["fields"]:
            row = by_role.setdefault(role, {"total": 0})
            row["total"] += 1
            row[status] = row.get(status, 0) + 1

    total_bytes = sum(r["bytes"] for r in results)
    ok_bytes = sum(r["correct_role_bytes"] for r in results)
    return {
        "files": len(results),
        "boundary_precision": precision,
        "boundary_recall": recall,
        "boundary_f1": f1,
        "role_byte_accuracy": ok_bytes / total_bytes if total_bytes else 0.0,
        "by_role": by_role,
    }


def render(summary):
    lines = [
        f"Файлів: {summary['files']}",
        f"Межі полів: точність {100 * summary['boundary_precision']:.1f} %, "
        f"повнота {100 * summary['boundary_recall']:.1f} %, F1 {summary['boundary_f1']:.3f}",
        f"Байти з правильною роллю: {100 * summary['role_byte_accuracy']:.1f} %",
        "",
        f"{'роль':14s}{'усього':>8s}{'точно':>8s}{'не та роль':>12s}{'злито':>8s}{'розбито':>9s}{'інше':>7s}",
    ]
    for role, row in sorted(summary["by_role"].items()):
        lines.append(
            f"{role:14s}{row['total']:8d}{row.get('exact_correct', 0):8d}"
            f"{row.get('exact_wrong_role', 0):12d}{row.get('merged', 0):8d}"
            f"{row.get('split', 0):9d}{row.get('other', 0):7d}"
        )
    return "\n".join(lines)


def main():
    from demo.make_xdt_samples import main as generate
    from rebin import analyze

    generate()
    samples = ROOT / "demo" / "samples_xdt1"
    report = analyze([str(samples)], reader="demo.xdt_reader:parse_file", limit=20)

    results = []
    for item in report["all_fields"]:
        data = (samples / item["file"]).read_bytes()
        pred = [tuple(x) for x in item["fields"]]
        results.append(evaluate_file(pred, truth_fields(data), len(data)))

    summary = aggregate(results)
    text = render(summary)
    print(text)

    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "eval_xdt1.txt").write_text(text + "\n", encoding="utf-8")
    (out / "eval_xdt1.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("\nSaved: results/eval_xdt1.txt, results/eval_xdt1.json")


if __name__ == "__main__":
    main()
