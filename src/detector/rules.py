import struct

AGREE_MIN = 0.6
X86_FAMILY = {3, 62}


def elf_machine(path):
    with open(path, "rb") as f:
        h = f.read(20)
    if len(h) < 20 or h[:4] != b"\x7fELF":
        return None
    fmt = "<H" if h[5] == 1 else ">H"
    return struct.unpack(fmt, h[18:20])[0]


def apply_rules(lvl, kind, pred, truth, machine=None):
    if kind != "ELF" or pred is None:
        return lvl, [], False

    reasons = []
    if truth is None:
        reasons.append("ELF без читаної таблиці секцій")
    elif machine in X86_FAMILY:
        agree = float((pred == truth).mean())
        if agree < AGREE_MIN:
            reasons.append(
                f"розмітка за вмістом збігається з таблицею секцій лише на {agree * 100:.1f} %"
            )

    raised = bool(reasons) and lvl == "low"
    return ("mid" if raised else lvl), reasons, raised