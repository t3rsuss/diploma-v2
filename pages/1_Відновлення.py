"""Інтерфейс спільного аналізу структури за програмою-читачем."""
import hashlib
import json
import pathlib
import sys
import tempfile

import pandas as pd
import streamlit as st

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyze_all import analyze_set

READERS = {
    "PNG — Pillow": {"fmt": "png"},
    "GIF — Pillow": {"fmt": "gif"},
    "ICO — Pillow": {"fmt": "ico"},
    "WAV — wave": {"fmt": "wav"},
    "GZIP — gzip": {"fmt": "gz"},
    "DOCX / ZIP — zipfile": {"fmt": "docx"},
    "XDT1 — демонстраційний читач": {
        "reader": "demo.xdt_reader:parse_file",
    },
    "XDT2 — демонстраційний читач": {
        "reader": "demo.xdt2:parse_file",
    },
    "XDT3 — демонстраційний читач": {
        "reader": "demo.xdt3:parse_file",
    },
    "CFG1 — демонстраційний читач": {
        "reader": "demo.cfg1:parse_file",
    },
}

st.set_page_config(page_title="Відновлення структури", layout="wide")
st.title("Відновлення структури за програмою-читачем")
st.caption(
    "Зразки одного формату → спостереження за читанням → "
    "гіпотези меж і ролей полів → аналіз вмісту."
)
st.info(
    "Вибір читача задає програму для обробки даних, а не готову "
    "схему для алгоритму відновлення. Доступні лише встановлені читачі."
)

with st.form("joint_recovery_form"):
    reader_name = st.selectbox("Програма-читач", list(READERS))
    uploads = st.file_uploader(
        "Від 5 до 30 різних файлів одного формату",
        accept_multiple_files=True,
    )
    submitted = st.form_submit_button("Відновити та проаналізувати")

if submitted:
    st.session_state.pop("joint_recovery_report", None)

    if not uploads or not 5 <= len(uploads) <= 30:
        st.error("Потрібно завантажити від 5 до 30 файлів.")
    else:
        accepted, validation, seen = [], [], set()

        for index, upload in enumerate(uploads):
            data = upload.getvalue()
            item_id = f"sample_{index:03d}.bin"
            entry = {
                "file": upload.name,
                "input_id": item_id,
                "stage": "upload",
            }
            if not 16 <= len(data) <= 300_000:
                entry.update(
                    status="rejected",
                    reason=f"Supported file size: 16..300000 bytes; got {len(data)}",
                )
            else:
                digest = hashlib.sha256(data).hexdigest()
                if digest in seen:
                    entry.update(status="rejected", reason="duplicate_sha256")
                else:
                    seen.add(digest)
                    entry.update(status="accepted")
                    accepted.append((item_id, upload.name, data, digest))
            validation.append(entry)

        audit, reports, run_error = [], [], None
        if len(accepted) < 5:
            run_error = "Після перевірки залишилося менше 5 різних зразків."
        else:
            try:
                with st.spinner("Трасування читача та відновлення структури..."):
                    with tempfile.TemporaryDirectory(prefix="rebin_joint_") as folder:
                        for item_id, _, data, _ in accepted:
                            pathlib.Path(folder, item_id).write_bytes(data)
                        reports = analyze_set(
                            [folder],
                            limit=30,
                            sample_audit=audit,
                            **READERS[reader_name],
                        )
            except Exception as exc:
                run_error = f"{type(exc).__name__}: {exc}"

        names = {
            item_id: original
            for item_id, original, _, _ in accepted
        }
        for entry in reports + audit:
            item_id = entry["file"]
            entry["input_id"] = item_id
            entry["file"] = names.get(item_id, item_id)
            entry.pop("path", None)

        payload = {
            "schema_version": 2,
            "run_status": "error" if run_error else "ok",
            "run_error": run_error,
            "reader": reader_name,
            "mode": "joint_sample_inference",
            "risk_policy": "v2_entropy_in_read_blocks_is_informational",
            "input_manifest": [
                {
                    "input_id": item_id,
                    "name": original,
                    "size": len(data),
                    "sha256": digest,
                }
                for item_id, original, data, digest in accepted
            ],
            "upload_audit": validation,
            "sample_audit": audit,
            "limitations": [
                "Межі й ролі полів є гіпотезами, а не підтвердженою специфікацією.",
                "Усі придатні зразки беруть участь у спільному відновленні.",
                "Це не незалежне оцінювання на відкладеній вибірці.",
                "Контекст читання сам по собі не доводить роль поля.",
                "Трасування обмежене перехопленими операціями Python-читача.",
                "Рівень ризику не є вердиктом про шкідливість або її ймовірністю.",
                "Збіги заголовків PE/ELF не підтверджують повний виконуваний файл.",
                "Висока ентропія сама по собі не доводить шифрування чи загрозу.",
            ],
            "reports": reports,
        }
        st.session_state["joint_recovery_report"] = payload

payload = st.session_state.get("joint_recovery_report")
if payload:
    reports = payload["reports"]
    good = [r for r in reports if r["status"] == "ok"]
    bad = [r for r in reports if r["status"] != "ok"]

    st.caption("Читач цього запуску: " + payload["reader"])
    a, b, c = st.columns(3)
    a.metric("Прийнято різних зразків", len(payload["input_manifest"]))
    b.metric("Успішних звітів", len(good))
    c.metric("Помилок аналізу файлів", len(bad))

    if payload["run_error"]:
        st.error(payload["run_error"])

    st.warning(
        "Система формує гіпотези структури. Вона не гарантує повного "
        "відновлення формату та не генерує незалежний парсер."
    )

    if good:
        choices = {
            r["input_id"]: f"{r['file']} [{r['input_id']}]"
            for r in good
        }
        selected = st.selectbox(
            "Файл для перегляду структури",
            list(choices),
            format_func=choices.get,
        )
        report = next(r for r in good if r["input_id"] == selected)

        st.subheader("Гіпотези полів")
        st.caption(
            f"Розмір: {report['size']} байтів. "
            f"SHA-256: {report['sha256']}"
        )
        fields = pd.DataFrame(report["fields"]).rename(columns={
            "start": "початок",
            "end": "кінець",
            "size": "довжина",
            "role": "гіпотеза ролі",
            "context": "пов'язане місце читання",
            "hex": "перші байти (hex)",
        })
        st.dataframe(fields, hide_index=True, width="stretch")

        st.subheader("Пояснення гіпотез довжин")
        st.caption(
            "Підтримка правила — частка числових збігів серед перевірених "
            "подій читання цієї вибірки, а не ймовірність правильності. "
            "Збіг у поточному файлі показано окремо. "
            "Пояснюються кандидати правил довжин, а не всі ролі полів."
        )
        evidence = report.get("length_evidence", [])
        if evidence:
            rows = []
            for item in evidence:
                target = item["related_interval"]
                rows.append({
                    "поле": f"{item['field'][0]}..{item['field'][1]}",
                    "значення": item["value"],
                    "кодування": item["encoding"],
                    "пов'язаний інтервал": (
                        f"{target[0]}..{target[1]}" if target is not None else "—"
                    ),
                    "збіг у цьому файлі": item["local_read_match"],
                    "збігів": item["matching_events"],
                    "перевірено подій": item["checked_events"],
                    "підтримка правила": item["event_support"],
                    "файлів зі збігами": item["files_with_matching_events"],
                    "контекст читання": item["context"],
                })
            st.dataframe(
                pd.DataFrame(rows), hide_index=True, width="stretch",
            )
        else:
            st.info("Для цього файла пояснень правил довжин немає.")

        with st.expander("Покриття та коректність інтервалів"):
            st.json(report["interval_audit"])

        st.subheader("Застосування до аналізу загроз")
        st.write("Евристичний рівень:", report["risk"])
        findings = report["block_findings"]
        if findings:
            st.dataframe(
                pd.DataFrame(findings),
                hide_index=True,
                width="stretch",
            )
        else:
            st.info("У відновлених блоках індикаторів не виявлено.")

        with st.expander("Аналіз непрочитаних ділянок"):
            st.json(report["unread_scan"])

    if bad:
        st.subheader("Файли, які не вдалося проаналізувати")
        st.dataframe(
            pd.DataFrame(bad), hide_index=True, width="stretch",
        )

    with st.expander("Журнал приймання та обробки зразків"):
        st.write("Перевірка завантажень")
        st.dataframe(
            pd.DataFrame(payload["upload_audit"]),
            hide_index=True,
            width="stretch",
        )
        st.write("Відбір, читання та участь у відновленні")
        st.dataframe(
            pd.DataFrame(payload["sample_audit"]),
            hide_index=True,
            width="stretch",
        )

    with st.expander("Обмеження методу"):
        for limitation in payload["limitations"]:
            st.write("- " + limitation)

    st.download_button(
        "Завантажити повний звіт JSON",
        data=json.dumps(payload, ensure_ascii=False, indent=2),
        file_name="recovery_report.json",
        mime="application/json",
    )
