import hashlib
import json
import pathlib
import sys
import tempfile

import pandas as pd
import streamlit as st

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rebin import analyze

st.set_page_config(
    page_title="Відновлення структури",
    layout="wide",
)

st.title("Відновлення структури за програмою-читачем")
st.caption(
    "Кілька зразків одного формату → трасування читання → "
    "кандидати меж і ролей полів. Це експериментальне відновлення, "
    "а не розбір за готовою специфікацією Kaitai."
)

st.info(
    "На цій сторінці доступні встановлені читачі. "
    "Назва читача потрібна для запуску програми, яка обробляє дані. "
    "Ролі полів є гіпотезами; вони можуть містити помилки."
)

with st.form("recovery_form"):
    fmt = st.selectbox(
        "Встановлений читач",
        ["png", "gif", "ico", "wav", "gz", "docx"],
    )
    uploads = st.file_uploader(
        "Зразки одного формату: від 5 до 30 файлів",
        accept_multiple_files=True,
        key="recovery_samples",
    )
    submitted = st.form_submit_button("Відновити структуру")

if submitted:
    st.session_state.pop("recovery_report", None)

    if not uploads or not 5 <= len(uploads) <= 30:
        st.error("Завантаж від 5 до 30 файлів одного формату.")
    else:
        samples = []
        seen = set()
        problems = []

        for upload in uploads:
            data = upload.getvalue()
            if not 64 <= len(data) <= 300_000:
                problems.append(
                    f"{upload.name}: розмір має бути від 64 до 300000 байтів."
                )
                continue

            digest = hashlib.sha256(data).hexdigest()
            if digest in seen:
                problems.append(f"{upload.name}: дублікат іншого зразка.")
                continue

            seen.add(digest)
            samples.append((upload.name, data, digest))

        for problem in problems:
            st.warning(problem)

        if len(samples) < 5:
            st.error("Після перевірки залишилося менше 5 різних зразків.")
        else:
            try:
                with st.spinner("Трасування читача та відновлення полів..."):
                    with tempfile.TemporaryDirectory(prefix="rebin_ui_") as folder:
                        names = {}

                        for i, (original_name, data, digest) in enumerate(samples):
                            stored = f"sample_{i:03d}.bin"
                            pathlib.Path(folder, stored).write_bytes(data)
                            names[stored] = original_name

                        report = analyze(
                            [folder],
                            fmt=fmt,
                            limit=30,
                            min_size=64,
                            max_size=300_000,
                        )

                        report["example_file"] = names.get(
                            report["example_file"],
                            report["example_file"],
                        )
                        report["reader"] = fmt
                        report["uploaded_unique_files"] = len(samples)
                        report["input_manifest"] = [
                            {
                                "name": name,
                                "size": len(data),
                                "sha256": digest,
                            }
                            for name, data, digest in samples
                        ]
                        report["limitations"] = [
                            "Ролі та межі полів є евристичними гіпотезами.",
                            "Опис полів показано для одного прикладу.",
                            "Це не згенерований незалежний парсер.",
                            "Перевірка E19 не інтегрована в цей звіт.",
                            "Трасування не відображає внутрішні операції "
                            "нативного декодера.",
                        ]

                st.session_state["recovery_report"] = report

            except SystemExit as exc:
                st.error(str(exc))
            except Exception as exc:
                st.error(f"{type(exc).__name__}: {exc}")

report = st.session_state.get("recovery_report")

if report:
    a, b, c = st.columns(3)
    a.metric("Завантажено різних зразків", report["uploaded_unique_files"])
    b.metric("Успішно проаналізовано", report["files"])
    c.metric("Точок читання", len(report["points"]))

    if report["files"] < report["uploaded_unique_files"]:
        st.warning(
            "Частину зразків читач не обробив або не сформував для них "
            "трасу. Поточне ядро пропускає такі зразки без докладного журналу."
        )

    st.warning(
        "Таблиця містить кандидати полів, а не підтверджену специфікацію. "
        "Сталі байти можуть бути лише особливістю вибірки; "
        "позначення «довжина» може виникнути через числовий збіг."
    )

    st.subheader("Кандидати полів")
    st.write("Приклад файла:", report["example_file"])

    fields = pd.DataFrame(report["example_fields"])
    if not fields.empty:
        fields = fields.rename(columns={
            "start": "початок",
            "end": "кінець",
            "size": "довжина",
            "role": "гіпотеза ролі",
            "context": "точка читання",
            "hex": "перші байти (hex)",
        })
        st.dataframe(fields, hide_index=True, use_container_width=True)
    else:
        st.info("Кандидатів полів не отримано.")

    st.subheader("Контекст роботи читача")
    points = pd.DataFrame(report["points"])
    if not points.empty:
        points = points.rename(columns={
            "context": "точка читання",
            "files_share": "частка файлів",
            "per_file": "викликів на присутній файл",
            "length": "найчастіша довжина",
            "length_share": "частка цієї довжини",
            "role": "статистична характеристика",
        })
        st.dataframe(points, hide_index=True, use_container_width=True)

    st.caption(
        "Статистичні характеристики точок читання не є "
        "підтвердженням семантичної ролі поля."
    )

    st.download_button(
        "Завантажити звіт JSON",
        data=json.dumps(report, ensure_ascii=False, indent=2),
        file_name="recovery_report.json",
        mime="application/json",
    )
