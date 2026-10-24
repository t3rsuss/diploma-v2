import hashlib
import json
import pathlib
import tempfile

import pandas as pd
import streamlit as st

from src.pipeline import analyze_full

MAX_UPLOAD_BYTES = 20_000_000
REPORT_KEY = "single_file_report"
ERROR_KEY = "single_file_error"


def analyze_upload(data, name):
    if not data:
        raise ValueError("Файл порожній.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError(
            f"Файл перевищує ліміт {MAX_UPLOAD_BYTES:,} байтів."
        )

    name = pathlib.Path(name.replace("\\", "/")).name or "file.bin"
    suffix = pathlib.Path(name).suffix
    with tempfile.TemporaryDirectory(prefix="single_analysis_") as folder:
        path = pathlib.Path(folder) / ("sample" + suffix)
        path.write_bytes(data)
        report = analyze_full(path)

    report["file"] = name
    report["size"] = len(data)
    report["sha256"] = hashlib.sha256(data).hexdigest()
    report["analysis_scope"] = "single_file"
    return report


def clear_result():
    st.session_state.pop(REPORT_KEY, None)
    st.session_state.pop(ERROR_KEY, None)


def render_report(report):
    st.subheader("Результат аналізу")
    st.caption(
        f"Файл: {report['file']} | "
        f"Розмір: {report['size']:,} байтів"
    )

    unknown = report["format"] in ("unknown", "other")
    if unknown:
        st.warning("Формат не встановлено")
        st.write(
            "Виконано попередній аналіз вмісту. "
            "Класи областей є припущеннями моделі, "
            "а не відновленою специфікацією формату."
        )
    else:
        st.info("Визначений тип: " + report["format"].upper())
        st.caption(
            "Тип визначено методом: "
            + report["format_source"]
            + ". Це не гарантує коректності всього файла."
        )

    for flag in report.get("flags", []):
        st.warning(flag)

    structure = report.get("structure")
    regions = report.get("regions", [])

    if structure:
        st.subheader("Структура за готовим описом формату")
        st.caption(
            "Це розбір наявним парсером, "
            "а не автоматично виведена схема невідомого формату."
        )
        fields = pd.DataFrame(structure.get("fields", []))
        if not fields.empty:
            st.dataframe(
                fields.rename(columns={
                    "name": "поле", "start": "початок",
                    "end": "кінець", "type": "тип",
                }),
                hide_index=True, width="stretch",
            )
        st.write("Полів верхнього рівня:", structure["fields_total"])
        st.caption(
            f"Покриття верхнього рівня: "
            f"{100 * structure['coverage_top_level']:.1f} %. "
            "Покриття не є оцінкою правильності семантики."
        )

    if report.get("structure_error"):
        st.warning(
            "Готовий парсер не зміг завершити розбір: "
            + report["structure_error"]
        )

    if regions:
        st.subheader("Попередня карта вмісту")
        st.caption(
            "Межі та класи областей оцінено за вмістом. "
            "Наприклад, схожість області на PNG не підтверджує, "
            "що вона є повним коректним PNG-файлом."
        )
        st.dataframe(
            pd.DataFrame([
                {
                    "початок": region["start"],
                    "кінець": region["end"],
                    "байтів": region["length"],
                    "припущення про вміст": region["cls"],
                }
                for region in regions
            ]),
            hide_index=True, width="stretch",
        )

    observations = report.get("unknown_analysis")
    if observations:
        st.subheader("Спостереження за внутрішньою будовою")
        st.caption(
            "Це аналіз байтів одного файла без готової схеми. "
            "Ділянки профілю не є відновленими полями формату."
        )
        profile = pd.DataFrame(observations["profile"]).rename(columns={
            "start": "початок", "end": "кінець", "size": "байтів",
            "entropy": "ентропія",
            "zero_fraction": "частка нулів",
            "ascii_fraction": "частка друкованих ASCII",
            "observation": "спостереження",
        })
        st.dataframe(profile, hide_index=True, width="stretch")

        strings = observations["ascii_strings"]
        if strings:
            with st.expander("Текстові послідовності зі зсувами"):
                st.dataframe(
                    pd.DataFrame(strings), hide_index=True, width="stretch",
                )
                if observations["ascii_strings_limited"]:
                    st.caption("Показано лише перші послідовності в межах ліміту.")

        if observations["zero_runs"]:
            with st.expander("Нульові ділянки від 8 байтів"):
                st.dataframe(
                    pd.DataFrame(observations["zero_runs"]),
                    hide_index=True, width="stretch",
                )
                if observations["zero_runs_limited"]:
                    st.caption("Перелік обмежено.")

        candidates = observations["numeric_candidates"]
        with st.expander("Можливі числові зв’язки"):
            st.caption(
                "Перевірено дво- й чотирибайтні числа з початком "
                "у перших 64 байтах. matches_file_size — збіг із "
                "розміром файла; matches_bytes_after_field — "
                "із залишком після кандидата. Збіги можуть бути випадковими."
            )
            if candidates:
                st.dataframe(
                    pd.DataFrame(candidates), hide_index=True, width="stretch",
                )
            else:
                st.write("За цими обмеженими перевірками кандидатів не знайдено.")

    executable = report.get("executable_analysis")
    if executable:
        st.subheader("Спеціалізований аналіз PE/ELF")
        if executable.get("error"):
            st.warning(
                "Аналіз виконуваного файла не завершено: "
                + executable["error"]
            )
        else:
            labels = {
                "high": "Високий ризик за моделлю",
                "mid": "Підозрілий за моделлю",
                "low": "Низький ризик за моделлю",
            }
            st.write(labels.get(executable["level"], executable["level"]))
            st.caption(
                "Це результат спеціалізованого детектора, "
                "а не гарантія безпечності або шкідливості."
            )
            for reason in executable.get("reasons", []):
                st.write(reason)
    else:
        st.caption(
            "Загальний антивірусний вердикт для цього файла "
            "не формується. Карта вмісту сама по собі "
            "не визначає наявність загрози."
        )

    with st.expander("Технічні подробиці"):
        st.write("SHA-256:", report["sha256"])
        st.write("Сценарій:", report.get("branch", ""))
        candidate = report.get("format_candidate")
        if candidate:
            st.write("Непідтверджений кандидат:", candidate["format"])
        st.caption(
            "Оцінки моделей у звіті не є ймовірністю "
            "правильного відновлення структури."
        )
        st.json(report)

    st.download_button(
        "Завантажити звіт JSON",
        data=json.dumps(
            report, ensure_ascii=False, indent=2, default=float,
        ),
        file_name="analysis_report.json",
        mime="application/json",
    )


def main():
    st.set_page_config(
        page_title="Аналіз бінарних даних", layout="wide",
    )
    st.title("Аналіз бінарних даних")
    st.caption(
        "Завантажте один файл. Система спробує визначити тип "
        "і вибере доступний спосіб аналізу."
    )
    st.caption(
        "Файл не запускається як програма. "
        "Це не ізольоване середовище для небезпечних зразків."
    )

    upload = st.file_uploader(
        "Файл для аналізу — до 20 000 000 байтів",
        key="single_file_upload",
        on_change=clear_result,
    )
    if st.button("Проаналізувати", type="primary"):
        clear_result()
        if upload is None:
            st.session_state[ERROR_KEY] = "Спочатку виберіть файл."
        else:
            try:
                with st.spinner("Аналіз файла..."):
                    st.session_state[REPORT_KEY] = analyze_upload(
                        upload.getvalue(), upload.name,
                    )
            except Exception as exc:
                st.session_state[ERROR_KEY] = (
                    f"Аналіз не завершено: {type(exc).__name__}: {exc}"
                )

    error = st.session_state.get(ERROR_KEY)
    if error:
        st.error(error)
    report = st.session_state.get(REPORT_KEY)
    if report:
        render_report(report)


if __name__ == "__main__":
    main()
