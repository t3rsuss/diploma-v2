import json
import os
import pathlib
import sys
import tempfile

import matplotlib
import numpy as np
import pandas as pd
import streamlit as st
from matplotlib.colors import ListedColormap

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from src.pipeline import analyze_full
from src.segment import BONUS, LAM, segment
from src.triage.fragment import WIN, feats
from src.triage.triage import _fragment

LEVELS = {"high": "ймовірно шкідливий", "mid": "підозрілий", "low": "ймовірно безпечний"}


def window_map(data):
    n = len(data)
    step = WIN
    if n // step > 400:
        step = (n // 400 // 512 + 1) * 512
    starts = list(range(0, max(n - 511, 1), step))
    X = np.array([feats(data[o:o + WIN]) for o in starts])
    proba = _fragment().model.predict_proba(X)
    return starts, step, proba.argmax(1), proba.max(1), X[:, 256]


def colors_for(classes):
    cm = plt.get_cmap("hsv", len(classes))
    return [matplotlib.colors.to_hex(cm(i)) for i in range(len(classes))]


def draw_strip(idx, classes, width=100):
    n = len(idx)
    rows = int(np.ceil(n / width))
    arr = np.full(rows * width, -1)
    arr[:n] = idx
    arr = arr.reshape(rows, width) + 1
    cmap = ListedColormap(["#ffffff"] + colors_for(classes))
    fig, ax = plt.subplots(figsize=(10, max(0.8, rows * 0.18)))
    ax.imshow(arr, cmap=cmap, vmin=0, vmax=len(classes), aspect="auto", interpolation="nearest")
    ax.axis("off")
    fig.tight_layout()
    return fig


st.set_page_config(page_title="Сортувальник бінарних даних", layout="wide")
st.title("Інтелектуальний аналіз структури бінарних даних")
st.caption("Файл розглядається як дані: визначається формат, далі одна з трьох гілок: аналіз виконуваного "
           "файлу, опис структури відомого формату (Kaitai Struct) або карта областей за вмістом.")
up = st.file_uploader("Файл для аналізу (до 200 МБ)")

if up is not None:
    data = up.getvalue()
    suffix = pathlib.Path(up.name).suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as t:
        t.write(data)
        path = t.name
    try:
        with st.spinner("Аналіз..."):
            rep = analyze_full(path)
            is_exe = rep["format"] in ("pe", "elf")
            if not is_exe and "regions" not in rep:
                rep["regions"] = segment(data, _fragment())
            starts, step, idx, conf, ent = window_map(data)
    finally:
        os.unlink(path)

    c1, c2, c3 = st.columns(3)
    c1.metric("Формат", rep["format"])
    c2.metric("Джерело рішення", rep["format_source"])
    c3.metric("Впевненість", f"{rep['confidence']:.2f}")
    st.info(f"Гілка: {rep['branch']}")
    if rep["flags"]:
        for f in rep["flags"]:
            st.warning(f)
    else:
        st.success("Розбіжностей не виявлено")

    regs = rep.get("regions")
    if regs and len({r["cls"] for r in regs}) >= 2:
        st.warning(f"Експериментально: у даних виявлено {len(regs)} ділянок, серед них "
                   f"{len({r['cls'] for r in regs})} різних типів. Файл може бути контейнером або "
                   "містити вбудовані чи дописані дані.")

    st.subheader("Порівняння методів")
    m, fr = rep["magika"], rep["fragment_model"]
    st.dataframe(pd.DataFrame([
        {"метод": "розширення", "результат": rep["extension_class"] or "-", "оцінка": "-"},
        {"метод": "Magika", "результат": m["label"], "оцінка": m["score"]},
        {"метод": "модель фрагментів", "результат": fr["class"], "оцінка": fr["confidence"]},
    ]), hide_index=True)
    st.caption("Топ-3 моделі фрагментів: " + ", ".join(f"{k} {v}" for k, v in fr["top3"]))

    ex = rep.get("executable_analysis")
    if ex:
        st.subheader("Аналіз виконуваного файлу")
        if "error" in ex:
            st.error(ex["error"])
        else:
            msg = f"{LEVELS[ex['level']]} (оцінка {ex['score']:.3f}, {ex['model']})"
            {"high": st.error, "mid": st.warning, "low": st.success}[ex["level"]](msg)
            if ex["agreement_with_section_table"] is not None:
                st.write(f"Збіг розмітки за вмістом з таблицею секцій: "
                         f"{100 * ex['agreement_with_section_table']:.1f} %")
            for r in ex["reasons"]:
                st.info(r)

    stc = rep.get("structure")
    if stc:
        st.subheader("Структура за описом Kaitai Struct")
        k1, k2, k3 = st.columns(3)
        k1.metric("Парсер", stc["parser"].replace("kd_", ""))
        k2.metric("Полів верхнього рівня", stc["fields_total"])
        k3.metric("Покриття", f"{100 * stc['coverage_top_level']:.1f} %")
        df = pd.DataFrame(stc["fields"])
        if not df.empty:
            df["довжина"] = df["end"] - df["start"]
            df = df.rename(columns={"name": "поле", "start": "початок", "end": "кінець", "type": "тип"})
            st.dataframe(df, hide_index=True)
    if "structure_error" in rep:
        st.error("Помилка опису Kaitai: " + rep["structure_error"])

    if regs:
        st.subheader("Карта областей за вмістом")
        st.caption(f"Вітербі за ймовірностями моделі фрагментів (штраф за зміну класу {LAM:g}, "
                   f"бонус за сигнатуру {BONUS:g}), межі уточнено за сигнатурами формату.")
        st.dataframe(pd.DataFrame([{"зсув": r["start"], "довжина": r["length"], "клас": r["cls"],
                                    "впевненість": round(r["conf"], 2)} for r in regs]), hide_index=True)

    classes = _fragment().classes
    st.subheader("Розмітка вікнами (без згладжування)")
    st.caption(f"Вікно {WIN} Б, крок {step} Б. Кожне вікно класифікує модель фрагментів окремо.")
    st.pyplot(draw_strip(idx, classes))
    present = sorted(set(idx.tolist()))
    cols = colors_for(classes)
    st.markdown(" ".join(f"<span style='color:{cols[i]}'>■</span> {classes[i]}" for i in present),
                unsafe_allow_html=True)
    st.subheader("Профіль ентропії")
    st.line_chart(pd.DataFrame({"ентропія": ent}, index=starts))
    st.download_button("Завантажити звіт JSON", json.dumps(rep, ensure_ascii=False, indent=2, default=float),
                       file_name="report.json", mime="application/json")