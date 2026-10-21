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
from src.triage.fragment import WIN, feats
from src.triage.triage import _fragment, analyze

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
    ax.imshow(arr, cmap=cmap, vmin=0, vmax=len(classes), aspect="auto",
              interpolation="nearest")
    ax.axis("off")
    fig.tight_layout()
    return fig


def regions(starts, idx, conf, classes, size):
    out, s = [], 0
    for i in range(1, len(idx) + 1):
        if i == len(idx) or idx[i] != idx[s]:
            end = starts[i] if i < len(idx) else size
            out.append({"зсув": starts[s], "довжина": end - starts[s],
                        "клас": classes[idx[s]],
                        "впевненість": round(float(conf[s:i].mean()), 2)})
            s = i
    return out


st.set_page_config(page_title="Сортувальник бінарних даних", layout="wide")
st.title("Інтелектуальний аналіз структури бінарних даних")
st.caption("Файл розглядається як дані: визначається формат, будується карта структури, "
           "для виконуваних файлів вмикається аналіз PE/ELF.")
up = st.file_uploader("Файл для аналізу (до 200 МБ)")

if up is not None:
    data = up.getvalue()
    suffix = pathlib.Path(up.name).suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as t:
        t.write(data)
        path = t.name
    try:
        with st.spinner("Аналіз..."):
            rep = analyze(path)
            starts, step, idx, conf, ent = window_map(data)
    finally:
        os.unlink(path)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Формат", rep["format"])
    c2.metric("Джерело рішення", rep["format_source"])
    c3.metric("Впевненість", f"{rep['confidence']:.2f}")
    c4.metric("Гілка", rep["branch"])
    if rep["flags"]:
        for f in rep["flags"]:
            st.warning(f)
    else:
        st.success("Розбіжностей не виявлено")

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

    classes = _fragment().classes
    st.subheader("Карта структури за вмістом")
    st.caption(f"Вікно {WIN} Б, крок {step} Б. Це експериментальна розмітка: "
               f"кожне вікно класифікує модель фрагментів.")
    st.pyplot(draw_strip(idx, classes))
    present = sorted(set(idx.tolist()))
    cols = colors_for(classes)
    st.markdown(" ".join(
        f"<span style='color:{cols[i]}'>■</span> {classes[i]}" for i in present),
        unsafe_allow_html=True)
    st.subheader("Профіль ентропії")
    st.line_chart(pd.DataFrame({"ентропія": ent}, index=starts))
    st.subheader("Області")
    st.dataframe(pd.DataFrame(regions(starts, idx, conf, classes, len(data))),
                 hide_index=True)
    st.download_button("Завантажити звіт JSON",
                       json.dumps(rep, ensure_ascii=False, indent=2, default=float),
                       file_name="report.json", mime="application/json")