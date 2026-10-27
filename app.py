"""Точка входу вебзастосунку: навігація між сторінками."""
import pathlib
import sys

import streamlit as st

ROOT = pathlib.Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pages = [
    st.Page("views/single_file.py", title="Аналіз файла", default=True),
    st.Page("views/recovery.py", title="Відновлення структури"),
]

st.navigation(pages, position="top").run()
