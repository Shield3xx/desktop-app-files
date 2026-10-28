@echo off
cd /d "%~dp0"
python -m venv .venv
call .venv\Scripts\activate
pip install -r Requirements.txt
python main.py
pause