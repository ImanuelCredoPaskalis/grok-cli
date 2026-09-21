@echo off
title Grok CLI Mass Regist & Farming
cd /d "%~dp0"
echo ===================================================
echo   Menjalankan GROK CLI FARMING
echo ===================================================
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe mass_regist.py -i
) else (
    python mass_regist.py -i
)
pause
