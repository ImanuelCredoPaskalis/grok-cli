@echo off
title Grok Local Captcha Solver (:8877)
cd /d "%~dp0"
echo ===================================================
echo   Menjalankan Local Free Captcha Solver (:8877)
echo   JANGAN TUTUP JENDELA INI SELAMA FARMING BERJALAN!
echo ===================================================
if exist local-solver\venv\Scripts\python.exe (
    local-solver\venv\Scripts\python.exe local-solver\universal_solver.py
) else (
    python local-solver\universal_solver.py
)
pause
