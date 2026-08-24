@echo off
title Bitcoin Random Scanner - Puzzle #66 Mode
cd /d "%~dp0"
set PUZZLE_BITS=66
set TARGET_ADDRESSES=13zb1hQbWVsc2S7ZTGarKFbe9M8UbUm2Yea
echo =======================================================
echo   Starting Bitcoin Random Scanner (Puzzle #66 Mode)
echo   Target: 13zb1hQbWVsc2S7ZTGarKFbe9M8UbUm2Yea
echo   Web Dashboard: http://localhost:8080
echo =======================================================
btcrandom.exe
pause
