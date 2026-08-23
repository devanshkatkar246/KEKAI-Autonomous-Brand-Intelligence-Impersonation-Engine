@echo off
echo =====================================================================
echo  IKIGAI — Phishpedia Model Weight Downloader (Windows)
echo =====================================================================
python scripts\download_phishpedia_weights.py
if %ERRORLEVEL% EQU 0 (
    echo.
    echo [✓] Setup completed successfully! Full AI inference active.
) else (
    echo.
    echo [!] Weight download incomplete. Run setup script again to retry.
)
pause
