#!/usr/bin/env bash
echo "====================================================================="
echo " IKIGAI — Phishpedia Model Weight Downloader (Linux/macOS)"
echo "====================================================================="
python3 scripts/download_phishpedia_weights.py
if [ $? -eq 0 ]; then
    echo ""
    echo "[✓] Setup completed successfully! Full AI inference active."
else
    echo ""
    echo "[!] Weight download incomplete. Run setup script again to retry."
fi
