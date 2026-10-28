#!/bin/bash
cd "$(dirname "$0")"
sudo systemctl start clamav-daemon
python3 -m venv .venv
source .venv/bin/activate
pip install -r Requirements.txt
python main.py