#!/bin/bash

echo "[+] Installing Python requirements..."
pip install -r requirements.txt

echo "[+] Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

echo "[+] Done."
