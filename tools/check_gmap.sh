#!/bin/bash
pipx ensurepath
source ~/.bashrc
for api_key in $(cat /app/gcp_api_keys.txt | grep -o "AIza[a-zA-Z0-9\-_]\{35\}" | sort | uniq); do
    echo "[*] Scanning API key: $api_key" | tee -a /app/gmap_scan_results.txt
    echo "----------------------------------------" | tee -a /app/gmap_scan_results.txt
    yes | /root/.local/bin/gmapsapiscanner --api-key $api_key >> /app/gmap_scan_results.txt
done

if [ -s /app/gmap_scan_results.txt ]; then
    if grep -q "API key is  vulnerable" /app/gmap_scan_results.txt; then
        echo -e "\e[31m[!] Vulnerable Google Maps API keys found! Check /app/gmap_scan_results.txt for details.\e[0m" | tee -a /app/gmap_scan_logs.txt
    else
        echo "[*] No vulnerable Google Maps API keys found." | tee -a /app/gmap_scan_logs.txt
    fi
fi
