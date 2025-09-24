#!/bin/bash
#/tools/agneyastra_py/setup.sh | tee -a /app/firebase_check_logs.txt
mkdir -p ~/.config/agneyastra

for key in $(cat /app/gcp_api_keys.txt | grep -o "AIza[a-zA-Z0-9\-_]\{35\}" | sort | uniq); do
    echo "[*] Analyzing Firebase API key: $key with Agneyastra" | tee -a /app/firebase_check_logs.txt
    cd /tools/agneyastra_py || { echo "Directory /tools/agneyastra_py not found!"; exit 1; }
    python3 agneyastra.py --key $key --report_path /app/agneyastra_report_$key.html 2>&1 | tee -a /app/firebase_check_logs.txt
    exit_code=$?
    echo "[DEBUG] Agneyastra exit code: $exit_code" | tee -a /app/firebase_check_logs.txt
    if [ -s /app/agneyastra_report_$key.html ]; then
        if grep -q "vulnerable:true" /app/agneyastra_report_$key.html; then
            echo -e "\e[31m[!] Vulnerable Firebase API key found: $key \n Check /app/agneyastra_report_$key.html for details.\e[0m" | tee -a /app/firebase_check_logs.txt
        else
            echo "[+] No vulnerabilities found for Firebase API key: $key" | tee -a /app/firebase_check_logs.txt
        fi
    fi
done

for firebaseio_link in $(cat /app/firebaseio_links.txt | sort | uniq); do
    echo "[*] Checking firebaseio link: $firebaseio_link" | tee -a /app/firebaseio_check_logs.txt
    curl -s "$firebaseio_link/.json" | jq . >> /app/firebaseio_check_$(echo $firebaseio_link | sed 's/https\:\/\/\(.*\)\.firebaseio\.com/\1/').json
    if [ -s /app/firebaseio_check_$(echo $firebaseio_link | sed 's/https\:\/\/\(.*\)\.firebaseio\.com/\1/').json ]; then
        if grep -q "Permission denied" /app/firebaseio_check_$(echo $firebaseio_link | sed 's/https\:\/\/\(.*\)\.firebaseio\.com/\1/').json; then
            echo "[-] No public access for $firebaseio_link" | tee -a /app/firebaseio_check_logs.txt
        elif grep -q "deactivated" /app/firebaseio_check_$(echo $firebaseio_link | sed 's/https\:\/\/\(.*\)\.firebaseio\.com/\1/').json; then
            echo "[-] Firebase link $firebaseio_link is deactivated." | tee -a /app/firebaseio_check_logs.txt
        elif grep -q "not found" /app/firebaseio_check_$(echo $firebaseio_link | sed 's/https\:\/\/\(.*\)\.firebaseio\.com/\1/').json; then
            echo "[-] Firebase link $firebaseio_link not found." | tee -a /app/firebaseio_check_logs.txt
        else
            echo -e "\e[31m[!] Public access found for $firebaseio_link \n Check /app/firebaseio_check_$(echo $firebaseio_link | sed 's/https\:\/\/\(.*\)\.firebaseio\.com/\1/').json for details.\e[0m" | tee -a /app/firebaseio_check_logs.txt
        fi
    fi
done