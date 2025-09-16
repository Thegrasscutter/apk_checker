#!/bin/bash

for key in $(cat /app/gcp_api_keys.txt | grep -o "AIza[a-zA-Z0-9\-_]\{35\}" | sort | uniq); do
    echo "[*] Checking Firebase API key: $key" | tee -a /app/firebase_check_logs.txt
    curl -s "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key=$key" | jq . >> /app/firebase_check_$key.json
done

for key in $(cat /app/gcp_api_keys.txt | grep -o "AIza[a-zA-Z0-9\-_]\{35\}" | sort | uniq); do
    if [ -s /app/firebase_check_$key.json ]; then
        for authorizedDomain in $(cat /app/firebase_check_$key.json | jq -r '.authorizedDomains[]'); do
            if [[ "$authorizedDomain" != "localhost" && "$authorizedDomain" != *".firebaseapp.com" && "$authorizedDomain" != *".web.app" ]]; then
                echo -e "[*] Authorized domain found in Firebase config for key $key: $authorizedDomain \n This may be a valid domain. Check /app/firebase_check_$key.json for details." | tee -a /app/firebase_check_logs.txt
            elif [[ "$authorizedDomain" == "localhost" ]]; then
                echo -e "\e[31m[!] Localhost found in authorized domains for key $key. \n Potentional Vulnerability. Check /app/firebase_check_$key.json for details.\e[0m" | tee -a /app/firebase_check_logs.txt
            fi
        done
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