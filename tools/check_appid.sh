#!/bin/bash

TARGET_DIR="/app/android_decompiled"
LOG_FILE="/app/appid_check_logs.txt"

echo "[*] Starting Firebase AppID check..." | tee -a "$LOG_FILE"

# Extract unique GCP API keys
echo "[*] Extracting unique GCP API keys..." | tee -a "$LOG_FILE"
if [[ ! -f "/app/gcp_api_keys.txt" ]]; then
    echo "[-] GCP API keys file not found. Please run keys.sh first." | tee -a "$LOG_FILE"
    exit 0
fi

UNIQUE_KEYS=$(cat /app/gcp_api_keys.txt | grep -o "AIza[a-zA-Z0-9\-_]\{35\}" | sort | uniq)
if [[ -z "$UNIQUE_KEYS" ]]; then
    echo "[-] No valid GCP API keys found." | tee -a "$LOG_FILE"
    exit 0
fi

echo "[+] Found $(echo "$UNIQUE_KEYS" | wc -l) unique API keys" | tee -a "$LOG_FILE"

# Search for Firebase appID in decompiled APK
echo "[*] Searching for Firebase appID in decompiled APK..." | tee -a "$LOG_FILE"
FOUND_APP_IDS=$(grep -Proh "1:[0-9]+:(android|ios):[a-zA-Z0-9]+" "$TARGET_DIR" 2>/dev/null | sort | uniq)

if [[ -z "$FOUND_APP_IDS" ]]; then
    echo "[-] No Firebase appID found in decompiled APK." | tee -a "$LOG_FILE"
    exit 0
fi

# Generate both Android and iOS variants for each found app ID
echo "[*] Generating Android and iOS variants for found app IDs..." | tee -a "$LOG_FILE"
APP_IDS=""
shopt -s lastpipe
echo "$FOUND_APP_IDS" | while read -r found_id; do
    if [[ -z "$found_id" ]]; then
        continue
    fi
    
    # Extract the base pattern (project number and app identifier)
    # Pattern: 1:PROJECT_NUMBER:PLATFORM:APP_IDENTIFIER
    project_part=$(echo "$found_id" | sed 's/1:\([0-9]*\):\(android\|ios\):\([a-zA-Z0-9]*\)/1:\1/')
    app_identifier=$(echo "$found_id" | sed 's/1:\([0-9]*\):\(android\|ios\):\([a-zA-Z0-9]*\)/\3/')
    
    # Create both Android and iOS variants
    android_id="${project_part}:android:${app_identifier}"
    ios_id="${project_part}:ios:${app_identifier}"
    
    # Append to APP_IDS with proper line breaks
    APP_IDS+="${android_id}"$'\n'"${ios_id}"$'\n'
done

# Remove duplicates and empty lines
APP_IDS=$(echo -e "$APP_IDS" | sort | uniq | grep -v '^$')


if [[ -z "$APP_IDS" ]]; then
    echo "[-] No Firebase appID found in decompiled APK." | tee -a "$LOG_FILE"
    exit 0
fi

echo "[+] Found $(echo "$APP_IDS" | wc -l) unique appID(s):" | tee -a "$LOG_FILE"
echo "$APP_IDS" | while read -r app_id; do
    echo "    - $app_id" | tee -a "$LOG_FILE"
done

# Process each API key to get projectID from Firebase check files
echo "[*] Processing API keys and extracting projectIDs..." | tee -a "$LOG_FILE"

echo "$UNIQUE_KEYS" | while read -r api_key; do
    if [[ -z "$api_key" ]]; then
        continue
    fi
    
    echo "[*] Processing API key: $api_key" | tee -a "$LOG_FILE"
    
    # Check if Firebase check file exists for this API key
    firebase_check_file="/app/firebase_check_${api_key}.json"
    if [[ ! -f "$firebase_check_file" ]]; then
        echo "[-] Firebase check file not found for key $api_key: $firebase_check_file" | tee -a "$LOG_FILE"
        continue
    fi
    
    # Extract projectID from the JSON file
    project_id=$(jq -r '.projectId // empty' "$firebase_check_file" 2>/dev/null)
    if [[ -z "$project_id" || "$project_id" == "null" ]]; then
        echo "[-] No projectID found in Firebase check file for key $api_key" | tee -a "$LOG_FILE"
        continue
    fi
    
    echo "[+] Found projectID for $api_key: $project_id" | tee -a "$LOG_FILE"
    
    # Test each appID with this projectID and API key
    echo "$APP_IDS" | while read -r app_id; do
        if [[ -z "$app_id" ]]; then
            continue
        fi
        
        echo "[*] Testing Firebase Remote Config for appID: $app_id, projectID: $project_id, API key: $api_key" | tee -a "$LOG_FILE"
        for app_instance_id in "PROD" "DEV" "TEST"; do
            echo "[*] Using appInstanceId: $app_instance_id" | tee -a "$LOG_FILE"
            # Make the curl request
            response=$(curl -s -X POST "https://firebaseremoteconfig.googleapis.com/v1/projects/${project_id}/namespaces/firebase:fetch?key=${api_key}" \
                -H "Content-Type: application/json" \
                --data "{\"appId\": \"${app_id}\", \"appInstanceId\": \"${app_instance_id}\"}" \
                -w "%{http_code}")
            
            # Extract HTTP status code (last 3 characters)
            http_code="${response: -3}"
            response_body="${response%???}"
            
            # Log the result
            result_file="/app/firebase_remote_config_${api_key}_${project_id}_$(echo "$app_id" | tr ':' '_').json"

            if [[ "$http_code" == "200" ]]; then
                if [[ "$response_body" != *"NO_TEMPLATE"* ]]; then
                    echo -e "\e[31m[!] SUCCESS: Firebase Remote Config accessible!\e[0m" | tee -a "$LOG_FILE"
                    echo -e "\e[31m[!] AppID: $app_id\e[0m" | tee -a "$LOG_FILE"
                    echo -e "\e[31m[!] ProjectID: $project_id\e[0m" | tee -a "$LOG_FILE"
                    echo -e "\e[31m[!] API Key: $api_key\e[0m" | tee -a "$LOG_FILE"
                    echo -e "\e[31m[!] AppInstanceId: $app_instance_id\e[0m" | tee -a "$LOG_FILE"
                fi
                echo "[+] Response saved to: $result_file" | tee -a "$LOG_FILE"
                echo "AppID: $app_id, ProjectID: $project_id, API Key: $api_key, AppInstanceId: $app_instance_id" >> "$result_file"
                echo "$response_body" >> "$result_file"
            elif [[ "$http_code" == "400" ]]; then
                echo "[-] Bad request (400) - Invalid appID or parameters" | tee -a "$LOG_FILE"
            elif [[ "$http_code" == "401" ]]; then
                echo "[-] Unauthorized (401) - Invalid API key" | tee -a "$LOG_FILE"
            elif [[ "$http_code" == "403" ]]; then
                echo "[-] Forbidden (403) - API key lacks permissions" | tee -a "$LOG_FILE"
            elif [[ "$http_code" == "404" ]]; then
                echo "[-] Not found (404) - Invalid projectID or appID" | tee -a "$LOG_FILE"
            else
                echo "[-] HTTP $http_code - Unexpected response" | tee -a "$LOG_FILE"
            fi
            
            # Small delay to avoid rate limiting
            sleep 1
        done
    done
done

echo "[*] Firebase AppID check completed. Check $LOG_FILE for detailed results." | tee -a "$LOG_FILE"