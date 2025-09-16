#!/bin/bash

TARGET_DIR="/app/android_decompiled"

# Service account keys
echo "[*] Extracting GCP keys from $TARGET_DIR ..." | tee -a /app/keys_extraction_logs.txt

if [[ $(grep -Pzr "(?s){[^{}]*?service_account[^{}]*?private_key.*?}" "$TARGET_DIR") ]]; then
    echo "[+] GCP service account keys found and extracted to /app/gcp_service_account_keys.txt" | tee -a /app/keys_extraction_logs.txt
    grep -Pzr "(?s){[^{}]*?service_account[^{}]*?private_key.*?}" "$TARGET_DIR" > /app/gcp_service_account_keys.txt || true
else
    echo "[-] No GCP service account keys found." | tee -a /app/keys_extraction_logs.txt
fi

echo "[*] Extracting other GCP-related secrets from $TARGET_DIR ..." | tee -a /app/keys_extraction_logs.txt
# Legacy GCP creds
if [[ $(grep -Pzr "(?s){[^{}]*?client_id[^{}]*?client_secret.*?}" "$TARGET_DIR") ]]; then
    echo "[+] GCP legacy credentials found and extracted to /app/gcp_legacy_creds.txt" | tee -a /app/keys_extraction_logs.txt
    grep -Pzr "(?s){[^{}]*?client_id[^{}]*?client_secret.*?}" "$TARGET_DIR" > /app/gcp_legacy_creds.txt || true
else
    echo "[-] No GCP legacy credentials found." | tee -a /app/keys_extraction_logs.txt
fi

echo "[*] Extracting GCP API keys from $TARGET_DIR ..." | tee -a /app/keys_extraction_logs.txt
# Google API keys
if [[ $(grep -Pr "AIza[a-zA-Z0-9\\-_]{35}" "$TARGET_DIR") ]]; then
    echo "[+] GCP API keys found and extracted to /app/gcp_api_keys.txt" | tee -a /app/keys_extraction_logs.txt
    grep -Pr "AIza[a-zA-Z0-9\\-_]{35}" "$TARGET_DIR" > /app/gcp_api_keys.txt || true
else
    echo "[-] No GCP API keys found." | tee -a /app/keys_extraction_logs.txt
fi

echo "[*] Extracting OAUTH tokens from $TARGET_DIR ..." | tee -a /app/keys_extraction_logs.txt
# Google OAuth tokens
if [[ $(grep -Pr "ya29\.[a-zA-Z0-9_-]{100,200}" "$TARGET_DIR") ]]; then
    echo "[+] OAuth tokens found and extracted to /app/gcp_oauth_tokens.txt" | tee -a /app/keys_extraction_logs.txt
    grep -Pr "ya29\.[a-zA-Z0-9_-]{100,200}" "$TARGET_DIR" > /app/gcp_oauth_tokens.txt || true
else
    echo "[-] No OAuth tokens found." | tee -a /app/keys_extraction_logs.txt
fi

echo "[*] Extracting SSH keys from $TARGET_DIR ..." | tee -a /app/keys_extraction_logs.txt
# Generic SSH keys
if [[ $(grep -Pzr "(?s)-----BEGIN[ A-Z]*?PRIVATE KEY[a-zA-Z0-9/\+=\n-]*?END[ A-Z]*?PRIVATE KEY-----" "$TARGET_DIR") ]]; then
    echo "[+] SSH keys found and extracted to /app/generic_ssh_keys.txt" | tee -a /app/keys_extraction_logs.txt
    grep -Pzr "(?s)-----BEGIN[ A-Z]*?PRIVATE KEY[a-zA-Z0-9/\+=\n-]*?END[ A-Z]*?PRIVATE KEY-----" "$TARGET_DIR" > /app/generic_ssh_keys.txt || true
else
    echo "[-] No SSH keys found." | tee -a /app/keys_extraction_logs.txt
fi

echo "[*] Extracting GCP signed URLs from $TARGET_DIR ..." | tee -a /app/keys_extraction_logs.txt
# Signed storage URLs
if [[ $(grep -Pir "storage.googleapis.com.*?Goog-Signature=[a-f0-9]+" "$TARGET_DIR") ]]; then
    echo "[+] GCP signed storage URLs found and extracted to /app/gcp_signed_storage_urls.txt" | tee -a /app/keys_extraction_logs.txt
    grep -Pir "storage.googleapis.com.*?Goog-Signature=[a-f0-9]+" "$TARGET_DIR" > /app/gcp_signed_storage_urls.txt || true
else
    echo "[-] No GCP signed storage URLs found." | tee -a /app/keys_extraction_logs.txt
fi

echo "[*] Extracting GCP signed policy documents from $TARGET_DIR ..." | tee -a /app/keys_extraction_logs.txt
# Signed policy documents in HTML
if [[ $(grep -Pzr '(?s)<form action.*?googleapis.com.*?name="signature" value=".*?">' "$TARGET_DIR") ]]; then
    echo "[+] GCP signed policy documents found and extracted to /app/gcp_signed_policy_docs.txt" | tee -a /app/keys_extraction_logs.txt
    grep -Pzr '(?s)<form action.*?googleapis.com.*?name="signature" value=".*?">' "$TARGET_DIR" > /app/gcp_signed_policy_docs.txt || true
else
    echo "[-] No GCP signed policy documents found." | tee -a /app/keys_extraction_logs.txt
fi

echo "[*] Extracting firebaseio links from $TARGET_DIR ..." | tee -a /app/keys_extraction_logs.txt
# firebaseio links
if [[ $(grep -Pr "https://[a-zA-Z0-9_.+-]+\.firebaseio\.com" "$TARGET_DIR") ]]; then
    echo "[+] Firebaseio links found and extracted to /app/firebaseio_links.txt" | tee -a /app/keys_extraction_logs.txt
    grep -Proh "https://[a-zA-Z0-9_.+-]+\.firebaseio\.com" "$TARGET_DIR" > /app/firebaseio_links.txt || true
else
    echo "[-] No firebaseio links found." | tee -a /app/keys_extraction_logs.txt
fi

