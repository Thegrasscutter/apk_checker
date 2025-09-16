# APK Playbook

A Docker-based tool for analyzing Android APK files and extracting sensitive information such as API keys, Firebase configurations, and other security-related data.

## Setup

1. Place your APK file in the `/app` directory
2. Build the Docker image:
   ```bash
   docker build -t apk_playbook .
   ```
3. Run the container:
   ```bash
   docker run -it apk_playbook
   ```
4. If you want to try to gain access to the firebase app, when in the shell, run `python3 /tools/Firebase_Checker/firebase-checker.py`.
   It will prompt for the APK file location, use /app/Android.apk (or whatever you called it). The email address is whatever you want to authenticate with.

## What it does

This tool will automatically:
- Decompile the APK file
- Extract GCP API keys, Firebase configurations, and other sensitive data
- Check Firebase Remote Config accessibility
- Generate detailed logs and reports

## Output

All extracted data and logs will be available in the `/app` directory within the container.