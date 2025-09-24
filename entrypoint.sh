#!/bin/bash

# Activate virtual environment
source /tools/Firebase_Checker/venv/bin/activate

# Display information
echo "=================================="
echo "APK Analysis Complete!"
echo "=================================="
echo "Decompiled app is in: /app/android_decompiled"
echo "GMaps API results in: /app/gmaps_api_results.txt"
echo "Firebase check results in: /app/firebase_check.json and /app/firebase_checker_report.txt"
echo "RUN: python3 /tools/Firebase_Checker/firebase-checker.py to test for open firebase authentication vulnerabilities"
echo "=================================="

# Show log contents
if ls /app/*logs.txt 1> /dev/null 2>&1; then
    echo "Log contents:"
    cat /app/*logs.txt
    echo "=================================="
fi

# Function to copy files to output directory (if mounted)
copy_output_files() {
    if [ -d "/output" ]; then
        echo "Copying analysis results to host machine..."
        
        # Create timestamped directory
        TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
        OUTPUT_DIR="/output/apk_analysis_${TIMESTAMP}"
        mkdir -p "$OUTPUT_DIR"
        
        # Copy files with error handling
        cp -r /app/android_decompiled "$OUTPUT_DIR/" 2>/dev/null && echo "✓ Decompiled APK copied"
        cp /app/gmaps_api_results.txt "$OUTPUT_DIR/" 2>/dev/null && echo "✓ GMaps API results copied"
        cp /app/firebase_check.json "$OUTPUT_DIR/" 2>/dev/null && echo "✓ Firebase check JSON copied"
        cp /app/firebase_checker_report.txt "$OUTPUT_DIR/" 2>/dev/null && echo "✓ Firebase checker report copied"
        cp /app/*logs.txt "$OUTPUT_DIR/" 2>/dev/null && echo "✓ Log files copied"
        cp /app/agneyastra_report_*.html "$OUTPUT_DIR/" 2>/dev/null && echo "✓ Agneyastra reports copied"
        
        # Create a summary file
        cat > "$OUTPUT_DIR/analysis_summary.txt" << EOF
APK Analysis Summary
====================
Timestamp: $(date)
APK File: $APP_FILENAME
Analysis Directory: $OUTPUT_DIR

Files Generated:
- android_decompiled/: Decompiled APK contents
- gmaps_api_results.txt: Google Maps API scan results
- firebase_check.json: Firebase configuration check
- firebase_checker_report.txt: Detailed Firebase security report
- *logs.txt: Analysis logs

Next Steps:
1. Review the decompiled code in android_decompiled/
2. Check firebase_check.json for misconfigurations
3. Run additional Firebase security tests if needed
EOF
        
        echo "✓ Analysis summary created"
        echo "=================================="
        echo "All files copied to: $OUTPUT_DIR"
        echo "View summary: cat $OUTPUT_DIR/analysis_summary.txt"
        echo "=================================="
    else
        echo "No /output directory mounted. To copy files to host, run with:"
        echo "docker run -v /path/on/host:/output your_image_name"
        echo "=================================="
    fi
}

# Copy output files
copy_output_files

# Start interactive bash session
exec bash