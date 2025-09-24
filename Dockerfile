FROM ubuntu:latest
ARG APK
ENV APP_FILENAME=${APK:-Android.apk}
RUN apt-get update && apt-get install -y pipx git jq default-jdk apktool binutils curl python3 python3-pip python3-venv

#VOLUME /app:/app
COPY ./app/*.apk /app/
RUN pipx install git+https://github.com/ozguralp/gmapsapiscanner
RUN pipx ensurepath
WORKDIR /app
RUN apktool d ${APP_FILENAME} -o /app/android_decompiled
RUN mkdir /tools
WORKDIR /tools
RUN git clone https://github.com/Suryesh/Firebase_Checker.git
COPY ./tools /tools

# Use shell form to set APK env var at runtime
#RUN echo 'export APK=$(ls /app/*.apk | head -n 1)' >> /root/.bashrc
RUN chmod +x check_gmap.sh keys.sh check_firebase.sh check_appid.sh
RUN ./keys.sh
RUN ./check_gmap.sh
RUN ./check_appid.sh

# Set up Agneyastra environment before running Firebase checks
WORKDIR /tools/agneyastra_py
# Install agneyastra dependencies directly
RUN pip3 install -r requirements.txt --break-system-packages
# Also run the setup script for any additional configuration
#RUN ./setup.sh

# Now run Firebase check with proper environment setup
WORKDIR /tools
RUN echo "About to run check_firebase.sh..." && \
    ./check_firebase.sh && \
    echo "check_firebase.sh completed successfully" || \
    { echo "check_firebase.sh failed with exit code $?"; cat /app/firebase_check_logs.txt || echo "No log file found"; exit 1; }

WORKDIR /tools/Firebase_Checker
RUN python3 -m venv venv
RUN . venv/bin/activate && \
    pip install --upgrade pip && \
    pip install -r /tools/Firebase_Checker/requirements.txt
# Create a directory for output files
RUN mkdir -p /output

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app
#ENTRYPOINT ["/bin/bash"]
ENTRYPOINT ["/entrypoint.sh"]
#, "&&", "python3 /tools/Firebase_Checker/firebase-checker.py"]
#CMD ["-c", "echo 'Decompiled app is in /app/android_decompiled \n GMaps API results in /app/gmaps_api_results.txt \n Firebase check results in /app/firebase_check.json and /app/firebase_checker_report.txt \n RUN python3 /tools/Firebase_Checker/firebase-checker.py' && cat /app/*logs.txt && bash"]
