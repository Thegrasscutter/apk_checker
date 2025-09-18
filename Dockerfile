FROM ubuntu:latest
ARG APK
ENV APP_FILENAME=${APK:-Android.apk}
RUN apt-get update && apt-get install -y pipx git jq default-jdk apktool binutils curl

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
RUN ./check_firebase.sh
RUN ./check_appid.sh
WORKDIR /tools/Firebase_Checker
RUN python3 -m venv venv
RUN . venv/bin/activate && \
    pip install --upgrade pip && \
    pip install -r /tools/Firebase_Checker/requirements.txt
WORKDIR /app
    #echo "/app/${APP_FILENAME}" | firebase-checker.py | tee /app/firebase_checker_report.txt
#ENTRYPOINT ["/bin/bash"]
ENTRYPOINT ["/bin/bash", "-c", "source /tools/Firebase_Checker/venv/bin/activate && echo 'Decompiled app is in /app/android_decompiled \n GMaps API results in /app/gmaps_api_results.txt \n Firebase check results in /app/firebase_check.json and /app/firebase_checker_report.txt \n RUN python3 /tools/Firebase_Checker/firebase-checker.py to test for open firebase authentication vulnerabilities\n' && cat /app/*logs.txt && bash"]
#, "&&", "python3 /tools/Firebase_Checker/firebase-checker.py"]
#CMD ["-c", "echo 'Decompiled app is in /app/android_decompiled \n GMaps API results in /app/gmaps_api_results.txt \n Firebase check results in /app/firebase_check.json and /app/firebase_checker_report.txt \n RUN python3 /tools/Firebase_Checker/firebase-checker.py' && cat /app/*logs.txt && bash"]
