import os, time, re
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGFILE = os.path.join(BASE_DIR, "../logs/app_secure.log")
ALERTS = os.path.join(BASE_DIR, "../artifacts/alerts.log")

os.makedirs(os.path.join(BASE_DIR, "../artifacts"), exist_ok=True)

pat = re.compile(r"(;|&&|\| |LOGIN_FAILED)")
print("Monitoring secure app log...")

with open(LOGFILE, "r") as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        if pat.search(line):
            msg = f"ALERT: {line}"
            print(msg.strip())
            with open(ALERTS, "a") as a:
                a.write(msg)
