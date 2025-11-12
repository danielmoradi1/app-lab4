import os, time, re
LOGFILE = "../logs/app.log"
ALERTS = "../artifacts/alerts.log"

os.makedirs("artifacts", exist_ok=True)
pat = re.compile(r"(;|&&|\| |LOGIN_FAILED)")
print("Monitoring insecure app log...")
with open(LOGFILE, "a+") as f:
    f.seek(0,2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5); continue
        if pat.search(line):
            msg = f"ALERT: {line}"
            print(msg.strip())
            with open(ALERTS, "a") as a: a.write(msg)
