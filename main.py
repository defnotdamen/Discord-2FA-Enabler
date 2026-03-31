print("\033[38;5;88m" + r"""
                    ▓█████▄  ▄▄▄       ███▄ ▄███▓▓█████  ███▄    █
                    ▒██▀ ██▌▒████▄    ▓██▒▀█▀ ██▒▓█   ▀  ██ ▀█   █
                    ░██   █▌▒██  ▀█▄  ▓██    ▓██░▒███   ▓██  ▀█ ██▒
                    ░▓█▄   ▌░██▄▄▄▄██ ▒██    ▒██ ▒▓█  ▄ ▓██▒  ▐▌██▒
                    ░▒████▓  ▓█   ▓██▒▒██▒   ░██▒░▒████▒▒██░   ▓██░
                     ▒▒▓  ▒  ▒▒   ▓▒█░░ ▒░   ░  ░░░ ▒░ ░░ ▒░   ▒ ▒ 
                     ░ ▒  ▒   ▒   ▒▒ ░░  ░      ░ ░ ░  ░░ ░░   ░ ▒░
                     ░ ░  ░   ░   ▒   ░      ░      ░      ░   ░ ░ 
                       ░          ░  ░       ░      ░  ░         ░ 
                     ░                                             
""")


import pyotp
import base64
import json
import time
import uuid
import sys
import os
import random
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from curl_cffi.requests import Session

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
LOCK = threading.Lock()

class C:
    DG = "\033[38;5;238m"
    WH = "\033[38;5;255m"
    RS = "\033[0m"

    COLORS = {
        "SUCCESS":  "\033[38;5;46m",
        "ENABLED":  "\033[38;5;46m",
        "SAVE":     "\033[38;5;46m",
        "ERROR":    "\033[38;5;196m",
        "FAIL":     "\033[38;5;196m",
        "WARN":     "\033[38;5;226m",
        "INFO":     "\033[38;5;51m",
        "ADDING":   "\033[38;5;51m",
        "REQUEST":  "\033[38;5;201m",
        "AUTH":     "\033[38;5;87m",
        "DEBUG":    "\033[38;5;245m",
        "TOTP":     "\033[38;5;154m",
        "TOKEN":    "\033[38;5;154m",
        "DONE":     "\033[38;5;46m",
    }

    @staticmethod
    def log(stamp, msg, **kwargs):
        ts = time.strftime("%H:%M:%S")
        clr = C.COLORS.get(stamp.upper(), C.WH)
        dg = C.DG
        wh = C.WH
        rst = C.RS

        parts = []
        for k, v in kwargs.items():
            parts.append(f"{wh}{k}: {dg}[{clr}{v}{dg}]{rst}")

        detail = f" {dg}|{rst} ".join(parts) if parts else ""
        line = f"{wh}{ts} {dg}»{rst} {clr}{stamp:<8}{rst}{dg}•{rst} {wh}{msg}{rst}"
        if detail:
            line += f" {dg}|{rst} {detail}"
        with LOCK:
            print(line)

def super_props():
    p = {"os":"Windows","browser":"Chrome","device":"","system_locale":"en-US","has_client_mods":False,"browser_user_agent":UA,"browser_version":"146.0.0.0","os_version":"10","referrer":"","referring_domain":"","referrer_current":"","referring_domain_current":"","release_channel":"stable","client_build_number":519006,"client_event_source":None,"client_launch_id":str(uuid.uuid4()),"launch_signature":str(uuid.uuid4()),"client_heartbeat_session_id":str(uuid.uuid4()),"client_app_state":"focused"}
    return base64.b64encode(json.dumps(p, separators=(",", ":")).encode()).decode()

def headers(token, mfa=None):
    h = {"Authorization":token,"Content-Type":"application/json","User-Agent":UA,"X-Super-Properties":super_props(),"X-Discord-Locale":"en-US","X-Discord-Timezone":"Asia/Calcutta","X-Debug-Options":"bugReporterEnabled","Referer":"https://discord.com/channels/@me","Origin":"https://discord.com"}
    if mfa:
        h["X-Discord-MFA-Authorization"] = mfa
    return h

def cj(obj):
    return json.dumps(obj, separators=(",", ":"))

def load_proxies():
    if not os.path.exists("proxies.txt"):
        return []
    with open("proxies.txt") as f:
        lines = [l.strip() for l in f if l.strip()]
    proxies = []
    for line in lines:
        if "://" not in line:
            line = "http://" + line
        proxies.append(line)
    return proxies

def get_proxy(proxies):
    if not proxies:
        return None
    return random.choice(proxies)

def enable_2fa(email, password, token, thread, proxies, out_dir):
    secret = pyotp.random_base32(32)
    code = pyotp.TOTP(secret).now()

    C.log("ADDING", "2FA", email=email, thread=thread)

    proxy = get_proxy(proxies)
    with Session(impersonate="chrome", proxy=proxy) as s:
        # Step 1
        r = s.post("https://discord.com/api/v9/users/@me/mfa/totp/enable", data=cj({"code":code,"secret":secret}), headers=headers(token))
        d = r.json()
        if r.status_code == 200:
            return save_success(d, email, password, secret, code, out_dir, thread)
        if r.status_code != 401 or "mfa" not in d:
            C.log("FAIL", "2FA", email=email, error=str(d.get("message","unknown"))[:50], thread=thread)
            return None

        ticket = d["mfa"]["ticket"]

        # Step 2
        r = s.post("https://discord.com/api/v9/mfa/finish", data=cj({"ticket":ticket,"mfa_type":"password","data":password}), headers=headers(token))
        md = r.json()
        if r.status_code != 200 or "token" not in md:
            C.log("FAIL", "2FA", email=email, error=str(md.get("message","unknown"))[:50], thread=thread)
            return None

        mfa_token = md["token"]

        # Step 3
        r = s.post("https://discord.com/api/v9/users/@me/mfa/totp/enable", data=cj({"code":code,"secret":secret}), headers=headers(token, mfa=mfa_token))
        res = r.json()
        st = r.status_code

        if st == 400 and res.get("code") == 60008:
            time.sleep(31)
            new_code = pyotp.TOTP(secret).now()
            r = s.post("https://discord.com/api/v9/users/@me/mfa/totp/enable", data=cj({"code":new_code,"secret":secret}), headers=headers(token, mfa=mfa_token))
            res = r.json()
            st = r.status_code

        if st != 200:
            C.log("FAIL", "2FA", email=email, error=str(res.get("message","unknown"))[:50], thread=thread)
            return None

        return save_success(res, email, password, secret, code, out_dir, thread)

def save_success(data, email, password, secret, code, out_dir, thread):
    new_token = data.get("token", "")
    backups = [b["code"] for b in data.get("backup_codes", [])]
    otp = pyotp.TOTP(secret).now()

    C.log("ENABLED", "2FA", email=email, token=new_token[:25] + "***", secret=secret[:10] + "***", thread=thread)

    with LOCK:
        with open(os.path.join(out_dir, "success.txt"), "a") as f:
            f.write(f"{email}:{password}:{new_token}\n")
        with open(os.path.join(out_dir, "secrets.txt"), "a") as f:
            f.write(f"{email}:{password}:{new_token}:{secret}\n")
        with open(os.path.join(out_dir, "backup_codes.txt"), "a") as f:
            f.write(f"{email}:{password}:{new_token}:{','.join(backups)}\n")

    return True

def save_fail(line, out_dir):
    with LOCK:
        with open(os.path.join(out_dir, "failed.txt"), "a") as f:
            f.write(line + "\n")

def parse_line(line):
    line = line.strip()
    if not line:
        return None
    first = line.find(":")
    last = line.rfind(":")
    if first == -1 or first == last:
        return None
    return line[:first], line[first+1:last], line[last+1:]

def worker(line, thread, proxies, out_dir):
    parsed = parse_line(line)
    if not parsed:
        save_fail(line, out_dir)
        return False
    email, password, token = parsed
    try:
        result = enable_2fa(email, password, token, thread, proxies, out_dir)
        if not result:
            save_fail(line, out_dir)
            return False
        return True
    except Exception as e:
        C.log("FAIL", "2FA", email=email, error=str(e)[:50], thread=thread)
        save_fail(line, out_dir)
        return False

def main():
    input_file = "tokens.txt"

    if not os.path.exists(input_file):
        C.log("ERROR", "file not found", file=input_file)
        sys.exit(1)

    with open(input_file) as f:
        lines = [l.strip() for l in f if l.strip()]

    proxies = load_proxies()

    threads = int(input(f"\033[38;5;51m[?] Threads: \033[0m"))
    print()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join("output", ts)
    os.makedirs(out_dir, exist_ok=True)

    success = 0
    fail = 0

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(worker, line, i+1, proxies, out_dir): line for i, line in enumerate(lines)}
        for future in as_completed(futures):
            if future.result():
                success += 1
            else:
                fail += 1

    print()
    C.log("DONE", "finished", success=str(success), failed=str(fail), output=out_dir)

if __name__ == "__main__":
    main()
