"""
demo.py: automated session-fixation verification for all three modes.

Starts app.py once per mode (ports 5101-5103, plain HTTP so COOKIE_SECURE=0),
runs the attack scenarios, and checks each result against the expected outcome.

Usage:
    python demo.py              # all modes
    python demo.py --mode partial
Exit code is 0 only if every result matches the expectation.
"""
import argparse
import os
import secrets
import subprocess
import sys
import time

import requests

USER, PASSWORD = "alice", "correct-horse-battery"
VICTIM_UA = "Mozilla/5.0 (VictimBrowser/1.0) Gecko/20260101"
VICTIM_UA_UPDATED = "Mozilla/5.0 (VictimBrowser/1.1) Gecko/20260301"
ATTACKER_UA = "AttackerTool/9.9"
PORTS = {"broken": 5101, "partial": 5102, "secure": 5103}
VERBOSE = False
SID = os.environ.get("SESSION_COOKIE_NAME", "sid")

# scenario -> {mode: should the ATTACK / RECOVERY succeed?}
EXPECTED = {
    "url_param_fixation":  {"broken": True,  "partial": False, "secure": False},
    "cookie_planting":     {"broken": True,  "partial": True,  "secure": False},
    "stolen_id_other_ua":  {"broken": True,  "partial": False, "secure": False},
    "legit_ua_update":     {"broken": None,  "partial": True,  "secure": True},
    "reverify_bruteforce": {"broken": None,  "partial": False, "secure": False},
}


class Client:
    """Minimal HTTP client with a manual cookie store (so we can 'plant' cookies)."""

    def __init__(self, base, ua, name="victim"):
        self.base, self.ua, self.name, self.cookies = base, ua, name, {}

    def req(self, method, path, **kw):
        headers = {"User-Agent": self.ua}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        r = requests.request(method, self.base + path, headers=headers,
                             allow_redirects=False, timeout=5, **kw)
        for k, v in r.cookies.items():
            self.cookies[k] = v
        if VERBOSE:
            who = f"{self.name:<8}"
            sid = self.cookies.get(SID, "-")
            print(f"      {who} {method:4} {path:<34} sid_after={sid[:10]:<10} -> {r.status_code}")
        return r

    def login(self, path="/login"):
        return self.req("POST", path, data={"username": USER, "password": PASSWORD})


def got_dashboard(r):
    return r.status_code == 200 and "protected dashboard" in r.text


# ---------------------------------------------------------------- scenarios
def url_param_fixation(base):
    """Attacker invents an ID and tricks the victim into logging in with it in the URL."""
    token = "attacker-chosen-" + secrets.token_hex(8)
    victim = Client(base, VICTIM_UA)
    victim.req("GET", f"/login?{SID}={token}")
    victim.login(f"/login?{SID}={token}")
    attacker = Client(base, ATTACKER_UA, "attacker")
    attacker.cookies[SID] = token
    r = attacker.req("GET", "/dashboard")
    return got_dashboard(r), f"attacker GET /dashboard -> {r.status_code}"


def cookie_planting(base):
    """Deterministic efficacy proof: pre-login token planted into the victim's cookie store."""
    attacker = Client(base, VICTIM_UA, "attacker")   # header duplication: cloned User-Agent
    attacker.req("GET", "/login")                    # 1. obtain a valid pre-login token
    token = attacker.cookies[SID]
    victim = Client(base, VICTIM_UA)
    victim.cookies[SID] = token                    # 2. plant it in the victim client
    victim.login()                                   # 3. victim authenticates with planted cookie
    r = attacker.req("GET", "/dashboard")            # 4. attacker replays token + cloned UA
    return got_dashboard(r), f"attacker GET /dashboard -> {r.status_code}"


def stolen_id_other_ua(base):
    """Victim logs in normally; attacker replays the (leaked) ID with a different User-Agent."""
    victim = Client(base, VICTIM_UA)
    victim.req("GET", "/login")
    victim.login()
    attacker = Client(base, ATTACKER_UA, "attacker")
    attacker.cookies[SID] = victim.cookies[SID]
    r = attacker.req("GET", "/dashboard")
    return got_dashboard(r), f"attacker GET /dashboard -> {r.status_code}"


def legit_ua_update(base):
    """Browser auto-update mid-session: step-down, re-enter password, back in."""
    victim = Client(base, VICTIM_UA)
    victim.req("GET", "/login")
    victim.login()
    victim.ua = VICTIM_UA_UPDATED
    first = victim.req("GET", "/dashboard")          # expect 401 (stepped-down)
    victim.req("POST", "/reverify", data={"password": PASSWORD})
    second = victim.req("GET", "/dashboard")         # expect 200
    ok = first.status_code == 401 and got_dashboard(second)
    return ok, f"after UA change -> {first.status_code}, after re-verify -> {second.status_code}"


def reverify_bruteforce(base):
    """Attacker with a stolen ID hits step-down and guesses passwords. Session should get killed."""
    victim = Client(base, VICTIM_UA)
    victim.req("GET", "/login")
    victim.login()
    attacker = Client(base, ATTACKER_UA, "attacker")
    attacker.cookies[SID] = victim.cookies[SID]
    attacker.req("GET", "/dashboard")  # different UA, trips step-down
    for _ in range(3):
        attacker.req("POST", "/reverify", data={"password": "wrong-guess"})
    r = victim.req("GET", "/dashboard")
    still_alive = "not signed in" not in r.text
    return still_alive, f"victim GET /dashboard after 3 bad guesses -> {r.status_code}"


SCENARIOS = {
    "url_param_fixation": url_param_fixation,
    "cookie_planting": cookie_planting,
    "stolen_id_other_ua": stolen_id_other_ua,
    "legit_ua_update": legit_ua_update,
    "reverify_bruteforce": reverify_bruteforce,
}


# ------------------------------------------------------------------ runner
def start_server(mode):
    env = dict(os.environ, MODE=mode, PORT=str(PORTS[mode]), COOKIE_SECURE="0")
    here = os.path.dirname(os.path.abspath(__file__))
    proc = subprocess.Popen([sys.executable, os.path.join(here, "app.py")], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{PORTS[mode]}"
    for _ in range(50):
        try:
            if requests.get(base + "/healthz", timeout=1).ok:
                return proc, base
        except requests.RequestException:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError(f"server for MODE={mode} did not start")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=list(PORTS), help="run a single mode")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every request")
    args = ap.parse_args()
    global VERBOSE
    VERBOSE = args.verbose
    modes = [args.mode] if args.mode else list(PORTS)

    failures = 0
    for mode in modes:
        print(f"\n=== MODE={mode} ===")
        proc, base = start_server(mode)
        try:
            for name, fn in SCENARIOS.items():
                expected = EXPECTED[name][mode]
                if expected is None:
                    print(f"  [SKIP] {name}: not applicable in this mode")
                    continue
                actual, detail = fn(base)
                label = "ATTACK SUCCEEDED" if name != "legit_ua_update" else "RECOVERED"
                if not actual:
                    label = "ATTACK BLOCKED" if name != "legit_ua_update" else "NOT RECOVERED"
                ok = actual == expected
                failures += 0 if ok else 1
                print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {label} ({detail})")
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    print("\n" + ("All results match expectations." if not failures
                  else f"{failures} result(s) did not match expectations."))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
