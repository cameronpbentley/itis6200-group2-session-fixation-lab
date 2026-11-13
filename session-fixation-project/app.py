"""
Session-Fixation-Resistant Authentication Architecture (ITIS 6200, Group 2)

One Flask app, three modes selected with the MODE environment variable:

  MODE=broken   Accepts client-supplied session IDs (URL param or cookie),
                keeps the same ID across login, no cookie flags, no binding.
  MODE=partial  URL IDs rejected, only server-issued IDs accepted, hardened
                cookie, User-Agent binding. Does NOT renew the ID at login.
  MODE=secure   Everything in partial, plus the session ID is renewed at login
                (and again after step-up re-verification).

Run:   MODE=secure python app.py
Env:   PORT (default 5000), COOKIE_SECURE (default 1; set 0 for plain HTTP),
       SESSION_COOKIE_NAME (default sid; also the URL parameter name that is planted),
       DEMO_UI (default 1; set 0 to disable the /demo walkthrough)
Open:  http://127.0.0.1:5000/demo for the built-in guided walkthrough.
"""
import hashlib
import os
import secrets
import threading
import time

from flask import Flask, make_response, redirect, render_template_string, request
from werkzeug.security import check_password_hash, generate_password_hash

MODES = ("broken", "partial", "secure")
DEFAULT_MODE = os.environ.get("MODE", "secure").lower()
if DEFAULT_MODE not in MODES:
    raise SystemExit("MODE must be broken, partial, or secure")

COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME", "sid")  # group-assigned cookie name
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"
IDLE_TIMEOUT = 15 * 60       # seconds of inactivity
ABSOLUTE_TIMEOUT = 8 * 3600  # hard lifetime of a session
MAX_REVERIFY_ATTEMPTS = 3    # bad reverify attempts before the session is destroyed

USERNAME = os.environ.get("DEMO_USER", "alice")
PASSWORD = os.environ.get("DEMO_PASS", "correct-horse-battery")
USERS = {USERNAME: generate_password_hash(PASSWORD)}

# One server-side session store per mode, so the /demo walkthrough can run all
# three modes side by side without them sharing state.
SESSIONS = {m: {} for m in MODES}
LOCK = threading.Lock()

URL_SID_PARAMS = {"sid", "sessionid", "session_id", "sessid", "jsessionid", "phpsessid", "token", COOKIE_NAME.lower()}

app = Flask(__name__)


def mode() -> str:
    """Active mode for this request. Real traffic uses MODE; the in-process
    /demo walkthrough overrides it through the WSGI environ (not reachable
    from the network)."""
    return request.environ.get("demo.mode", DEFAULT_MODE)


def store() -> dict:
    return SESSIONS[mode()]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def ua_hash() -> str:
    return hashlib.sha256(request.headers.get("User-Agent", "").encode()).hexdigest()


def new_sid() -> str:
    return secrets.token_urlsafe(32)  # 256 bits


def create_session(sid: str, user=None) -> dict:
    now = time.time()
    rec = {
        "user": user,
        "created": now,
        "last_seen": now,
        "ua_hash": ua_hash() if user else None,
        "stepped_down": False,
        "reverify_fails": 0,
    }
    with LOCK:
        store()[sid] = rec
    return rec


def destroy_session(sid) -> None:
    with LOCK:
        store().pop(sid, None)


def client_sid():
    if mode() == "broken":
        # VULNERABLE: trusts a URL parameter first, then the cookie.
        return request.args.get(COOKIE_NAME) or request.cookies.get(COOKIE_NAME)
    return request.cookies.get(COOKIE_NAME)


def load_session():
    """Return (sid, record) for a live session, else (sid_or_None, None)."""
    sid = client_sid()
    if not sid:
        return None, None
    with LOCK:
        rec = store().get(sid)
        if rec is None:
            return sid, None
        now = time.time()
        if now - rec["last_seen"] > IDLE_TIMEOUT or now - rec["created"] > ABSOLUTE_TIMEOUT:
            store().pop(sid, None)
            return sid, None
        rec["last_seen"] = now
    return sid, rec


def attach_cookie(resp, sid):
    if mode() == "broken":
        resp.set_cookie(COOKIE_NAME, sid)  # no flags at all
    else:
        resp.set_cookie(COOKIE_NAME, sid, httponly=True, secure=COOKIE_SECURE,
                        samesite="Lax", max_age=ABSOLUTE_TIMEOUT, path="/")
    return resp


# --------------------------------------------------------------------------
# Strict session acceptance (partial + secure)
# --------------------------------------------------------------------------
@app.before_request
def reject_url_session_ids():
    if mode() == "broken":
        return None
    bad_query = any(k.lower() in URL_SID_PARAMS for k in request.args)
    bad_path = ";" in request.path  # e.g. /login;jsessionid=abc
    if bad_query or bad_path:
        return "Session identifiers in the URL are not accepted.", 400
    return None


@app.after_request
def no_cache(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------
PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<style>
 :root{--bg:#f6f7f9;--card:#fff;--ink:#14171c;--muted:#5d6673;--line:#dde1e7;--accent:#2563eb;
       --bad:#c0392b;--good:#1e8e4e;--warn:#b7791f}
 @media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--ink:#e8eaee;--muted:#9aa3b2;--line:#2a2f3a}}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,Segoe UI,sans-serif}
 nav{display:flex;gap:1rem;align-items:center;padding:.8rem 1.2rem;border-bottom:1px solid var(--line);background:var(--card)}
 nav b{margin-right:auto} nav a{color:var(--accent);text-decoration:none;font-size:.95rem}
 .badge{font-size:.75rem;font-weight:700;letter-spacing:.04em;padding:.2rem .55rem;border-radius:99px;color:#fff}
 .badge.broken{background:var(--bad)} .badge.partial{background:var(--warn)} .badge.secure{background:var(--good)}
 main{max-width:460px;margin:2.5rem auto;padding:0 1rem}
 .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1.4rem;box-shadow:0 1px 3px rgba(0,0,0,.05)}
 h1{margin:0 0 1rem;font-size:1.5rem}
 label{font-size:.85rem;color:var(--muted)}
 input{display:block;width:100%;padding:.65rem .75rem;margin:.25rem 0 .9rem;border:1px solid var(--line);
       border-radius:8px;background:var(--bg);color:var(--ink);font:inherit}
 button{width:100%;padding:.7rem;border:0;border-radius:8px;background:var(--accent);color:#fff;font:inherit;font-weight:600;cursor:pointer}
 button.ghost{background:transparent;color:var(--ink);border:1px solid var(--line)}
 .err{color:var(--bad)} .hint{font-size:.85rem;color:var(--muted)}
 .inspector{margin-top:1.1rem;padding:.8rem;border:1px dashed var(--line);border-radius:10px;font-size:.85rem}
 .inspector code{background:var(--bg);padding:.1rem .4rem;border-radius:5px;word-break:break-all}
 .inspector div+div{margin-top:.35rem}
</style></head><body>
<nav><b>Session Fixation Lab</b>
 <a href="/login">Login</a>{% if demo %}<a href="/demo">Guided walkthrough</a>{% endif %}
 <span class="badge {{ mode }}">MODE={{ mode }}</span></nav>
<main><div class="card">
<h1>{{ title }}</h1>
{{ body|safe }}
{% if sid %}<div class="inspector">
 <div>Session ID: <code>{{ sid[:14] }}…</code></div>
 <div>Cookie flags: {{ flags }}</div>
 <div class="hint">Compare this value before and after you log in.</div></div>{% endif %}
</div></main></body></html>"""

LOGIN_FORM = """
{% if error %}<p class="err">{{ error }}</p>{% endif %}
<form method="post" action="/login{{ qs }}">
  <label>Username</label><input name="username" autocomplete="username" required>
  <label>Password</label><input name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Log in</button>
</form>
<p class="hint">Demo account: alice / correct-horse-battery</p>"""

REVERIFY_FORM = """
<p class="err">Your browser or device changed since you signed in. Confirm your password to continue.</p>
<form method="post" action="/reverify">
  <label>Password</label><input name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Verify</button>
</form>"""


def page(title, body_template, status=200, sid=None, **ctx):
    m = mode()
    body = render_template_string(body_template, **ctx)
    flags = "none (no HttpOnly, no SameSite, no Secure)" if m == "broken" else \
        "HttpOnly, SameSite=Lax" + (", Secure" if COOKIE_SECURE else "")
    html = render_template_string(PAGE, title=title, body=body, mode=m, sid=sid, flags=flags,
                                  demo=os.environ.get("DEMO_UI", "1") == "1")
    return html, status


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    return {"ok": True, "mode": mode()}


@app.get("/")
def index():
    return redirect("/login")


@app.get("/login")
def login_form():
    sid, rec = load_session()
    if rec is None:
        if mode() == "broken" and sid:
            pass  # adopt the attacker-supplied ID as-is
        else:
            sid = new_sid()
        create_session(sid)
    qs = request.query_string.decode()
    body, status = page("Sign in", LOGIN_FORM, sid=sid, qs=("?" + qs) if qs else "")
    return attach_cookie(make_response(body, status), sid)


@app.post("/login")
def login_submit():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    sid, rec = load_session()

    if rec is None:
        if mode() == "broken" and sid:
            pass
        else:
            sid = new_sid()
        rec = create_session(sid)

    hashed = USERS.get(username)
    if not hashed or not check_password_hash(hashed, password):
        body, _ = page("Sign in", LOGIN_FORM, sid=sid, error="Invalid credentials.", qs="")
        return attach_cookie(make_response(body, 401), sid)

    if mode() == "secure":
        # PRIMARY CONTROL: invalidate the pre-auth session, issue a new ID.
        destroy_session(sid)
        sid = new_sid()
        create_session(sid, user=username)
    else:
        with LOCK:
            rec["user"] = username
            rec["ua_hash"] = ua_hash()
            rec["stepped_down"] = False

    return attach_cookie(make_response(redirect("/dashboard")), sid)


@app.get("/dashboard")
def dashboard():
    sid, rec = load_session()
    if rec is None or not rec["user"]:
        body, _ = page("Unauthorized", "<p>You are not signed in. <a href='/login'>Sign in</a></p>")
        return make_response(body, 401)

    if mode() in ("partial", "secure"):
        with LOCK:
            if rec["ua_hash"] != ua_hash():
                rec["stepped_down"] = True
            stepped = rec["stepped_down"]
        if stepped:
            body, _ = page("Verification required", REVERIFY_FORM)
            return make_response(body, 401)

    body, _ = page("Dashboard",
                   "<p>Welcome, {{ user }}. This is the protected dashboard.</p>"
                   "<form method='post' action='/logout'><button class='ghost'>Log out</button></form>",
                   sid=sid, user=rec["user"])
    return make_response(body, 200)


@app.post("/reverify")
def reverify():
    """Stepped-Down Verification State: re-enter password to rebind the UA."""
    sid, rec = load_session()
    if mode() == "broken" or rec is None or not rec["user"]:
        return "Unauthorized", 401
    if not rec["stepped_down"]:
        return redirect("/dashboard")

    hashed = USERS.get(rec["user"])
    if not hashed or not check_password_hash(hashed, request.form.get("password", "")):
        with LOCK:
            rec["reverify_fails"] += 1
            too_many = rec["reverify_fails"] >= MAX_REVERIFY_ATTEMPTS
        if too_many:
            # stops someone with a stolen ID from guessing passwords forever
            destroy_session(sid)
            body, _ = page("Signed out", "<p>Too many failed attempts. <a href='/login'>Sign in again</a></p>")
            resp = make_response(body, 401)
            resp.delete_cookie(COOKIE_NAME, path="/")
            return resp
        body, _ = page("Verification required", REVERIFY_FORM)
        return make_response(body, 401)

    user = rec["user"]
    if mode() == "secure":
        destroy_session(sid)
        sid = new_sid()
        create_session(sid, user=user)  # binds the new UA hash
    else:
        with LOCK:
            rec["ua_hash"] = ua_hash()
            rec["stepped_down"] = False
            rec["reverify_fails"] = 0
    return attach_cookie(make_response(redirect("/dashboard")), sid)


@app.post("/logout")
def logout():
    sid, _ = load_session()
    if sid:
        destroy_session(sid)
    resp = make_response(redirect("/login"))
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


# Built-in guided walkthrough at /demo
if os.environ.get("DEMO_UI", "1") == "1":
    import walkthrough
    walkthrough.register(app, USERNAME, PASSWORD, MODES, COOKIE_NAME)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f" * MODE={DEFAULT_MODE}  COOKIE_SECURE={COOKIE_SECURE}  user={USERNAME}")
    print(f" * Guided walkthrough: http://127.0.0.1:{port}/demo")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
