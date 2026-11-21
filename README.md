# Session-Fixation-Resistant Authentication Architecture

**ITIS 6200/8200 · Fall 2026 · Group 2 · Topic #10**

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Flask](https://img.shields.io/badge/built%20with-Flask-black)
![Status](https://img.shields.io/badge/status-in%20progress-orange)

**Group 2 Members:** Cameron Bentley, Greyson Brummer, Brian Tramuel

---

## 1. System Overview & Threat Model

This repository implements a Flask web application featuring a user login workflow and a protected dashboard (`/dashboard`) to evaluate **Session Fixation (CWE-384)** vulnerabilities and mitigations across three configurable security postures: `MODE=broken`, `MODE=partial`, and `MODE=secure`.

### Protected Asset & Threat Scope
- **Protected Asset:** The authenticated server-side session identifier (`SESSION_COOKIE_NAME`, default `sid`), which grants full account access without requiring password re-entry.
- **Threat Model (CWE-384):** An attacker forces a victim to adopt a predetermined session identifier prior to authentication via two primary vectors:
  1. **URL Parameter Planting:** Tricking the victim into authenticating via a crafted URL carrying an attacker-chosen token (e.g., `/login?sid=attacker-chosen-id`).
  2. **Cookie Planting:** Injecting a valid pre-login session cookie into the victim's client prior to authentication (simulating sibling-subdomain cookie leakage or network-level HTTP injection), optionally paired with **User-Agent header duplication**.
- **Out-of-Scope:** Offline password cracking, TLS cryptographic decryption, and Cross-Site Scripting (XSS).

### Evaluation Modes

| Mode | Active Controls | Behavior Under Session Fixation |
|---|---|---|
| `broken` | Accepts URL and cookie session IDs; retains pre-login ID across `POST /login`; sets cookies with zero flags; performs no User-Agent binding. | **Failure Case (Hijacked):** Both URL-parameter and cookie-planting attacks succeed (`HTTP 200` on `GET /dashboard`). |
| `partial` | Rejects URL session IDs (`HTTP 400`); enforces `HttpOnly`, `SameSite=Lax`, and `Secure` cookie attributes; binds sessions to a SHA-256 `User-Agent` hash with step-down recovery. **Omits session ID regeneration on login.** | **Deterministic Proof of Partial Failure:** URL fixation is blocked, but cookie planting paired with a cloned `User-Agent` header still succeeds (`HTTP 200` on `GET /dashboard`), proving defense-in-depth perimeter controls alone are insufficient without token rotation. |
| `secure` | Includes all `partial` controls **plus** cryptographic session ID regeneration (`secrets.token_urlsafe(32)`) on login and post-reverification, immediately invalidating pre-authentication tokens. | **Success Case (Protected):** All fixation and session-replay vectors are blocked (`HTTP 401 Unauthorized`). |

---

## 2. Implementation & OWASP Mapping

Our security architecture directly tracks the **OWASP Session Management Cheat Sheet**:

1. **Primary Mechanism — Session Identifier Regeneration (*OWASP: Renew Session ID After Login*):**
   - In `MODE=secure`, `login_submit()` in `app.py` calls `destroy_session(sid)` upon valid credential verification to purge the pre-authentication session from `SESSIONS["secure"]`.
   - It immediately generates a fresh 256-bit cryptographically random token via `secrets.token_urlsafe(32)` (`new_sid()`), binds the authenticated user exclusively to that new token, and issues it via `Set-Cookie`.
2. **Cookie Attribute Hardening (*OWASP: Cookies*):**
   - In `partial` and `secure` modes, `attach_cookie()` serves session identifiers with `HttpOnly=True` (blocking `document.cookie` access), `SameSite="Lax"` (mitigating cross-site request forgery), `Secure=True` (enforcing HTTPS transport; configurable via `COOKIE_SECURE=0` for local `127.0.0.1` testing), `Path=/`, an `8-hour` absolute lifetime (`ABSOLUTE_TIMEOUT`), and a `15-minute` inactivity timeout (`IDLE_TIMEOUT`), alongside `Cache-Control: no-store`.
3. **Strict Session Acceptance (*OWASP: Accept Only Server-Generated Session IDs*):**
   - The `@app.before_request` hook (`reject_url_session_ids()`) inspects every incoming request in `partial` and `secure` modes and rejects any query-string session parameters (`?sid=...`, `?sessionid=...`, `?token=...`, etc.) or path-parameter tokens (`;jsessionid=...`) with `HTTP 400`.
4. **Adaptive User-Agent Binding & Graceful Degradation:**
   - Authenticated sessions store `hashlib.sha256(User-Agent)`. If a legitimate browser or OS auto-update modifies the `User-Agent` string mid-session, `GET /dashboard` transitions the session into a **Stepped-Down Verification State** (`HTTP 401`) serving `/reverify` rather than locking out legitimate users.
   - Re-entering the valid password at `POST /reverify` updates the bound `User-Agent` hash (and rotates the session ID again in `MODE=secure`). To prevent password-guessing against a leaked cookie, `MAX_REVERIFY_ATTEMPTS = 3` destroys the session after three failed attempts.

---

## 3. Repository Structure

```text
itis6200-group2-session-fixation-lab/
├── README.md                        # System documentation, OWASP mapping, and setup guide
└── session-fixation-project/
    ├── app.py                       # Flask application implementing broken, partial, and secure modes
    ├── demo.py                      # Automated verification suite testing all modes and assertions
    ├── walkthrough.py               # Interactive browser timeline & mode comparison matrix at /demo
    ├── requirements.txt             # Python dependencies (Flask, requests)
    └── run_all.sh                   # Convenience script to execute the full automated test suite
```

---

## 4. Setup & Reproducibility Instructions

### Prerequisites
- Python 3.9 or newer

### Step 1: Clone & Install Dependencies

```bash
git clone [https://github.com/cameronpbentley/itis6200-group2-session-fixation-lab.git](https://github.com/cameronpbentley/itis6200-group2-session-fixation-lab.git)
cd itis6200-group2-session-fixation-lab/session-fixation-project
```

Create and activate a virtual environment, then install dependencies:

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process Bypass
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Step 2: Run the Automated Success & Failure Verification (`demo.py`)

`demo.py` automatically launches isolated instances of `app.py` for `MODE=broken` (port `5101`), `MODE=partial` (port `5102`), and `MODE=secure` (port `5103`) over local HTTP (`COOKIE_SECURE=0`), runs all five test scenarios (`url_param_fixation`, `cookie_planting`, `stolen_id_other_ua`, `legit_ua_update`, `reverify_bruteforce`), and asserts every HTTP status and dashboard response:

```bash
python demo.py -v
# Or execute via the provided shell script:
bash run_all.sh
```

Expected final output:
```text
All results match expectations.
```

To run an individual mode directly:
```bash
python demo.py --mode broken    # Failure case: URL & cookie fixation succeed (HTTP 200)
python demo.py --mode partial   # Partial failure proof: cookie planting + cloned UA succeeds (HTTP 200)
python demo.py --mode secure    # Success case: all fixation attacks blocked (HTTP 401)
```

### Step 3: Run the Interactive Browser Walkthrough (`/demo`)

To manually inspect the login flow, cookie flags, and interactive attack timeline in a web browser, start `app.py` with `COOKIE_SECURE=0` (required for `http://127.0.0.1` local testing):

**macOS / Linux:**
```bash
MODE=secure COOKIE_SECURE=0 python app.py
```

**Windows (PowerShell):**
```powershell
$env:MODE="secure"; $env:COOKIE_SECURE="0"; python app.py
```

- **Interactive Walkthrough & Comparison Matrix:** http://127.0.0.1:5000/demo
- **Direct Login Endpoint:** http://127.0.0.1:5000/login
- **Demo Account Credentials:** `alice` / `correct-horse-battery`
- **Optional Environment Variables:** `MODE` (`broken` | `partial` | `secure`), `SESSION_COOKIE_NAME` (default: `sid`), `COOKIE_SECURE` (default: `1`), `PORT` (default: `5000`).
