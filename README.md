# Session Fixation Lab

**ITIS 6200/8200 · Group 2 · Topic #10: Session-Fixation-Resistant Authentication Architecture**

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Flask](https://img.shields.io/badge/built%20with-Flask-black)
![Status](https://img.shields.io/badge/status-planning-orange)

**Group:** Cameron Bentley, Greyson Brummer, Brian Tramuel

---

## Current Status

*Last updated: Nov 9, 2026 · Target: Dec 1, 2026*

**Planning stage.** The sections below describe how the project is designed to work. The code is not fully written yet, so the setup and run steps will not work until the files are committed.

**Planned code**
- [ ] `app.py`: Flask app with `broken`, `partial`, and `secure` modes
- [ ] `demo.py`: automated attack verification
- [ ] `walkthrough.py`: browser walkthrough at `/demo`
- [ ] `requirements.txt`: Python dependencies

**Planned writing and presentation**
- [ ] Written report (docx and PDF)
- [ ] AI Appendix
- [ ] Slides and presentation
- [ ] Individual reflections

---

## About

A small Flask login app that will run in three modes, so the same session fixation attack can be replayed against each one.

**Our assigned seed (from registration order)**
- Session cookie name: `TBD`
- Planting method: `TBD` (URL parameter / subdomain cookie / both)

### What is the attack?

In session fixation, the attacker gets a victim to use a session ID the attacker already knows (for example, through a link carrying the ID, or a cookie set from a sibling subdomain). The victim then logs in. If the server keeps using that same ID after login, the attacker can reuse it and is now logged in as the victim, without ever learning the password.

### The three modes

| Mode | Behavior |
|---|---|
| `broken` | Accepts attacker-planted session IDs and keeps them after login |
| `partial` | Has cookie hardening and User-Agent binding, but does not renew the ID at login |
| `secure` | Renews the session ID at login, invalidating the pre-login ID |

---

## Expected Behavior

This is the target the code should meet. Each mode is attacked with the same steps: the attacker plants an ID, the victim logs in, and the attacker tries to use that ID.

| Mode | What should happen |
|---|---|
| `broken` | The attacker's planted ID is accepted before login and still works after the victim logs in. **Attack succeeds.** |
| `partial` | Cookie flags (`Secure`, `HttpOnly`, `SameSite`) and User-Agent binding make the attack harder, but the ID is not renewed at login. An attacker who matches the victim's User-Agent can still reuse the planted ID. **Attack still succeeds in the right conditions**, which shows why hardening alone is not enough. |
| `secure` | A new session ID is issued at login and the old one is invalidated. The attacker's planted ID no longer works. **Attack fails.** |

The automated check (`demo.py`) should confirm these three outcomes, and the `/demo` walkthrough should let a TA run the attack live before and after the fix.

---

## Mechanisms (planned)

- **Primary:** Session ID regeneration on every privilege change, specifically on successful login, which invalidates any pre-authentication session ID.
- **Supporting:** Cookie attribute hardening (`Secure`, `HttpOnly`, `SameSite`).
- **Supporting:** Session binding check (for example, binding the session to the User-Agent).

---

## Getting Started (once code is added)

> These steps apply after `app.py`, `demo.py`, `walkthrough.py`, and `requirements.txt` are committed. Until then they will not work.

### Requirements

- Python 3.9 or newer

### Setup

1. Clone this repo and open a terminal in the project folder.
2. Create and activate a virtual environment.

**Windows (PowerShell)**
```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process Bypass
.venv\Scripts\Activate.ps1
```

**Mac / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies (`requirements.txt` should be in the repo root).
```bash
pip install -r requirements.txt
```

### Run the automated check

```bash
python demo.py -v
```

It should end with `All results match expectations.`

### Start the app

`COOKIE_SECURE=0` is only for local testing over plain HTTP. Do not use it in a real deployment.

**Windows (PowerShell)**
```powershell
$env:MODE="secure"; $env:COOKIE_SECURE="0"; python app.py
```

**Mac / Linux**
```bash
MODE=secure COOKIE_SECURE=0 python app.py
```

Then open the guided walkthrough at **http://127.0.0.1:5000/demo**.

Demo login: `alice` / `correct-horse-battery`

Change `MODE` to `broken` or `partial` to compare.

---

## Planned Files

| File | Purpose |
|---|---|
| `app.py` | The Flask app and all three modes |
| `walkthrough.py` | The `/demo` browser walkthrough |
| `demo.py` | Automated attack verification |
| `requirements.txt` | Python dependencies |

---

## Team Checklist

Every member should:

- [ ] Read this README and tell the group if anything is unclear
- [ ] Pick a part of the written work: threat model, mechanism justification, failure case, or AI Appendix
- [ ] Add your name next to your part in the table below (more than one owner per task is fine)
- [ ] Once the code is committed, run the setup steps and report anything that breaks
- [ ] Read `app.py` until you can explain how each mode differs, especially the `secure` branch of `login_submit`

### Task Owners

| Task | Owner |
|---|---|
| Code and demo | |
| Written report | |
| Slides and presentation | |
| AI Appendix | |
| GitHub README (final version) | Cameron |

---

## Deliverables

- [ ] Written report (docx and PDF)
- [ ] Public GitHub repo with working `broken` and `secure` modes and a README the TAs can follow
- [ ] 10 minute presentation with live defense and 2 minutes of Q&A
- [ ] AI Appendix
- [ ] Individual reflection assignments (each person writes their own)

---

## Known Issues / Questions

- (Add anything that breaks or confuses you here. Please note it here instead of editing `app.py` directly, so we don't overwrite each other.)
