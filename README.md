# Session Fixation Lab

**ITIS 6200/8200 · Group 2 · Topic #10: Session-Fixation-Resistant Authentication Architecture**


![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Flask](https://img.shields.io/badge/built%20with-Flask-black)
![Status](https://img.shields.io/badge/status-work%20in%20progress-orange)

**Group:** Cameron Bentley, Greyson Brummer, Brian Tramuel

---

## About

A small Flask login app that runs in three modes, so the same session fixation attack can be replayed against each one.

| Mode | Behavior |
|---|---|
| `broken` | Accepts attacker-planted session IDs and keeps them after login |
| `partial` | Has cookie hardening and User-Agent binding, but does not renew the ID at login |
| `secure` | Renews the session ID at login |

---

## Getting Started

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

3. Install dependencies.
   ```bash
   pip install -r requirements.txt
   ```

### Run the automated check

```bash
python demo.py -v
```

It should end with `All results match expectations.`

### Start the app

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

## Team Checklist

Every member should:

- [ ] Run the steps above and tell the group if anything breaks
- [ ] Read `app.py` until you can explain how each mode differs, especially the `secure` branch of `login_submit`
- [ ] Pick a part of the written work: threat model, mechanism justification, failure case, or AI Appendix
- [ ] Add your name next to your part in the table below (can be more than one for each)

### Task Owners

| Task | Owner |
|---|---|
| Code and demo |  |
| Written report | |
| Slides and presentation | |
| AI Appendix | |
| GitHub README (final version) | |

---

## Deliverables

- [ ] Written report (docx and PDF)
- [ ] Public GitHub repo with working `broken` and `secure` modes and a README the TAs can follow
- [ ] 10 minute presentation with live defense and 2 minutes of Q&A
- [ ] AI Appendix
- [ ] Individual reflection assignments (each person writes their own)

---

## Project Files

| File | Purpose |
|---|---|
| `app.py` | The Flask app and all three modes |
| `walkthrough.py` | The `/demo` browser walkthrough |
| `demo.py` | Automated attack verification |
| `requirements.txt` | Python dependencies |
