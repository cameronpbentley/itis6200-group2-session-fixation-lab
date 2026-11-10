"""
Guided browser walkthrough served at /demo.

The page asks the server to replay each attack in-process (Flask test client,
with the mode forced per run) and returns a step-by-step trace that the page
animates. Victim and attacker keep separate cookie stores, exactly like
demo.py, so no browser tricks are needed.
"""
from http.cookies import SimpleCookie

from flask import Response, jsonify, request

UA_VICTIM = "Mozilla/5.0 (VictimBrowser/1.0)"
UA_VICTIM_UPDATED = "Mozilla/5.0 (VictimBrowser/1.1)"
UA_ATTACKER = "AttackerTool/9.9"
MARKER = "protected dashboard"
SID = "sid"  # set from the app's SESSION_COOKIE_NAME in register()

SCENARIOS = {
    "url_param": {
        "label": "URL parameter planting",
        "blurb": "The attacker sends the victim a link that carries a session ID the attacker chose.",
    },
    "cookie_planting": {
        "label": "Cookie planting (cloned User-Agent)",
        "blurb": "The attacker gets a real pre-login ID, plants it in the victim's browser, and copies the victim's User-Agent.",
    },
    "stolen_id": {
        "label": "Stolen ID, different browser",
        "blurb": "The victim logs in normally. The attacker later replays the leaked ID from another browser.",
    },
    "ua_update": {
        "label": "Legitimate browser update",
        "blurb": "A real user's browser auto-updates mid-session. Does the app lock them out or let them recover?",
    },
}

DETAIL = {
    ("url_param", "broken"): "The server adopted the attacker's ID and kept it after login.",
    ("url_param", "partial"): "IDs in the URL are rejected, so the attacker's token is never planted.",
    ("url_param", "secure"): "IDs in the URL are rejected, so the attacker's token is never planted.",
    ("cookie_planting", "broken"): "No ID renewal and no binding: the planted ID became the logged-in session.",
    ("cookie_planting", "partial"): "Defense in depth was not enough. Cookie flags and User-Agent binding held, but the ID never changed at login, and the attacker cloned the User-Agent.",
    ("cookie_planting", "secure"): "The ID was renewed at login, so the planted pre-login token is dead.",
    ("stolen_id", "broken"): "Nothing ties the ID to the browser, so any holder of it gets in.",
    ("stolen_id", "partial"): "User-Agent binding caught the mismatch and demanded the password.",
    ("stolen_id", "secure"): "User-Agent binding caught the mismatch and demanded the password.",
}


def _short(sid):
    return None if not sid else (sid[:8] + "…" if len(sid) > 8 else sid)


class Actor:
    def __init__(self, app, steps, mode, name, ua, form_creds):
        self.client = app.test_client(use_cookies=False)
        self.steps, self.mode, self.name, self.ua = steps, mode, name, ua
        self.cookies, self.creds = {}, form_creds

    def note(self, title, note, kind="note"):
        step = {"actor": self.name, "kind": kind, "title": title, "note": note}
        self.steps.append(step)
        return step

    def req(self, method, path, title, form=None):
        headers = {"User-Agent": self.ua}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        sent = self.cookies.get(SID)
        r = self.client.open(path, method=method, headers=headers, data=form,
                             environ_overrides={"demo.mode": self.mode})
        set_sid, flags = None, []
        for h in r.headers.getlist("Set-Cookie"):
            c = SimpleCookie()
            c.load(h)
            if SID in c:
                m = c[SID]
                set_sid = m.value
                flags = [n for n, on in (("HttpOnly", m["httponly"]), ("Secure", m["secure"]),
                                         ("SameSite=" + m["samesite"], m["samesite"])) if on]
        if set_sid:
            self.cookies[SID] = set_sid
        body = r.get_data(as_text=True)
        if r.status_code == 200 and MARKER in body:
            outcome = "Dashboard shown"
        elif r.status_code == 401 and "confirm your password" in body.lower():
            outcome = "Password re-verification required"
        elif r.status_code == 401:
            outcome = "Unauthorized"
        elif r.status_code == 400:
            outcome = "Rejected: session ID in URL"
        elif r.status_code in (301, 302):
            outcome = "Redirect to " + r.headers.get("Location", "")
        else:
            outcome = "Page served"
        step = {"actor": self.name, "kind": "request", "title": title,
                "request": f"{method} {path}", "status": r.status_code, "outcome": outcome,
                "cookie_sent": _short(sent), "cookie_set": _short(set_sid),
                "changed": bool(set_sid and sent and set_sid != sent),
                "flags": flags, "note": "", "ua": self.ua}
        self.steps.append(step)
        return step

    def login_form(self):
        return {"username": self.creds[0], "password": self.creds[1]}


def run_scenario(app, creds, mode, scenario):
    steps = []
    V = lambda ua=UA_VICTIM: Actor(app, steps, mode, "victim", ua, creds)
    A = lambda ua=UA_ATTACKER: Actor(app, steps, mode, "attacker", ua, creds)
    verdict = {}

    if scenario == "url_param":
        att, vic = A(), V()
        token = "attacker-chosen-id"
        att.note("Attacker invents a session ID",
                 f"The attacker picks the value '{token}' and builds the link /login?{SID}={token}. "
                 "They have no account and do not know the password.", "plant")
        s = vic.req("GET", f"/login?{SID}={token}", "Victim clicks the attacker's link")
        s["note"] = ("The server adopts the attacker's ID as the victim's session." if s["status"] == 200
                     else "The server refuses session IDs that arrive in the URL. Nothing is planted.")
        s = vic.req("POST", f"/login?{SID}={token}", "Victim logs in with the real password", vic.login_form())
        s["note"] = ("Login succeeds and the server keeps the attacker's ID, now marked authenticated."
                     if s["status"] == 302 else "Rejected again. The victim is not logged in under the attacker's ID.")
        att.cookies[SID] = token
        s = att.req("GET", "/dashboard", "Attacker opens the dashboard with the ID they chose")

    elif scenario == "cookie_planting":
        att, vic = A(UA_VICTIM), V()
        s = att.req("GET", "/login", "Attacker requests the login page")
        s["note"] = ("The server issues a genuine pre-login session ID. The attacker also copies the victim's "
                     "User-Agent header to get past User-Agent binding.")
        vic.cookies[SID] = att.cookies[SID]
        vic.note("Attacker plants that ID in the victim's browser",
                 "In the real world: a cookie set from a sibling subdomain, or injected over plain HTTP. "
                 "The victim now carries the attacker's ID.", "plant")
        s = vic.req("POST", "/login", "Victim logs in with the planted cookie", vic.login_form())
        s["note"] = ("The ID is renewed. The planted token no longer maps to anything." if s["changed"]
                     else "The same ID is promoted to an authenticated session. It never changed.")
        s = att.req("GET", "/dashboard", "Attacker replays the planted ID with the cloned User-Agent")

    elif scenario == "stolen_id":
        vic, att = V(), A()
        vic.req("GET", "/login", "Victim opens the login page")
        vic.req("POST", "/login", "Victim logs in", vic.login_form())
        att.cookies[SID] = vic.cookies[SID]
        att.note("The session ID leaks",
                 "Shared computer, proxy log, or sniffed traffic. The attacker now holds the victim's current ID "
                 "and uses a different browser.", "plant")
        s = att.req("GET", "/dashboard", "Attacker replays the stolen ID from a different browser")
        s["note"] = ("The User-Agent no longer matches, so the session is stepped down and asks for the password."
                     if s["status"] == 401 else "Nothing ties the ID to a browser, so the attacker is in.")

    elif scenario == "ua_update":
        vic = V()
        vic.req("GET", "/login", "Victim opens the login page")
        vic.req("POST", "/login", "Victim logs in", vic.login_form())
        vic.ua = UA_VICTIM_UPDATED
        vic.note("The browser auto-updates", "The User-Agent string changes from 1.0 to 1.1 mid-session.", "plant")
        s = vic.req("GET", "/dashboard", "Victim reloads the dashboard")
        if s["status"] == 401:
            s["note"] = "Mismatch detected: the session steps down instead of locking the user out."
            s = vic.req("POST", "/reverify", "Victim re-enters their password", {"password": creds[1]})
            s["note"] = "Password confirmed. The User-Agent binding is updated" + \
                        (" and a fresh session ID is issued." if mode == "secure" else ".")
            vic.req("GET", "/dashboard", "Victim reloads the dashboard again")
        else:
            s["note"] = "No binding in this mode, so there is no step-up check at all."

    last = steps[-1]
    if scenario == "ua_update":
        ok = last["outcome"] == "Dashboard shown"
        if mode == "broken":
            verdict = {"tone": "neutral", "short": "No step-up",
                       "headline": "No binding, so nothing to recover from.",
                       "detail": "Any browser holding the ID is accepted, which is also why theft works."}
        else:
            verdict = {"tone": "good" if ok else "bad", "short": "Recovers" if ok else "Locked out",
                       "headline": "Legitimate user recovers after re-verifying." if ok else "User was locked out.",
                       "detail": "Graceful degradation: a mismatch asks for the password instead of killing the session."}
    else:
        hit = last["outcome"] == "Dashboard shown"
        verdict = {"tone": "bad" if hit else "good", "short": "HIJACKED" if hit else "Blocked",
                   "headline": ("Session hijacked: the attacker is logged in as alice without the password."
                                if hit else "Attack blocked: the attacker gets 401 Unauthorized."),
                   "detail": DETAIL[(scenario, mode)]}
    return {"mode": mode, "scenario": scenario, "steps": steps, "verdict": verdict}


def register(app, username, password, modes, cookie_name="sid"):
    global SID
    SID = cookie_name
    creds = (username, password)

    @app.get("/demo")
    def demo_page():
        return Response(HTML, mimetype="text/html")

    @app.get("/demo/api/meta")
    def demo_meta():
        return jsonify({"scenarios": SCENARIOS, "modes": list(modes)})

    @app.get("/demo/api/run")
    def demo_run():
        mode = request.args.get("mode", "")
        scenario = request.args.get("scenario", "")
        if mode not in modes or scenario not in SCENARIOS:
            return jsonify({"error": "bad mode or scenario"}), 400
        return jsonify(run_scenario(app, creds, mode, scenario))


HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Session Fixation Walkthrough</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#14171c;--muted:#5d6673;--line:#dde1e7;--accent:#2563eb;
 --bad:#c0392b;--badbg:#fdecea;--good:#1e8e4e;--goodbg:#e8f6ee;--warn:#b7791f;--neutralbg:#eef0f4;
 --atk:#c0392b;--vic:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--ink:#e8eaee;--muted:#9aa3b2;--line:#2a2f3a;
 --badbg:#3a1a17;--goodbg:#12301f;--neutralbg:#22262f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,"Segoe UI",sans-serif}
header{padding:1rem 1.4rem;background:var(--card);border-bottom:1px solid var(--line);display:flex;gap:1rem;align-items:center;flex-wrap:wrap}
header h1{font-size:1.2rem;margin:0;margin-right:auto}
header a{color:var(--accent);text-decoration:none;font-size:.95rem}
.wrap{max-width:1100px;margin:1.4rem auto;padding:0 1rem;display:grid;grid-template-columns:300px 1fr;gap:1.2rem}
@media (max-width:820px){.wrap{grid-template-columns:1fr}}
.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1rem 1.1rem}
.panel h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:0 0 .6rem}
.seg{display:flex;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.seg button{flex:1;padding:.55rem .3rem;border:0;background:transparent;color:var(--ink);font:inherit;font-weight:600;cursor:pointer}
.seg button.on[data-m=broken]{background:var(--bad);color:#fff}
.seg button.on[data-m=partial]{background:var(--warn);color:#fff}
.seg button.on[data-m=secure]{background:var(--good);color:#fff}
select{width:100%;padding:.55rem;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font:inherit}
.blurb{font-size:.9rem;color:var(--muted);margin:.5rem 0 0}
.stack>*+*{margin-top:1rem}
.ctrl{display:flex;gap:.5rem;flex-wrap:wrap}
.btn{padding:.55rem .9rem;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink);font:inherit;font-weight:600;cursor:pointer}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn:disabled{opacity:.45;cursor:default}
ul.feat{list-style:none;padding:0;margin:0;font-size:.9rem}
ul.feat li{display:flex;gap:.5rem;padding:.25rem 0}
.dot{width:.7rem;height:.7rem;border-radius:50%;margin-top:.4rem;flex:none}
.dot.on{background:var(--good)} .dot.off{background:var(--bad)}
.tl{display:flex;flex-direction:column;gap:.9rem}
.empty{color:var(--muted);text-align:center;padding:3rem 1rem}
.step{display:flex;animation:in .35s ease}
@keyframes in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.step.victim{justify-content:flex-end}
.step .card{width:min(100%,520px);border:1px solid var(--line);border-left-width:5px;border-radius:12px;background:var(--card);padding:.8rem 1rem}
.step.attacker .card{border-left-color:var(--atk)} .step.victim .card{border-left-color:var(--vic);border-left-width:1px;border-right-width:5px;border-right-color:var(--vic)}
.who{font-size:.72rem;font-weight:800;letter-spacing:.07em;text-transform:uppercase}
.attacker .who{color:var(--atk)} .victim .who{color:var(--vic)}
.title{font-weight:650;margin:.1rem 0 .3rem}
.req{font-family:ui-monospace,Consolas,monospace;font-size:.85rem;background:var(--bg);border-radius:6px;padding:.3rem .5rem;word-break:break-all}
.chips{display:flex;gap:.4rem;flex-wrap:wrap;margin:.5rem 0}
.chip{font-size:.75rem;padding:.15rem .5rem;border-radius:99px;background:var(--neutralbg);font-family:ui-monospace,Consolas,monospace}
.chip.s2{background:var(--goodbg);color:var(--good)} .chip.s3{background:var(--neutralbg)}
.chip.s4{background:var(--badbg);color:var(--bad)} .chip.changed{background:var(--goodbg);color:var(--good)}
.chip.same{background:var(--badbg);color:var(--bad)}
.note{font-size:.92rem;color:var(--muted);margin:.2rem 0 0}
.plant .card{border-style:dashed}
.verdict{border-radius:14px;padding:1rem 1.2rem;animation:in .4s ease}
.verdict.bad{background:var(--badbg);border:1px solid var(--bad)} .verdict.good{background:var(--goodbg);border:1px solid var(--good)}
.verdict.neutral{background:var(--neutralbg);border:1px solid var(--line)}
.verdict b{display:block;font-size:1.05rem;margin-bottom:.2rem}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{padding:.5rem;border-bottom:1px solid var(--line);text-align:center}
th:first-child,td:first-child{text-align:left}
td.bad{background:var(--badbg);color:var(--bad);font-weight:700} td.good{background:var(--goodbg);color:var(--good);font-weight:700}
td.neutral{background:var(--neutralbg)}
</style></head><body>
<header><h1>Session Fixation Walkthrough</h1><a href="/login">Open the real login</a></header>
<div class="wrap">
 <aside class="stack">
  <div class="panel"><h2>1. Server mode</h2>
   <div class="seg" id="modes"></div>
   <ul class="feat" id="feat" style="margin-top:.8rem"></ul></div>
  <div class="panel"><h2>2. Attack scenario</h2>
   <select id="scenario"></select><p class="blurb" id="blurb"></p></div>
  <div class="panel"><h2>3. Play</h2>
   <div class="ctrl">
    <button class="btn primary" id="next">Start</button>
    <button class="btn" id="auto">Auto-play</button>
    <button class="btn" id="reset">Reset</button></div></div>
 </aside>
 <section class="stack">
  <div class="panel"><h2>Timeline</h2><div class="tl" id="tl"><div class="empty">Pick a mode and scenario, then press Start.</div></div></div>
  <div class="panel"><h2>Compare every mode</h2>
   <p class="blurb" style="margin-top:0">Runs all scenarios against all three modes.</p>
   <div class="ctrl" style="margin:.6rem 0"><button class="btn" id="cmp">Run comparison</button></div>
   <div id="matrix"></div></div>
 </section>
</div>
<script>
const MODEINFO={
 broken:[["Accepts session IDs from the URL",1],["Renews the ID at login",0],["Cookie flags (HttpOnly, SameSite, Secure)",0],["User-Agent binding",0]],
 partial:[["Rejects session IDs in the URL",1],["Renews the ID at login",0],["Cookie flags (HttpOnly, SameSite, Secure)",1],["User-Agent binding",1]],
 secure:[["Rejects session IDs in the URL",1],["Renews the ID at login",1],["Cookie flags (HttpOnly, SameSite, Secure)",1],["User-Agent binding with step-up",1]]};
let meta,mode="broken",data=null,idx=0,timer=null;
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

function drawFeat(){
 $("feat").innerHTML=MODEINFO[mode].map(([t,on])=>`<li><span class="dot ${on?"on":"off"}"></span><span>${esc(t)}</span></li>`).join("");
 document.querySelectorAll("#modes button").forEach(b=>b.classList.toggle("on",b.dataset.m===mode));
}
function stopAuto(){clearInterval(timer);timer=null;$("auto").textContent="Auto-play"}
function reset(){
 stopAuto();data=null;idx=0;
 $("tl").innerHTML='<div class="empty">Pick a mode and scenario, then press Start.</div>';
 $("next").textContent="Start";$("next").disabled=false;
}
function stepHTML(s){
 let h=`<div class="step ${s.actor} ${s.kind!=="request"?"plant":""}"><div class="card"><div class="who">${s.actor}</div><div class="title">${esc(s.title)}</div>`;
 if(s.kind==="request"){
  const cls="s"+String(s.status)[0];
  h+=`<div class="req">${esc(s.request)}</div><div class="chips">
   <span class="chip ${cls}">HTTP ${s.status}</span><span class="chip">${esc(s.outcome)}</span>`;
  h+=`<span class="chip">cookie sent: ${s.cookie_sent?esc(s.cookie_sent):"none"}</span>`;
  if(s.cookie_set){h+=`<span class="chip">cookie set: ${esc(s.cookie_set)}</span>`;
   if(s.cookie_sent)h+=s.changed?`<span class="chip changed">ID changed</span>`:`<span class="chip same">same ID</span>`;
   if(s.flags.length)h+=`<span class="chip">${esc(s.flags.join(" · "))}</span>`;}
  h+=`</div>`;
 }
 if(s.note)h+=`<p class="note">${esc(s.note)}</p>`;
 return h+`</div></div>`;
}
function verdictHTML(v){return `<div class="verdict ${v.tone}"><b>${esc(v.headline)}</b>${esc(v.detail)}</div>`}
async function load(){
 const r=await fetch(`/demo/api/run?mode=${mode}&scenario=${$("scenario").value}`);
 data=await r.json();idx=0;$("tl").innerHTML="";
}
async function next(){
 if(!data)await load();
 if(idx<data.steps.length){
  $("tl").insertAdjacentHTML("beforeend",stepHTML(data.steps[idx++]));
  $("next").textContent="Next step";
 }
 if(idx>=data.steps.length&&!$("tl").querySelector(".verdict")){
  $("tl").insertAdjacentHTML("beforeend",verdictHTML(data.verdict));
  $("next").textContent="Done";$("next").disabled=true;stopAuto();
 }
 $("tl").lastElementChild.scrollIntoView({behavior:"smooth",block:"nearest"});
}
function auto(){
 if(timer){stopAuto();return}
 if($("next").disabled)reset();
 $("auto").textContent="Pause";next();timer=setInterval(next,1500);
}
async function compare(){
 $("matrix").innerHTML='<p class="blurb">Running…</p>';
 const sc=Object.keys(meta.scenarios);
 const res={};
 await Promise.all(sc.flatMap(s=>meta.modes.map(async m=>{
  const r=await fetch(`/demo/api/run?mode=${m}&scenario=${s}`);res[s+"|"+m]=(await r.json()).verdict;})));
 let h="<table><tr><th>Scenario</th>"+meta.modes.map(m=>`<th>${m}</th>`).join("")+"</tr>";
 for(const s of sc){h+=`<tr><td>${esc(meta.scenarios[s].label)}</td>`+
  meta.modes.map(m=>{const v=res[s+"|"+m];return `<td class="${v.tone}">${esc(v.short)}</td>`}).join("")+"</tr>";}
 $("matrix").innerHTML=h+"</table>";
}
(async()=>{
 meta=await (await fetch("/demo/api/meta")).json();
 $("modes").innerHTML=meta.modes.map(m=>`<button data-m="${m}">${m}</button>`).join("");
 $("scenario").innerHTML=Object.entries(meta.scenarios).map(([k,v])=>`<option value="${k}">${esc(v.label)}</option>`).join("");
 const blurb=()=>$("blurb").textContent=meta.scenarios[$("scenario").value].blurb;
 blurb();drawFeat();
 $("modes").onclick=e=>{if(e.target.dataset.m){mode=e.target.dataset.m;drawFeat();reset()}};
 $("scenario").onchange=()=>{blurb();reset()};
 $("next").onclick=()=>{stopAuto();next()};$("auto").onclick=auto;$("reset").onclick=reset;$("cmp").onclick=compare;
})();
</script></body></html>
"""
