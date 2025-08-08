import os, sys, json, platform, re, webview

APP = "OTPWrapper"

def cfg_path():
    if platform.system() == "Windows":
        base = os.getenv("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, f"{APP}.json")
    return os.path.join(os.path.expanduser("~"), f".{APP.lower()}.json")

def load_cfg():
    p = cfg_path()
    if os.path.exists(p):
        try:
            with open(p, "r") as f:
                c = json.load(f)
                if isinstance(c, dict) and "host" in c and "port" in c:
                    return c
        except:
            pass
    return {}

def save_cfg(c):
    try:
        with open(cfg_path(), "w") as f:
            json.dump(c, f)
    except:
        pass

def valid_host(h):
    if not h or len(h) > 253:
        return False
    if re.match(r"^[A-Za-z0-9.-]+$", h) is None:
        return False
    if ".." in h or h.startswith(".") or h.endswith("."):
        return False
    return True

def valid_port(p):
    if not str(p).isdigit():
        return False
    n = int(p)
    return 1 <= n <= 65535

def build_url(c):
    scheme = "https" if str(c["port"]) == "443" else "http"
    return f"{scheme}://{c['host']}:{c['port']}/"

FORM_HTML_TEMPLATE = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OTP Server</title>
<style>
html,body{height:100%;margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#111;color:#f5f5f5}
.container{display:flex;align-items:center;justify-content:center;height:100%}
.card{width:380px;background:#1b1b1b;border-radius:16px;padding:24px;box-shadow:0 8px 24px rgba(0,0,0,.6)}
h1{font-size:20px;margin:0 0 16px 0;text-align:center}
label{display:block;font-size:13px;margin-top:10px;opacity:.85}
input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #333;background:#0f0f0f;color:#fff;font-size:14px;outline:none}
input:focus{border-color:#555}
.actions{margin-top:20px;text-align:center}
button{padding:10px 18px;border:0;border-radius:10px;background:#9146ff;color:#fff;font-weight:600;cursor:pointer;font-size:14px}
button:disabled{opacity:.5;cursor:not-allowed}
.err{margin-top:8px;color:#ff6b6b;font-size:12px;min-height:16px;text-align:center}
</style></head><body>
<div class="container"><div class="card">
<h1>OTP Server</h1>
<label>Host or IP</label>
<input id="host" value="{host}" placeholder="e.g. 192.168.0.14 or otp.local" autofocus>
<label>Port</label>
<input id="port" value="{port}" placeholder="7440">
<div class="actions"><button id="ok">OK</button></div>
<div class="err" id="err"></div>
</div></div>
<script>
const h=document.getElementById('host'), p=document.getElementById('port'), b=document.getElementById('ok'), e=document.getElementById('err');
function submit(){ e.textContent=''; b.disabled=true;
  window.pywebview.api.submit(h.value.trim(), p.value.trim()).then(r=>{
    if(!r.ok){ e.textContent=r.msg||'Invalid input'; b.disabled=false; }
  }).catch(()=>{ e.textContent='Failed'; b.disabled=false; });
}
b.addEventListener('click',submit);
document.addEventListener('keydown',ev=>{ if(ev.key==='Enter') submit(); });
</script>
</body></html>
"""

class Api:
    def __init__(self):
        self.win = None
    def set_window(self, w):
        self.win = w
    def submit(self, host, port):
        if not valid_host(host):
            return {"ok": False, "msg": "Invalid host"}
        if not valid_port(port):
            return {"ok": False, "msg": "Invalid port"}
        cfg = {"host": host, "port": int(port)}
        save_cfg(cfg)
        url = build_url(cfg)
        self.win.load_url(url)
        self.win.title = f"OTP Tool — {url}"
        self.win.resize(1100, 760)
        return {"ok": True}

def main():
    cfg = load_cfg()
    if cfg:
        url = build_url(cfg)
        win = webview.create_window(f"OTP Tool — {url}", url=url, width=1100, height=760, resizable=True)
        webview.start()
    else:
        api = Api()
        html = FORM_HTML_TEMPLATE.format(host=cfg.get("host", ""), port=cfg.get("port", "7440"))
        win = webview.create_window("OTP Server", html=html, width=420, height=280, resizable=True, js_api=api)
        api.set_window(win)
        webview.start()

if __name__ == "__main__":
    main()