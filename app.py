import ipaddress, re, subprocess, shlex, os, socket, time
from flask import Flask, request, jsonify

app = Flask(__name__)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def is_domain(target: str) -> bool:
    return bool(DOMAIN_RE.match(target)) and not is_ip(target)

def icmp_ping(host: str, count: int = 3, timeout: int = 2):
    cmd = f"ping -n -c {count} -W {timeout} {shlex.quote(host)}"
    try:
        out = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=8
        )
        ok = out.returncode == 0 or "0% packet loss" in out.stdout
        avg = None
        for line in out.stdout.splitlines():
            if "min/avg/max" in line:
                avg = float(line.split("/")[4])
                break
        return ok, avg
    except subprocess.TimeoutExpired:
        return False, None

def tcp_check(host: str, port: int = 443, timeout: int = 2):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        return True, round((time.time() - t0) * 1000, 2)
    except Exception:
        return False, None
    finally:
        s.close()

@app.route("/ping")
def ping_handler():
    auth_header = request.headers.get("Authorization")
    if auth_header != os.getenv("AUTH_TOKEN"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    target = request.args.get("target", "").strip()
    count = int(request.args.get("count", 3))

    if not target or not (is_ip(target) or is_domain(target)):
        return jsonify({"ok": False, "error": "invalid target"}), 400

    ok, avg = icmp_ping(target, count)
    method = "icmp"

    if not ok:
        ok, avg = tcp_check(target, 443)
        method = "tcp:443"

    return jsonify({
        "ok": ok,
        "method": method,
        "avg_ms": avg,
        "target": target
    })
    
if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=5000)
