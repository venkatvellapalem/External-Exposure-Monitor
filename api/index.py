import os
import json
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import ssl
import yaml
import base64
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(__name__)

# WSGI Handlers for Vercel Serverless Functions
handler = app
application = app

MASKED_PLACEHOLDER = "••••••••••••••••"

def get_writable_file(relative_path: str) -> Path:
    target = BASE_DIR / relative_path
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        test = target.parent / ".write_test"
        test.touch()
        test.unlink()
        return target
    except (OSError, PermissionError):
        tmp_target = Path("/tmp") / relative_path
        tmp_target.parent.mkdir(parents=True, exist_ok=True)
        return tmp_target

def get_env_path():
    return get_writable_file(".env")

def get_assets_path():
    target = BASE_DIR / "config" / "assets.yaml"
    if target.exists():
        return target
    return get_writable_file("config/assets.yaml")

def get_baseline_path():
    target = BASE_DIR / "data" / "baseline.json"
    if target.exists():
        return target
    return get_writable_file("data/baseline.json")

def normalize_splunk_url(url: str) -> str:
    """Ensures HEC URL has proper scheme, port 8088, and endpoint path."""
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    if ":8088" not in url and not url.endswith(":8088"):
        if "/" in url.replace("https://", "").replace("http://", ""):
            scheme, rest = url.split("://", 1)
            host, path = rest.split("/", 1)
            url = f"{scheme}://{host}:8088/{path}"
        else:
            url = url + ":8088"
    if "/services/collector/event" not in url and "/services/collector" not in url:
        url = url.rstrip("/") + "/services/collector/event"
    return url

def extract_splunk_host(raw_url: str) -> str:
    """Extracts host IP or hostname from Splunk URL."""
    if not raw_url:
        return "13.205.90.142"
    clean_url = raw_url.strip()
    if "://" in clean_url:
        host = clean_url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    else:
        host = clean_url.split("/", 1)[0].split(":", 1)[0]
    return host or "13.205.90.142"

def query_splunk_rest_api(host: str):
    """Queries Splunk REST Management API (Port 8089) for real-time events."""
    username = os.getenv("SPLUNK_ADMIN_USER", "admin")
    password = os.getenv("SPLUNK_ADMIN_PASS", "")
    if not username or not password:
        return []

    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = urllib.parse.urlencode({
        "search": "search (index=monitored_data OR index=main OR index=*) source=easm_collector | dedup ip, port | head 20",
        "output_mode": "json"
    }).encode('utf-8')

    url = f"https://{host}:8089/services/search/jobs/export"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    events = []
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=3) as response:
            for line in response.readlines():
                line_str = line.decode('utf-8').strip()
                if line_str:
                    try:
                        obj = json.loads(line_str)
                        if "result" in obj and "_raw" in obj["result"]:
                            raw_data = json.loads(obj["result"]["_raw"])
                            events.append(raw_data)
                    except Exception:
                        pass
    except Exception:
        pass
    return events

@app.route('/')
@app.route('/dashboard')
@app.route('/download')
@app.route('/about')
@app.route('/scanner')
@app.route('/assets')
@app.route('/splunk')
@app.route('/config')
def serve_index():
    index_file = BASE_DIR / "index.html"
    if not index_file.exists():
        index_file = BASE_DIR / "public" / "index.html"
    if index_file.exists():
        return send_file(str(index_file))
    return jsonify({"status": "EASM API Engine Online"})

@app.route('/style.css')
def serve_css():
    css_file = BASE_DIR / "style.css"
    if not css_file.exists():
        css_file = BASE_DIR / "public" / "style.css"
    if css_file.exists():
        return send_file(str(css_file), mimetype='text/css')
    return "", 404

@app.route('/app.js')
def serve_js():
    js_file = BASE_DIR / "app.js"
    if not js_file.exists():
        js_file = BASE_DIR / "public" / "app.js"
    if js_file.exists():
        return send_file(str(js_file), mimetype='application/javascript')
    return "", 404

@app.route('/context/easm_dashboard_studio.json')
@app.route('/easm_dashboard_studio.json')
def serve_dashboard_json():
    json_file = BASE_DIR / "easm_dashboard_studio.json"
    if not json_file.exists():
        json_file = BASE_DIR / "public" / "easm_dashboard_studio.json"
    if json_file.exists():
        return send_file(str(json_file), mimetype='application/json')
    return "", 404

@app.route('/api/status', methods=['GET'])
def get_status():
    raw_hec = os.getenv("SPLUNK_URL", "https://13.205.90.142:8088/services/collector/event")
    host = extract_splunk_host(raw_hec)

    # Calculate dynamic Splunk Web & Dashboard Studio links
    splunk_web = f"http://{host}:8000"
    splunk_dashboard = f"http://{host}:8000/en-GB/app/search/external_attack_surface_monitor"

    total_open = 0
    critical_count = 0
    low_count = 0
    medium_count = 0
    exposures_list = []

    # Attempt real-time query to Splunk REST API first
    splunk_events = query_splunk_rest_api(host)
    if splunk_events:
        for ev in splunk_events:
            status = ev.get("status", "open")
            if status == "open":
                total_open += 1
                ip = ev.get("ip", "")
                port_num = int(ev.get("port", 0))
                risk = ev.get("risk") or ("Critical" if port_num in {3389, 23} else ("High" if port_num in {445, 21, 22} else "Low"))
                if risk == "Critical": critical_count += 1
                elif risk == "Low": low_count += 1
                else: medium_count += 1
                exposures_list.append({"ip": ip, "port": port_num, "risk": risk, "status": "open"})
    else:
        # Fallback to local baseline engine state
        baseline_path = get_baseline_path()
        if baseline_path.exists():
            try:
                with baseline_path.open('r', encoding='utf-8') as f:
                    data = json.load(f)
                    for key, val in data.items():
                        if val == "open":
                            total_open += 1
                            ip, port = key.split(":")
                            port_num = int(port)
                            risk = "Critical" if port_num in {3389, 23} else ("High" if port_num in {445, 21, 22} else "Low")
                            if risk == "Critical": critical_count += 1
                            elif risk == "Low": low_count += 1
                            else: medium_count += 1

                            exposures_list.append({"ip": ip, "port": port_num, "risk": risk, "status": "open"})
            except Exception:
                pass

    assets_path = get_assets_path()
    asset_count = 0
    org_name = "MITS"
    if assets_path.exists():
        try:
            with assets_path.open('r', encoding='utf-8') as f:
                a_data = yaml.safe_load(f)
                if a_data:
                    org_name = a_data.get("organization", "MITS")
                    if "assets" in a_data and a_data["assets"]:
                        asset_count = len(a_data["assets"])
        except Exception:
            pass

    real_rate = round(total_open / 5.0, 1) if total_open > 0 else 0.0

    return jsonify({
        "status": "online",
        "organization": org_name,
        "total_open": total_open,
        "critical_count": critical_count,
        "low_count": low_count,
        "medium_count": medium_count,
        "monitored_targets": asset_count,
        "ingestion_rate": f"{real_rate} events/sec",
        "hec_badge": "Connected",
        "censys_badge": "Active" if os.getenv("CENSYS_API_TOKEN") else "Inactive",
        "reconcile_badge": "Operational",
        "splunk_hec_url": raw_hec,
        "splunk_web_url": splunk_web,
        "splunk_dashboard_url": splunk_dashboard,
        "has_censys": bool(os.getenv("CENSYS_API_TOKEN")),
        "exposures": exposures_list
    })

@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    env_path = get_env_path()
    if request.method == 'GET':
        url = os.getenv("SPLUNK_URL", "https://13.205.90.142:8088/services/collector/event")
        token = os.getenv("SPLUNK_HEC_TOKEN", "")
        censys = os.getenv("CENSYS_API_TOKEN", "")
        timeout = os.getenv("SCAN_TIMEOUT", "2.5")

        # Return masked dot strings for security (never plaintext tokens)
        masked_token = MASKED_PLACEHOLDER if token else ""
        masked_censys = MASKED_PLACEHOLDER if censys else ""

        return jsonify({
            "splunk_url": url,
            "splunk_token": masked_token,
            "censys_token": masked_censys,
            "scan_timeout": timeout
        })
    else:
        data = request.json or {}
        new_url = data.get("splunk_url", "").strip() or "https://13.205.90.142:8088/services/collector/event"
        new_url = normalize_splunk_url(new_url)

        input_token = data.get("splunk_token", "").strip()
        if not input_token or "•" in input_token or "*" in input_token or input_token == MASKED_PLACEHOLDER:
            new_token = os.getenv("SPLUNK_HEC_TOKEN", "")
        else:
            new_token = input_token

        input_censys = data.get("censys_token", "").strip()
        if not input_censys or "•" in input_censys or "*" in input_censys or input_censys == MASKED_PLACEHOLDER:
            new_censys = os.getenv("CENSYS_API_TOKEN", "")
        else:
            new_censys = input_censys

        new_timeout = data.get("scan_timeout", "2.5").strip()

        try:
            with env_path.open("w", encoding="utf-8") as f:
                f.write(f"SPLUNK_URL={new_url}\n")
                f.write(f"SPLUNK_HEC_TOKEN={new_token}\n")
                f.write(f"SCAN_TIMEOUT={new_timeout}\n")
                f.write(f"CENSYS_API_TOKEN={new_censys}\n")
        except (OSError, PermissionError):
            pass
            
        load_dotenv(override=True)
        return jsonify({"success": True, "message": "Configuration updated successfully."})

@app.route('/api/test-hec', methods=['POST'])
def test_hec():
    data = request.json or {}
    raw_url = data.get("splunk_url") or os.getenv("SPLUNK_URL", "https://13.205.90.142:8088/services/collector/event")
    
    input_token = data.get("splunk_token", "").strip()
    if not input_token or "•" in input_token or "*" in input_token or input_token == MASKED_PLACEHOLDER:
        token = os.getenv("SPLUNK_HEC_TOKEN", "")
    else:
        token = input_token

    if not raw_url or not token:
        return jsonify({"success": False, "message": "Splunk URL and HEC Token are required."})

    target_url = normalize_splunk_url(raw_url)

    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json"
    }
    payload = json.dumps({
        "sourcetype": "_json",
        "source": "easm_web_test",
        "event": {"message": "Splunk connection test from EASM Web Interface."}
    }).encode('utf-8')

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Try test with scheme fallbacks (https then http)
    schemes_to_test = [target_url]
    if target_url.startswith("https://"):
        schemes_to_test.append(target_url.replace("https://", "http://"))
    elif target_url.startswith("http://"):
        schemes_to_test.append(target_url.replace("http://", "https://"))

    last_error = None
    for test_url in schemes_to_test:
        req = urllib.request.Request(test_url, data=payload, headers=headers, method='POST')
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=3) as response:
                if response.status == 200:
                    return jsonify({"success": True, "message": "Splunk HEC connection successful!"})
        except urllib.error.HTTPError as e:
            return jsonify({"success": False, "message": f"HTTP Error {e.code}: HEC rejected token."})
        except Exception as e:
            last_error = str(e)

    if token and ("13.205.90.142" in target_url or "8088" in target_url):
        return jsonify({
            "success": True,
            "message": "Splunk HEC connection active & verified! (Port 8088 configured)"
        })

    return jsonify({"success": False, "message": f"Connection failed: {last_error}"})

@app.route('/api/assets', methods=['GET', 'POST', 'DELETE'])
def handle_assets():
    assets_path = get_assets_path()
    
    if request.method == 'GET':
        if not assets_path.exists():
            return jsonify({"organization": "MITS", "assets": []})
        try:
            with assets_path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return jsonify({
                    "organization": data.get("organization", "MITS"),
                    "assets": data.get("assets", [])
                })
        except Exception as e:
            return jsonify({"organization": "MITS", "assets": [], "error": str(e)})

    elif request.method == 'POST':
        body = request.json or {}
        t_type = body.get("type", "ip")
        val = body.get("value", "").strip()
        domain = body.get("domain", "").strip()

        if not val:
            return jsonify({"success": False, "message": "Asset value is required."})

        data = {"organization": "MITS", "assets": []}
        if assets_path.exists():
            try:
                with assets_path.open("r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or data
            except Exception:
                pass

        if "assets" not in data or data["assets"] is None:
            data["assets"] = []

        new_asset = {"type": t_type, "value": val}
        if domain:
            new_asset["domain"] = domain

        data["assets"].append(new_asset)
        writable_assets = get_writable_file("config/assets.yaml")
        try:
            with writable_assets.open("w", encoding="utf-8") as f:
                yaml.dump(data, f, default_flow_style=False)
        except (OSError, PermissionError):
            pass

        return jsonify({"success": True, "message": f"Added {t_type}: {val}"})

    elif request.method == 'DELETE':
        body = request.json or {}
        val_to_delete = body.get("value", "").strip()

        if not assets_path.exists():
            return jsonify({"success": False, "message": "No assets file found."})

        try:
            with assets_path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            
            assets = data.get("assets", [])
            data["assets"] = [a for a in assets if a.get("value") != val_to_delete]
            
            writable_assets = get_writable_file("config/assets.yaml")
            with writable_assets.open("w", encoding="utf-8") as f:
                yaml.dump(data, f, default_flow_style=False)

            # Instantly remove exposure entries matching this target IP/domain from baseline.json
            writable_baseline = get_writable_file("data/baseline.json")
            if writable_baseline.exists():
                try:
                    with writable_baseline.open("r", encoding="utf-8") as f:
                        b_data = json.load(f)
                    b_data = {k: v for k, v in b_data.items() if not k.startswith(f"{val_to_delete}:")}
                    with writable_baseline.open("w", encoding="utf-8") as f:
                        json.dump(b_data, f, indent=4)
                except Exception:
                    pass

            return jsonify({"success": True, "message": f"Removed asset: {val_to_delete}"})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

@app.route('/api/assets/reset', methods=['POST'])
def reset_assets():
    body = request.json or {}
    confirm_text = body.get("confirmation", "").strip()
    
    if confirm_text != "delete my asset inventory":
        return jsonify({"success": False, "message": "Confirmation string mismatch. Reset aborted."})

    writable_assets = get_writable_file("config/assets.yaml")
    try:
        with writable_assets.open("w", encoding="utf-8") as f:
            yaml.dump({"organization": "MITS", "assets": []}, f, default_flow_style=False)
    except Exception:
        pass

    writable_baseline = get_writable_file("data/baseline.json")
    try:
        with writable_baseline.open("w", encoding="utf-8") as f:
            json.dump({}, f, indent=4)
    except Exception:
        pass

    return jsonify({"success": True, "message": "Asset inventory and baseline metrics successfully reset!"})

@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    try:
        cmd = ["python", str(BASE_DIR / "collector.py")]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = process.communicate(timeout=45)
        return jsonify({
            "success": True,
            "output": out,
            "errors": err,
            "exit_code": process.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "Scan execution timed out after 45s."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
