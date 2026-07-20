import os
import json
import subprocess
import urllib.request
import urllib.error
import ssl
import yaml
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder="../public", static_url_path="")

BASE_DIR = Path(__file__).resolve().parent.parent

# ponytail: simple serverless entrypoint for Vercel and local dev. Standard Flask API without ORM or unneeded middleware.

def get_env_path():
    return BASE_DIR / ".env"

def get_assets_path():
    return BASE_DIR / "config" / "assets.yaml"

def get_baseline_path():
    return BASE_DIR / "data" / "baseline.json"

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    if (Path(app.static_folder) / path).exists():
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    baseline_path = get_baseline_path()
    total_open = 0
    critical_count = 0
    if baseline_path.exists():
        try:
            with baseline_path.open('r', encoding='utf-8') as f:
                data = json.load(f)
                total_open = sum(1 for v in data.values() if v == "open")
        except Exception:
            pass

    assets_path = get_assets_path()
    asset_count = 0
    if assets_path.exists():
        try:
            with assets_path.open('r', encoding='utf-8') as f:
                a_data = yaml.safe_load(f)
                if a_data and "assets" in a_data:
                    asset_count = len(a_data["assets"])
        except Exception:
            pass

    return jsonify({
        "status": "online",
        "total_open": total_open,
        "monitored_targets": asset_count,
        "splunk_url": os.getenv("SPLUNK_URL", ""),
        "has_censys": bool(os.getenv("CENSYS_API_TOKEN"))
    })

@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    env_path = get_env_path()
    if request.method == 'GET':
        url = os.getenv("SPLUNK_URL", "")
        token = os.getenv("SPLUNK_HEC_TOKEN", "")
        censys = os.getenv("CENSYS_API_TOKEN", "")
        timeout = os.getenv("SCAN_TIMEOUT", "2.5")
        
        masked_hec = token[:6] + "..." + token[-4:] if len(token) > 10 else ("****" if token else "")
        masked_censys = censys[:6] + "..." + censys[-4:] if len(censys) > 10 else ("****" if censys else "")

        return jsonify({
            "splunk_url": url,
            "splunk_token_masked": masked_hec,
            "censys_token_masked": masked_censys,
            "scan_timeout": timeout
        })
    else:
        data = request.json or {}
        new_url = data.get("splunk_url", "").strip()
        new_token = data.get("splunk_token", "").strip()
        new_censys = data.get("censys_token", "").strip()
        new_timeout = data.get("scan_timeout", "2.5").strip()

        # Load existing if omitted
        if not new_token:
            new_token = os.getenv("SPLUNK_HEC_TOKEN", "")
        if not new_censys and "censys_token" not in data:
            new_censys = os.getenv("CENSYS_API_TOKEN", "")

        with env_path.open("w", encoding="utf-8") as f:
            f.write(f"SPLUNK_URL={new_url}\n")
            f.write(f"SPLUNK_HEC_TOKEN={new_token}\n")
            f.write(f"SCAN_TIMEOUT={new_timeout}\n")
            f.write(f"CENSYS_API_TOKEN={new_censys}\n")
            
        load_dotenv(override=True)
        return jsonify({"success": True, "message": "Configuration updated successfully."})

@app.route('/api/test-hec', methods=['POST'])
def test_hec():
    data = request.json or {}
    url = data.get("splunk_url") or os.getenv("SPLUNK_URL", "")
    token = data.get("splunk_token") or os.getenv("SPLUNK_HEC_TOKEN", "")

    if not url or not token:
        return jsonify({"success": False, "message": "Splunk URL and HEC Token are required."})

    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json"
    }
    payload = json.dumps({
        "sourcetype": "_json",
        "source": "easm_web_test",
        "event": {"message": "Splunk connection test from EASM Web Interface."}
    }).encode('utf-8')
    
    req = urllib.request.Request(url, data=payload, headers=headers, method='POST')
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
            if response.status == 200:
                return jsonify({"success": True, "message": "Splunk HEC connection successful!"})
    except urllib.error.HTTPError as e:
        return jsonify({"success": False, "message": f"HTTP Error {e.code}: HEC rejected token."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Connection failed: {str(e)}"})
        
    return jsonify({"success": False, "message": "Unknown connection error."})

@app.route('/api/assets', methods=['GET', 'POST', 'DELETE'])
def handle_assets():
    assets_path = get_assets_path()
    
    if request.method == 'GET':
        if not assets_path.exists():
            return jsonify({"organization": "Default", "assets": []})
        try:
            with assets_path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return jsonify({
                    "organization": data.get("organization", "Default"),
                    "assets": data.get("assets", [])
                })
        except Exception as e:
            return jsonify({"organization": "Default", "assets": [], "error": str(e)})

    elif request.method == 'POST':
        body = request.json or {}
        t_type = body.get("type", "ip")
        val = body.get("value", "").strip()
        domain = body.get("domain", "").strip()

        if not val:
            return jsonify({"success": False, "message": "Asset value is required."})

        data = {"organization": "Enterprise Network", "assets": []}
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
        assets_path.parent.mkdir(parents=True, exist_ok=True)
        with assets_path.open("w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False)

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
            
            with assets_path.open("w", encoding="utf-8") as f:
                yaml.dump(data, f, default_flow_style=False)

            return jsonify({"success": True, "message": f"Removed asset: {val_to_delete}"})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

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
