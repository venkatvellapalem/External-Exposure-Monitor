import os
import json
import urllib.request
import urllib.error
import ssl
import yaml
from pathlib import Path

def test_splunk_hec(url, token):
    print("\n[+] Testing connection to Splunk HEC...")
    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json"
    }
    payload = json.dumps({
        "sourcetype": "_json",
        "source": "easm_setup_wizard",
        "event": {"message": "Splunk connection test from EASM Setup Wizard."}
    }).encode('utf-8')
    
    req = urllib.request.Request(url, data=payload, headers=headers, method='POST')
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
            res = json.loads(response.read().decode('utf-8'))
            if response.status == 200:
                print("[-] Success! Splunk HEC responded successfully.")
                return True
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error {e.code}: HEC rejected the request. Check your Token.")
    except urllib.error.URLError as e:
        print(f"[!] Network Error: Failed to reach Splunk HEC. Check your URL/IP. Reason: {e.reason}")
    except Exception as e:
        print(f"[!] Unexpected error during test: {e}")
    return False

def main():
    print("=" * 50)
    print(" EASM Collector Configuration Wizard ")
    print("=" * 50)

    # 1. Load existing config if available
    env_path = Path(".env")
    current_url = ""
    current_token = ""
    current_timeout = "2.5"
    
    if env_path.exists():
        with env_path.open("r") as f:
            for line in f:
                if line.startswith("SPLUNK_URL="):
                    current_url = line.split("=", 1)[1].strip()
                elif line.startswith("SPLUNK_HEC_TOKEN="):
                    current_token = line.split("=", 1)[1].strip()
                elif line.startswith("SCAN_TIMEOUT="):
                    current_timeout = line.split("=", 1)[1].strip()

    # Clean Prompts for HEC configuration
    use_existing_hec = "n"
    if current_url and current_token:
        # Mask the token for clean display
        masked_token = current_token[:6] + "..." + current_token[-6:] if len(current_token) > 12 else "****"
        print("Existing Splunk HEC Config Found:")
        print(f"  URL: {current_url}")
        print(f"  Token: {masked_token}")
        use_existing_hec = input("Use existing HEC configuration? (y/n) -> ").strip().lower() or "y"

    if use_existing_hec == "y":
        url = current_url
        token = current_token
    else:
        url = input("Splunk HEC URL -> ").strip()
        token = input("Splunk HEC Token -> ").strip()

    if not url or not token:
        print("[!] Splunk URL and HEC Token are required to run the collector.")
        return

    # Prompt for SCAN_TIMEOUT
    timeout_str = input(f"Connection Scan Timeout (seconds) [{current_timeout}] -> ").strip() or current_timeout
    try:
        float(timeout_str)
    except ValueError:
        timeout_str = "2.5"

    # Test connection
    test_conn = input("Test HEC connection now? (y/n) -> ").strip().lower() or "y"
    if test_conn == "y":
        test_splunk_hec(url, token)

    # Write .env
    with env_path.open("w") as f:
        f.write(f"SPLUNK_URL={url}\n")
        f.write(f"SPLUNK_HEC_TOKEN={token}\n")
        f.write(f"SCAN_TIMEOUT={timeout_str}\n")
    print("[-] Config parameters saved to .env")

    # 2. Configure Assets
    assets_path = Path("config/assets.yaml")
    assets = []
    
    if assets_path.exists():
        try:
            with assets_path.open("r") as f:
                data = yaml.safe_load(f)
                if data and "assets" in data:
                    assets = data["assets"]
        except Exception:
            pass

    use_existing_assets = "n"
    if assets:
        print(f"\nExisting inventory contains {len(assets)} targets.")
        use_existing_assets = input("Use existing target inventory? (y/n) -> ").strip().lower() or "y"

    if use_existing_assets != "y":
        org = input("\nOrganization Name -> ").strip() or "Blue Corp"
        new_assets = []
        
        # Sequenced configuration loop
        print("\n--- Configure Asset Inventory ---")
        while True:
            print("\nSelect target type:")
            print("  1: Single IP (e.g. 8.8.8.8)")
            print("  2: CIDR Range (e.g. 192.168.1.0/24)")
            print("  3: Domain Name (e.g. google.com)")
            
            choice = input("Choice (1-3) -> ").strip()
            if choice not in {"1", "2", "3"}:
                print("[!] Invalid choice. Please enter 1, 2, or 3.")
                continue
                
            t_type = "ip" if choice == "1" else "cidr" if choice == "2" else "domain"
            value = input(f"Enter {t_type} target value -> ").strip()
            while not value:
                value = input(f"Enter {t_type} target value -> ").strip()
                
            new_assets.append({"type": t_type, "value": value})
            print(f"[-] Added {t_type}: {value}")
            
            another = input("Would you like to add another asset? (y/n) -> ").strip().lower()
            if another != "y":
                break

        config_data = {
            "organization": org,
            "assets": new_assets
        }
        assets_path.parent.mkdir(parents=True, exist_ok=True)
        with assets_path.open("w") as f:
            yaml.dump(config_data, f, default_flow_style=False)
        print(f"[-] Asset configuration saved to {assets_path}")

    print("\n[+] Configuration complete! Run the scanner with: python collector.py")
    print("=" * 50)

if __name__ == "__main__":
    main()
