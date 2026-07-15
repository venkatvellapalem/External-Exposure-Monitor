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
    
    if env_path.exists():
        with env_path.open("r") as f:
            for line in f:
                if line.startswith("SPLUNK_URL="):
                    current_url = line.split("=", 1)[1].strip()
                elif line.startswith("SPLUNK_HEC_TOKEN="):
                    current_token = line.split("=", 1)[1].strip()

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

    # Test connection
    test_conn = input("Test HEC connection now? (y/n) -> ").strip().lower() or "y"
    if test_conn == "y":
        test_splunk_hec(url, token)

    # Write .env
    with env_path.open("w") as f:
        f.write(f"SPLUNK_URL={url}\n")
        f.write(f"SPLUNK_HEC_TOKEN={token}\n")
    print("[-] Splunk config saved.")

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
        
        # Explicit Public IP / CIDR question
        public_target = input("Public IP or CIDR to scan -> ").strip()
        while not public_target:
            print("[!] You must specify at least one target IP or CIDR to scan.")
            public_target = input("Public IP or CIDR to scan -> ").strip()
            
        new_assets = []
        # Simple type detection
        t_type = "cidr" if "/" in public_target else "ip"
        new_assets.append({"type": t_type, "value": public_target})
        print(f"[-] Added public target ({t_type}): {public_target}")

        # Ask for other targets
        print("\nEnter additional targets (IPs, CIDRs, or Domains). Press Enter on an empty line to finish:")
        while True:
            target = input("Additional Target -> ").strip()
            if not target:
                break
            
            if "/" in target:
                t_type = "cidr"
            elif any(c.isalpha() for c in target) and "." in target:
                t_type = "domain"
            else:
                t_type = "ip"
                
            new_assets.append({"type": t_type, "value": target})
            print(f"[-] Added ({t_type}): {target}")

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
