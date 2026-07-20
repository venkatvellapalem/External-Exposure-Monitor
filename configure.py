import os
import json
import urllib.request
import urllib.error
import ssl
import yaml
from pathlib import Path

def normalize_splunk_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    
    # 1. Add scheme if missing (default to https since Splunk HEC defaults to SSL)
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
        
    # 2. Add default port 8088 if no port is specified in the host portion
    scheme, rest = url.split("//", 1)
    host_path = rest.split("/", 1)
    host_port = host_path[0]
    path = host_path[1] if len(host_path) > 1 else ""
    
    if ":" not in host_port:
        host_port = host_port + ":8088"
        
    url = f"{scheme}//{host_port}"
    if path:
        url = f"{url}/{path}"
        
    # 3. Add path "/services/collector/event" if collector is missing from path
    if "services/collector" not in url:
        if not url.endswith("/"):
            url += "/"
        url += "services/collector/event"
        
    return url

def test_splunk_hec_direct(url, token):
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
            if response.status == 200:
                print("[-] Success! Splunk HEC responded successfully.")
                return True
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error {e.code}: HEC rejected the request. Check your Token.")
    except urllib.error.URLError as e:
        print(f"[!] Network Error: Failed to reach Splunk HEC. Reason: {e.reason}")
    except Exception as e:
        print(f"[!] Connection error: {e}")
    return False

def test_splunk_hec(url, token):
    print(f"\n[+] Testing connection to Splunk HEC at: {url}")
    success = test_splunk_hec_direct(url, token)
    if success:
        return url, True
        
    if url.startswith("http://"):
        fallback_url = url.replace("http://", "https://", 1)
        print(f"[!] Connection failed using HTTP. Retrying with HTTPS: {fallback_url}...")
        if test_splunk_hec_direct(fallback_url, token):
            print("[+] HTTPS connection succeeded! Updating HEC URL to use HTTPS.")
            return fallback_url, True
            
    elif url.startswith("https://"):
        fallback_url = url.replace("https://", "http://", 1)
        print(f"[!] Connection failed using HTTPS. Retrying with HTTP: {fallback_url}...")
        if test_splunk_hec_direct(fallback_url, token):
            print("[+] HTTP connection succeeded! Updating HEC URL to use HTTP.")
            return fallback_url, True
            
    return url, False

def main():
    print("=" * 50)
    print(" EASM Collector Configuration Wizard ")
    print("=" * 50)

    # 1. Load existing config if available
    env_path = Path(".env")
    current_url = ""
    current_token = ""
    current_timeout = "2.5"
    current_censys_token = ""
    
    if env_path.exists():
        with env_path.open("r") as f:
            for line in f:
                if line.startswith("SPLUNK_URL="):
                    current_url = line.split("=", 1)[1].strip()
                elif line.startswith("SPLUNK_HEC_TOKEN="):
                    current_token = line.split("=", 1)[1].strip()
                elif line.startswith("SCAN_TIMEOUT="):
                    current_timeout = line.split("=", 1)[1].strip()
                elif line.startswith("CENSYS_API_TOKEN="):
                    current_censys_token = line.split("=", 1)[1].strip()

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

    url = normalize_splunk_url(url)

    if not url or not token:
        print("[!] Splunk URL and HEC Token are required to run the collector.")
        return

    # Prompt for Censys Passive Integration
    print("\n--- Censys Passive Integration (Optional) ---")
    use_existing_censys = "n"
    if current_censys_token:
        masked_secret = current_censys_token[:6] + "..." + current_censys_token[-6:] if len(current_censys_token) > 12 else "****"
        print(f"Existing Censys Config Found:")
        print(f"  Token: {masked_secret}")
        use_existing_censys = input("Use existing Censys token? (y/n) -> ").strip().lower() or "y"

    if use_existing_censys == "y":
        censys_token = current_censys_token
    else:
        censys_token = input("Censys Personal Access Token (Press Enter to skip) -> ").strip()

    # Prompt for SCAN_TIMEOUT
    print("\n--- Scanner Connection Settings ---")
    timeout_str = input(f"Connection Scan Timeout (seconds) [{current_timeout}] -> ").strip() or current_timeout
    try:
        float(timeout_str)
    except ValueError:
        timeout_str = "2.5"

    # Test connection
    test_conn = input("\nTest Splunk HEC connection now? (y/n) -> ").strip().lower() or "y"
    if test_conn == "y":
        url, success = test_splunk_hec(url, token)

    # Write .env
    with env_path.open("w") as f:
        f.write(f"SPLUNK_URL={url}\n")
        f.write(f"SPLUNK_HEC_TOKEN={token}\n")
        f.write(f"SCAN_TIMEOUT={timeout_str}\n")
        f.write(f"CENSYS_API_TOKEN={censys_token}\n")
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
                
            asset_entry = {"type": t_type, "value": value}
            if t_type == "ip":
                domain_val = input("Associated Domain Name (Press Enter if none) -> ").strip()
                if domain_val:
                    asset_entry["domain"] = domain_val

            new_assets.append(asset_entry)
            print(f"[-] Added {t_type}: {value}" + (f" (Domain: {asset_entry['domain']})" if asset_entry.get("domain") else ""))
            
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
