import json
import yaml
from pathlib import Path
from api.index import app

print("=== Running End-to-End Asset Sync & API Test Suite ===")
client = app.test_client()

# 1. Test GET /api/status
res = client.get('/api/status')
assert res.status_code == 200, f"GET /api/status failed: {res.status_code}"
status_data = res.get_json()
print("[+] Test 1 Passed: GET /api/status returned status:", status_data.get("status"))

# 2. Test GET /api/assets
res = client.get('/api/assets')
assert res.status_code == 200, f"GET /api/assets failed: {res.status_code}"
initial_assets = res.get_json().get("assets", [])
print(f"[+] Test 2 Passed: GET /api/assets returned {len(initial_assets)} assets")

# 3. Test POST /api/assets (Add Test Target IP)
test_ip = "198.51.100.99"
res = client.post('/api/assets', json={
    "type": "ip",
    "value": test_ip,
    "domain": "test-sync.org"
})
assert res.status_code == 200, f"POST /api/assets failed: {res.status_code}"
add_data = res.get_json()
assert add_data.get("success") == True, f"Failed adding asset: {add_data}"
print(f"[+] Test 3 Passed: Successfully added test target asset '{test_ip}'")

# 4. Verify asset is present in GET /api/assets and config/assets.yaml
res = client.get('/api/assets')
current_assets = res.get_json().get("assets", [])
found = any(a.get("value") == test_ip for a in current_assets)
assert found, f"Test asset '{test_ip}' not found after addition!"
print(f"[+] Test 4 Passed: Verified '{test_ip}' present in API asset inventory")

# Check file system config/assets.yaml directly
assets_yaml = Path("config/assets.yaml")
if assets_yaml.exists():
    with assets_yaml.open("r", encoding="utf-8") as f:
        y_data = yaml.safe_load(f) or {}
        file_found = any(a.get("value") == test_ip for a in y_data.get("assets", []))
        assert file_found, f"Test asset '{test_ip}' not written to config/assets.yaml!"
        print(f"[+] Test 5 Passed: Verified '{test_ip}' synchronized directly into config/assets.yaml file")

# 5. Test DELETE /api/assets
res = client.delete('/api/assets', json={"value": test_ip})
assert res.status_code == 200, f"DELETE /api/assets failed: {res.status_code}"
del_data = res.get_json()
assert del_data.get("success") == True, f"Failed deleting asset: {del_data}"
print(f"[+] Test 6 Passed: Successfully deleted test target asset '{test_ip}'")

# 6. Verify asset is removed from inventory
res = client.get('/api/assets')
post_del_assets = res.get_json().get("assets", [])
still_found = any(a.get("value") == test_ip for a in post_del_assets)
assert not still_found, f"Test asset '{test_ip}' still present after deletion!"
print(f"[+] Test 7 Passed: Verified '{test_ip}' removed cleanly from asset inventory")

print("\nALL ASSET SYNC AND API TESTS PASSED 100% SUCCESSFULLY!")
