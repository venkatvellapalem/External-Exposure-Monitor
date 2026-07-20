document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initCopyButtons();
    initPlatformTabs();
    loadStatus();
    loadConfig();
    loadAssets();

    document.getElementById('btn-run-scan')?.addEventListener('click', runScan);
    document.getElementById('form-add-asset')?.addEventListener('submit', addAsset);
    document.getElementById('form-config')?.addEventListener('submit', saveConfig);
    document.getElementById('btn-test-hec')?.addEventListener('click', testHec);
    document.getElementById('btn-clear-log')?.addEventListener('click', () => {
        document.getElementById('scan-log-output').textContent = '=== EASM Collector Console Output ===\nWaiting for scan trigger...';
    });
});

function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            const targetTab = link.getAttribute('data-tab');
            switchTab(targetTab);
        });
    });
}

function switchTab(tabId) {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.toggle('active', link.getAttribute('data-tab') === tabId);
    });
    document.querySelectorAll('.tab-content').forEach(section => {
        section.classList.toggle('active', section.id === tabId);
    });
}

function initPlatformTabs() {
    const commands = {
        win: "irm https://raw.githubusercontent.com/venkatvellapalem/External-Exposure-Monitor/main/install.ps1 | iex",
        mac: "curl -sSL https://raw.githubusercontent.com/venkatvellapalem/External-Exposure-Monitor/main/install.sh | bash",
        nix: "curl -sSL https://raw.githubusercontent.com/venkatvellapalem/External-Exposure-Monitor/main/install.sh | bash"
    };
    const footnotes = {
        win: "Copy and run this command in PowerShell",
        mac: "Copy and run this command in Terminal",
        nix: "Copy and run this command in Linux Shell"
    };

    document.querySelectorAll('.platform-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.platform-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            const platform = tab.getAttribute('data-platform');
            document.getElementById('install-command').textContent = commands[platform];
            document.getElementById('install-footnote').textContent = footnotes[platform];
        });
    });
}

function initCopyButtons() {
    document.getElementById('btn-copy-install')?.addEventListener('click', () => {
        const text = document.getElementById('install-command').textContent;
        navigator.clipboard.writeText(text).then(() => {
            showToast("Installation command copied to clipboard!");
        });
    });
}

function showToast(msg) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

async function loadStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        document.getElementById('stat-total-open').textContent = data.total_open || 0;
        document.getElementById('stat-monitored-targets').textContent = data.monitored_targets || 0;
        document.getElementById('stat-engine-status').textContent = `Collector Status: ${data.status.toUpperCase()}`;
        if (data.splunk_url) {
            document.getElementById('link-open-splunk').href = data.splunk_url.split('/services/collector')[0];
        }
    } catch (e) {
        console.error("Failed to load status:", e);
    }
}

async function loadConfig() {
    try {
        const res = await fetch('/api/config');
        const data = await res.json();
        if (data.splunk_url) document.getElementById('cfg-splunk-url').value = data.splunk_url;
        if (data.scan_timeout) document.getElementById('cfg-scan-timeout').value = data.scan_timeout;
    } catch (e) {
        console.error("Failed to load config:", e);
    }
}

async function saveConfig(e) {
    e.preventDefault();
    const url = document.getElementById('cfg-splunk-url').value;
    const token = document.getElementById('cfg-splunk-token').value;
    const censys = document.getElementById('cfg-censys-token').value;
    const timeout = document.getElementById('cfg-scan-timeout').value;

    try {
        const res = await fetch('/api/config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                splunk_url: url,
                splunk_token: token,
                censys_token: censys,
                scan_timeout: timeout
            })
        });
        const data = await res.json();
        if (data.success) {
            showToast("System settings saved to .env");
            loadStatus();
        } else {
            showToast("Failed to save config: " + data.message);
        }
    } catch (err) {
        showToast("Error saving config.");
    }
}

async function testHec() {
    const url = document.getElementById('cfg-splunk-url').value;
    const token = document.getElementById('cfg-splunk-token').value;

    showToast("Testing connection to Splunk HEC...");
    try {
        const res = await fetch('/api/test-hec', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ splunk_url: url, splunk_token: token })
        });
        const data = await res.json();
        showToast(data.message);
    } catch (err) {
        showToast("Connection test failed.");
    }
}

async function loadAssets() {
    try {
        const res = await fetch('/api/assets');
        const data = await res.json();
        const tbody = document.getElementById('assets-table-body');
        tbody.innerHTML = '';

        if (!data.assets || data.assets.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-muted">No assets registered yet.</td></tr>';
            return;
        }

        data.assets.forEach(asset => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><span class="brand-badge">${asset.type.toUpperCase()}</span></td>
                <td><strong>${asset.value}</strong></td>
                <td>${asset.domain || 'N/A'}</td>
                <td><button class="btn-delete-asset" onclick="deleteAsset('${asset.value}')">Delete</button></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Failed to load assets:", e);
    }
}

async function addAsset(e) {
    e.preventDefault();
    const type = document.getElementById('asset-type').value;
    const val = document.getElementById('asset-value').value;
    const domain = document.getElementById('asset-domain').value;

    try {
        const res = await fetch('/api/assets', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ type: type, value: val, domain: domain })
        });
        const data = await res.json();
        if (data.success) {
            showToast(data.message);
            document.getElementById('asset-value').value = '';
            document.getElementById('asset-domain').value = '';
            loadAssets();
            loadStatus();
        } else {
            showToast("Failed: " + data.message);
        }
    } catch (e) {
        showToast("Error adding asset.");
    }
}

async function deleteAsset(val) {
    if (!confirm(`Remove ${val} from target inventory?`)) return;

    try {
        const res = await fetch('/api/assets', {
            method: 'DELETE',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ value: val })
        });
        const data = await res.json();
        if (data.success) {
            showToast(data.message);
            loadAssets();
            loadStatus();
        } else {
            showToast("Failed to remove: " + data.message);
        }
    } catch (e) {
        showToast("Error removing asset.");
    }
}

async function runScan() {
    const btn = document.getElementById('btn-run-scan');
    const statusText = document.getElementById('scan-status-indicator');
    const logBox = document.getElementById('scan-log-output');

    btn.disabled = true;
    statusText.textContent = "Scan in progress...";
    logBox.textContent += "\n\n>>> Triggering EASM Scan Execution Engine...\n";

    try {
        const res = await fetch('/api/scan', { method: 'POST' });
        const data = await res.json();

        if (data.output) {
            logBox.textContent += data.output;
        }
        if (data.errors) {
            logBox.textContent += "\n" + data.errors;
        }

        statusText.textContent = data.success ? "Scan complete!" : "Scan finished with errors";
        showToast(data.success ? "Scan execution finished!" : "Scan error.");
        loadStatus();
    } catch (err) {
        logBox.textContent += "\n[!] Connection error running scan.\n";
        statusText.textContent = "Scan failed";
        showToast("Scan failed.");
    } finally {
        btn.disabled = false;
    }
}
