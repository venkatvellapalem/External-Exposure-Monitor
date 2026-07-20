document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initCopyButtons();
    initPlatformTabs();
    initAssetTypeListener();
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

    window.addEventListener('popstate', handlePopState);
});

const TAB_SLUG_MAP = {
    'tab-dashboard': 'dashboard',
    'tab-scanner': 'scanner',
    'tab-assets': 'assets',
    'tab-download': 'download',
    'tab-about': 'about',
    'tab-splunk': 'splunk',
    'tab-config': 'config'
};

const SLUG_TAB_MAP = {
    'dashboard': 'tab-dashboard',
    'scanner': 'tab-scanner',
    'assets': 'tab-assets',
    'download': 'tab-download',
    'about': 'tab-about',
    'splunk': 'tab-splunk',
    'config': 'tab-config'
};

function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            const targetTab = link.getAttribute('data-tab');
            switchTab(targetTab, true);
        });
    });

    const path = window.location.pathname.replace('/', '').toLowerCase();
    if (path === '' || path === 'index.html') {
        history.replaceState({ tab: 'tab-dashboard' }, '', '/dashboard');
        switchTab('tab-dashboard', false);
    } else if (SLUG_TAB_MAP[path]) {
        switchTab(SLUG_TAB_MAP[path], false);
    } else {
        switchTab('tab-dashboard', false);
    }
}

function switchTab(tabId, updateUrl = true) {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.toggle('active', link.getAttribute('data-tab') === tabId);
    });
    document.querySelectorAll('.tab-content').forEach(section => {
        section.classList.toggle('active', section.id === tabId);
    });

    if (updateUrl && TAB_SLUG_MAP[tabId]) {
        const slug = '/' + TAB_SLUG_MAP[tabId];
        if (window.location.pathname !== slug) {
            history.pushState({ tab: tabId }, '', slug);
        }
    }
}

function handlePopState(e) {
    const path = window.location.pathname.replace('/', '').toLowerCase();
    if (SLUG_TAB_MAP[path]) {
        switchTab(SLUG_TAB_MAP[path], false);
    } else {
        switchTab('tab-dashboard', false);
    }
}

function initAssetTypeListener() {
    const typeSelect = document.getElementById('asset-type');
    const valueInput = document.getElementById('asset-value');
    const domainInput = document.getElementById('asset-domain');

    if (!typeSelect || !valueInput || !domainInput) return;

    const placeholders = {
        ip: { value: "203.0.113.195", domain: "example.com" },
        cidr: { value: "192.168.1.0/24", domain: "internal-network.local" },
        domain: { value: "subdomain.example.com", domain: "example.com" }
    };

    const updatePlaceholders = () => {
        const selected = typeSelect.value;
        if (placeholders[selected]) {
            valueInput.placeholder = placeholders[selected].value;
            domainInput.placeholder = placeholders[selected].domain;
            valueInput.setAttribute('placeholder', placeholders[selected].value);
            domainInput.setAttribute('placeholder', placeholders[selected].domain);
        }
    };

    typeSelect.addEventListener('change', updatePlaceholders);
    typeSelect.addEventListener('input', updatePlaceholders);
    updatePlaceholders();
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

        // Dashboard Metrics
        if (document.getElementById('dash-total-open')) document.getElementById('dash-total-open').textContent = data.total_open || 0;
        if (document.getElementById('dash-monitored-targets')) document.getElementById('dash-monitored-targets').textContent = data.monitored_targets || 0;
        if (document.getElementById('dash-crit-count')) document.getElementById('dash-crit-count').textContent = data.critical_count || 0;
        if (document.getElementById('dash-low-count')) document.getElementById('dash-low-count').textContent = data.low_count || 0;
        if (document.getElementById('dash-sys-status')) document.getElementById('dash-sys-status').textContent = data.status ? data.status.toUpperCase() : 'ONLINE';
        if (document.getElementById('dash-org-name')) document.getElementById('dash-org-name').textContent = `Organization: ${data.organization || 'MITS'}`;

        // Direct Dashboard Studio Link
        const dashUrl = data.splunk_dashboard_url || "http://13.205.90.142:8000/en-GB/app/search/external_attack_surface_monitor";
        const link8000 = document.getElementById('link-splunk-8000');
        const dashLink8000 = document.getElementById('dash-btn-splunk-8000');
        if (link8000) link8000.href = dashUrl;
        if (dashLink8000) dashLink8000.href = dashUrl;
    } catch (e) {
        console.error("Failed to load status:", e);
    }
}

async function loadConfig() {
    try {
        const res = await fetch('/api/config');
        const data = await res.json();
        if (data.splunk_url) document.getElementById('cfg-splunk-url').value = data.splunk_url;
        if (data.splunk_token) document.getElementById('cfg-splunk-token').value = data.splunk_token;
        if (data.censys_token) document.getElementById('cfg-censys-token').value = data.censys_token;
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
            showToast("System settings saved successfully!");
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
        const payload = JSON.stringify({
            sourcetype: "_json",
            source: "easm_web_browser_test",
            event: { message: "Splunk connection test from browser client." }
        });

        const res = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Splunk ${token}`,
                'Content-Type': 'application/json'
            },
            body: payload,
            mode: 'cors'
        });

        if (res.ok) {
            showToast("Splunk HEC connection successful! (Direct browser test)");
            return;
        }
    } catch (browserErr) {
        console.log("Direct browser test failed or CORS restricted, attempting server proxy...", browserErr);
    }

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
