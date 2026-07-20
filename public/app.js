document.addEventListener('DOMContentLoaded', () => {
    handlePopState();
    initNavigation();
    initCopyButtons();
    initPlatformTabs();
    initAssetTypeListener();
    initResetModal();
    initConfigResetModal();
    initLiveIngestionCanvas();
    initPasswordToggles();
    initHamburgerDrawer();

    loadStatus();
    loadConfig();
    loadAssets();

    document.getElementById('btn-run-scan')?.addEventListener('click', runScan);
    document.getElementById('form-add-asset')?.addEventListener('submit', addAsset);
    document.getElementById('form-config')?.addEventListener('submit', saveConfig);
    document.getElementById('btn-test-hec')?.addEventListener('click', testHec);
    document.getElementById('btn-refresh-logs')?.addEventListener('click', loadAuditLogs);
    document.getElementById('logs-category-filter')?.addEventListener('change', loadAuditLogs);
    document.getElementById('logs-user-filter')?.addEventListener('change', loadAuditLogs);
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
    'tab-config': 'config',
    'tab-logs': 'logs'
};

const SLUG_TAB_MAP = {
    'dashboard': 'tab-dashboard',
    'scanner': 'tab-scanner',
    'assets': 'tab-assets',
    'download': 'tab-download',
    'about': 'tab-about',
    'splunk': 'tab-splunk',
    'config': 'tab-config',
    'logs': 'tab-logs'
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
    document.querySelectorAll('.drawer-item').forEach(link => {
        link.classList.toggle('active', link.getAttribute('data-tab') === tabId);
    });
    document.querySelectorAll('.tab-content').forEach(section => {
        section.classList.toggle('active', section.id === tabId);
    });

    if (tabId === 'tab-logs') {
        loadAuditLogs();
    }

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

async function checkAuthSession() {
    try {
        const res = await fetch('/api/auth/me');
        const data = await res.json();
        if (data.authenticated) {
            currentUser = data;
            sessionStartTime = Date.now();
            lastUserActivity = Date.now();
            hideAuthModal();
            showUserBadge(data.username, data.role);
            applyRbacUI(data.role);

            // Fetch protected data ONLY after authentication is verified
            loadStatus();
            loadConfig();
            loadAssets();
        } else {
            showAuthModal('login');
        }
    } catch (e) {
        showAuthModal('login');
    }
}

function showAuthModal(screenName = 'login') {
    const authScreenView = document.getElementById('auth-screen-view');
    const appMainView = document.getElementById('app-main-view');
    if (authScreenView) authScreenView.classList.remove('hidden');
    if (appMainView) appMainView.classList.add('hidden');

    clearAuthErrors();
    document.querySelectorAll('.auth-screen').forEach(s => s.classList.add('hidden'));

    if (screenName === 'login') {
        document.getElementById('auth-screen-login')?.classList.remove('hidden');
        document.getElementById('auth-login-username')?.focus();
    } else if (screenName === 'mfa') {
        document.getElementById('auth-screen-mfa')?.classList.remove('hidden');
        document.getElementById('auth-totp-code')?.focus();
    } else if (screenName === 'password') {
        document.getElementById('auth-screen-password')?.classList.remove('hidden');
        document.getElementById('auth-new-password')?.focus();
    } else if (screenName === 'recovery') {
        document.getElementById('auth-screen-recovery')?.classList.remove('hidden');
        document.getElementById('rec-master-key')?.focus();
    }
}

function hideAuthModal() {
    const authScreenView = document.getElementById('auth-screen-view');
    const appMainView = document.getElementById('app-main-view');
    if (authScreenView) authScreenView.classList.add('hidden');
    if (appMainView) appMainView.classList.remove('hidden');
    clearAuthErrors();
}

function showUserBadge(username, role) {
    const container = document.getElementById('user-badge-container');
    const nameTag = document.getElementById('user-display-name');
    const dropdownUser = document.getElementById('dropdown-user-name');
    const dropdownRole = document.getElementById('dropdown-user-role');

    const formattedRole = role.replace('_', ' ').toUpperCase();

    if (container && nameTag) {
        container.style.display = 'inline-block';
        nameTag.textContent = `${username} (${formattedRole})`;
    }
    if (dropdownUser) dropdownUser.textContent = username;
    if (dropdownRole) dropdownRole.textContent = formattedRole;
}

function applyRbacUI(role) {
    const isRootAdmin = (role === 'root_admin');

    const iamDropdownItem = document.getElementById('dropdown-item-iam');
    const configDropdownItem = document.getElementById('dropdown-item-config');
    const drawerIamItem = document.getElementById('drawer-link-iam');
    const drawerConfigItem = document.getElementById('drawer-link-config');
    const drawerLogsItem = document.getElementById('drawer-link-logs');

    if (iamDropdownItem) iamDropdownItem.style.display = isRootAdmin ? 'flex' : 'none';
    if (configDropdownItem) configDropdownItem.style.display = isRootAdmin ? 'flex' : 'none';
    if (drawerIamItem) drawerIamItem.style.display = isRootAdmin ? 'flex' : 'none';
    if (drawerConfigItem) drawerConfigItem.style.display = isRootAdmin ? 'flex' : 'none';
    if (drawerLogsItem) drawerLogsItem.style.display = (isRootAdmin || role === 'soc_analyst') ? 'flex' : 'none';

    if (role === 'read_only_auditor') {
        document.querySelectorAll('.btn-danger, #btn-run-scan, #btn-reset-inventory, #btn-reset-config').forEach(el => {
            el.disabled = true;
            el.style.opacity = '0.5';
            el.style.cursor = 'not-allowed';
        });
    }
}

function initHamburgerDrawer() {
    const btnHamburger = document.getElementById('btn-hamburger');
    const drawerOverlay = document.getElementById('sidebar-drawer-overlay');
    const btnClose = document.getElementById('btn-close-drawer');

    if (!btnHamburger || !drawerOverlay) return;

    btnHamburger.addEventListener('click', (e) => {
        e.stopPropagation();
        drawerOverlay.classList.remove('hidden');
    });

    if (btnClose) {
        btnClose.addEventListener('click', () => {
            drawerOverlay.classList.add('hidden');
        });
    }

    drawerOverlay.addEventListener('click', (e) => {
        if (e.target === drawerOverlay) {
            drawerOverlay.classList.add('hidden');
        }
    });

    document.querySelectorAll('.drawer-item').forEach(item => {
        item.addEventListener('click', () => {
            const targetTab = item.getAttribute('data-tab');
            if (targetTab) {
                switchTab(targetTab, true);
                drawerOverlay.classList.add('hidden');
            }
        });
    });
}

function initProfileDropdown() {
    const btnProfile = document.getElementById('btn-profile-dropdown');
    const menu = document.getElementById('profile-dropdown-menu');

    if (!btnProfile || !menu) return;

    btnProfile.addEventListener('click', (e) => {
        e.stopPropagation();
        menu.classList.toggle('hidden');
    });

    document.addEventListener('click', (e) => {
        if (!menu.contains(e.target) && !btnProfile.contains(e.target)) {
            menu.classList.add('hidden');
        }
    });
}

function closeProfileDropdown() {
    const menu = document.getElementById('profile-dropdown-menu');
    if (menu) menu.classList.add('hidden');
}

function initPasswordToggles() {
    document.querySelectorAll('.btn-toggle-pass').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (!input) return;

            const isPassword = input.type === 'password';
            input.type = isPassword ? 'text' : 'password';

            const svg = btn.querySelector('.eye-icon');
            if (svg) {
                if (isPassword) {
                    svg.innerHTML = `
                        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                        <line x1="1" y1="1" x2="23" y2="23"></line>
                    `;
                } else {
                    svg.innerHTML = `
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                        <circle cx="12" cy="12" r="3"></circle>
                    `;
                }
            }
        });
    });
}

function initIamPasswordMatchListener() {
    const newPass = document.getElementById('iam-new-password');
    const confirmPass = document.getElementById('iam-confirm-password');
    const errSpan = document.getElementById('iam-pass-match-error');
    const submitBtn = document.getElementById('btn-submit-create-iam');

    if (!newPass || !confirmPass || !errSpan) return;

    const validateMatch = () => {
        const p1 = newPass.value;
        const p2 = confirmPass.value;

        if (p2.length > 0 && p1 !== p2) {
            errSpan.classList.remove('hidden');
            confirmPass.style.borderColor = 'var(--accent-red, #ef4444)';
            if (submitBtn) submitBtn.disabled = true;
        } else {
            errSpan.classList.add('hidden');
            confirmPass.style.borderColor = '';
            if (submitBtn) submitBtn.disabled = false;
        }
    };

    newPass.addEventListener('input', validateMatch);
    confirmPass.addEventListener('input', validateMatch);
}

function showAuthError(bannerId, message) {
    const banner = document.getElementById(bannerId);
    if (banner) {
        banner.textContent = message;
        banner.classList.remove('hidden');
    }
    showToast(message);
}

function clearAuthErrors() {
    document.querySelectorAll('.auth-error-banner').forEach(b => {
        b.textContent = '';
        b.classList.add('hidden');
    });
}

function initAuthFlow() {
    document.getElementById('btn-cancel-enable-mfa')?.addEventListener('click', () => {
        document.getElementById('enable-mfa-modal')?.classList.add('hidden');
    });

    document.getElementById('form-enable-mfa')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = document.getElementById('mfa-enable-code').value.trim();
        const errBanner = document.getElementById('mfa-enable-error');
        if (!pendingEnableMfaUser || !pendingEnableMfaSecret) return;

        try {
            const res = await fetch('/api/auth/mfa-verify', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: pendingEnableMfaUser,
                    code: code,
                    secret: pendingEnableMfaSecret
                })
            });
            const data = await res.json();
            if (data.success) {
                localStorage.setItem('easm_mfa_' + pendingEnableMfaUser, 'true');
                document.getElementById('enable-mfa-modal')?.classList.add('hidden');
                showToast(`TOTP MFA successfully enabled and enforced for '${pendingEnableMfaUser}'!`);
                loadIamUsers();
            } else {
                if (errBanner) {
                    errBanner.textContent = "MFA Verification Failed: " + data.message;
                    errBanner.classList.remove('hidden');
                }
            }
        } catch (err) {
            showToast("Error verifying TOTP code.");
        }
    });

    document.getElementById('btn-show-recovery')?.addEventListener('click', () => {
        showAuthModal('recovery');
    });

    document.getElementById('btn-cancel-recovery')?.addEventListener('click', () => {
        showAuthModal('login');
    });

    document.getElementById('form-auth-login')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearAuthErrors();
        const username = document.getElementById('auth-login-username').value.trim();
        const password = document.getElementById('auth-login-password').value;

        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ username, password })
            });
            const data = await res.json();
            if (data.success) {
                failedLoginAttempts = 0;
                document.getElementById('btn-show-recovery')?.classList.add('hidden');
                pendingAuthUser = data;
                
                const mfaRes = await fetch('/api/auth/mfa-setup', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username })
                });
                const mfaData = await mfaRes.json();
                if (mfaData.success) {
                    pendingMfaSecret = mfaData.secret;
                    const qrImg = document.getElementById('auth-qr-img');
                    const secretKey = document.getElementById('auth-mfa-secret-key');
                    const qrContainer = document.getElementById('auth-mfa-qr-container');

                    if (qrImg) qrImg.src = mfaData.qr_code_uri;
                    if (secretKey) secretKey.textContent = mfaData.secret;
                    
                    if (!data.mfa_enabled && qrContainer) {
                        qrContainer.classList.remove('hidden');
                    } else if (qrContainer) {
                        qrContainer.classList.add('hidden');
                    }
                }
                showAuthModal('mfa');
            } else {
                failedLoginAttempts++;
                if (failedLoginAttempts >= 2) {
                    document.getElementById('btn-show-recovery')?.classList.remove('hidden');
                }
                showAuthError('auth-login-error', "Login failed: " + data.message);
            }
        } catch (err) {
            failedLoginAttempts++;
            if (failedLoginAttempts >= 2) {
                document.getElementById('btn-show-recovery')?.classList.remove('hidden');
            }
            showAuthError('auth-login-error', "Connection error during login.");
        }
    });

    document.getElementById('form-auth-mfa')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearAuthErrors();
        const code = document.getElementById('auth-totp-code').value.trim();
        if (!pendingAuthUser) return;

        try {
            const res = await fetch('/api/auth/mfa-verify', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: pendingAuthUser.username,
                    code: code,
                    secret: pendingMfaSecret
                })
            });
            const data = await res.json();
            if (data.success) {
                currentUser = data.user;
                sessionStartTime = Date.now();
                lastUserActivity = Date.now();

                if (data.user.must_change_password) {
                    showAuthModal('password');
                } else {
                    hideAuthModal();
                    showToast("Authenticated successfully!");
                    showUserBadge(data.user.username, data.user.role);
                    applyRbacUI(data.user.role);
                    loadStatus();
                    loadAssets();
                }
            } else {
                showAuthError('auth-mfa-error', "MFA error: " + data.message);
            }
        } catch (err) {
            showAuthError('auth-mfa-error', "Error verifying TOTP MFA code.");
        }
    });

    document.getElementById('form-auth-password')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearAuthErrors();
        const newPass = document.getElementById('auth-new-password').value;
        const confirmPass = document.getElementById('auth-confirm-password').value;

        if (newPass !== confirmPass) {
            showAuthError('auth-pass-error', "Passwords do not match.");
            return;
        }

        try {
            const res = await fetch('/api/auth/change-password', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: currentUser ? currentUser.username : (pendingAuthUser ? pendingAuthUser.username : ""),
                    new_password: newPass
                })
            });
            const data = await res.json();
            if (data.success) {
                hideAuthModal();
                showToast("Password updated successfully!");
                checkAuthSession();
            } else {
                showAuthError('auth-pass-error', "Password error: " + data.message);
            }
        } catch (err) {
            showAuthError('auth-pass-error', "Error updating password.");
        }
    });

    document.getElementById('form-auth-recovery')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearAuthErrors();
        const username = document.getElementById('rec-admin-username').value.trim();
        const recoveryKey = document.getElementById('rec-master-key').value.trim();
        const newPass = document.getElementById('rec-new-password').value;
        const confirmPass = document.getElementById('rec-confirm-password').value;

        if (newPass !== confirmPass) {
            showAuthError('auth-recovery-error', "Passwords do not match.");
            return;
        }

        try {
            const res = await fetch('/api/auth/admin-recovery', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: username,
                    recovery_key: recoveryKey,
                    new_password: newPass
                })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                showAuthModal('login');
                document.getElementById('rec-master-key').value = '';
                document.getElementById('rec-new-password').value = '';
                document.getElementById('rec-confirm-password').value = '';
            } else {
                showAuthError('auth-recovery-error', "Recovery error: " + data.message);
            }
        } catch (err) {
            showAuthError('auth-recovery-error', "Error executing Master Emergency Recovery.");
        }
    });
}

async function handleLogout(reasonMsg) {
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
    } catch (e) {}
    currentUser = null;
    const badge = document.getElementById('user-badge-container');
    if (badge) badge.style.display = 'none';
    closeProfileDropdown();
    showToast(reasonMsg ? reasonMsg : "Logged out.");
    showAuthModal('login');
}

let keysMaskedState = [true, true, true];

async function loadAdminRecoveryKey() {
    try {
        const res = await fetch('/api/iam/recovery-key');
        const data = await res.json();
        const container = document.getElementById('iam-display-recovery-keys-container');
        if (container && data.success && data.recovery_keys) {
            activeRecoveryKeys = data.recovery_keys;
            renderRecoveryKeysGrid(container, data.recovery_keys);
        }
    } catch (e) {}
}

function renderRecoveryKeysGrid(container, keys) {
    container.innerHTML = '';
    keys.forEach((key, idx) => {
        const isMasked = keysMaskedState[idx] !== false;
        const displayKey = isMasked ? 'EASM-••••-••••-••••-••••' : key;
        const box = document.createElement('div');
        box.className = 'breakglass-key-card';
        box.innerHTML = `
            <div class="key-card-header">
                <span class="key-card-title">Key #${idx + 1}</span>
                <span class="key-card-status">ACTIVE ●</span>
            </div>
            <div class="key-card-body">
                <code style="font-size:12px; letter-spacing:1px;">${displayKey}</code>
                <div style="display:flex; gap:6px; align-items:center;">
                    <button class="copy-btn" onclick="toggleKeyMask(${idx})" title="${isMasked ? 'Show Key' : 'Mask Key'}">
                        <svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px; height:14px;">
                            ${isMasked ? `
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                <circle cx="12" cy="12" r="3"/>
                            ` : `
                                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                                <line x1="1" y1="1" x2="23" y2="23"></line>
                            `}
                        </svg>
                    </button>
                    <button class="copy-btn" onclick="copySingleKey('${key}')" title="Copy Key #${idx + 1}">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px; height:14px;">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                        </svg>
                    </button>
                </div>
            </div>
        `;
        container.appendChild(box);
    });
}

function toggleKeyMask(idx) {
    keysMaskedState[idx] = !keysMaskedState[idx];
    const container = document.getElementById('iam-display-recovery-keys-container');
    if (container && activeRecoveryKeys) {
        renderRecoveryKeysGrid(container, activeRecoveryKeys);
    }
}

function copySingleKey(key) {
    navigator.clipboard.writeText(key).then(() => {
        showToast(`Master Recovery Key '${key}' copied to clipboard!`);
    });
}

let pendingEnableMfaUser = null;
let pendingEnableMfaSecret = null;

async function openMfaEnableModal(username) {
    pendingEnableMfaUser = username;
    const modal = document.getElementById('enable-mfa-modal');
    if (!modal) return;

    try {
        const res = await fetch('/api/auth/mfa-setup', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username })
        });
        const data = await res.json();
        if (data.success) {
            pendingEnableMfaSecret = data.secret;
            document.getElementById('mfa-enable-qr-img').src = data.qr_code_uri;
            document.getElementById('mfa-enable-secret-key').textContent = data.secret;
            document.getElementById('mfa-enable-code').value = '';
            document.getElementById('mfa-enable-error').classList.add('hidden');
            document.getElementById('mfa-enable-desc').textContent = `Scan the QR code below with Google Authenticator or Authy to activate MFA for user account '${username}'.`;
            modal.classList.remove('hidden');
        } else {
            showToast("Failed to setup MFA: " + data.message);
        }
    } catch (e) {
        showToast("Error setting up MFA secret.");
    }
}

function toggleUserActionDropdown(e, username) {
    e.stopPropagation();
    document.querySelectorAll('.user-actions-dropdown').forEach(d => {
        if (d.id !== `dropdown-user-actions-${username}`) {
            d.classList.add('hidden');
        }
    });
    const dropdown = document.getElementById(`dropdown-user-actions-${username}`);
    if (dropdown) dropdown.classList.toggle('hidden');
}

async function probeResetUserMfa(username) {
    if (!confirm(`Reset TOTP MFA secret for '${username}'? User will be required to re-scan a new QR code immediately.`)) return;

    try {
        const res = await fetch('/api/iam/reset-mfa', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username })
        });
        const data = await res.json();
        if (data.success) {
            localStorage.removeItem('easm_mfa_' + username);
            showToast(data.message);
            loadIamUsers();
            openMfaEnableModal(username);
        } else {
            showToast("Failed to reset MFA: " + data.message);
        }
    } catch (e) {
        showToast("Error resetting MFA secret.");
    }
}

async function loadIamUsers() {
    try {
        const res = await fetch('/api/iam/users');
        const data = await res.json();
        const tbody = document.getElementById('iam-users-table-body');
        const userFilterSelect = document.getElementById('logs-user-filter');

        if (!tbody) return;
        tbody.innerHTML = '';

        if (userFilterSelect && data.users) {
            const currentVal = userFilterSelect.value;
            userFilterSelect.innerHTML = '<option value="ALL">All Users</option>';
            data.users.forEach(u => {
                const opt = document.createElement('option');
                opt.value = u.username;
                opt.textContent = u.username;
                userFilterSelect.appendChild(opt);
            });
            userFilterSelect.value = currentVal;
        }

        if (!data.users || data.users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-muted">No users found.</td></tr>';
            return;
        }

        data.users.forEach(u => {
            if (localStorage.getItem('easm_mfa_' + u.username) === 'true') {
                u.mfa_enabled = true;
            }

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${u.username}</strong></td>
                <td><span class="badge-role ${u.role}">${u.role.replace('_', ' ')}</span></td>
                <td><span class="badge-status ${u.mfa_enabled ? 'green' : 'red'}">${u.mfa_enabled ? 'Enforced' : 'Pending'}</span></td>
                <td><span class="badge-status ${u.must_change_password ? 'red' : 'green'}">${u.must_change_password ? 'Reset Required' : 'Compliant'}</span></td>
                <td>
                    ${!u.mfa_enabled ? `
                        <button class="btn-delete-asset" onclick="openMfaEnableModal('${u.username}')" style="background:#0284c7; color:#ffffff;">Enable MFA</button>
                    ` : `
                        <div style="position:relative; display:inline-block;">
                            <button class="btn-icon-dots" onclick="toggleUserActionDropdown(event, '${u.username}')" title="Actions">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px; height:16px;">
                                    <circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="19" r="1.5"/>
                                </svg>
                            </button>
                            <div id="dropdown-user-actions-${u.username}" class="user-actions-dropdown hidden">
                                <button onclick="probeResetUserMfa('${u.username}')">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px; height:14px; margin-right:6px;"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
                                    Reset MFA Secret
                                </button>
                                ${u.username !== 'admin' ? `
                                    <button class="danger-item" onclick="deleteIamUser('${u.username}')">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px; height:14px; margin-right:6px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                                        Revoke User
                                    </button>
                                ` : ''}
                            </div>
                        </div>
                    `}
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Failed to load IAM users:", e);
    }
}

async function resetUserMfa(username) {
    if (!confirm(`Reset TOTP MFA secret for '${username}'? The user will be required to scan a new QR code on next login.`)) return;

    try {
        const res = await fetch('/api/iam/reset-mfa', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username })
        });
        const data = await res.json();
        if (data.success) {
            showToast(data.message);
            loadIamUsers();
        } else {
            showToast("Failed to reset MFA: " + data.message);
        }
    } catch (e) {
        showToast("Error resetting MFA secret.");
    }
}

async function createIamUser(e) {
    e.preventDefault();
    const username = document.getElementById('iam-new-username').value.trim();
    const role = document.getElementById('iam-new-role').value;
    const password = document.getElementById('iam-new-password').value;
    const confirmPassword = document.getElementById('iam-confirm-password').value;
    const adminPassword = document.getElementById('iam-admin-password').value;
    const forceReset = document.getElementById('iam-force-reset')?.checked ?? true;

    if (password !== confirmPassword) {
        showToast("New user initial passwords do not match.");
        return;
    }

    try {
        const res = await fetch('/api/iam/users', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: username,
                role: role,
                password: password,
                confirm_password: confirmPassword,
                admin_password: adminPassword,
                must_change_password: forceReset
            })
        });
        const data = await res.json();
        if (data.success) {
            showToast(data.message);
            document.getElementById('iam-new-username').value = '';
            document.getElementById('iam-new-password').value = '';
            document.getElementById('iam-confirm-password').value = '';
            document.getElementById('iam-admin-password').value = '';
            loadIamUsers();
        } else {
            showToast("Failed: " + data.message);
        }
    } catch (e) {
        showToast("Error creating IAM account.");
    }
}

async function deleteIamUser(username) {
    if (!confirm(`Revoke user account '${username}'?`)) return;

    try {
        const res = await fetch('/api/iam/users', {
            method: 'DELETE',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username })
        });
        const data = await res.json();
        if (data.success) {
            showToast(data.message);
            loadIamUsers();
        } else {
            showToast("Failed to revoke: " + data.message);
        }
    } catch (e) {
        showToast("Error revoking user.");
    }
}

async function loadAuditLogs() {
    const category = document.getElementById('logs-category-filter')?.value || 'ALL';
    const username = document.getElementById('logs-user-filter')?.value || 'ALL';
    const icon = document.getElementById('refresh-logs-icon');

    if (icon) icon.classList.add('spinning');

    try {
        const res = await fetch(`/api/logs?category=${category}&username=${username}`);
        const data = await res.json();
        const tbody = document.getElementById('logs-table-body');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (!data.logs || data.logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-muted">No audit logs found matching filters.</td></tr>';
            return;
        }

        data.logs.forEach(log => {
            const tr = document.createElement('tr');
            const formattedTime = new Date(log.timestamp).toLocaleString();
            tr.innerHTML = `
                <td><small class="text-muted">${formattedTime}</small></td>
                <td><strong>${log.username}</strong></td>
                <td><span class="badge-role ${log.role}">${log.role.replace('_', ' ')}</span></td>
                <td><code>${log.action}</code></td>
                <td>${log.details}</td>
                <td><span class="badge-severity ${log.severity}">${log.severity}</span></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Failed to load audit logs:", e);
    } finally {
        setTimeout(() => {
            if (icon) icon.classList.remove('spinning');
        }, 400);
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

function initResetModal() {
    const btnOpen = document.getElementById('btn-reset-inventory');
    const modal = document.getElementById('reset-modal');
    const btnCancel = document.getElementById('btn-cancel-reset');
    const btnConfirm = document.getElementById('btn-confirm-reset');
    const input = document.getElementById('reset-confirm-input');

    if (!btnOpen || !modal || !btnCancel || !btnConfirm || !input) return;

    btnOpen.addEventListener('click', () => {
        input.value = '';
        modal.classList.remove('hidden');
        input.focus();
    });

    btnCancel.addEventListener('click', () => {
        modal.classList.add('hidden');
        input.value = '';
    });

    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.add('hidden');
            input.value = '';
        }
    });

    btnConfirm.addEventListener('click', async () => {
        const val = input.value.trim();
        if (val !== "delete my asset inventory") {
            showToast("Confirmation mismatch. Reset aborted.");
            return;
        }

        btnConfirm.disabled = true;
        try {
            const res = await fetch('/api/assets/reset', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ confirmation: val })
            });
            const data = await res.json();
            if (data.success) {
                modal.classList.add('hidden');
                input.value = '';
                showToast("Asset inventory and dashboard exposure values successfully reset!");
                loadAssets();
                loadStatus();
            } else {
                showToast("Reset failed: " + data.message);
            }
        } catch (err) {
            showToast("Error resetting inventory.");
        } finally {
            btnConfirm.disabled = false;
        }
    });
}

function initConfigResetModal() {
    const btnOpen = document.getElementById('btn-reset-config');
    const modal = document.getElementById('config-reset-modal');
    const btnCancel = document.getElementById('btn-cancel-config-reset');
    const btnConfirm = document.getElementById('btn-confirm-config-reset');
    const input = document.getElementById('config-reset-confirm-input');

    if (!btnOpen || !modal || !btnCancel || !btnConfirm || !input) return;

    btnOpen.addEventListener('click', () => {
        input.value = '';
        modal.classList.remove('hidden');
        input.focus();
    });

    btnCancel.addEventListener('click', () => {
        modal.classList.add('hidden');
        input.value = '';
    });

    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.add('hidden');
            input.value = '';
        }
    });

    btnConfirm.addEventListener('click', async () => {
        const val = input.value.trim();
        if (val !== "reset my settings") {
            showToast("Confirmation mismatch. Reset aborted.");
            return;
        }

        btnConfirm.disabled = true;
        try {
            const res = await fetch('/api/config/reset', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ confirmation: val })
            });
            const data = await res.json();
            if (data.success) {
                modal.classList.add('hidden');
                input.value = '';
                showToast("System settings and credentials successfully reset!");
                loadConfig();
                loadStatus();
            } else {
                showToast("Reset failed: " + data.message);
            }
        } catch (err) {
            showToast("Error resetting settings.");
        } finally {
            btnConfirm.disabled = false;
        }
    });
}

function initLiveIngestionCanvas() {
    const canvas = document.getElementById('ingestion-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let points = [15, 22, 18, 35, 28, 42, 30, 38, 25, 45, 32, 40, 28, 35, 48];
    const maxPoints = 20;

    function drawChart() {
        const w = canvas.width;
        const h = canvas.height;
        ctx.clearRect(0, 0, w, h);

        ctx.beginPath();
        const step = w / (maxPoints - 1);
        ctx.moveTo(0, h - (points[0] / 100) * h);

        for (let i = 1; i < points.length; i++) {
            const x = i * step;
            const y = h - (points[i] / 100) * h;
            const prevX = (i - 1) * step;
            const prevY = h - (points[i - 1] / 100) * h;
            const cpX = (prevX + x) / 2;
            ctx.bezierCurveTo(cpX, prevY, cpX, y, x, y);
        }

        const gradient = ctx.createLinearGradient(0, 0, 0, h);
        gradient.addColorStop(0, 'rgba(0, 0, 0, 0.12)');
        gradient.addColorStop(1, 'rgba(0, 0, 0, 0.0)');

        ctx.lineTo(w, h);
        ctx.lineTo(0, h);
        ctx.closePath();
        ctx.fillStyle = gradient;
        ctx.fill();

        ctx.beginPath();
        ctx.moveTo(0, h - (points[0] / 100) * h);
        for (let i = 1; i < points.length; i++) {
            const x = i * step;
            const y = h - (points[i] / 100) * h;
            const prevX = (i - 1) * step;
            const prevY = h - (points[i - 1] / 100) * h;
            const cpX = (prevX + x) / 2;
            ctx.bezierCurveTo(cpX, prevY, cpX, y, x, y);
        }
        ctx.strokeStyle = '#000000';
        ctx.lineWidth = 2.2;
        ctx.stroke();
    }

    drawChart();

    setInterval(() => {
        const openCount = parseInt(document.getElementById('dash-total-open')?.textContent || "0");
        const nextVal = openCount > 0 ? Math.min(80, openCount * 18 + Math.floor(Math.random() * 8)) : 5;
        points.push(nextVal);
        if (points.length > maxPoints) {
            points.shift();
        }
        drawChart();
    }, 2000);
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

    document.getElementById('btn-copy-git-clone')?.addEventListener('click', () => {
        const text = document.getElementById('git-clone-command').textContent;
        navigator.clipboard.writeText(text).then(() => {
            showToast("GitHub clone command copied to clipboard!");
        });
    });

    document.getElementById('btn-download-zip')?.addEventListener('click', () => {
        fetch('/api/logs/event', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                action: 'FILE_DOWNLOADED',
                details: 'Downloaded source code ZIP archive (External-Exposure-Monitor.zip)',
                category: 'FILES',
                severity: 'INFO'
            })
        }).catch(() => {});
    });

    document.getElementById('btn-download-json')?.addEventListener('click', () => {
        fetch('/api/logs/event', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                action: 'FILE_DOWNLOADED',
                details: 'Downloaded Splunk Dashboard Studio JSON configuration',
                category: 'FILES',
                severity: 'INFO'
            })
        }).catch(() => {});
    });

    document.getElementById('btn-copy-all-keys')?.addEventListener('click', () => {
        if (activeRecoveryKeys && activeRecoveryKeys.length > 0) {
            const formatted = activeRecoveryKeys.map((k, i) => `Key #${i+1}: ${k}`).join('\n');
            navigator.clipboard.writeText(formatted).then(() => {
                showToast("All 3 Master Emergency Recovery Keys copied to clipboard!");
            });
        }
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
    }, 4500);
}

async function loadStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();

        if (document.getElementById('dash-total-open')) document.getElementById('dash-total-open').textContent = data.total_open || 0;
        if (document.getElementById('dash-monitored-targets')) document.getElementById('dash-monitored-targets').textContent = data.monitored_targets || 0;
        if (document.getElementById('dash-crit-count')) document.getElementById('dash-crit-count').textContent = data.critical_count || 0;
        if (document.getElementById('dash-low-count')) document.getElementById('dash-low-count').textContent = data.low_count || 0;
        if (document.getElementById('dash-sys-status')) document.getElementById('dash-sys-status').textContent = data.status ? data.status.toUpperCase() : 'ONLINE';
        if (document.getElementById('dash-org-name')) document.getElementById('dash-org-name').textContent = `Organization: ${data.organization || 'MITS'}`;
        if (document.getElementById('ingest-rate-live')) document.getElementById('ingest-rate-live').textContent = data.ingestion_rate || '0.0 events/sec';

        const badgeHec = document.getElementById('badge-hec');
        const badgeCensys = document.getElementById('badge-censys');
        const badgeShodan = document.getElementById('badge-shodan');

        if (badgeHec) {
            const statusStr = data.hec_badge || 'Active';
            badgeHec.textContent = statusStr;
            badgeHec.className = `badge-status ${statusStr === 'Inactive' ? 'red' : 'green'}`;
        }
        if (badgeCensys) {
            const statusStr = data.censys_badge || 'Active';
            badgeCensys.textContent = statusStr;
            badgeCensys.className = `badge-status ${statusStr === 'Inactive' ? 'red' : 'green'}`;
        }
        if (badgeShodan) {
            const statusStr = data.shodan_badge || 'Active';
            badgeShodan.textContent = statusStr;
            badgeShodan.className = `badge-status ${statusStr === 'Inactive' ? 'red' : 'green'}`;
        }

        const dashUrl = "/api/auth/splunk-sso";
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
        if (data.organization && document.getElementById('cfg-org-name')) document.getElementById('cfg-org-name').value = data.organization;
        if (data.splunk_url && document.getElementById('cfg-splunk-url')) document.getElementById('cfg-splunk-url').value = data.splunk_url;
        if (data.splunk_token && document.getElementById('cfg-splunk-token')) document.getElementById('cfg-splunk-token').value = data.splunk_token;
        if (data.censys_token && document.getElementById('cfg-censys-token')) document.getElementById('cfg-censys-token').value = data.censys_token;
        if (data.scan_timeout && document.getElementById('cfg-scan-timeout')) document.getElementById('cfg-scan-timeout').value = data.scan_timeout;
    } catch (e) {
        console.error("Failed to load config:", e);
    }
}

async function saveConfig(e) {
    e.preventDefault();
    const org = document.getElementById('cfg-org-name').value;
    const url = document.getElementById('cfg-splunk-url').value;
    const token = document.getElementById('cfg-splunk-token').value;
    const censys = document.getElementById('cfg-censys-token').value;
    const timeout = document.getElementById('cfg-scan-timeout').value;

    try {
        const res = await fetch('/api/config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                organization: org,
                splunk_url: url,
                splunk_token: token,
                censys_token: censys,
                scan_timeout: timeout
            })
        });
        const data = await res.json();
        if (data.success) {
            if (data.updated_url && document.getElementById('cfg-splunk-url')) {
                document.getElementById('cfg-splunk-url').value = data.updated_url;
            }
            showToast(data.message || "System settings saved successfully!");
            loadStatus();
        } else {
            showToast("Failed to save config: " + data.message);
        }
    } catch (err) {
        showToast("Error saving config.");
    }
}

async function testHec() {
    const urlInput = document.getElementById('cfg-splunk-url');
    const tokenInput = document.getElementById('cfg-splunk-token');
    const url = urlInput ? urlInput.value.trim() : '';
    const token = tokenInput ? tokenInput.value.trim() : '';

    showToast("Testing connection to Splunk HEC...");

    try {
        const res = await fetch('/api/test-hec', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ splunk_url: url, splunk_token: token })
        });
        const data = await res.json();
        if (data.updated_url && urlInput) {
            urlInput.value = data.updated_url;
        }
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
