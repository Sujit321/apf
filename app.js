// ===== APF Resource Person Dashboard — App Logic =====

// ===== Data Layer (In-Memory Only — No Browser Storage) =====
const DB = {
    _store: {},
    get(key) {
        const data = this._store[key];
        if (!data) return [];
        try { return JSON.parse(JSON.stringify(data)); }
        catch { return []; }
    },
    set(key, data) {
        this._store[key] = JSON.parse(JSON.stringify(data));
    },
    clear() {
        this._store = {};
    },
    generateId() {
        return Date.now().toString(36) + (Math.random().toString(36) + '00000').substring(2, 7);
    }
};

// ===== Password Protection =====
const PasswordManager = {
    HASH_KEY: 'apf_password_hash',
    LOCK_TIME_KEY: 'apf_autolock_minutes',

    async hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password + 'apf_salt_2026');
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    isPasswordSet() {
        return !!localStorage.getItem(this.HASH_KEY);
    },

    getStoredHash() {
        return localStorage.getItem(this.HASH_KEY);
    },

    setHash(hash) {
        localStorage.setItem(this.HASH_KEY, hash);
    },

    removeHash() {
        localStorage.removeItem(this.HASH_KEY);
    },

    getAutoLockMinutes() {
        return parseInt(localStorage.getItem(this.LOCK_TIME_KEY) || '0', 10);
    },

    setAutoLockMinutes(mins) {
        localStorage.setItem(this.LOCK_TIME_KEY, String(mins));
    }
};

// ===== Encrypted File Storage (AES-256-GCM) =====
const CryptoEngine = {
    SALT_LENGTH: 16,
    IV_LENGTH: 12,
    ITERATIONS: 100000,
    FILE_MAGIC: 'APF_ENC_V1',

    async deriveKey(password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: this.ITERATIONS, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    },

    async encrypt(password, data) {
        const encoder = new TextEncoder();
        const salt = crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
        const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
        const key = await this.deriveKey(password, salt);
        const plaintext = encoder.encode(JSON.stringify(data));
        const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);

        // Format: MAGIC | salt | iv | ciphertext
        const magic = encoder.encode(this.FILE_MAGIC);
        const result = new Uint8Array(magic.length + salt.length + iv.length + ciphertext.byteLength);
        result.set(magic, 0);
        result.set(salt, magic.length);
        result.set(iv, magic.length + salt.length);
        result.set(new Uint8Array(ciphertext), magic.length + salt.length + iv.length);
        return result;
    },

    async decrypt(password, buffer) {
        const decoder = new TextDecoder();
        const data = new Uint8Array(buffer);
        const magicLen = this.FILE_MAGIC.length;

        // Verify magic header
        const magic = decoder.decode(data.slice(0, magicLen));
        if (magic !== this.FILE_MAGIC) throw new Error('Not a valid APF encrypted file');

        const salt = data.slice(magicLen, magicLen + this.SALT_LENGTH);
        const iv = data.slice(magicLen + this.SALT_LENGTH, magicLen + this.SALT_LENGTH + this.IV_LENGTH);
        const ciphertext = data.slice(magicLen + this.SALT_LENGTH + this.IV_LENGTH);

        const key = await this.deriveKey(password, salt);
        const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
        return JSON.parse(decoder.decode(plaintext));
    }
};

// ===== Encrypted Cache (stores AES-256 encrypted blob in browser) =====
const EncryptedCache = {
    CACHE_KEY: 'apf_encrypted_cache',
    SAVE_TIME_KEY: 'apf_last_enc_save',

    exists() {
        return !!localStorage.getItem(this.CACHE_KEY);
    },

    async save(password) {
        try {
            const allData = { _meta: { app: 'APF Dashboard', version: 2, cachedAt: new Date().toISOString() } };
            ENCRYPTED_DATA_KEYS.forEach(k => { allData[k] = DB.get(k); });
            const encrypted = await CryptoEngine.encrypt(password, allData);
            // Store as base64 string
            const binary = String.fromCharCode(...encrypted);
            localStorage.setItem(this.CACHE_KEY, btoa(binary));
            const now = new Date().toISOString();
            localStorage.setItem(this.SAVE_TIME_KEY, now);
            lastEncSaveTime = now;
            return true;
        } catch (err) {
            console.error('Cache save failed:', err);
            return false;
        }
    },

    async load(password) {
        const b64 = localStorage.getItem(this.CACHE_KEY);
        if (!b64) throw new Error('No cached data');
        const binary = atob(b64);
        const buffer = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) buffer[i] = binary.charCodeAt(i);
        return CryptoEngine.decrypt(password, buffer.buffer);
    },

    clear() {
        localStorage.removeItem(this.CACHE_KEY);
        localStorage.removeItem(this.SAVE_TIME_KEY);
    },

    getLastSaveTime() {
        return localStorage.getItem(this.SAVE_TIME_KEY);
    }
};

// ===== File System Access API — Direct File Read/Write =====
const FileLink = {
    _handle: null,      // FileSystemFileHandle
    _dbName: 'apf_filehandle_db',
    _storeName: 'handles',

    // Check if File System Access API is available
    isSupported() {
        return 'showSaveFilePicker' in window && 'showOpenFilePicker' in window;
    },

    // Open IndexedDB to persist the file handle across sessions
    _openDB() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(this._dbName, 1);
            req.onupgradeneeded = () => req.result.createObjectStore(this._storeName);
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    },

    // Save handle to IndexedDB
    async _persistHandle(handle) {
        const db = await this._openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(this._storeName, 'readwrite');
            tx.objectStore(this._storeName).put(handle, 'fileHandle');
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    },

    // Load handle from IndexedDB
    async _loadPersistedHandle() {
        try {
            const db = await this._openDB();
            return new Promise((resolve, reject) => {
                const tx = db.transaction(this._storeName, 'readonly');
                const req = tx.objectStore(this._storeName).get('fileHandle');
                req.onsuccess = () => resolve(req.result || null);
                req.onerror = () => reject(req.error);
            });
        } catch { return null; }
    },

    // Clear persisted handle
    async _clearPersistedHandle() {
        try {
            const db = await this._openDB();
            return new Promise((resolve) => {
                const tx = db.transaction(this._storeName, 'readwrite');
                tx.objectStore(this._storeName).delete('fileHandle');
                tx.oncomplete = () => resolve();
                tx.onerror = () => resolve();
            });
        } catch {}
    },

    // Check if we have an active linked file
    isLinked() {
        return !!this._handle;
    },

    // Get linked file name
    getFileName() {
        return this._handle ? this._handle.name : null;
    },

    // Link a new file (create or pick existing)
    async linkNewFile() {
        if (!this.isSupported()) return false;
        try {
            const handle = await window.showSaveFilePicker({
                suggestedName: `APF_Data_${new Date().toISOString().split('T')[0]}.apf`,
                types: [{ description: 'APF Encrypted Data', accept: { 'application/octet-stream': ['.apf'] } }]
            });
            this._handle = handle;
            await this._persistHandle(handle);
            return true;
        } catch (err) {
            if (err.name !== 'AbortError') console.error('Link new file failed:', err);
            return false;
        }
    },

    // Link an existing file
    async linkExistingFile() {
        if (!this.isSupported()) return null;
        try {
            const [handle] = await window.showOpenFilePicker({
                types: [{ description: 'APF Encrypted Data', accept: { 'application/octet-stream': ['.apf'] } }]
            });
            this._handle = handle;
            await this._persistHandle(handle);
            return handle;
        } catch (err) {
            if (err.name !== 'AbortError') console.error('Link existing file failed:', err);
            return null;
        }
    },

    // Unlink file
    async unlink() {
        this._handle = null;
        await this._clearPersistedHandle();
    },

    // Verify permission (may prompt user)
    async verifyPermission(readWrite = true) {
        if (!this._handle) return false;
        const mode = readWrite ? 'readwrite' : 'read';
        if ((await this._handle.queryPermission({ mode })) === 'granted') return true;
        if ((await this._handle.requestPermission({ mode })) === 'granted') return true;
        return false;
    },

    // Write encrypted data directly to the linked file
    async writeToFile(password) {
        if (!this._handle) return false;
        try {
            if (!(await this.verifyPermission(true))) return false;
            const allData = { _meta: { app: 'APF Dashboard', version: 2, savedAt: new Date().toISOString() } };
            ENCRYPTED_DATA_KEYS.forEach(k => { allData[k] = DB.get(k); });
            const encrypted = await CryptoEngine.encrypt(password, allData);
            const writable = await this._handle.createWritable();
            await writable.write(encrypted);
            await writable.close();
            const now = new Date().toISOString();
            localStorage.setItem(EncryptedCache.SAVE_TIME_KEY, now);
            lastEncSaveTime = now;
            return true;
        } catch (err) {
            console.error('File write failed:', err);
            return false;
        }
    },

    // Read and decrypt data from the linked file
    async readFromFile(password) {
        if (!this._handle) return null;
        try {
            if (!(await this.verifyPermission(false))) return null;
            const file = await this._handle.getFile();
            const buffer = await file.arrayBuffer();
            return await CryptoEngine.decrypt(password, buffer);
        } catch (err) {
            console.error('File read failed:', err);
            return null;
        }
    },

    // Try to restore the persisted handle from a previous session
    async restoreHandle() {
        const handle = await this._loadPersistedHandle();
        if (handle) { this._handle = handle; return true; }
        return false;
    }
};

// Session password (kept in memory for auto-cache)
let _sessionPassword = null;

// Session persistence across page refresh (sessionStorage — cleared on tab close)
const SessionPersist = {
    _KEY: 'apf_session_token',
    save(password) {
        try { sessionStorage.setItem(this._KEY, btoa(password)); } catch {}
    },
    restore() {
        try {
            const t = sessionStorage.getItem(this._KEY);
            return t ? atob(t) : null;
        } catch { return null; }
    },
    clear() {
        try { sessionStorage.removeItem(this._KEY); } catch {}
    }
};

// Unsaved changes tracking
let hasUnsavedChanges = false;
let lastEncSaveTime = null;
const ENCRYPTED_DATA_KEYS = ['visits', 'trainings', 'observations', 'resources', 'notes', 'ideas', 'reflections', 'contacts', 'plannerTasks', 'goalTargets', 'followupStatus'];

function markUnsavedChanges() {
    hasUnsavedChanges = true;
    const badge = document.getElementById('encUnsavedBadge');
    if (badge) badge.style.display = '';
    // Auto-save debounced
    scheduleAutoSave();
}

function clearUnsavedChanges() {
    hasUnsavedChanges = false;
    const badge = document.getElementById('encUnsavedBadge');
    if (badge) badge.style.display = 'none';
}

// Debounced auto-save: writes to linked file + browser cache after 2s of inactivity
let _autoSaveTimer = null;
let _autoSaveBusy = false;

async function performAutoSave() {
    if (!_sessionPassword || _autoSaveBusy) return;
    _autoSaveBusy = true;
    try {
        // 1. Write directly to linked .apf file (if linked)
        if (FileLink.isLinked()) {
            await FileLink.writeToFile(_sessionPassword);
        }
        // 2. Also save to browser cache as fallback
        await EncryptedCache.save(_sessionPassword);
        clearUnsavedChanges();
        updateEncryptedFileStatus();
    } catch (err) {
        console.error('Auto-save failed:', err);
    }
    _autoSaveBusy = false;
}

function scheduleAutoSave() {
    if (!_sessionPassword) return;
    if (_autoSaveTimer) clearTimeout(_autoSaveTimer);
    _autoSaveTimer = setTimeout(performAutoSave, 2000);
}

// Periodic auto-save every 30 seconds (safety net)
let _periodicSaveInterval = null;
function startPeriodicSave() {
    if (_periodicSaveInterval) clearInterval(_periodicSaveInterval);
    _periodicSaveInterval = setInterval(() => {
        if (hasUnsavedChanges && _sessionPassword) {
            performAutoSave();
        }
    }, 30000);
}
function stopPeriodicSave() {
    if (_periodicSaveInterval) { clearInterval(_periodicSaveInterval); _periodicSaveInterval = null; }
}

// Wrap DB.set to track changes
const _originalDBSet = DB.set.bind(DB);
DB.set = function(key, data) {
    _originalDBSet(key, data);
    if (ENCRYPTED_DATA_KEYS.includes(key)) {
        markUnsavedChanges();
    }
};

async function getEncryptionPassword() {
    // Use session password if available
    if (_sessionPassword) return _sessionPassword;
    return new Promise((resolve) => {
        const pwd = prompt('Enter your password to encrypt/decrypt the file:');
        resolve(pwd);
    });
}

async function saveEncryptedFile() {
    if (!PasswordManager.isPasswordSet()) {
        showToast('Please set a password first (below) to encrypt files', 'error');
        return;
    }

    const pwd = await getEncryptionPassword();
    if (!pwd) return;

    // Verify password
    const hash = await PasswordManager.hashPassword(pwd);
    if (hash !== PasswordManager.getStoredHash()) {
        showToast('Incorrect password', 'error');
        return;
    }

    try {
        showToast('Encrypting data...', 'info');
        const allData = { _meta: { app: 'APF Dashboard', version: 2, exportedAt: new Date().toISOString() } };
        ENCRYPTED_DATA_KEYS.forEach(k => { allData[k] = DB.get(k); });

        // If linked file exists, write there too
        if (FileLink.isLinked()) {
            await FileLink.writeToFile(pwd);
        }

        // Download a copy
        const encrypted = await CryptoEngine.encrypt(pwd, allData);
        const blob = new Blob([encrypted], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const d = new Date();
        a.href = url;
        a.download = `APF_Data_${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}.apf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        lastEncSaveTime = new Date().toISOString();
        await EncryptedCache.save(pwd);
        clearUnsavedChanges();
        updateEncryptedFileStatus();
        showToast('Encrypted file saved! 🔐');
    } catch (err) {
        console.error('Encryption failed:', err);
        showToast('Encryption failed: ' + err.message, 'error');
    }
}

async function loadEncryptedFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (!file.name.endsWith('.apf')) {
        showToast('Please select an .apf encrypted file', 'error');
        event.target.value = '';
        return;
    }

    if (!confirm('⚠️ LOAD ENCRYPTED FILE\n\nThis will REPLACE all current data with the data from the encrypted file.\n\nContinue?')) {
        event.target.value = '';
        return;
    }

    const pwd = await getEncryptionPassword();
    if (!pwd) { event.target.value = ''; return; }

    try {
        showToast('Decrypting file...', 'info');
        const buffer = await file.arrayBuffer();
        const data = await CryptoEngine.decrypt(pwd, buffer);

        if (!data._meta || data._meta.app !== 'APF Dashboard') {
            showToast('Invalid file — not an APF Dashboard backup', 'error');
            event.target.value = '';
            return;
        }

        // Load all data into in-memory store
        DB.clear();
        ENCRYPTED_DATA_KEYS.forEach(k => {
            if (data[k] !== undefined && Array.isArray(data[k])) {
                _originalDBSet(k, data[k]);
            }
        });

        // Also set the password from the file's password
        if (!PasswordManager.isPasswordSet()) {
            const hash = await PasswordManager.hashPassword(pwd);
            PasswordManager.setHash(hash);
        }

        lastEncSaveTime = new Date().toISOString();
        // Sync to linked file + browser cache
        if (FileLink.isLinked()) await FileLink.writeToFile(pwd);
        await EncryptedCache.save(pwd);
        clearUnsavedChanges();
        updateEncryptedFileStatus();
        showToast('Data restored from encrypted file! 🔓', 'success');
        setTimeout(() => navigateTo('dashboard'), 500);
    } catch (err) {
        console.error('Decryption failed:', err);
        if (err.message.includes('Not a valid')) {
            showToast('Not a valid APF encrypted file', 'error');
        } else {
            showToast('Decryption failed — wrong password or corrupted file', 'error');
        }
    }
    event.target.value = '';
}

function updateEncryptedFileStatus() {
    const el = document.getElementById('encryptedFileStatus');
    if (!el) return;

    const lastSave = lastEncSaveTime || EncryptedCache.getLastSaveTime();
    const hasPwd = PasswordManager.isPasswordSet();
    const linked = FileLink.isLinked();
    const fname = FileLink.getFileName();

    if (!hasPwd) {
        el.innerHTML = '<div class="enc-status-row warning"><i class="fas fa-exclamation-triangle"></i> Set a password first to enable encrypted storage</div>';
    } else {
        let html = '';
        // File link status
        if (linked) {
            html += `<div class="enc-status-row linked">
                <i class="fas fa-link"></i>
                <span>Linked to <strong>${escapeHtml(fname)}</strong> — auto-reading &amp; writing</span>
                <button class="btn btn-outline" onclick="unlinkFile()" style="padding:5px 12px;font-size:11px;border-radius:8px;"><i class="fas fa-unlink"></i> Unlink</button>
            </div>`;
        } else if (FileLink.isSupported()) {
            html += `<div class="enc-status-row unlinked">
                <i class="fas fa-unlink"></i>
                <span>No file linked — link one for auto read/write</span>
                <button class="btn btn-outline" onclick="linkFile()" style="padding:5px 12px;font-size:11px;border-radius:8px;"><i class="fas fa-link"></i> Link File</button>
            </div>`;
        }
        // Last save time
        if (lastSave) {
            const d = new Date(lastSave);
            const timeStr = d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
            html += `<div class="enc-status-row saved"><i class="fas fa-check-circle"></i> Last auto-saved: ${escapeHtml(timeStr)}${hasUnsavedChanges ? ' <span class="unsaved-badge">Saving...</span>' : ''}</div>`;
        } else {
            html += '<div class="enc-status-row no-save"><i class="fas fa-info-circle"></i> No data saved yet — make changes and they\'ll auto-save</div>';
        }
        el.innerHTML = html;
    }
}

// Link / Unlink file actions
async function linkFile() {
    if (!PasswordManager.isPasswordSet()) {
        showToast('Set a password first', 'error');
        return;
    }
    const choice = confirm('Do you want to:\n\nOK = Create a NEW .apf file\nCancel = Open an EXISTING .apf file');
    let success = false;
    if (choice) {
        success = await FileLink.linkNewFile();
        if (success && _sessionPassword) {
            await FileLink.writeToFile(_sessionPassword);
            showToast(`File created & linked: ${FileLink.getFileName()} 📂`);
        }
    } else {
        const handle = await FileLink.linkExistingFile();
        if (handle) {
            success = true;
            // Read data from the linked file
            try {
                const data = await FileLink.readFromFile(_sessionPassword);
                if (data && data._meta && data._meta.app === 'APF Dashboard') {
                    if (confirm('Load data from this file? (This will replace current data)')) {
                        DB.clear();
                        ENCRYPTED_DATA_KEYS.forEach(k => {
                            if (data[k] !== undefined && Array.isArray(data[k])) {
                                _originalDBSet(k, data[k]);
                            }
                        });
                        lastEncSaveTime = new Date().toISOString();
                        clearUnsavedChanges();
                        navigateTo('dashboard');
                    }
                }
                showToast(`File linked: ${FileLink.getFileName()} 📂`);
            } catch {
                showToast('File linked but could not read — wrong password?', 'error');
            }
        }
    }
    if (success) {
        updateEncryptedFileStatus();
        startPeriodicSave();
    }
}

async function unlinkFile() {
    await FileLink.unlink();
    updateEncryptedFileStatus();
    showToast('File unlinked. Auto-save still goes to browser cache.', 'info');
}

let autoLockTimer = null;
let isAppUnlocked = false;

function resetAutoLockTimer() {
    if (autoLockTimer) clearTimeout(autoLockTimer);
    const mins = PasswordManager.getAutoLockMinutes();
    if (mins > 0 && PasswordManager.isPasswordSet() && isAppUnlocked) {
        autoLockTimer = setTimeout(() => {
            lockApp();
            showToast('Auto-locked due to inactivity', 'info');
        }, mins * 60 * 1000);
    }
}

function initAutoLock() {
    ['click', 'keydown', 'mousemove', 'touchstart', 'scroll'].forEach(evt => {
        document.addEventListener(evt, resetAutoLockTimer, { passive: true });
    });
    resetAutoLockTimer();
}

function showLockScreen(mode) {
    const lockScreen = document.getElementById('lockScreen');
    const subtitle = document.getElementById('lockSubtitle');
    const confirmGroup = document.getElementById('lockConfirmGroup');
    const submitBtn = document.getElementById('lockSubmitBtn');
    const errorEl = document.getElementById('lockError');

    lockScreen.style.display = 'flex';
    errorEl.textContent = '';
    document.getElementById('lockPassword').value = '';

    if (mode === 'setup') {
        subtitle.textContent = 'Create a password to protect your dashboard';
        confirmGroup.style.display = '';
        document.getElementById('lockPasswordConfirm').value = '';
        submitBtn.innerHTML = '<i class="fas fa-lock"></i> Set Password & Enter';
        lockScreen.dataset.mode = 'setup';
    } else {
        subtitle.textContent = 'Enter your password to continue';
        confirmGroup.style.display = 'none';
        submitBtn.innerHTML = '<i class="fas fa-unlock"></i> Unlock';
        lockScreen.dataset.mode = 'unlock';
    }

    // Hide emergency reset & reset tap counter
    const emergencyEl = document.getElementById('lockEmergencyReset');
    if (emergencyEl) emergencyEl.style.display = 'none';
    lockIconTapCount = 0;

    setTimeout(() => document.getElementById('lockPassword').focus(), 100);
}

function hideLockScreen() {
    document.getElementById('lockScreen').style.display = 'none';
    isAppUnlocked = true;
    resetAutoLockTimer();
    updatePasswordUI();
    updateSidebarLockBtn();
}

async function handlePasswordSubmit(e) {
    e.preventDefault();
    const errorEl = document.getElementById('lockError');
    const password = document.getElementById('lockPassword').value;
    const lockScreen = document.getElementById('lockScreen');
    const mode = lockScreen.dataset.mode;

    if (mode === 'setup') {
        const confirm = document.getElementById('lockPasswordConfirm').value;
        if (password.length < 4) {
            errorEl.textContent = 'Password must be at least 4 characters';
            shakeContainer();
            return;
        }
        if (password !== confirm) {
            errorEl.textContent = 'Passwords do not match';
            shakeContainer();
            return;
        }
        const hash = await PasswordManager.hashPassword(password);
        PasswordManager.setHash(hash);
        _sessionPassword = password;
        SessionPersist.save(password);
        hideLockScreen();
        showToast('Password set! Your dashboard is now protected 🔒');
        showWelcomeScreen();
    } else {
        const hash = await PasswordManager.hashPassword(password);
        if (hash === PasswordManager.getStoredHash()) {
            _sessionPassword = password;
            SessionPersist.save(password);
            hideLockScreen();
            // If app already running (just locked), go back directly
            if (appInitialized) {
                isAppUnlocked = true;
                initApp();
                startPeriodicSave();
            } else {
                // Try: 1) Linked file → 2) Browser cache → 3) Welcome screen
                let loaded = false;

                // Try linked .apf file first
                if (FileLink.isLinked()) {
                    try {
                        const data = await FileLink.readFromFile(password);
                        if (data && data._meta && data._meta.app === 'APF Dashboard') {
                            DB.clear();
                            ENCRYPTED_DATA_KEYS.forEach(k => {
                                if (data[k] !== undefined && Array.isArray(data[k])) {
                                    _originalDBSet(k, data[k]);
                                }
                            });
                            lastEncSaveTime = EncryptedCache.getLastSaveTime();
                            clearUnsavedChanges();
                            isAppUnlocked = true;
                            initApp();
                            startPeriodicSave();
                            const fname = FileLink.getFileName();
                            showToast(`Data loaded from ${fname || 'linked file'} 📂`, 'success');
                            loaded = true;
                        }
                    } catch (err) {
                        console.error('Linked file read failed:', err);
                    }
                }

                // Try browser cache
                if (!loaded && EncryptedCache.exists()) {
                    try {
                        const data = await EncryptedCache.load(password);
                        if (data._meta && data._meta.app === 'APF Dashboard') {
                            DB.clear();
                            ENCRYPTED_DATA_KEYS.forEach(k => {
                                if (data[k] !== undefined && Array.isArray(data[k])) {
                                    _originalDBSet(k, data[k]);
                                }
                            });
                            lastEncSaveTime = EncryptedCache.getLastSaveTime();
                            clearUnsavedChanges();
                            isAppUnlocked = true;
                            initApp();
                            startPeriodicSave();
                            showToast('Welcome back! Data loaded automatically 🔓', 'success');
                            loaded = true;
                        }
                    } catch (err) {
                        console.error('Cache load failed:', err);
                        EncryptedCache.clear();
                    }
                }

                if (!loaded) {
                    showWelcomeScreen();
                }
            }
        } else {
            errorEl.textContent = 'Incorrect password';
            shakeContainer();
            document.getElementById('lockPassword').value = '';
            document.getElementById('lockPassword').focus();
        }
    }
}

function shakeContainer() {
    const container = document.querySelector('.lock-container');
    container.classList.remove('lock-shake');
    void container.offsetWidth;
    container.classList.add('lock-shake');
}

function lockApp() {
    isAppUnlocked = false;
    SessionPersist.clear();
    if (autoLockTimer) clearTimeout(autoLockTimer);
    showLockScreen('unlock');
}

function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    const icon = btn.querySelector('i');
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.replace('fa-eye', 'fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.replace('fa-eye-slash', 'fa-eye');
    }
}

// Hidden emergency reset — revealed by tapping lock icon 5 times
let lockIconTapCount = 0;
let lockIconTapTimer = null;

function handleLockIconTap() {
    lockIconTapCount++;
    if (lockIconTapTimer) clearTimeout(lockIconTapTimer);
    lockIconTapTimer = setTimeout(() => { lockIconTapCount = 0; }, 3000);

    if (lockIconTapCount >= 5) {
        const emergencyEl = document.getElementById('lockEmergencyReset');
        if (emergencyEl) emergencyEl.style.display = '';
        lockIconTapCount = 0;
    }
}

// Attach tap listener once DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const iconEl = document.getElementById('lockIconTap');
    if (iconEl) iconEl.addEventListener('click', handleLockIconTap);
});

function resetPasswordPrompt() {
    if (!confirm('⚠️ EMERGENCY RESET\n\nThis will PERMANENTLY DELETE all your visits, trainings, observations, notes, ideas, contacts, reflections, and everything else.\n\nThe password will also be removed.\n\nThis CANNOT be undone!')) return;
    const answer = prompt('Type ERASE ALL MY DATA to confirm:');
    if (answer !== 'ERASE ALL MY DATA') {
        showToast('Reset cancelled', 'info');
        const emergencyEl = document.getElementById('lockEmergencyReset');
        if (emergencyEl) emergencyEl.style.display = 'none';
        return;
    }
    DB.clear();
    lastEncSaveTime = null;
    _sessionPassword = null;
    clearUnsavedChanges();
    stopPeriodicSave();
    SessionPersist.clear();
    EncryptedCache.clear();
    FileLink.unlink();
    PasswordManager.removeHash();
    hideLockScreen();
    appInitialized = false;
    showToast('All data cleared. Password removed.', 'info');
    showWelcomeScreen();
}

// Password management from settings
async function openPasswordSetup() {
    showLockScreen('setup');
}

async function openPasswordChange() {
    const currentPwd = prompt('Enter your current password:');
    if (!currentPwd) return;
    const hash = await PasswordManager.hashPassword(currentPwd);
    if (hash !== PasswordManager.getStoredHash()) {
        showToast('Current password is incorrect', 'error');
        return;
    }
    showLockScreen('setup');
}

async function removePassword() {
    const currentPwd = prompt('Enter your current password to remove protection:');
    if (!currentPwd) return;
    const hash = await PasswordManager.hashPassword(currentPwd);
    if (hash !== PasswordManager.getStoredHash()) {
        showToast('Incorrect password', 'error');
        return;
    }
    PasswordManager.removeHash();
    SessionPersist.clear();
    if (autoLockTimer) clearTimeout(autoLockTimer);
    updatePasswordUI();
    updateSidebarLockBtn();
    showToast('Password protection removed 🔓');
}

function setAutoLockTime(value) {
    PasswordManager.setAutoLockMinutes(parseInt(value, 10));
    resetAutoLockTimer();
    showToast(`Auto-lock ${value === '0' ? 'disabled' : 'set to ' + value + ' min'}`);
}

function updatePasswordUI() {
    const isSet = PasswordManager.isPasswordSet();
    const statusEl = document.getElementById('passwordStatus');
    const statusText = document.getElementById('passwordStatusText');
    const setBtn = document.getElementById('btnSetPassword');
    const changeBtn = document.getElementById('btnChangePassword');
    const removeBtn = document.getElementById('btnRemovePassword');
    const autoLockSetting = document.getElementById('passwordAutoLockSetting');

    if (!statusEl) return;

    if (isSet) {
        statusEl.innerHTML = '<span class="status-badge active"><i class="fas fa-check-circle"></i> Password Active</span>';
        statusText.textContent = 'Your dashboard is password-protected.';
        setBtn.style.display = 'none';
        changeBtn.style.display = '';
        removeBtn.style.display = '';
        autoLockSetting.style.display = '';
        document.getElementById('autoLockTime').value = String(PasswordManager.getAutoLockMinutes());
    } else {
        statusEl.innerHTML = '<span class="status-badge inactive"><i class="fas fa-unlock"></i> Not Protected</span>';
        statusText.textContent = 'Protect your dashboard with a password. Data stays locked until you enter it.';
        setBtn.style.display = '';
        changeBtn.style.display = 'none';
        removeBtn.style.display = 'none';
        autoLockSetting.style.display = 'none';
    }
}

function updateSidebarLockBtn() {
    let btn = document.getElementById('sidebarLockBtn');
    if (PasswordManager.isPasswordSet()) {
        if (!btn) {
            btn = document.createElement('button');
            btn.id = 'sidebarLockBtn';
            btn.className = 'sidebar-lock-btn';
            btn.title = 'Lock Dashboard';
            btn.innerHTML = '<i class="fas fa-lock"></i>';
            btn.onclick = lockApp;
            const header = document.querySelector('.sidebar-header');
            if (header) {
                header.style.position = 'relative';
                header.appendChild(btn);
            }
        }
        btn.style.display = 'flex';
    } else if (btn) {
        btn.style.display = 'none';
    }
}

// ===== Navigation =====
function navigateTo(section) {
    // Update nav
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const navItem = document.querySelector(`[data-section="${section}"]`);
    if (navItem) navItem.classList.add('active');

    // Update sections
    document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
    const sec = document.getElementById(`section-${section}`);
    if (sec) {
        sec.classList.remove('active');
        // Re-trigger animation
        void sec.offsetWidth;
        sec.classList.add('active');
    }

    // Close mobile sidebar
    closeMobileSidebar();

    // Refresh section data
    refreshSection(section);
}

function refreshSection(section) {
    switch (section) {
        case 'dashboard': renderDashboard(); break;
        case 'visits': renderVisits(); break;
        case 'training': renderTrainings(); break;
        case 'observations': renderObservations(); break;
        case 'reports': break;
        case 'resources': renderResources(); break;
        case 'excel': break;
        case 'notes': renderNotes(); break;
        case 'planner': renderPlanner(); break;
        case 'goals': renderGoals(); break;
        case 'analytics': renderAnalytics(); break;
        case 'followups': renderFollowups(); break;
        case 'ideas': renderIdeas(); break;
        case 'schools': renderSchoolProfiles(); break;
        case 'reflections': initReflectionMonthFilter(); renderReflections(); break;
        case 'contacts': renderContacts(); break;
        case 'backup': renderBackupInfo(); break;
    }
}

// ===== Mobile Sidebar =====
function closeMobileSidebar() {
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebarOverlay').classList.remove('active');
}

// ===== Desktop Sidebar Toggle =====
function toggleDesktopSidebar() {
    const sidebar = document.getElementById('sidebar');
    const body = document.body;
    const btn = document.getElementById('sidebarToggle');
    const isCollapsed = sidebar.classList.toggle('collapsed');
    body.classList.toggle('sidebar-collapsed', isCollapsed);
    
    if (btn) {
        btn.title = isCollapsed ? 'Expand sidebar' : 'Collapse sidebar';
    }
    
    // Add tooltip data to nav items when collapsed
    document.querySelectorAll('.nav-item').forEach(item => {
        const label = item.querySelector('span')?.textContent || '';
        item.setAttribute('data-tooltip', label);
    });
    
    // Save preference
    try { localStorage.setItem('apf_sidebar_collapsed', isCollapsed ? '1' : '0'); } catch(e) {}
    
    // Trigger resize for charts
    setTimeout(() => window.dispatchEvent(new Event('resize')), 350);
}

function restoreSidebarState() {
    try {
        const saved = localStorage.getItem('apf_sidebar_collapsed');
        if (saved === '1') {
            const sidebar = document.getElementById('sidebar');
            const body = document.body;
            const btn = document.getElementById('sidebarToggle');
            sidebar.classList.add('collapsed');
            body.classList.add('sidebar-collapsed');
            if (btn) btn.title = 'Expand sidebar';
            document.querySelectorAll('.nav-item').forEach(item => {
                const label = item.querySelector('span')?.textContent || '';
                item.setAttribute('data-tooltip', label);
            });
        }
    } catch(e) {}
}

// ===== Toast Notifications =====
function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    const icons = { success: 'fa-check-circle', error: 'fa-exclamation-circle', info: 'fa-info-circle' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<i class="fas ${icons[type] || 'fa-info-circle'}"></i><span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ===== Modal Functions =====
function openModal(id) {
    document.getElementById(id).classList.add('active');
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
}

// ===== Quick Add =====
function openQuickAdd() {
    openModal('quickAddModal');
}

// ===== DASHBOARD =====
function renderDashboard() {
    const visits = DB.get('visits');
    const trainings = DB.get('trainings');
    const observations = DB.get('observations');

    // Date
    const now = new Date();
    const opts = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
    document.getElementById('dashboardDate').textContent = now.toLocaleDateString('en-IN', opts);

    // Metrics
    document.getElementById('metricTotalVisits').textContent = visits.length;
    document.getElementById('metricTrainings').textContent = trainings.length;
    document.getElementById('metricObservations').textContent = observations.length;

    // Unique schools
    const schools = new Set();
    visits.forEach(v => schools.add((v.school || '').toLowerCase().trim()));
    observations.forEach(o => schools.add((o.school || '').toLowerCase().trim()));
    document.getElementById('metricSchools').textContent = schools.size;

    // Upcoming visits
    const upcoming = visits
        .filter(v => v.status === 'planned' && new Date(v.date) >= new Date(now.toDateString()))
        .sort((a, b) => new Date(a.date) - new Date(b.date))
        .slice(0, 5);

    const upcomingEl = document.getElementById('upcomingVisitsList');
    if (upcoming.length === 0) {
        upcomingEl.innerHTML = `<div class="empty-state small"><i class="fas fa-calendar-plus"></i><p>No upcoming visits scheduled</p></div>`;
    } else {
        upcomingEl.innerHTML = upcoming.map(v => {
            const d = new Date(v.date);
            const day = d.getDate();
            const mon = d.toLocaleString('en', { month: 'short' });
            return `<div class="upcoming-item">
                <div class="upcoming-date">${day}<br>${mon}</div>
                <div class="upcoming-info">
                    <h4>${escapeHtml(v.school)}</h4>
                    <p>${escapeHtml(v.purpose || '')}</p>
                </div>
            </div>`;
        }).join('');
    }

    // Recent activity
    const allItems = [
        ...visits.map(v => ({ type: 'visit', icon: 'fa-school', cls: 'visit', text: `Visit to <strong>${escapeHtml(v.school)}</strong> — ${v.status}`, time: v.createdAt || v.date, date: v.date })),
        ...trainings.map(t => ({ type: 'training', icon: 'fa-chalkboard-teacher', cls: 'training', text: `Training: <strong>${escapeHtml(t.title)}</strong>`, time: t.createdAt || t.date, date: t.date })),
        ...observations.map(o => ({ type: 'observation', icon: 'fa-clipboard-check', cls: 'observation', text: `Observation at <strong>${escapeHtml(o.school)}</strong> — ${escapeHtml(o.subject)}`, time: o.createdAt || o.date, date: o.date })),
    ].sort((a, b) => new Date(b.time) - new Date(a.time)).slice(0, 8);

    const actEl = document.getElementById('recentActivityList');
    if (allItems.length === 0) {
        actEl.innerHTML = `<div class="empty-state small"><i class="fas fa-history"></i><p>No recent activity</p></div>`;
    } else {
        actEl.innerHTML = allItems.map(a => {
            const timeAgo = getTimeAgo(a.time);
            return `<div class="activity-item">
                <div class="activity-icon ${a.cls}"><i class="fas ${a.icon}"></i></div>
                <div class="activity-content">
                    <p>${a.text}</p>
                    <div class="activity-time">${timeAgo}</div>
                </div>
            </div>`;
        }).join('');
    }

    // Dashboard mini-charts
    renderDashboardCharts(visits, trainings, observations);
}

// ===== Dashboard Mini Charts =====
let dashboardCharts = {};

function renderDashboardCharts(visits, trainings, observations) {
    // Monthly activity line chart (last 6 months)
    if (dashboardCharts.monthly) dashboardCharts.monthly.destroy();
    const monthlyCanvas = document.getElementById('dashboardMonthlyChart');
    if (monthlyCanvas) {
        const now = new Date();
        const labels = [];
        const vData = [], tData = [], oData = [];
        for (let i = -5; i <= 0; i++) {
            const d = new Date(now.getFullYear(), now.getMonth() + i, 1);
            labels.push(d.toLocaleDateString('en', { month: 'short' }));
            const y = d.getFullYear(), m = d.getMonth();
            vData.push(visits.filter(v => { const vd = new Date(v.date); return vd.getFullYear() === y && vd.getMonth() === m; }).length);
            tData.push(trainings.filter(t => { const td = new Date(t.date); return td.getFullYear() === y && td.getMonth() === m; }).length);
            oData.push(observations.filter(o => { const od = new Date(o.date); return od.getFullYear() === y && od.getMonth() === m; }).length);
        }
        dashboardCharts.monthly = new Chart(monthlyCanvas, {
            type: 'line',
            data: {
                labels,
                datasets: [
                    { label: 'Visits', data: vData, borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.08)', fill: true, tension: 0.4, pointRadius: 4 },
                    { label: 'Trainings', data: tData, borderColor: '#8b5cf6', backgroundColor: 'rgba(139,92,246,0.08)', fill: true, tension: 0.4, pointRadius: 4 },
                    { label: 'Observations', data: oData, borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.08)', fill: true, tension: 0.4, pointRadius: 4 },
                ]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#9ca3b8', font: { size: 11 } } } },
                scales: {
                    x: { ticks: { color: '#6b7280' }, grid: { color: 'rgba(255,255,255,0.04)' } },
                    y: { beginAtZero: true, ticks: { color: '#6b7280', stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.04)' } }
                }
            }
        });
    }

    // Visit status doughnut
    if (dashboardCharts.status) dashboardCharts.status.destroy();
    const statusCanvas = document.getElementById('dashboardStatusChart');
    if (statusCanvas) {
        const statusCount = { completed: 0, planned: 0, cancelled: 0 };
        visits.forEach(v => { if (statusCount[v.status] !== undefined) statusCount[v.status]++; });
        const hasData = Object.values(statusCount).some(v => v > 0);
        if (hasData) {
            dashboardCharts.status = new Chart(statusCanvas, {
                type: 'doughnut',
                data: {
                    labels: ['Completed', 'Planned', 'Cancelled'],
                    datasets: [{ data: [statusCount.completed, statusCount.planned, statusCount.cancelled], backgroundColor: ['#10b981', '#3b82f6', '#ef4444'], borderWidth: 0 }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { position: 'right', labels: { color: '#9ca3b8', font: { size: 12 } } } },
                    cutout: '65%',
                }
            });
            statusCanvas.style.display = '';
            const emptyMsg = statusCanvas.parentElement.querySelector('.empty-state');
            if (emptyMsg) emptyMsg.remove();
        } else {
            statusCanvas.style.display = 'none';
            if (!statusCanvas.parentElement.querySelector('.empty-state')) {
                statusCanvas.insertAdjacentHTML('afterend', '<div class="empty-state small"><i class="fas fa-chart-pie"></i><p>Add visits to see status breakdown</p></div>');
            }
        }
    }
}

// ===== SCHOOL VISITS =====
function openVisitModal(id) {
    document.getElementById('visitForm').reset();
    document.getElementById('visitId').value = '';
    document.getElementById('visitDate').value = new Date().toISOString().split('T')[0];
    document.getElementById('visitModalTitle').innerHTML = '<i class="fas fa-school"></i> New School Visit';

    if (id) {
        const visits = DB.get('visits');
        const v = visits.find(x => x.id === id);
        if (v) {
            document.getElementById('visitId').value = v.id;
            document.getElementById('visitSchool').value = v.school;
            document.getElementById('visitBlock').value = v.block || '';
            document.getElementById('visitDate').value = v.date;
            document.getElementById('visitStatus').value = v.status;
            document.getElementById('visitPurpose').value = v.purpose || 'Classroom Observation';
            document.getElementById('visitNotes').value = v.notes || '';
            document.getElementById('visitFollowUp').value = v.followUp || '';
            document.getElementById('visitModalTitle').innerHTML = '<i class="fas fa-school"></i> Edit Visit';
        }
    }
    openModal('visitModal');
}

function saveVisit(e) {
    e.preventDefault();
    const visits = DB.get('visits');
    const id = document.getElementById('visitId').value;
    const data = {
        school: document.getElementById('visitSchool').value.trim(),
        block: document.getElementById('visitBlock').value.trim(),
        date: document.getElementById('visitDate').value,
        status: document.getElementById('visitStatus').value,
        purpose: document.getElementById('visitPurpose').value,
        notes: document.getElementById('visitNotes').value.trim(),
        followUp: document.getElementById('visitFollowUp').value.trim(),
    };

    if (id) {
        const idx = visits.findIndex(v => v.id === id);
        if (idx > -1) {
            visits[idx] = { ...visits[idx], ...data, updatedAt: new Date().toISOString() };
        }
        showToast('Visit updated successfully');
    } else {
        data.id = DB.generateId();
        data.createdAt = new Date().toISOString();
        visits.push(data);
        showToast('Visit added successfully');
    }

    DB.set('visits', visits);
    closeModal('visitModal');
    renderVisits();
    renderDashboard();
    refreshPlannerIfVisible();
}

function deleteVisit(id) {
    if (!confirm('Delete this school visit?')) return;
    let visits = DB.get('visits');
    visits = visits.filter(v => v.id !== id);
    DB.set('visits', visits);
    showToast('Visit deleted', 'info');
    renderVisits();
    renderDashboard();
    refreshPlannerIfVisible();
}

function renderVisits() {
    const visits = DB.get('visits');
    const container = document.getElementById('visitsContainer');
    const statusFilter = document.getElementById('visitStatusFilter').value;
    const search = document.getElementById('visitSearchInput').value.toLowerCase();

    let filtered = visits.filter(v => {
        if (statusFilter !== 'all' && v.status !== statusFilter) return false;
        if (search && !(v.school || '').toLowerCase().includes(search) && !(v.block || '').toLowerCase().includes(search)) return false;
        return true;
    }).sort((a, b) => new Date(b.date) - new Date(a.date));

    if (filtered.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-school"></i><h3>No visits found</h3><p>${visits.length === 0 ? 'Start planning your visits by clicking "New Visit"' : 'Try adjusting your filters'}</p></div>`;
        return;
    }

    container.innerHTML = filtered.map(v => {
        const d = new Date(v.date);
        const day = d.getDate();
        const month = d.toLocaleString('en', { month: 'short' });
        const badgeClass = `badge-${v.status}`;
        return `<div class="visit-item" onclick="openVisitModal('${v.id}')">
            <div class="visit-date-badge">
                <div class="day">${day}</div>
                <div class="month">${month}</div>
            </div>
            <div class="visit-info">
                <h4>${escapeHtml(v.school)}</h4>
                <p>${escapeHtml(v.purpose || '')}</p>
                <div class="visit-meta">
                    ${v.block ? `<span><i class="fas fa-map-marker-alt"></i> ${escapeHtml(v.block)}</span>` : ''}
                    <span><i class="fas fa-calendar"></i> ${d.toLocaleDateString('en-IN')}</span>
                </div>
            </div>
            <div class="visit-actions">
                <span class="badge ${badgeClass}">${v.status}</span>
                <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteVisit('${v.id}')"><i class="fas fa-trash"></i></button>
            </div>
        </div>`;
    }).join('');
}

function setVisitView(view) {
    document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`.view-btn[data-view="${view}"]`)?.classList.add('active');
    // For now, both views show list (calendar view can be extended)
    renderVisits();
}

// ===== TEACHER TRAINING =====
function openTrainingModal(id) {
    document.getElementById('trainingForm').reset();
    document.getElementById('trainingId').value = '';
    document.getElementById('trainingDate').value = new Date().toISOString().split('T')[0];
    document.getElementById('trainingModalTitle').innerHTML = '<i class="fas fa-chalkboard-teacher"></i> New Training';

    if (id) {
        const trainings = DB.get('trainings');
        const t = trainings.find(x => x.id === id);
        if (t) {
            document.getElementById('trainingId').value = t.id;
            document.getElementById('trainingTitle').value = t.title;
            document.getElementById('trainingTopic').value = t.topic || '';
            document.getElementById('trainingDate').value = t.date;
            document.getElementById('trainingDuration').value = t.duration || 3;
            document.getElementById('trainingVenue').value = t.venue || '';
            document.getElementById('trainingStatus').value = t.status;
            document.getElementById('trainingAttendees').value = t.attendees || '';
            document.getElementById('trainingTarget').value = t.target || 'Primary Teachers';
            document.getElementById('trainingNotes').value = t.notes || '';
            document.getElementById('trainingFeedback').value = t.feedback || '';
            document.getElementById('trainingModalTitle').innerHTML = '<i class="fas fa-chalkboard-teacher"></i> Edit Training';
        }
    }
    openModal('trainingModal');
}

function saveTraining(e) {
    e.preventDefault();
    const trainings = DB.get('trainings');
    const id = document.getElementById('trainingId').value;
    const data = {
        title: document.getElementById('trainingTitle').value.trim(),
        topic: document.getElementById('trainingTopic').value.trim(),
        date: document.getElementById('trainingDate').value,
        duration: parseFloat(document.getElementById('trainingDuration').value) || 3,
        venue: document.getElementById('trainingVenue').value.trim(),
        status: document.getElementById('trainingStatus').value,
        attendees: parseInt(document.getElementById('trainingAttendees').value) || 0,
        target: document.getElementById('trainingTarget').value,
        notes: document.getElementById('trainingNotes').value.trim(),
        feedback: document.getElementById('trainingFeedback').value.trim(),
    };

    if (id) {
        const idx = trainings.findIndex(t => t.id === id);
        if (idx > -1) {
            trainings[idx] = { ...trainings[idx], ...data, updatedAt: new Date().toISOString() };
        }
        showToast('Training updated successfully');
    } else {
        data.id = DB.generateId();
        data.createdAt = new Date().toISOString();
        trainings.push(data);
        showToast('Training added successfully');
    }

    DB.set('trainings', trainings);
    closeModal('trainingModal');
    renderTrainings();
    renderDashboard();
    refreshPlannerIfVisible();
}

function deleteTraining(id) {
    if (!confirm('Delete this training session?')) return;
    let trainings = DB.get('trainings');
    trainings = trainings.filter(t => t.id !== id);
    DB.set('trainings', trainings);
    showToast('Training deleted', 'info');
    renderTrainings();
    renderDashboard();
    refreshPlannerIfVisible();
}

function renderTrainings() {
    const trainings = DB.get('trainings');
    const container = document.getElementById('trainingsContainer');
    const statusFilter = document.getElementById('trainingStatusFilter').value;
    const search = document.getElementById('trainingSearchInput').value.toLowerCase();

    let filtered = trainings.filter(t => {
        if (statusFilter !== 'all' && t.status !== statusFilter) return false;
        if (search && !t.title.toLowerCase().includes(search) && !(t.topic || '').toLowerCase().includes(search)) return false;
        return true;
    }).sort((a, b) => new Date(b.date) - new Date(a.date));

    if (filtered.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-chalkboard-teacher"></i><h3>No training sessions found</h3><p>${trainings.length === 0 ? 'Create your first training by clicking "New Training"' : 'Try adjusting your filters'}</p></div>`;
        return;
    }

    container.innerHTML = filtered.map(t => {
        const d = new Date(t.date);
        const badgeClass = `badge-${t.status}`;
        return `<div class="training-card" onclick="openTrainingModal('${t.id}')">
            <div class="training-card-header">
                <div>
                    <h4>${escapeHtml(t.title)}</h4>
                    ${t.topic ? `<div class="training-topic">${escapeHtml(t.topic)}</div>` : ''}
                </div>
                <span class="badge ${badgeClass}">${t.status}</span>
            </div>
            <div class="training-details">
                <span class="training-detail"><i class="fas fa-calendar"></i> ${d.toLocaleDateString('en-IN')}</span>
                <span class="training-detail"><i class="fas fa-clock"></i> ${t.duration}h</span>
                ${t.attendees ? `<span class="training-detail"><i class="fas fa-users"></i> ${t.attendees} attendees</span>` : ''}
                ${t.venue ? `<span class="training-detail"><i class="fas fa-map-marker-alt"></i> ${escapeHtml(t.venue)}</span>` : ''}
                <span class="training-detail"><i class="fas fa-user-tag"></i> ${escapeHtml(t.target || 'Primary Teachers')}</span>
            </div>
            <div class="training-card-actions">
                <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); openTrainingModal('${t.id}')"><i class="fas fa-edit"></i> Edit</button>
                <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteTraining('${t.id}')"><i class="fas fa-trash"></i> Delete</button>
            </div>
        </div>`;
    }).join('');
}

// ===== OBSERVATIONS =====
let observationRatings = { engagement: 0, methodology: 0, tlm: 0 };

function initStarRatings() {
    document.querySelectorAll('.star-rating').forEach(group => {
        const field = group.dataset.field;
        group.querySelectorAll('i').forEach(star => {
            star.addEventListener('click', () => {
                const val = parseInt(star.dataset.value);
                observationRatings[field] = val;
                updateStars(group, val);
            });
            star.addEventListener('mouseenter', () => {
                const val = parseInt(star.dataset.value);
                highlightStars(group, val);
            });
            star.addEventListener('mouseleave', () => {
                updateStars(group, observationRatings[field]);
            });
        });
    });
}

function updateStars(group, val) {
    group.querySelectorAll('i').forEach(s => {
        s.classList.toggle('active', parseInt(s.dataset.value) <= val);
    });
}

function highlightStars(group, val) {
    updateStars(group, val);
}

function openObservationModal(id) {
    document.getElementById('observationForm').reset();
    document.getElementById('observationId').value = '';
    document.getElementById('observationDate').value = new Date().toISOString().split('T')[0];
    document.getElementById('observationModalTitle').innerHTML = '<i class="fas fa-clipboard-check"></i> New Observation';
    observationRatings = { engagement: 0, methodology: 0, tlm: 0 };
    document.querySelectorAll('.star-rating').forEach(g => updateStars(g, 0));

    if (id) {
        const observations = DB.get('observations');
        const o = observations.find(x => x.id === id);
        if (o) {
            document.getElementById('observationId').value = o.id;
            document.getElementById('observationSchool').value = o.school;
            document.getElementById('observationTeacher').value = o.teacher || '';
            document.getElementById('observationDate').value = o.date;
            document.getElementById('observationClass').value = o.class || 'Class 1';
            document.getElementById('observationSubject').value = o.subject;
            document.getElementById('observationTopic').value = o.topic || '';
            document.getElementById('observationStrengths').value = o.strengths || '';
            document.getElementById('observationAreas').value = o.areas || '';
            document.getElementById('observationSuggestions').value = o.suggestions || '';
            observationRatings = { engagement: o.engagement || 0, methodology: o.methodology || 0, tlm: o.tlm || 0 };
            updateStars(document.getElementById('ratingEngagement'), o.engagement || 0);
            updateStars(document.getElementById('ratingMethodology'), o.methodology || 0);
            updateStars(document.getElementById('ratingTLM'), o.tlm || 0);
            document.getElementById('observationModalTitle').innerHTML = '<i class="fas fa-clipboard-check"></i> Edit Observation';
        }
    }
    openModal('observationModal');
}

function saveObservation(e) {
    e.preventDefault();
    const observations = DB.get('observations');
    const id = document.getElementById('observationId').value;
    const data = {
        school: document.getElementById('observationSchool').value.trim(),
        teacher: document.getElementById('observationTeacher').value.trim(),
        date: document.getElementById('observationDate').value,
        class: document.getElementById('observationClass').value,
        subject: document.getElementById('observationSubject').value,
        topic: document.getElementById('observationTopic').value.trim(),
        engagement: observationRatings.engagement,
        methodology: observationRatings.methodology,
        tlm: observationRatings.tlm,
        strengths: document.getElementById('observationStrengths').value.trim(),
        areas: document.getElementById('observationAreas').value.trim(),
        suggestions: document.getElementById('observationSuggestions').value.trim(),
    };

    if (id) {
        const idx = observations.findIndex(o => o.id === id);
        if (idx > -1) {
            observations[idx] = { ...observations[idx], ...data, updatedAt: new Date().toISOString() };
        }
        showToast('Observation updated successfully');
    } else {
        data.id = DB.generateId();
        data.createdAt = new Date().toISOString();
        observations.push(data);
        showToast('Observation saved successfully');
    }

    DB.set('observations', observations);
    closeModal('observationModal');
    renderObservations();
    renderDashboard();
    refreshPlannerIfVisible();
}

function deleteObservation(id) {
    if (!confirm('Delete this observation?')) return;
    let observations = DB.get('observations');
    observations = observations.filter(o => o.id !== id);
    DB.set('observations', observations);
    showToast('Observation deleted', 'info');
    renderObservations();
    renderDashboard();
    refreshPlannerIfVisible();
}

function renderObservations() {
    const observations = DB.get('observations');
    const container = document.getElementById('observationsContainer');
    const subjectFilter = document.getElementById('observationSubjectFilter').value;
    const search = document.getElementById('observationSearchInput').value.toLowerCase();

    let filtered = observations.filter(o => {
        if (subjectFilter !== 'all' && o.subject !== subjectFilter) return false;
        if (search && !(o.school || '').toLowerCase().includes(search) && !(o.teacher || '').toLowerCase().includes(search)) return false;
        return true;
    }).sort((a, b) => new Date(b.date) - new Date(a.date));

    if (filtered.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-clipboard-check"></i><h3>No observations found</h3><p>${observations.length === 0 ? 'Start documenting classroom observations' : 'Try adjusting your filters'}</p></div>`;
        return;
    }

    container.innerHTML = filtered.map(o => {
        const d = new Date(o.date);
        const starsHtml = (val) => {
            let s = '';
            for (let i = 1; i <= 5; i++) s += `<i class="fas fa-star" style="color:${i <= val ? 'var(--accent)' : 'var(--text-muted)'}; font-size:10px;"></i>`;
            return s;
        };
        const preview = o.strengths || o.areas || o.suggestions || '';
        return `<div class="observation-item" onclick="openObservationModal('${o.id}')">
            <div class="observation-header">
                <h4>${escapeHtml(o.school)}</h4>
                <span class="observation-date">${d.toLocaleDateString('en-IN')}</span>
            </div>
            <div class="observation-meta-row">
                ${o.teacher ? `<span><i class="fas fa-user"></i> ${escapeHtml(o.teacher)}</span>` : ''}
                <span><i class="fas fa-book"></i> ${escapeHtml(o.subject)}</span>
                <span><i class="fas fa-graduation-cap"></i> ${escapeHtml(o.class || '')}</span>
                ${o.topic ? `<span><i class="fas fa-tag"></i> ${escapeHtml(o.topic)}</span>` : ''}
            </div>
            <div class="observation-ratings">
                <span class="mini-rating">Engagement: <span class="stars">${starsHtml(o.engagement)}</span></span>
                <span class="mini-rating">Methodology: <span class="stars">${starsHtml(o.methodology)}</span></span>
                <span class="mini-rating">TLM Use: <span class="stars">${starsHtml(o.tlm)}</span></span>
            </div>
            ${preview ? `<div class="observation-notes-preview">${escapeHtml(preview)}</div>` : ''}
            <div class="observation-item-actions">
                <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); openObservationModal('${o.id}')"><i class="fas fa-edit"></i> Edit</button>
                <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteObservation('${o.id}')"><i class="fas fa-trash"></i> Delete</button>
            </div>
        </div>`;
    }).join('');
}

// ===== RESOURCES =====
function openResourceModal(id) {
    document.getElementById('resourceForm').reset();
    document.getElementById('resourceId').value = '';
    document.getElementById('resourceModalTitle').innerHTML = '<i class="fas fa-book-open"></i> Add Resource';

    if (id) {
        const resources = DB.get('resources');
        const r = resources.find(x => x.id === id);
        if (r) {
            document.getElementById('resourceId').value = r.id;
            document.getElementById('resourceTitle').value = r.title;
            document.getElementById('resourceType').value = r.type;
            document.getElementById('resourceSubject').value = r.subject || 'Mathematics';
            document.getElementById('resourceGrade').value = r.grade || '';
            document.getElementById('resourceSource').value = r.source || '';
            document.getElementById('resourceDescription').value = r.description || '';
            document.getElementById('resourceTags').value = (r.tags || []).join(', ');
            document.getElementById('resourceModalTitle').innerHTML = '<i class="fas fa-book-open"></i> Edit Resource';
        }
    }
    openModal('resourceModal');
}

function saveResource(e) {
    e.preventDefault();
    const resources = DB.get('resources');
    const id = document.getElementById('resourceId').value;
    const tagsRaw = document.getElementById('resourceTags').value;
    const data = {
        title: document.getElementById('resourceTitle').value.trim(),
        type: document.getElementById('resourceType').value,
        subject: document.getElementById('resourceSubject').value,
        grade: document.getElementById('resourceGrade').value.trim(),
        source: document.getElementById('resourceSource').value.trim(),
        description: document.getElementById('resourceDescription').value.trim(),
        tags: tagsRaw ? tagsRaw.split(',').map(t => t.trim()).filter(Boolean) : [],
    };

    if (id) {
        const idx = resources.findIndex(r => r.id === id);
        if (idx > -1) {
            resources[idx] = { ...resources[idx], ...data, updatedAt: new Date().toISOString() };
        }
        showToast('Resource updated successfully');
    } else {
        data.id = DB.generateId();
        data.createdAt = new Date().toISOString();
        resources.push(data);
        showToast('Resource added successfully');
    }

    DB.set('resources', resources);
    closeModal('resourceModal');
    renderResources();
}

function deleteResource(id) {
    if (!confirm('Delete this resource?')) return;
    let resources = DB.get('resources');
    resources = resources.filter(r => r.id !== id);
    DB.set('resources', resources);
    showToast('Resource deleted', 'info');
    renderResources();
}

function renderResources() {
    const resources = DB.get('resources');
    const container = document.getElementById('resourcesContainer');
    const typeFilter = document.getElementById('resourceTypeFilter').value;
    const subjectFilter = document.getElementById('resourceSubjectFilter').value;
    const search = document.getElementById('resourceSearchInput').value.toLowerCase();

    let filtered = resources.filter(r => {
        if (typeFilter !== 'all' && r.type !== typeFilter) return false;
        if (subjectFilter !== 'all' && r.subject !== subjectFilter) return false;
        if (search && !r.title.toLowerCase().includes(search) && !(r.description || '').toLowerCase().includes(search)) return false;
        return true;
    }).sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

    if (filtered.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-book-open"></i><h3>No resources found</h3><p>${resources.length === 0 ? 'Build your resource library by clicking "Add Resource"' : 'Try adjusting your filters'}</p></div>`;
        return;
    }

    const typeIcons = {
        'Worksheet': { icon: 'fa-file-alt', cls: 'worksheet' },
        'Lesson Plan': { icon: 'fa-clipboard-list', cls: 'lesson-plan' },
        'Activity': { icon: 'fa-puzzle-piece', cls: 'activity' },
        'Reference': { icon: 'fa-book', cls: 'reference' },
        'TLM': { icon: 'fa-shapes', cls: 'tlm' },
        'Video': { icon: 'fa-video', cls: 'video' },
        'Other': { icon: 'fa-file', cls: 'other' },
    };

    container.innerHTML = filtered.map(r => {
        const ti = typeIcons[r.type] || typeIcons['Other'];
        return `<div class="resource-card" onclick="openResourceModal('${r.id}')">
            <div class="resource-card-icon ${ti.cls}"><i class="fas ${ti.icon}"></i></div>
            <h4>${escapeHtml(r.title)}</h4>
            ${r.description ? `<p>${escapeHtml(r.description)}</p>` : '<p>&nbsp;</p>'}
            <div class="resource-tags">
                <span class="resource-tag">${escapeHtml(r.type)}</span>
                <span class="resource-tag">${escapeHtml(r.subject)}</span>
                ${r.grade ? `<span class="resource-tag">${escapeHtml(r.grade)}</span>` : ''}
                ${(r.tags || []).slice(0, 3).map(t => `<span class="resource-tag">${escapeHtml(t)}</span>`).join('')}
            </div>
            <div class="resource-card-footer">
                <span>${r.source ? escapeHtml(r.source) : 'No source'}</span>
                <div class="resource-card-actions">
                    <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); openResourceModal('${r.id}')"><i class="fas fa-edit"></i></button>
                    <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteResource('${r.id}')"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        </div>`;
    }).join('');
}

// ===== REPORTS =====
let currentReportType = 'monthly';

function setReportType(type) {
    currentReportType = type;
    document.querySelectorAll('.report-type-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`.report-type-btn[data-type="${type}"]`)?.classList.add('active');
}

function generateReport() {
    const month = parseInt(document.getElementById('reportMonthFilter').value);
    const year = parseInt(document.getElementById('reportYearFilter').value);
    const output = document.getElementById('reportOutput');

    const visits = DB.get('visits');
    const trainings = DB.get('trainings');
    const observations = DB.get('observations');

    if (currentReportType === 'monthly') {
        generateMonthlyReport(output, visits, trainings, observations, month, year);
    } else if (currentReportType === 'school') {
        generateSchoolReport(output, visits, trainings, observations);
    } else {
        generateSummaryReport(output, visits, trainings, observations);
    }
}

function generateMonthlyReport(output, visits, trainings, observations, month, year) {
    const monthName = new Date(year, month).toLocaleString('en', { month: 'long' });

    const monthVisits = visits.filter(v => {
        const d = new Date(v.date);
        return d.getMonth() === month && d.getFullYear() === year;
    });
    const monthTrainings = trainings.filter(t => {
        const d = new Date(t.date);
        return d.getMonth() === month && d.getFullYear() === year;
    });
    const monthObs = observations.filter(o => {
        const d = new Date(o.date);
        return d.getMonth() === month && d.getFullYear() === year;
    });

    const completedVisits = monthVisits.filter(v => v.status === 'completed').length;
    const totalAttendees = monthTrainings.reduce((sum, t) => sum + (t.attendees || 0), 0);
    const totalTrainingHours = monthTrainings.reduce((sum, t) => sum + (t.duration || 0), 0);

    output.innerHTML = `<div class="report-content">
        <h2>Monthly Report — ${monthName} ${year}</h2>
        <p class="report-subtitle">Report generated on ${new Date().toLocaleDateString('en-IN')}</p>

        <div class="report-stats-grid">
            <div class="report-stat">
                <div class="stat-value">${monthVisits.length}</div>
                <div class="stat-label">School Visits</div>
            </div>
            <div class="report-stat">
                <div class="stat-value">${completedVisits}</div>
                <div class="stat-label">Completed</div>
            </div>
            <div class="report-stat">
                <div class="stat-value">${monthTrainings.length}</div>
                <div class="stat-label">Trainings</div>
            </div>
            <div class="report-stat">
                <div class="stat-value">${totalAttendees}</div>
                <div class="stat-label">Teachers Trained</div>
            </div>
            <div class="report-stat">
                <div class="stat-value">${totalTrainingHours}h</div>
                <div class="stat-label">Training Hours</div>
            </div>
            <div class="report-stat">
                <div class="stat-value">${monthObs.length}</div>
                <div class="stat-label">Observations</div>
            </div>
        </div>

        ${monthVisits.length > 0 ? `<h3>School Visits</h3>
        <table class="report-table">
            <thead><tr><th>Date</th><th>School</th><th>Purpose</th><th>Status</th></tr></thead>
            <tbody>${monthVisits.sort((a, b) => new Date(a.date) - new Date(b.date)).map(v => `<tr>
                <td>${new Date(v.date).toLocaleDateString('en-IN')}</td>
                <td>${escapeHtml(v.school)}</td>
                <td>${escapeHtml(v.purpose || '-')}</td>
                <td><span class="badge badge-${v.status}">${v.status}</span></td>
            </tr>`).join('')}</tbody>
        </table>` : ''}

        ${monthTrainings.length > 0 ? `<h3>Training Sessions</h3>
        <table class="report-table">
            <thead><tr><th>Date</th><th>Title</th><th>Duration</th><th>Attendees</th><th>Target</th></tr></thead>
            <tbody>${monthTrainings.sort((a, b) => new Date(a.date) - new Date(b.date)).map(t => `<tr>
                <td>${new Date(t.date).toLocaleDateString('en-IN')}</td>
                <td>${escapeHtml(t.title)}</td>
                <td>${t.duration}h</td>
                <td>${t.attendees || '-'}</td>
                <td>${escapeHtml(t.target || '-')}</td>
            </tr>`).join('')}</tbody>
        </table>` : ''}

        ${monthObs.length > 0 ? `<h3>Classroom Observations</h3>
        <table class="report-table">
            <thead><tr><th>Date</th><th>School</th><th>Teacher</th><th>Subject</th><th>Class</th></tr></thead>
            <tbody>${monthObs.sort((a, b) => new Date(a.date) - new Date(b.date)).map(o => `<tr>
                <td>${new Date(o.date).toLocaleDateString('en-IN')}</td>
                <td>${escapeHtml(o.school)}</td>
                <td>${escapeHtml(o.teacher || '-')}</td>
                <td>${escapeHtml(o.subject)}</td>
                <td>${escapeHtml(o.class || '-')}</td>
            </tr>`).join('')}</tbody>
        </table>` : ''}

        ${monthVisits.length === 0 && monthTrainings.length === 0 && monthObs.length === 0 ?
            '<div class="empty-state"><i class="fas fa-inbox"></i><h3>No data for this month</h3><p>No visits, trainings, or observations recorded for this period.</p></div>' : ''}
    </div>`;
}

function generateSchoolReport(output, visits, trainings, observations) {
    const schoolMap = {};

    visits.forEach(v => {
        const key = (v.school || '').toLowerCase().trim();
        if (!schoolMap[key]) schoolMap[key] = { name: v.school || '', visits: 0, observations: 0, lastVisit: null };
        schoolMap[key].visits++;
        const d = new Date(v.date);
        if (!schoolMap[key].lastVisit || d > schoolMap[key].lastVisit) schoolMap[key].lastVisit = d;
    });

    observations.forEach(o => {
        const key = (o.school || '').toLowerCase().trim();
        if (!schoolMap[key]) schoolMap[key] = { name: o.school || '', visits: 0, observations: 0, lastVisit: null };
        schoolMap[key].observations++;
    });

    const schools = Object.values(schoolMap).sort((a, b) => (b.visits + b.observations) - (a.visits + a.observations));

    if (schools.length === 0) {
        output.innerHTML = '<div class="empty-state"><i class="fas fa-school"></i><h3>No school data available</h3><p>Add school visits or observations to generate this report.</p></div>';
        return;
    }

    output.innerHTML = `<div class="report-content">
        <h2>School-wise Report</h2>
        <p class="report-subtitle">${schools.length} schools covered | Report generated on ${new Date().toLocaleDateString('en-IN')}</p>
        <table class="report-table">
            <thead><tr><th>School</th><th>Total Visits</th><th>Observations</th><th>Last Visit</th></tr></thead>
            <tbody>${schools.map(s => `<tr>
                <td><strong>${escapeHtml(s.name)}</strong></td>
                <td>${s.visits}</td>
                <td>${s.observations}</td>
                <td>${s.lastVisit ? s.lastVisit.toLocaleDateString('en-IN') : '-'}</td>
            </tr>`).join('')}</tbody>
        </table>
    </div>`;
}

function generateSummaryReport(output, visits, trainings, observations) {
    const totalAttendees = trainings.reduce((sum, t) => sum + (t.attendees || 0), 0);
    const totalHours = trainings.reduce((sum, t) => sum + (t.duration || 0), 0);
    const completedVisits = visits.filter(v => v.status === 'completed').length;

    // Subject breakdown
    const subjectCount = {};
    observations.forEach(o => {
        subjectCount[o.subject] = (subjectCount[o.subject] || 0) + 1;
    });

    // Average ratings
    const ratedObs = observations.filter(o => o.engagement || o.methodology || o.tlm);
    const avgEngagement = ratedObs.length ? (ratedObs.reduce((s, o) => s + (o.engagement || 0), 0) / ratedObs.length).toFixed(1) : '-';
    const avgMethodology = ratedObs.length ? (ratedObs.reduce((s, o) => s + (o.methodology || 0), 0) / ratedObs.length).toFixed(1) : '-';
    const avgTLM = ratedObs.length ? (ratedObs.reduce((s, o) => s + (o.tlm || 0), 0) / ratedObs.length).toFixed(1) : '-';

    const schools = new Set();
    visits.forEach(v => schools.add((v.school || '').toLowerCase().trim()));
    observations.forEach(o => schools.add((o.school || '').toLowerCase().trim()));

    output.innerHTML = `<div class="report-content">
        <h2>Overall Summary</h2>
        <p class="report-subtitle">All-time summary report | Generated on ${new Date().toLocaleDateString('en-IN')}</p>

        <div class="report-stats-grid">
            <div class="report-stat"><div class="stat-value">${schools.size}</div><div class="stat-label">Schools Covered</div></div>
            <div class="report-stat"><div class="stat-value">${visits.length}</div><div class="stat-label">Total Visits</div></div>
            <div class="report-stat"><div class="stat-value">${completedVisits}</div><div class="stat-label">Completed Visits</div></div>
            <div class="report-stat"><div class="stat-value">${trainings.length}</div><div class="stat-label">Trainings</div></div>
            <div class="report-stat"><div class="stat-value">${totalAttendees}</div><div class="stat-label">Teachers Trained</div></div>
            <div class="report-stat"><div class="stat-value">${totalHours}h</div><div class="stat-label">Training Hours</div></div>
            <div class="report-stat"><div class="stat-value">${observations.length}</div><div class="stat-label">Observations</div></div>
        </div>

        ${Object.keys(subjectCount).length > 0 ? `<h3>Observations by Subject</h3>
        <table class="report-table">
            <thead><tr><th>Subject</th><th>Observations</th></tr></thead>
            <tbody>${Object.entries(subjectCount).sort((a, b) => b[1] - a[1]).map(([sub, cnt]) =>
        `<tr><td>${escapeHtml(sub)}</td><td>${cnt}</td></tr>`
    ).join('')}</tbody>
        </table>` : ''}

        ${ratedObs.length > 0 ? `<h3>Average Classroom Ratings</h3>
        <div class="report-stats-grid">
            <div class="report-stat"><div class="stat-value">${avgEngagement}/5</div><div class="stat-label">Engagement</div></div>
            <div class="report-stat"><div class="stat-value">${avgMethodology}/5</div><div class="stat-label">Methodology</div></div>
            <div class="report-stat"><div class="stat-value">${avgTLM}/5</div><div class="stat-label">TLM Usage</div></div>
        </div>` : ''}
    </div>`;
}

function printReport() {
    window.print();
}

// ===== QUICK NOTES =====
function addNewNote() {
    const notes = DB.get('notes');
    const colors = ['amber', 'blue', 'green', 'purple', 'red'];
    const note = {
        id: DB.generateId(),
        title: '',
        content: '',
        color: colors[notes.length % colors.length],
        createdAt: new Date().toISOString(),
        editing: true,
    };
    notes.unshift(note);
    DB.set('notes', notes);
    renderNotes();
}

function saveNote(id) {
    const notes = DB.get('notes');
    const idx = notes.findIndex(n => n.id === id);
    if (idx === -1) return;

    const titleEl = document.getElementById(`noteTitle-${id}`);
    const contentEl = document.getElementById(`noteContent-${id}`);
    const title = titleEl ? titleEl.value.trim() : '';
    const content = contentEl ? contentEl.value.trim() : '';

    if (!title && !content) {
        notes.splice(idx, 1);
        DB.set('notes', notes);
        renderNotes();
        showToast('Empty note discarded', 'info');
        return;
    }

    notes[idx].title = title || 'Untitled Note';
    notes[idx].content = content;
    delete notes[idx].editing;

    // Get selected color
    const activeColor = document.querySelector(`#noteColors-${id} .color-dot.active`);
    if (activeColor) notes[idx].color = activeColor.dataset.color;

    DB.set('notes', notes);
    renderNotes();
    showToast('Note saved');
}

function editNote(id) {
    const notes = DB.get('notes');
    const idx = notes.findIndex(n => n.id === id);
    if (idx === -1) return;
    notes[idx].editing = true;
    DB.set('notes', notes);
    renderNotes();
}

function deleteNote(id) {
    if (!confirm('Delete this note?')) return;
    let notes = DB.get('notes');
    notes = notes.filter(n => n.id !== id);
    DB.set('notes', notes);
    showToast('Note deleted', 'info');
    renderNotes();
}

function setNoteColor(id, color) {
    document.querySelectorAll(`#noteColors-${id} .color-dot`).forEach(d => d.classList.remove('active'));
    document.querySelector(`#noteColors-${id} .color-dot[data-color="${color}"]`)?.classList.add('active');
}

function renderNotes() {
    const notes = DB.get('notes');
    const container = document.getElementById('notesContainer');

    if (notes.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-sticky-note"></i><h3>No notes yet</h3><p>Click "New Note" to start jotting things down</p></div>`;
        return;
    }

    container.innerHTML = notes.map(n => {
        if (n.editing) {
            return `<div class="note-card color-${n.color || 'amber'}">
                <input type="text" class="note-input" id="noteTitle-${n.id}" placeholder="Note title..." value="${escapeHtml(n.title || '')}">
                <textarea class="note-textarea" id="noteContent-${n.id}" placeholder="Write your note here...">${escapeHtml(n.content || '')}</textarea>
                <div class="note-color-picker" id="noteColors-${n.id}">
                    <div class="color-dot amber ${n.color === 'amber' ? 'active' : ''}" data-color="amber" onclick="setNoteColor('${n.id}','amber')"></div>
                    <div class="color-dot blue ${n.color === 'blue' ? 'active' : ''}" data-color="blue" onclick="setNoteColor('${n.id}','blue')"></div>
                    <div class="color-dot green ${n.color === 'green' ? 'active' : ''}" data-color="green" onclick="setNoteColor('${n.id}','green')"></div>
                    <div class="color-dot purple ${n.color === 'purple' ? 'active' : ''}" data-color="purple" onclick="setNoteColor('${n.id}','purple')"></div>
                    <div class="color-dot red ${n.color === 'red' ? 'active' : ''}" data-color="red" onclick="setNoteColor('${n.id}','red')"></div>
                </div>
                <div class="note-card-actions">
                    <button class="btn btn-sm btn-primary" onclick="saveNote('${n.id}')"><i class="fas fa-check"></i> Save</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteNote('${n.id}')"><i class="fas fa-trash"></i></button>
                </div>
            </div>`;
        }
        const date = new Date(n.createdAt).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });
        return `<div class="note-card color-${n.color || 'amber'}">
            <div class="note-card-header">
                <h4>${escapeHtml(n.title)}</h4>
                <span class="note-date">${date}</span>
            </div>
            <p>${escapeHtml(n.content)}</p>
            <div class="note-card-actions">
                <button class="btn btn-sm btn-outline" onclick="editNote('${n.id}')"><i class="fas fa-edit"></i> Edit</button>
                <button class="btn btn-sm btn-danger" onclick="deleteNote('${n.id}')"><i class="fas fa-trash"></i></button>
            </div>
        </div>`;
    }).join('');
}

// ===== WEEKLY PLANNER =====
let plannerWeekOffset = 0;

// Auto-refresh planner when engagement data changes
function refreshPlannerIfVisible() {
    const plannerSection = document.getElementById('section-planner');
    if (plannerSection && plannerSection.classList.contains('active')) {
        renderPlanner();
    }
}

function getPlannerWeekDates(offset = 0) {
    const now = new Date();
    const dayOfWeek = now.getDay(); // 0=Sun
    const monday = new Date(now);
    monday.setDate(now.getDate() - (dayOfWeek === 0 ? 6 : dayOfWeek - 1) + (offset * 7));
    monday.setHours(0, 0, 0, 0);

    const days = [];
    const dayNames = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
    for (let i = 0; i < 7; i++) {
        const d = new Date(monday);
        d.setDate(monday.getDate() + i);
        days.push({
            date: d,
            dateKey: `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`,
            dayName: dayNames[i],
            isToday: d.toDateString() === new Date().toDateString(),
        });
    }
    return days;
}

function navigatePlannerWeek(dir) {
    if (dir === 0) {
        plannerWeekOffset = 0;
    } else {
        plannerWeekOffset += dir;
    }
    renderPlanner();
}

function renderPlanner() {
    const days = getPlannerWeekDates(plannerWeekOffset);
    const tasks = DB.get('plannerTasks');

    // Auto-populate from visits, trainings, observations for this week
    const visits = DB.get('visits');
    const trainings = DB.get('trainings');
    const observations = DB.get('observations');

    // Week header
    const startDate = days[0].date;
    const endDate = days[6].date;
    const startStr = startDate.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });
    const endStr = endDate.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });

    const headerEl = document.getElementById('plannerWeekHeader');
    headerEl.innerHTML = `<span class="week-label">📅 Week of ${startStr} — ${endStr}</span>`;

    // Build grid
    const gridEl = document.getElementById('plannerGrid');
    gridEl.innerHTML = days.map(day => {
        const dayTasks = tasks.filter(t => t.date === day.dateKey);

        // Auto tasks from other sections
        const autoTasks = [];
        visits.filter(v => v.date === day.dateKey).forEach(v => {
            autoTasks.push({ text: `🏫 ${v.school} — ${v.purpose || 'Visit'}`, type: 'visit', auto: true, status: v.status });
        });
        trainings.filter(t => t.date === day.dateKey).forEach(t => {
            autoTasks.push({ text: `🎓 ${t.title}`, type: 'training', auto: true, status: t.status });
        });
        observations.filter(o => o.date === day.dateKey).forEach(o => {
            autoTasks.push({ text: `📋 Observation — ${o.school}`, type: 'observation', auto: true });
        });

        const allTasks = [...autoTasks, ...dayTasks];
        const taskCount = allTasks.length;

        const dateDisplay = day.date.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });

        return `<div class="planner-day-card ${day.isToday ? 'today' : ''}">
            <div class="planner-day-header">
                <span class="planner-day-name">${day.dayName}${day.isToday ? ' (Today)' : ''}</span>
                <span class="planner-day-date">${dateDisplay}</span>
                ${taskCount > 0 ? `<span class="planner-day-count">${taskCount}</span>` : ''}
            </div>
            <div class="planner-day-body">
                ${autoTasks.map(t => `
                    <div class="planner-task type-${t.type} ${t.status === 'completed' ? 'completed' : ''}">
                        <span class="planner-task-text">${escapeHtml(t.text)}</span>
                    </div>
                `).join('')}
                ${dayTasks.map(t => `
                    <div class="planner-task type-${t.type || 'other'} ${t.done ? 'completed' : ''}">
                        <div class="planner-task-check" onclick="togglePlannerTask('${t.id}')">
                            ${t.done ? '<i class="fas fa-check"></i>' : ''}
                        </div>
                        <span class="planner-task-text">${escapeHtml(t.text)}</span>
                        <button class="planner-task-delete" onclick="deletePlannerTask('${t.id}')" title="Delete">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                `).join('')}
                <div class="planner-add-task">
                    <input type="text" id="plannerInput-${day.dateKey}" placeholder="Add task..." onkeydown="if(event.key==='Enter') addPlannerTask('${day.dateKey}')">
                    <select id="plannerType-${day.dateKey}">
                        <option value="other">Task</option>
                        <option value="visit">Visit</option>
                        <option value="training">Training</option>
                        <option value="observation">Obs.</option>
                        <option value="meeting">Meeting</option>
                    </select>
                    <button onclick="addPlannerTask('${day.dateKey}')" title="Add">
                        <i class="fas fa-plus"></i>
                    </button>
                </div>
            </div>
        </div>`;
    }).join('');
}

function addPlannerTask(dateKey) {
    const input = document.getElementById(`plannerInput-${dateKey}`);
    const typeSelect = document.getElementById(`plannerType-${dateKey}`);
    const text = input.value.trim();
    if (!text) return;

    const tasks = DB.get('plannerTasks');
    tasks.push({
        id: DB.generateId(),
        date: dateKey,
        text: text,
        type: typeSelect.value,
        done: false,
        createdAt: new Date().toISOString(),
    });
    DB.set('plannerTasks', tasks);
    renderPlanner();
    showToast('Task added');
}

function togglePlannerTask(id) {
    const tasks = DB.get('plannerTasks');
    const idx = tasks.findIndex(t => t.id === id);
    if (idx > -1) {
        tasks[idx].done = !tasks[idx].done;
        DB.set('plannerTasks', tasks);
        renderPlanner();
    }
}

function deletePlannerTask(id) {
    let tasks = DB.get('plannerTasks');
    tasks = tasks.filter(t => t.id !== id);
    DB.set('plannerTasks', tasks);
    renderPlanner();
    showToast('Task removed', 'info');
}

// ===== GOAL TRACKER =====
let goalTrendChart = null;

function initGoalMonthSelector() {
    const select = document.getElementById('goalMonth');
    if (!select) return;
    const now = new Date();
    select.innerHTML = '';
    for (let i = -3; i <= 3; i++) {
        const d = new Date(now.getFullYear(), now.getMonth() + i, 1);
        const val = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
        const label = d.toLocaleDateString('en-IN', { month: 'long', year: 'numeric' });
        const opt = document.createElement('option');
        opt.value = val;
        opt.textContent = label;
        if (i === 0) opt.selected = true;
        select.appendChild(opt);
    }
}

function getSelectedGoalMonth() {
    const val = document.getElementById('goalMonth').value;
    if (!val) {
        const now = new Date();
        return { year: now.getFullYear(), month: now.getMonth() };
    }
    const [y, m] = val.split('-').map(Number);
    return { year: y, month: m - 1 };
}

function saveGoalTargets() {
    const { year, month } = getSelectedGoalMonth();
    const key = `${year}-${String(month + 1).padStart(2, '0')}`;

    const targets = {
        visits: parseInt(document.getElementById('goalVisits').value) || 0,
        trainings: parseInt(document.getElementById('goalTrainings').value) || 0,
        observations: parseInt(document.getElementById('goalObservations').value) || 0,
        teachers: parseInt(document.getElementById('goalTeachers').value) || 0,
        resources: parseInt(document.getElementById('goalResources').value) || 0,
    };

    const allGoals = DB.get('goalTargets');
    // Store as array of { monthKey, targets }
    const existing = allGoals.find(g => g.monthKey === key);
    if (existing) {
        existing.targets = targets;
    } else {
        allGoals.push({ monthKey: key, targets });
    }
    DB.set('goalTargets', allGoals);
    showToast('Targets saved');
    renderGoals();
}

function getGoalTargets(monthKey) {
    const allGoals = DB.get('goalTargets');
    const found = allGoals.find(g => g.monthKey === monthKey);
    return found ? found.targets : { visits: 15, trainings: 4, observations: 10, teachers: 50, resources: 5 };
}

function getGoalActuals(year, month) {
    const visits = DB.get('visits').filter(v => {
        const d = new Date(v.date);
        return d.getFullYear() === year && d.getMonth() === month;
    });
    const completedVisits = visits.filter(v => v.status === 'completed').length;

    const trainings = DB.get('trainings').filter(t => {
        const d = new Date(t.date);
        return d.getFullYear() === year && d.getMonth() === month;
    });
    const completedTrainings = trainings.filter(t => t.status === 'completed').length;

    const observations = DB.get('observations').filter(o => {
        const d = new Date(o.date);
        return d.getFullYear() === year && d.getMonth() === month;
    });

    const teachersReached = trainings.reduce((sum, t) => sum + (t.attendees || 0), 0);

    const resources = DB.get('resources').filter(r => {
        if (!r.createdAt) return false;
        const d = new Date(r.createdAt);
        return d.getFullYear() === year && d.getMonth() === month;
    });

    return {
        visits: completedVisits,
        trainings: completedTrainings,
        observations: observations.length,
        teachers: teachersReached,
        resources: resources.length,
    };
}

function renderGoals() {
    const { year, month } = getSelectedGoalMonth();
    const monthKey = `${year}-${String(month + 1).padStart(2, '0')}`;
    const targets = getGoalTargets(monthKey);
    const actuals = getGoalActuals(year, month);

    // Update form inputs
    document.getElementById('goalVisits').value = targets.visits;
    document.getElementById('goalTrainings').value = targets.trainings;
    document.getElementById('goalObservations').value = targets.observations;
    document.getElementById('goalTeachers').value = targets.teachers;
    document.getElementById('goalResources').value = targets.resources;

    // Render progress cards
    const metrics = [
        { key: 'visits', label: 'School Visits', icon: 'fa-school', cls: 'visits' },
        { key: 'trainings', label: 'Training Sessions', icon: 'fa-chalkboard-teacher', cls: 'trainings' },
        { key: 'observations', label: 'Observations', icon: 'fa-clipboard-check', cls: 'observations' },
        { key: 'teachers', label: 'Teachers Reached', icon: 'fa-users', cls: 'teachers' },
        { key: 'resources', label: 'Resources Created', icon: 'fa-book-open', cls: 'resources' },
    ];

    const gridEl = document.getElementById('goalsProgressGrid');
    gridEl.innerHTML = metrics.map(m => {
        const actual = actuals[m.key] || 0;
        const target = targets[m.key] || 1;
        const pct = Math.min(Math.round((actual / target) * 100), 200);
        const displayPct = Math.min(pct, 100);

        let statusClass, statusText;
        if (pct >= 100) {
            statusClass = 'exceeded';
            statusText = pct === 100 ? '100% ✓' : `${pct}% 🎉`;
        } else if (pct >= 60) {
            statusClass = 'on-track';
            statusText = `${pct}%`;
        } else {
            statusClass = 'behind';
            statusText = `${pct}%`;
        }

        return `<div class="goal-progress-card">
            <div class="goal-icon ${m.cls}"><i class="fas ${m.icon}"></i></div>
            <div class="goal-label">${m.label}</div>
            <div class="goal-numbers">
                <span class="goal-current">${actual}</span>
                <span class="goal-target">/ ${target}</span>
            </div>
            <span class="goal-percent ${statusClass}">${statusText}</span>
            <div class="goal-progress-bar">
                <div class="goal-progress-bar-fill ${m.cls}" style="width: ${displayPct}%"></div>
            </div>
        </div>`;
    }).join('');

    // Render trend chart
    renderGoalTrendChart();
}

function renderGoalTrendChart() {
    const canvas = document.getElementById('goalTrendChart');
    if (!canvas) return;

    if (goalTrendChart) {
        goalTrendChart.destroy();
        goalTrendChart = null;
    }

    const now = new Date();
    const months = [];
    const visitsData = [];
    const trainingsData = [];
    const observationsData = [];

    for (let i = -5; i <= 0; i++) {
        const d = new Date(now.getFullYear(), now.getMonth() + i, 1);
        const label = d.toLocaleDateString('en', { month: 'short', year: '2-digit' });
        months.push(label);

        const actuals = getGoalActuals(d.getFullYear(), d.getMonth());
        visitsData.push(actuals.visits);
        trainingsData.push(actuals.trainings);
        observationsData.push(actuals.observations);
    }

    goalTrendChart = new Chart(canvas, {
        type: 'line',
        data: {
            labels: months,
            datasets: [
                {
                    label: 'Visits',
                    data: visitsData,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 5,
                    pointHoverRadius: 7,
                },
                {
                    label: 'Trainings',
                    data: trainingsData,
                    borderColor: '#8b5cf6',
                    backgroundColor: 'rgba(139, 92, 246, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 5,
                    pointHoverRadius: 7,
                },
                {
                    label: 'Observations',
                    data: observationsData,
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 5,
                    pointHoverRadius: 7,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#9ca3b8', font: { family: 'Inter' } },
                },
            },
            scales: {
                x: {
                    ticks: { color: '#6b7280' },
                    grid: { color: 'rgba(255,255,255,0.04)' },
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: '#6b7280', stepSize: 1 },
                    grid: { color: 'rgba(255,255,255,0.04)' },
                },
            },
        },
    });
}

// ===== ANALYTICS =====
let analyticsCharts = {};

function getAnalyticsDateRange() {
    const range = document.getElementById('analyticsRange')?.value || 'month';
    const now = new Date();
    let start;
    switch (range) {
        case 'month':
            start = new Date(now.getFullYear(), now.getMonth(), 1);
            break;
        case 'quarter':
            const qMonth = Math.floor(now.getMonth() / 3) * 3;
            start = new Date(now.getFullYear(), qMonth, 1);
            break;
        case 'year':
            start = new Date(now.getFullYear(), 0, 1);
            break;
        default:
            start = new Date(2000, 0, 1);
    }
    return { start, end: now, range };
}

function filterByDateRange(items, dateField, range) {
    return items.filter(item => {
        const d = new Date(item[dateField]);
        return d >= range.start && d <= range.end;
    });
}

function renderAnalytics() {
    const range = getAnalyticsDateRange();
    const allVisits = DB.get('visits');
    const allTrainings = DB.get('trainings');
    const allObservations = DB.get('observations');
    const allResources = DB.get('resources');

    const visits = filterByDateRange(allVisits, 'date', range);
    const trainings = filterByDateRange(allTrainings, 'date', range);
    const observations = filterByDateRange(allObservations, 'date', range);

    // === Smart Insights ===
    renderAnalyticsInsights(visits, trainings, observations, allVisits, allObservations);

    // === KPI Cards ===
    renderAnalyticsKPIs(visits, trainings, observations);

    // === Charts ===
    renderVisitPurposeChart(visits);
    renderSchoolCoverageChart(visits, observations);
    renderObsRatingsChart(observations);
    renderSubjectDistChart(observations);
    renderTrainingImpactChart(trainings);
    renderWeeklyHeatmapChart(visits, trainings, observations);

    // === Activity Timeline ===
    renderActivityTimeline(visits, trainings, observations);
}

function renderAnalyticsInsights(visits, trainings, observations, allVisits, allObs) {
    const panel = document.getElementById('analyticsInsightsPanel');
    const insights = [];

    // Completion rate
    const completed = visits.filter(v => v.status === 'completed').length;
    const planned = visits.filter(v => v.status === 'planned').length;
    const total = visits.length;
    if (total > 0) {
        const rate = Math.round((completed / total) * 100);
        insights.push({
            icon: 'fa-check-circle',
            color: rate >= 70 ? 'success' : rate >= 40 ? 'warning' : 'danger',
            text: `Visit completion rate: <strong>${rate}%</strong> (${completed} of ${total})`
        });
    }

    // Pending follow-ups
    const pendingFollowups = allVisits.filter(v => v.followUp && v.followUp.trim() && v.status === 'completed');
    if (pendingFollowups.length > 0) {
        insights.push({
            icon: 'fa-exclamation-triangle',
            color: 'warning',
            text: `<strong>${pendingFollowups.length}</strong> visit(s) have follow-up actions pending`
        });
    }

    // Schools not visited recently (>21 days)
    const schoolLastVisit = {};
    allVisits.forEach(v => {
        const key = (v.school || '').toLowerCase().trim();
        if (!key) return;
        const d = new Date(v.date);
        if (!schoolLastVisit[key] || d > schoolLastVisit[key].date) {
            schoolLastVisit[key] = { date: d, name: v.school };
        }
    });
    const staleSchools = Object.values(schoolLastVisit).filter(s => {
        const daysSince = Math.floor((new Date() - s.date) / 86400000);
        return daysSince > 21;
    });
    if (staleSchools.length > 0) {
        insights.push({
            icon: 'fa-clock',
            color: 'info',
            text: `<strong>${staleSchools.length}</strong> school(s) not visited in 3+ weeks: ${staleSchools.slice(0, 3).map(s => escapeHtml(s.name)).join(', ')}${staleSchools.length > 3 ? '...' : ''}`
        });
    }

    // Average observation ratings
    const ratedObs = observations.filter(o => o.engagement || o.methodology || o.tlm);
    if (ratedObs.length >= 2) {
        const avgEng = (ratedObs.reduce((s, o) => s + (o.engagement || 0), 0) / ratedObs.length).toFixed(1);
        const avgMeth = (ratedObs.reduce((s, o) => s + (o.methodology || 0), 0) / ratedObs.length).toFixed(1);
        const avgTlm = (ratedObs.reduce((s, o) => s + (o.tlm || 0), 0) / ratedObs.length).toFixed(1);
        const lowest = Math.min(parseFloat(avgEng), parseFloat(avgMeth), parseFloat(avgTlm));
        const lowestName = lowest === parseFloat(avgTlm) ? 'TLM Usage' : lowest === parseFloat(avgMeth) ? 'Methodology' : 'Engagement';
        insights.push({
            icon: 'fa-lightbulb',
            color: 'purple',
            text: `Lowest avg rating: <strong>${lowestName} (${lowest}/5)</strong> — consider focused support in this area`
        });
    }

    // Training reach
    const teachersReached = trainings.reduce((s, t) => s + (t.attendees || 0), 0);
    if (trainings.length > 0) {
        insights.push({
            icon: 'fa-graduation-cap',
            color: 'success',
            text: `Reached <strong>${teachersReached} teachers</strong> through <strong>${trainings.length}</strong> training session(s)`
        });
    }

    // Planned visits coming up
    if (planned > 0) {
        insights.push({
            icon: 'fa-calendar-check',
            color: 'info',
            text: `<strong>${planned}</strong> visit(s) still planned — remember to update status after visiting`
        });
    }

    panel.innerHTML = insights.length === 0
        ? '<div class="insight-card color-info"><i class="fas fa-info-circle"></i><span>Add more data to see smart insights here</span></div>'
        : insights.map(i => `<div class="insight-card color-${i.color}"><i class="fas ${i.icon}"></i><span>${i.text}</span></div>`).join('');
}

function renderAnalyticsKPIs(visits, trainings, observations) {
    const grid = document.getElementById('analyticsKpiGrid');
    const completed = visits.filter(v => v.status === 'completed').length;
    const totalHours = trainings.reduce((s, t) => s + (t.duration || 0), 0);
    const teachersReached = trainings.reduce((s, t) => s + (t.attendees || 0), 0);
    const schools = new Set();
    visits.forEach(v => schools.add((v.school || '').toLowerCase().trim()));
    observations.forEach(o => schools.add((o.school || '').toLowerCase().trim()));
    
    const ratedObs = observations.filter(o => o.engagement || o.methodology || o.tlm);
    const avgRating = ratedObs.length
        ? ((ratedObs.reduce((s, o) => s + (o.engagement || 0) + (o.methodology || 0) + (o.tlm || 0), 0)) / (ratedObs.length * 3)).toFixed(1)
        : '-';
    
    const completionRate = visits.length > 0 ? Math.round((completed / visits.length) * 100) : 0;

    const kpis = [
        { label: 'Visits Completed', value: completed, icon: 'fa-check-double', cls: 'kpi-blue' },
        { label: 'Schools Covered', value: schools.size, icon: 'fa-map-marker-alt', cls: 'kpi-green' },
        { label: 'Teachers Reached', value: teachersReached, icon: 'fa-users', cls: 'kpi-purple' },
        { label: 'Training Hours', value: totalHours + 'h', icon: 'fa-clock', cls: 'kpi-amber' },
        { label: 'Observations', value: observations.length, icon: 'fa-clipboard-check', cls: 'kpi-teal' },
        { label: 'Avg Rating', value: avgRating + '/5', icon: 'fa-star', cls: 'kpi-pink' },
        { label: 'Completion Rate', value: completionRate + '%', icon: 'fa-chart-line', cls: 'kpi-green' },
        { label: 'Trainings Held', value: trainings.length, icon: 'fa-chalkboard-teacher', cls: 'kpi-blue' },
    ];

    grid.innerHTML = kpis.map(k => `
        <div class="analytics-kpi ${k.cls}">
            <div class="kpi-icon"><i class="fas ${k.icon}"></i></div>
            <div class="kpi-value">${k.value}</div>
            <div class="kpi-label">${k.label}</div>
        </div>
    `).join('');
}

function destroyChart(key) {
    if (analyticsCharts[key]) {
        analyticsCharts[key].destroy();
        analyticsCharts[key] = null;
    }
}

const ANALYTICS_COLORS = ['#f59e0b', '#3b82f6', '#10b981', '#8b5cf6', '#ef4444', '#06b6d4', '#f97316', '#ec4899', '#14b8a6', '#6366f1'];

function renderVisitPurposeChart(visits) {
    destroyChart('purposeChart');
    const canvas = document.getElementById('chartVisitPurpose');
    if (!canvas) return;

    const purposeCount = {};
    visits.forEach(v => {
        const p = v.purpose || 'Other';
        purposeCount[p] = (purposeCount[p] || 0) + 1;
    });

    const labels = Object.keys(purposeCount);
    const data = Object.values(purposeCount);

    if (labels.length === 0) {
        canvas.style.display = 'none';
        if (!canvas.parentElement.querySelector('.empty-state')) canvas.insertAdjacentHTML('afterend', '<div class="empty-state small"><i class="fas fa-chart-pie"></i><p>No visit data in this period</p></div>');
        return;
    }
    canvas.style.display = '';
    const emptyMsg0 = canvas.parentElement.querySelector('.empty-state'); if (emptyMsg0) emptyMsg0.remove();

    analyticsCharts.purposeChart = new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{ data, backgroundColor: ANALYTICS_COLORS.slice(0, labels.length), borderWidth: 0 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { position: 'right', labels: { color: '#9ca3b8', font: { family: 'Inter', size: 12 } } } }
        }
    });
}

function renderSchoolCoverageChart(visits, observations) {
    destroyChart('schoolChart');
    const canvas = document.getElementById('chartSchoolCoverage');
    if (!canvas) return;

    const schoolCount = {};
    visits.forEach(v => {
        const name = (v.school || '').trim();
        schoolCount[name] = (schoolCount[name] || 0) + 1;
    });
    observations.forEach(o => {
        const name = (o.school || '').trim();
        schoolCount[name] = (schoolCount[name] || 0) + 1;
    });

    const sorted = Object.entries(schoolCount).sort((a, b) => b[1] - a[1]).slice(0, 10);
    if (sorted.length === 0) {
        canvas.style.display = 'none';
        if (!canvas.parentElement.querySelector('.empty-state')) canvas.insertAdjacentHTML('afterend', '<div class="empty-state small"><i class="fas fa-school"></i><p>No school data in this period</p></div>');
        return;
    }
    canvas.style.display = '';
    { const e = canvas.parentElement.querySelector('.empty-state'); if (e) e.remove(); }

    analyticsCharts.schoolChart = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: sorted.map(s => s[0].length > 25 ? s[0].substring(0, 25) + '...' : s[0]),
            datasets: [{ label: 'Activities', data: sorted.map(s => s[1]), backgroundColor: '#3b82f6', borderRadius: 6, barThickness: 24 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { beginAtZero: true, ticks: { color: '#6b7280', stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { ticks: { color: '#9ca3b8', font: { size: 11 } }, grid: { display: false } }
            }
        }
    });
}

function renderObsRatingsChart(observations) {
    destroyChart('ratingsChart');
    const canvas = document.getElementById('chartObsRatings');
    if (!canvas) return;

    const rated = observations.filter(o => o.engagement || o.methodology || o.tlm);
    if (rated.length === 0) {
        canvas.style.display = 'none';
        if (!canvas.parentElement.querySelector('.empty-state')) canvas.insertAdjacentHTML('afterend', '<div class="empty-state small"><i class="fas fa-star"></i><p>No rated observations in this period</p></div>');
        return;
    }
    canvas.style.display = '';
    { const e = canvas.parentElement.querySelector('.empty-state'); if (e) e.remove(); }

    const avgEng = (rated.reduce((s, o) => s + (o.engagement || 0), 0) / rated.length).toFixed(1);
    const avgMeth = (rated.reduce((s, o) => s + (o.methodology || 0), 0) / rated.length).toFixed(1);
    const avgTlm = (rated.reduce((s, o) => s + (o.tlm || 0), 0) / rated.length).toFixed(1);

    analyticsCharts.ratingsChart = new Chart(canvas, {
        type: 'radar',
        data: {
            labels: ['Engagement', 'Methodology', 'TLM Usage'],
            datasets: [{
                label: 'Average Rating',
                data: [avgEng, avgMeth, avgTlm],
                borderColor: '#f59e0b',
                backgroundColor: 'rgba(245, 158, 11, 0.15)',
                pointBackgroundColor: '#f59e0b',
                pointRadius: 6,
                borderWidth: 2,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            scales: {
                r: {
                    beginAtZero: true, max: 5, stepSize: 1,
                    ticks: { color: '#6b7280', backdropColor: 'transparent' },
                    grid: { color: 'rgba(255,255,255,0.06)' },
                    pointLabels: { color: '#9ca3b8', font: { size: 13, family: 'Inter' } }
                }
            },
            plugins: { legend: { labels: { color: '#9ca3b8' } } }
        }
    });
}

function renderSubjectDistChart(observations) {
    destroyChart('subjectChart');
    const canvas = document.getElementById('chartSubjectDist');
    if (!canvas) return;

    const subjectCount = {};
    observations.forEach(o => {
        subjectCount[o.subject] = (subjectCount[o.subject] || 0) + 1;
    });

    const labels = Object.keys(subjectCount);
    const data = Object.values(subjectCount);

    if (labels.length === 0) {
        canvas.style.display = 'none';
        if (!canvas.parentElement.querySelector('.empty-state')) canvas.insertAdjacentHTML('afterend', '<div class="empty-state small"><i class="fas fa-book"></i><p>No observations in this period</p></div>');
        return;
    }
    canvas.style.display = '';
    { const e = canvas.parentElement.querySelector('.empty-state'); if (e) e.remove(); }

    analyticsCharts.subjectChart = new Chart(canvas, {
        type: 'polarArea',
        data: {
            labels,
            datasets: [{ data, backgroundColor: ANALYTICS_COLORS.slice(0, labels.length).map(c => c + '99'), borderWidth: 0 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            scales: { r: { ticks: { color: '#6b7280', backdropColor: 'transparent' }, grid: { color: 'rgba(255,255,255,0.06)' } } },
            plugins: { legend: { position: 'right', labels: { color: '#9ca3b8', font: { family: 'Inter' } } } }
        }
    });
}

function renderTrainingImpactChart(trainings) {
    destroyChart('trainingChart');
    const canvas = document.getElementById('chartTrainingImpact');
    if (!canvas) return;

    const sorted = [...trainings].sort((a, b) => new Date(a.date) - new Date(b.date));
    if (sorted.length === 0) {
        canvas.style.display = 'none';
        if (!canvas.parentElement.querySelector('.empty-state')) canvas.insertAdjacentHTML('afterend', '<div class="empty-state small"><i class="fas fa-users"></i><p>No trainings in this period</p></div>');
        return;
    }
    canvas.style.display = '';
    { const e = canvas.parentElement.querySelector('.empty-state'); if (e) e.remove(); }

    analyticsCharts.trainingChart = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: sorted.map(t => t.title.length > 20 ? t.title.substring(0, 20) + '...' : t.title),
            datasets: [
                { label: 'Attendees', data: sorted.map(t => t.attendees || 0), backgroundColor: '#8b5cf6', borderRadius: 6 },
                { label: 'Duration (h)', data: sorted.map(t => t.duration || 0), backgroundColor: '#06b6d4', borderRadius: 6 },
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#9ca3b8' } } },
            scales: {
                x: { ticks: { color: '#6b7280', font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { beginAtZero: true, ticks: { color: '#6b7280' }, grid: { color: 'rgba(255,255,255,0.04)' } }
            }
        }
    });
}

function renderWeeklyHeatmapChart(visits, trainings, observations) {
    destroyChart('heatmapChart');
    const canvas = document.getElementById('chartWeeklyHeatmap');
    if (!canvas) return;

    const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const dayCounts = [0, 0, 0, 0, 0, 0, 0];

    [...visits, ...trainings, ...observations].forEach(item => {
        const d = new Date(item.date);
        if (!isNaN(d)) dayCounts[d.getDay()]++;
    });

    if (dayCounts.every(c => c === 0)) {
        canvas.style.display = 'none';
        if (!canvas.parentElement.querySelector('.empty-state')) canvas.insertAdjacentHTML('afterend', '<div class="empty-state small"><i class="fas fa-calendar"></i><p>No activities in this period</p></div>');
        return;
    }
    canvas.style.display = '';
    { const e = canvas.parentElement.querySelector('.empty-state'); if (e) e.remove(); }

    const maxVal = Math.max(...dayCounts);
    const colors = dayCounts.map(c => {
        const intensity = maxVal > 0 ? c / maxVal : 0;
        return `rgba(245, 158, 11, ${0.15 + intensity * 0.75})`;
    });

    analyticsCharts.heatmapChart = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: dayNames,
            datasets: [{ label: 'Activities', data: dayCounts, backgroundColor: colors, borderRadius: 8, barThickness: 36 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#9ca3b8', font: { weight: '600' } }, grid: { display: false } },
                y: { beginAtZero: true, ticks: { color: '#6b7280', stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.04)' } }
            }
        }
    });
}

function renderActivityTimeline(visits, trainings, observations) {
    const container = document.getElementById('activityTimeline');
    const countEl = document.getElementById('timelineCount');

    const items = [
        ...visits.map(v => ({ type: 'visit', icon: 'fa-school', cls: 'tl-visit', title: v.school, detail: v.purpose || '', status: v.status, date: v.date, time: v.createdAt || v.date })),
        ...trainings.map(t => ({ type: 'training', icon: 'fa-chalkboard-teacher', cls: 'tl-training', title: t.title, detail: `${t.attendees || 0} attendees · ${t.duration || 0}h`, status: t.status, date: t.date, time: t.createdAt || t.date })),
        ...observations.map(o => ({ type: 'observation', icon: 'fa-clipboard-check', cls: 'tl-observation', title: `${o.school} — ${o.subject}`, detail: o.teacher ? `Teacher: ${o.teacher}` : '', status: '', date: o.date, time: o.createdAt || o.date })),
    ].sort((a, b) => new Date(b.date) - new Date(a.date));

    countEl.textContent = `${items.length} activities`;

    if (items.length === 0) {
        container.innerHTML = '<div class="empty-state small"><i class="fas fa-stream"></i><p>No activities in this period</p></div>';
        return;
    }

    container.innerHTML = items.map(item => {
        const d = new Date(item.date);
        const dateStr = d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
        return `<div class="timeline-item">
            <div class="timeline-dot ${item.cls}"><i class="fas ${item.icon}"></i></div>
            <div class="timeline-content">
                <div class="timeline-header">
                    <strong>${escapeHtml(item.title)}</strong>
                    ${item.status ? `<span class="badge badge-${item.status}">${item.status}</span>` : ''}
                </div>
                ${item.detail ? `<p class="timeline-detail">${escapeHtml(item.detail)}</p>` : ''}
                <span class="timeline-date">${dateStr}</span>
            </div>
        </div>`;
    }).join('');
}

// ===== FOLLOW-UP TRACKER =====
function renderFollowups() {
    const visits = DB.get('visits');
    const observations = DB.get('observations');
    const followupStatus = DB.get('followupStatus'); // [{id, done}]
    const filter = document.getElementById('followupFilter')?.value || 'pending';

    // Collect follow-ups from visits
    let followups = [];
    visits.forEach(v => {
        if (v.followUp && v.followUp.trim()) {
            const isDone = followupStatus.some(f => f.id === v.id && f.done);
            followups.push({
                id: v.id,
                source: 'visit',
                school: v.school,
                date: v.date,
                text: v.followUp,
                done: isDone,
                icon: 'fa-school',
                cls: 'followup-visit',
            });
        }
    });

    // Collect suggestions from observations
    observations.forEach(o => {
        if (o.suggestions && o.suggestions.trim()) {
            const isDone = followupStatus.some(f => f.id === o.id && f.done);
            followups.push({
                id: o.id,
                source: 'observation',
                school: o.school,
                date: o.date,
                text: o.suggestions,
                done: isDone,
                icon: 'fa-clipboard-check',
                cls: 'followup-obs',
                teacher: o.teacher,
            });
        }
    });

    followups.sort((a, b) => new Date(b.date) - new Date(a.date));

    // Stats
    const totalCount = followups.length;
    const doneCount = followups.filter(f => f.done).length;
    const pendingCount = totalCount - doneCount;
    const completionPct = totalCount > 0 ? Math.round((doneCount / totalCount) * 100) : 0;

    const statsEl = document.getElementById('followupStats');
    statsEl.innerHTML = `
        <div class="followup-stat-card">
            <div class="followup-stat-icon pending"><i class="fas fa-hourglass-half"></i></div>
            <div class="followup-stat-value">${pendingCount}</div>
            <div class="followup-stat-label">Pending</div>
        </div>
        <div class="followup-stat-card">
            <div class="followup-stat-icon done"><i class="fas fa-check-circle"></i></div>
            <div class="followup-stat-value">${doneCount}</div>
            <div class="followup-stat-label">Completed</div>
        </div>
        <div class="followup-stat-card">
            <div class="followup-stat-icon total"><i class="fas fa-list"></i></div>
            <div class="followup-stat-value">${totalCount}</div>
            <div class="followup-stat-label">Total</div>
        </div>
        <div class="followup-stat-card">
            <div class="followup-stat-icon rate"><i class="fas fa-chart-line"></i></div>
            <div class="followup-stat-value">${completionPct}%</div>
            <div class="followup-stat-label">Completion</div>
        </div>
    `;

    // Filter
    if (filter === 'pending') followups = followups.filter(f => !f.done);
    else if (filter === 'done') followups = followups.filter(f => f.done);

    const container = document.getElementById('followupsContainer');
    if (followups.length === 0) {
        const msg = filter === 'pending' ? 'No pending follow-ups — great job!' : filter === 'done' ? 'No completed follow-ups yet' : 'No follow-ups recorded yet';
        container.innerHTML = `<div class="empty-state"><i class="fas fa-tasks"></i><h3>${msg}</h3><p>Follow-ups are auto-collected from visit notes and observation suggestions</p></div>`;
        return;
    }

    container.innerHTML = followups.map(f => {
        const d = new Date(f.date);
        const dateStr = d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
        const daysSince = Math.floor((new Date() - d) / 86400000);
        const urgency = !f.done && daysSince > 14 ? 'urgent' : !f.done && daysSince > 7 ? 'moderate' : '';

        return `<div class="followup-item ${f.done ? 'done' : ''} ${urgency}">
            <div class="followup-check" onclick="toggleFollowup('${f.id}')">
                ${f.done ? '<i class="fas fa-check-circle"></i>' : '<i class="far fa-circle"></i>'}
            </div>
            <div class="followup-body">
                <div class="followup-header">
                    <span class="followup-source ${f.cls}"><i class="fas ${f.icon}"></i> ${f.source === 'visit' ? 'Visit' : 'Observation'}</span>
                    <span class="followup-school">${escapeHtml(f.school)}</span>
                    ${f.teacher ? `<span class="followup-teacher"><i class="fas fa-user"></i> ${escapeHtml(f.teacher)}</span>` : ''}
                </div>
                <p class="followup-text">${escapeHtml(f.text)}</p>
                <div class="followup-footer">
                    <span class="followup-date"><i class="fas fa-calendar"></i> ${dateStr}</span>
                    ${!f.done && daysSince > 0 ? `<span class="followup-age ${urgency}">${daysSince}d ago</span>` : ''}
                </div>
            </div>
        </div>`;
    }).join('');
}

function toggleFollowup(id) {
    const followupStatus = DB.get('followupStatus');
    const existing = followupStatus.find(f => f.id === id);
    if (existing) {
        existing.done = !existing.done;
    } else {
        followupStatus.push({ id, done: true });
    }
    DB.set('followupStatus', followupStatus);
    renderFollowups();
    showToast(existing && !existing.done ? 'Follow-up marked as pending' : 'Follow-up completed');
}

// ===== IDEA TRACKER =====
let currentIdeaView = 'board';

function setIdeaView(view) {
    currentIdeaView = view;
    document.querySelectorAll('.idea-view-toggle .view-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.view === view);
    });
    renderIdeas();
}

function openIdeaModal(id) {
    const form = document.getElementById('ideaForm');
    form.reset();
    document.getElementById('ideaId').value = '';
    document.getElementById('ideaModalTitle').innerHTML = '<i class="fas fa-lightbulb"></i> New Idea';

    // Reset color picker
    document.querySelectorAll('#ideaColorPicker .color-dot').forEach((dot, i) => {
        dot.classList.toggle('active', i === 0);
    });

    if (id) {
        const ideas = DB.get('ideas');
        const idea = ideas.find(i => i.id === id);
        if (idea) {
            document.getElementById('ideaModalTitle').innerHTML = '<i class="fas fa-lightbulb"></i> Edit Idea';
            document.getElementById('ideaId').value = idea.id;
            document.getElementById('ideaTitle').value = idea.title;
            document.getElementById('ideaCategory').value = idea.category || 'Other';
            document.getElementById('ideaStatus').value = idea.status || 'spark';
            document.getElementById('ideaPriority').value = idea.priority || 'medium';
            document.getElementById('ideaDescription').value = idea.description || '';
            document.getElementById('ideaTags').value = (idea.tags || []).join(', ');
            document.getElementById('ideaInspiration').value = idea.inspiration || '';

            // Set color
            const color = idea.color || '#f59e0b';
            document.querySelectorAll('#ideaColorPicker .color-dot').forEach(dot => {
                dot.classList.toggle('active', dot.dataset.color === color);
            });
        }
    }

    document.getElementById('ideaModal').classList.add('active');
}

function pickIdeaColor(el) {
    document.querySelectorAll('#ideaColorPicker .color-dot').forEach(d => d.classList.remove('active'));
    el.classList.add('active');
}

function saveIdea(e) {
    e.preventDefault();
    const ideas = DB.get('ideas');
    const id = document.getElementById('ideaId').value;
    const activeColor = document.querySelector('#ideaColorPicker .color-dot.active');
    const tagsRaw = document.getElementById('ideaTags').value;
    const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim()).filter(Boolean) : [];

    const idea = {
        id: id || DB.generateId(),
        title: document.getElementById('ideaTitle').value.trim(),
        category: document.getElementById('ideaCategory').value,
        status: document.getElementById('ideaStatus').value,
        priority: document.getElementById('ideaPriority').value,
        description: document.getElementById('ideaDescription').value.trim(),
        tags: tags,
        inspiration: document.getElementById('ideaInspiration').value.trim(),
        color: activeColor ? activeColor.dataset.color : '#f59e0b',
        createdAt: id ? (ideas.find(i => i.id === id) || {}).createdAt || new Date().toISOString() : new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    if (id) {
        const idx = ideas.findIndex(i => i.id === id);
        if (idx !== -1) ideas[idx] = idea;
    } else {
        ideas.push(idea);
    }

    DB.set('ideas', ideas);
    closeModal('ideaModal');
    renderIdeas();
    showToast(id ? 'Idea updated!' : 'New idea captured! ✨');
}

function deleteIdea(id) {
    if (!confirm('Delete this idea?')) return;
    let ideas = DB.get('ideas');
    ideas = ideas.filter(i => i.id !== id);
    DB.set('ideas', ideas);
    renderIdeas();
    showToast('Idea deleted');
}

function moveIdeaStatus(id, newStatus) {
    const ideas = DB.get('ideas');
    const idea = ideas.find(i => i.id === id);
    if (idea) {
        idea.status = newStatus;
        idea.updatedAt = new Date().toISOString();
        DB.set('ideas', ideas);
        renderIdeas();
    }
}

function renderIdeaStats() {
    const ideas = DB.get('ideas');
    const statuses = { spark: 0, exploring: 0, 'in-progress': 0, done: 0, archived: 0 };
    ideas.forEach(i => { if (statuses.hasOwnProperty(i.status)) statuses[i.status]++; });

    const statsConfig = [
        { emoji: '✨', label: 'Sparks', value: statuses.spark, color: '#f59e0b' },
        { emoji: '🔍', label: 'Exploring', value: statuses.exploring, color: '#3b82f6' },
        { emoji: '🚀', label: 'In Progress', value: statuses['in-progress'], color: '#8b5cf6' },
        { emoji: '✅', label: 'Done', value: statuses.done, color: '#10b981' },
        { emoji: '📦', label: 'Archived', value: statuses.archived, color: '#6b7280' },
        { emoji: '💡', label: 'Total Ideas', value: ideas.length, color: '#ec4899' }
    ];

    document.getElementById('ideaStats').innerHTML = statsConfig.map(s => `
        <div class="idea-stat-card" style="--stat-color: ${s.color}">
            <div class="stat-emoji">${s.emoji}</div>
            <div class="stat-value">${s.value}</div>
            <div class="stat-label">${s.label}</div>
        </div>
    `).join('');
}

function getFilteredIdeas() {
    let ideas = DB.get('ideas');
    const catFilter = document.getElementById('ideaCategoryFilter').value;
    const searchTerm = (document.getElementById('ideaSearchInput').value || '').toLowerCase();

    if (catFilter !== 'all') {
        ideas = ideas.filter(i => i.category === catFilter);
    }
    if (searchTerm) {
        ideas = ideas.filter(i =>
            (i.title || '').toLowerCase().includes(searchTerm) ||
            (i.description || '').toLowerCase().includes(searchTerm) ||
            (i.tags || []).some(t => t.toLowerCase().includes(searchTerm)) ||
            (i.inspiration || '').toLowerCase().includes(searchTerm) ||
            (i.category || '').toLowerCase().includes(searchTerm)
        );
    }
    return ideas;
}

function buildIdeaCard(idea) {
    const priorityLabels = { high: '🔴 High', medium: '🟡 Med', low: '🟢 Low' };
    const categoryEmojis = { Teaching: '🎓', Activity: '🎨', Training: '📋', Resource: '📚', Community: '🤝', Tech: '💻', Other: '💡' };
    const d = new Date(idea.createdAt);
    const dateStr = d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });

    const tagsHtml = (idea.tags || []).slice(0, 3).map(t => `<span class="idea-tag">${escapeHtml(t)}</span>`).join('');
    const descSnippet = idea.description ? `<div class="idea-card-desc">${escapeHtml(idea.description)}</div>` : '';

    // Status badge for grid/list views
    const statusLabels = { spark: '✨ Spark', exploring: '🔍 Exploring', 'in-progress': '🚀 In Progress', done: '✅ Done', archived: '📦 Archived' };

    return `
        <div class="idea-card" style="--card-accent: ${idea.color || '#f59e0b'}" onclick="openIdeaModal('${idea.id}')">
            <div class="idea-card-header">
                <div class="idea-card-title">${escapeHtml(idea.title)}</div>
                <span class="idea-card-priority ${idea.priority}">${priorityLabels[idea.priority] || '🟡 Med'}</span>
            </div>
            ${descSnippet}
            ${tagsHtml ? `<div class="idea-card-tags">${tagsHtml}</div>` : ''}
            <div class="idea-card-footer">
                <div class="idea-card-category">${categoryEmojis[idea.category] || '💡'} ${escapeHtml(idea.category || 'Other')}</div>
                <span class="idea-card-date">${dateStr}</span>
                <div class="idea-card-actions" onclick="event.stopPropagation()">
                    <button onclick="openIdeaModal('${idea.id}')" title="Edit"><i class="fas fa-pen"></i></button>
                    <button class="delete-btn" onclick="deleteIdea('${idea.id}')" title="Delete"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        </div>
    `;
}

function renderIdeas() {
    renderIdeaStats();
    const ideas = getFilteredIdeas();
    const container = document.getElementById('ideasContainer');

    if (ideas.length === 0) {
        container.innerHTML = `
            <div class="idea-empty">
                <i class="fas fa-lightbulb"></i>
                <h3>No ideas yet</h3>
                <p>Click <strong>"New Idea"</strong> to capture your first spark ✨</p>
            </div>
        `;
        return;
    }

    if (currentIdeaView === 'board') {
        renderIdeaBoard(ideas, container);
    } else if (currentIdeaView === 'grid') {
        renderIdeaGrid(ideas, container);
    } else {
        renderIdeaList(ideas, container);
    }
}

function renderIdeaBoard(ideas, container) {
    const columns = [
        { key: 'spark', title: '✨ Spark', color: '#f59e0b' },
        { key: 'exploring', title: '🔍 Exploring', color: '#3b82f6' },
        { key: 'in-progress', title: '🚀 In Progress', color: '#8b5cf6' },
        { key: 'done', title: '✅ Done', color: '#10b981' }
    ];

    const sortedByPriority = (arr) => {
        const order = { high: 0, medium: 1, low: 2 };
        return arr.sort((a, b) => (order[a.priority] || 1) - (order[b.priority] || 1));
    };

    container.innerHTML = `<div class="idea-board">
        ${columns.map(col => {
            const colIdeas = sortedByPriority(ideas.filter(i => i.status === col.key));
            return `
                <div class="idea-board-column">
                    <div class="idea-column-header">
                        <span class="col-title" style="color: ${col.color}">${col.title}</span>
                        <span class="col-count">${colIdeas.length}</span>
                    </div>
                    <div class="idea-column-body">
                        ${colIdeas.length ? colIdeas.map(idea => buildIdeaCard(idea)).join('') : '<div style="text-align:center;color:var(--text-muted);font-size:13px;padding:20px 0;">No ideas here</div>'}
                    </div>
                </div>
            `;
        }).join('')}
    </div>`;
}

function renderIdeaGrid(ideas, container) {
    const sorted = [...ideas].sort((a, b) => new Date(b.updatedAt || b.createdAt) - new Date(a.updatedAt || a.createdAt));
    container.innerHTML = `<div class="idea-grid">${sorted.map(idea => {
        const statusLabels = { spark: '✨ Spark', exploring: '🔍 Exploring', 'in-progress': '🚀 In Progress', done: '✅ Done', archived: '📦 Archived' };
        // Wrap card with status badge overlay
        return `<div style="position:relative">
            <span class="idea-status-badge ${idea.status}" style="position:absolute;top:12px;right:12px;z-index:1;">${statusLabels[idea.status] || idea.status}</span>
            ${buildIdeaCard(idea)}
        </div>`;
    }).join('')}</div>`;
}

function renderIdeaList(ideas, container) {
    const sorted = [...ideas].sort((a, b) => new Date(b.updatedAt || b.createdAt) - new Date(a.updatedAt || a.createdAt));
    const statusLabels = { spark: '✨ Spark', exploring: '🔍 Exploring', 'in-progress': '🚀 In Progress', done: '✅ Done', archived: '📦 Archived' };
    container.innerHTML = `<div class="idea-list">${sorted.map(idea => `
        <div class="idea-card" style="--card-accent: ${idea.color || '#f59e0b'}" onclick="openIdeaModal('${idea.id}')">
            <div style="flex:1;min-width:0;">
                <div class="idea-card-header">
                    <div class="idea-card-title">${escapeHtml(idea.title)}</div>
                </div>
            </div>
            <span class="idea-status-badge ${idea.status}">${statusLabels[idea.status] || escapeHtml(idea.status)}</span>
            <span class="idea-card-priority ${idea.priority}">${escapeHtml(idea.priority)}</span>
            <span class="idea-card-category">${escapeHtml(idea.category || 'Other')}</span>
            <span class="idea-card-date">${new Date(idea.createdAt).toLocaleDateString('en-IN', { day:'numeric', month:'short' })}</span>
            <div class="idea-card-actions" onclick="event.stopPropagation()" style="opacity:1;">
                <button onclick="openIdeaModal('${idea.id}')" title="Edit"><i class="fas fa-pen"></i></button>
                <button class="delete-btn" onclick="deleteIdea('${idea.id}')" title="Delete"><i class="fas fa-trash"></i></button>
            </div>
        </div>
    `).join('')}</div>`;
}

// ===== SCHOOL PROFILES =====
function getSchoolData() {
    const visits = DB.get('visits');
    const observations = DB.get('observations');
    const schoolMap = {};

    visits.forEach(v => {
        const key = (v.school || '').trim().toLowerCase();
        if (!schoolMap[key]) schoolMap[key] = { name: (v.school || '').trim(), block: v.block || '', visits: [], observations: [] };
        if (v.block && !schoolMap[key].block) schoolMap[key].block = v.block;
        schoolMap[key].visits.push(v);
    });

    observations.forEach(o => {
        const key = (o.school || '').trim().toLowerCase();
        if (!schoolMap[key]) schoolMap[key] = { name: (o.school || '').trim(), block: '', visits: [], observations: [] };
        schoolMap[key].observations.push(o);
    });

    return schoolMap;
}

function renderSchoolProfiles() {
    const schoolMap = getSchoolData();
    const searchTerm = (document.getElementById('schoolSearchInput').value || '').toLowerCase();
    let schools = Object.values(schoolMap);

    if (searchTerm) {
        schools = schools.filter(s =>
            s.name.toLowerCase().includes(searchTerm) ||
            (s.block || '').toLowerCase().includes(searchTerm)
        );
    }

    // Sort by total activity (most active first)
    schools.sort((a, b) => (b.visits.length + b.observations.length) - (a.visits.length + a.observations.length));

    // Summary stats
    const totalSchools = Object.keys(schoolMap).length;
    const totalVisits = Object.values(schoolMap).reduce((s, sc) => s + sc.visits.length, 0);
    const totalObs = Object.values(schoolMap).reduce((s, sc) => s + sc.observations.length, 0);
    const avgPerSchool = totalSchools > 0 ? ((totalVisits + totalObs) / totalSchools).toFixed(1) : 0;

    document.getElementById('schoolSummaryStats').innerHTML = `
        <div class="school-summary-stat"><div class="stat-icon">🏫</div><div class="stat-value">${totalSchools}</div><div class="stat-label">Schools</div></div>
        <div class="school-summary-stat"><div class="stat-icon">📍</div><div class="stat-value">${totalVisits}</div><div class="stat-label">Total Visits</div></div>
        <div class="school-summary-stat"><div class="stat-icon">📋</div><div class="stat-value">${totalObs}</div><div class="stat-label">Observations</div></div>
        <div class="school-summary-stat"><div class="stat-icon">📊</div><div class="stat-value">${avgPerSchool}</div><div class="stat-label">Avg per School</div></div>
    `;

    // Show school list (hide detail view)
    document.getElementById('schoolDetailView').style.display = 'none';
    const container = document.getElementById('schoolProfilesContainer');
    container.style.display = '';

    if (schools.length === 0) {
        container.innerHTML = '<div class="idea-empty"><i class="fas fa-school"></i><h3>No schools found</h3><p>Schools will appear here automatically from your visits and observations.</p></div>';
        return;
    }

    container.innerHTML = `<div class="school-cards-grid">${schools.map(school => {
        const lastVisit = school.visits.filter(v => v.date).sort((a, b) => b.date.localeCompare(a.date))[0];
        const avgRating = school.observations.length > 0
            ? (school.observations.reduce((s, o) => s + ((o.engagement || 0) + (o.methodology || 0) + (o.tlm || 0)) / 3, 0) / school.observations.length).toFixed(1)
            : null;
        const schoolKey = school.name.trim().toLowerCase();
        const safeKey = encodeURIComponent(schoolKey).replace(/'/g, '%27');

        return `
            <div class="school-profile-card" onclick="showSchoolDetail('${safeKey}')">
                <div class="school-card-name"><i class="fas fa-school"></i> ${escapeHtml(school.name)}</div>
                <div class="school-card-block">${escapeHtml(school.block || 'Block not specified')}</div>
                <div class="school-card-metrics">
                    <div class="school-metric"><div class="metric-value">${school.visits.length}</div><div class="metric-label">Visits</div></div>
                    <div class="school-metric"><div class="metric-value">${school.observations.length}</div><div class="metric-label">Obs.</div></div>
                    <div class="school-metric"><div class="metric-value">${school.visits.filter(v => v.status === 'completed').length}</div><div class="metric-label">Done</div></div>
                </div>
                <div class="school-card-footer">
                    <div class="school-last-visit"><i class="fas fa-clock"></i> ${lastVisit ? new Date(lastVisit.date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }) : 'No visits'}</div>
                    ${avgRating ? `<div class="school-rating"><i class="fas fa-star"></i> ${avgRating}/5</div>` : ''}
                </div>
            </div>
        `;
    }).join('')}</div>`;
}

function showSchoolDetail(encodedKey) {
    const schoolKey = decodeURIComponent(encodedKey);
    const schoolMap = getSchoolData();
    const school = schoolMap[schoolKey];
    if (!school) return;

    document.getElementById('schoolProfilesContainer').style.display = 'none';
    const detailView = document.getElementById('schoolDetailView');
    detailView.style.display = '';

    const completedVisits = school.visits.filter(v => v.status === 'completed').length;
    const plannedVisits = school.visits.filter(v => v.status === 'planned').length;
    const teachers = [...new Set(school.observations.map(o => o.teacher).filter(Boolean))];
    const subjects = [...new Set(school.observations.map(o => o.subject).filter(Boolean))];
    const avgRating = school.observations.length > 0
        ? (school.observations.reduce((s, o) => s + ((o.engagement || 0) + (o.methodology || 0) + (o.tlm || 0)) / 3, 0) / school.observations.length).toFixed(1)
        : 'N/A';

    // All activities timeline
    const activities = [
        ...school.visits.map(v => ({ type: 'visit', date: v.date, title: `${v.purpose || 'Visit'}`, detail: v.notes || '', status: v.status })),
        ...school.observations.map(o => ({ type: 'observation', date: o.date, title: `Observation — ${o.subject || ''}`, detail: `Teacher: ${o.teacher || 'N/A'} | ${o.topic || ''}`, status: '' }))
    ].sort((a, b) => b.date.localeCompare(a.date));

    detailView.innerHTML = `
        <div class="school-detail">
            <div class="school-detail-header">
                <button class="back-btn" onclick="renderSchoolProfiles()"><i class="fas fa-arrow-left"></i> Back</button>
                <h2><i class="fas fa-school"></i> ${escapeHtml(school.name)}</h2>
            </div>
            ${school.block ? `<p style="color:var(--text-muted);margin-bottom:20px;"><i class="fas fa-map-marker-alt" style="color:var(--amber);margin-right:6px;"></i>${escapeHtml(school.block)}</p>` : ''}
            <div class="school-detail-stats">
                <div class="school-detail-stat"><div class="stat-value">${school.visits.length}</div><div class="stat-label">Total Visits</div></div>
                <div class="school-detail-stat"><div class="stat-value">${completedVisits}</div><div class="stat-label">Completed</div></div>
                <div class="school-detail-stat"><div class="stat-value">${plannedVisits}</div><div class="stat-label">Planned</div></div>
                <div class="school-detail-stat"><div class="stat-value">${school.observations.length}</div><div class="stat-label">Observations</div></div>
                <div class="school-detail-stat"><div class="stat-value">${teachers.length}</div><div class="stat-label">Teachers</div></div>
                <div class="school-detail-stat"><div class="stat-value">${avgRating}</div><div class="stat-label">Avg Rating</div></div>
            </div>
            ${teachers.length > 0 ? `<div style="margin-bottom:20px;"><strong style="color:var(--text-secondary);font-size:13px;">Teachers observed:</strong> <span style="color:var(--text-muted);font-size:13px;">${escapeHtml(teachers.join(', '))}</span></div>` : ''}
            ${subjects.length > 0 ? `<div style="margin-bottom:20px;"><strong style="color:var(--text-secondary);font-size:13px;">Subjects covered:</strong> <span style="color:var(--text-muted);font-size:13px;">${escapeHtml(subjects.join(', '))}</span></div>` : ''}
            <div class="school-detail-timeline">
                <h3><i class="fas fa-history" style="color:var(--amber);margin-right:8px;"></i>Activity Timeline (${activities.length})</h3>
                ${activities.length > 0 ? activities.map(a => `
                    <div class="school-timeline-item">
                        <div class="school-timeline-icon ${a.type}"><i class="fas ${a.type === 'visit' ? 'fa-school' : 'fa-clipboard-check'}"></i></div>
                        <div class="school-timeline-content">
                            <div class="timeline-title">${escapeHtml(a.title)}${a.status ? ` <span style="font-size:11px;opacity:0.7;">(${escapeHtml(a.status)})</span>` : ''}</div>
                            ${a.detail ? `<div class="timeline-details">${escapeHtml(a.detail)}</div>` : ''}
                        </div>
                        <div class="school-timeline-date">${new Date(a.date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}</div>
                    </div>
                `).join('') : '<p style="color:var(--text-muted);text-align:center;padding:30px;">No activities recorded yet</p>'}
            </div>
        </div>
    `;
}

// ===== REFLECTIONS JOURNAL =====
function initReflectionMonthFilter() {
    const sel = document.getElementById('reflectionMonthFilter');
    if (!sel) return;
    const now = new Date();
    sel.innerHTML = '<option value="all">All Months</option>';
    for (let i = 0; i < 12; i++) {
        const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
        const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
        const label = d.toLocaleDateString('en-IN', { month: 'long', year: 'numeric' });
        sel.innerHTML += `<option value="${key}">${label}</option>`;
    }
}

function openReflectionModal(id) {
    const form = document.getElementById('reflectionForm');
    form.reset();
    document.getElementById('reflectionId').value = '';
    document.getElementById('reflectionModalTitle').innerHTML = '<i class="fas fa-journal-whills"></i> New Reflection';

    const now = new Date();
    document.getElementById('reflectionMonth').value = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

    if (id) {
        const reflections = DB.get('reflections');
        const r = reflections.find(x => x.id === id);
        if (r) {
            document.getElementById('reflectionModalTitle').innerHTML = '<i class="fas fa-journal-whills"></i> Edit Reflection';
            document.getElementById('reflectionId').value = r.id;
            document.getElementById('reflectionMonth').value = r.month || '';
            document.getElementById('reflectionMood').value = r.mood || 'good';
            document.getElementById('reflectionWentWell').value = r.wentWell || '';
            document.getElementById('reflectionChallenges').value = r.challenges || '';
            document.getElementById('reflectionLearnings').value = r.learnings || '';
            document.getElementById('reflectionNextSteps').value = r.nextSteps || '';
            document.getElementById('reflectionGratitude').value = r.gratitude || '';
        }
    }

    openModal('reflectionModal');
}

function saveReflection(e) {
    e.preventDefault();
    const reflections = DB.get('reflections');
    const id = document.getElementById('reflectionId').value;

    const reflection = {
        id: id || DB.generateId(),
        month: document.getElementById('reflectionMonth').value,
        mood: document.getElementById('reflectionMood').value,
        wentWell: document.getElementById('reflectionWentWell').value.trim(),
        challenges: document.getElementById('reflectionChallenges').value.trim(),
        learnings: document.getElementById('reflectionLearnings').value.trim(),
        nextSteps: document.getElementById('reflectionNextSteps').value.trim(),
        gratitude: document.getElementById('reflectionGratitude').value.trim(),
        createdAt: id ? (reflections.find(r => r.id === id) || {}).createdAt || new Date().toISOString() : new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    if (id) {
        const idx = reflections.findIndex(r => r.id === id);
        if (idx !== -1) reflections[idx] = reflection;
    } else {
        reflections.push(reflection);
    }

    DB.set('reflections', reflections);
    closeModal('reflectionModal');
    renderReflections();
    showToast(id ? 'Reflection updated' : 'Reflection saved! 🌟');
}

function deleteReflection(id) {
    if (!confirm('Delete this reflection?')) return;
    let reflections = DB.get('reflections');
    reflections = reflections.filter(r => r.id !== id);
    DB.set('reflections', reflections);
    renderReflections();
    showToast('Reflection deleted');
}

function renderReflections() {
    let reflections = DB.get('reflections');
    const filter = document.getElementById('reflectionMonthFilter').value;

    if (filter !== 'all') {
        reflections = reflections.filter(r => r.month === filter);
    }

    reflections.sort((a, b) => (b.month || '').localeCompare(a.month || ''));

    const container = document.getElementById('reflectionsContainer');

    if (reflections.length === 0) {
        container.innerHTML = `<div class="reflection-empty"><i class="fas fa-journal-whills"></i><h3>No reflections yet</h3><p>Take a moment to reflect on your month — click "New Reflection" to start.</p></div>`;
        return;
    }

    const moodEmojis = { great: '😊', good: '🙂', okay: '😐', challenging: '😟', difficult: '😔' };

    container.innerHTML = `<div class="reflections-grid">${reflections.map(r => {
        const monthLabel = r.month ? new Date(r.month + '-01').toLocaleDateString('en-IN', { month: 'long', year: 'numeric' }) : 'Unknown';
        const sections = [];
        if (r.wentWell) sections.push({ label: 'What went well', cls: 'went-well', icon: 'fa-check-circle', text: r.wentWell });
        if (r.challenges) sections.push({ label: 'Challenges', cls: 'challenges', icon: 'fa-exclamation-circle', text: r.challenges });
        if (r.learnings) sections.push({ label: 'Key Learnings', cls: 'learnings', icon: 'fa-brain', text: r.learnings });
        if (r.nextSteps) sections.push({ label: 'Next Steps', cls: 'next-steps', icon: 'fa-arrow-right', text: r.nextSteps });
        if (r.gratitude) sections.push({ label: 'Gratitude', cls: 'gratitude', icon: 'fa-heart', text: r.gratitude });

        return `
            <div class="reflection-card">
                <div class="reflection-card-header">
                    <span class="reflection-month-label">${monthLabel}</span>
                    <span class="reflection-mood">${moodEmojis[r.mood] || '🙂'}</span>
                </div>
                <div class="reflection-card-body">
                    ${sections.map(s => `
                        <div class="reflection-section">
                            <div class="reflection-section-label ${s.cls}"><i class="fas ${s.icon}"></i> ${s.label}</div>
                            <div class="reflection-section-text">${escapeHtml(s.text)}</div>
                        </div>
                    `).join('')}
                </div>
                <div class="reflection-card-footer">
                    <button onclick="openReflectionModal('${r.id}')"><i class="fas fa-pen"></i> Edit</button>
                    <button class="delete-btn" onclick="deleteReflection('${r.id}')"><i class="fas fa-trash"></i> Delete</button>
                </div>
            </div>
        `;
    }).join('')}</div>`;
}

// ===== CONTACT DIRECTORY =====
function openContactModal(id) {
    const form = document.getElementById('contactForm');
    form.reset();
    document.getElementById('contactId').value = '';
    document.getElementById('contactModalTitle').innerHTML = '<i class="fas fa-address-book"></i> Add Contact';

    if (id) {
        const contacts = DB.get('contacts');
        const c = contacts.find(x => x.id === id);
        if (c) {
            document.getElementById('contactModalTitle').innerHTML = '<i class="fas fa-address-book"></i> Edit Contact';
            document.getElementById('contactId').value = c.id;
            document.getElementById('contactName').value = c.name || '';
            document.getElementById('contactRole').value = c.role || 'Other';
            document.getElementById('contactSchool').value = c.school || '';
            document.getElementById('contactPhone').value = c.phone || '';
            document.getElementById('contactEmail').value = c.email || '';
            document.getElementById('contactBlock').value = c.block || '';
            document.getElementById('contactNotes').value = c.notes || '';
        }
    }

    openModal('contactModal');
}

function saveContact(e) {
    e.preventDefault();
    const contacts = DB.get('contacts');
    const id = document.getElementById('contactId').value;

    const contact = {
        id: id || DB.generateId(),
        name: document.getElementById('contactName').value.trim(),
        role: document.getElementById('contactRole').value,
        school: document.getElementById('contactSchool').value.trim(),
        phone: document.getElementById('contactPhone').value.trim(),
        email: document.getElementById('contactEmail').value.trim(),
        block: document.getElementById('contactBlock').value.trim(),
        notes: document.getElementById('contactNotes').value.trim(),
        createdAt: id ? (contacts.find(c => c.id === id) || {}).createdAt || new Date().toISOString() : new Date().toISOString()
    };

    if (id) {
        const idx = contacts.findIndex(c => c.id === id);
        if (idx !== -1) contacts[idx] = contact;
    } else {
        contacts.push(contact);
    }

    DB.set('contacts', contacts);
    closeModal('contactModal');
    renderContacts();
    showToast(id ? 'Contact updated' : 'Contact added! 📇');
}

function deleteContact(id) {
    if (!confirm('Delete this contact?')) return;
    let contacts = DB.get('contacts');
    contacts = contacts.filter(c => c.id !== id);
    DB.set('contacts', contacts);
    renderContacts();
    showToast('Contact deleted');
}

function renderContacts() {
    let contacts = DB.get('contacts');
    const roleFilter = document.getElementById('contactRoleFilter').value;
    const searchTerm = (document.getElementById('contactSearchInput').value || '').toLowerCase();

    if (roleFilter !== 'all') {
        contacts = contacts.filter(c => c.role === roleFilter);
    }
    if (searchTerm) {
        contacts = contacts.filter(c =>
            (c.name || '').toLowerCase().includes(searchTerm) ||
            (c.school || '').toLowerCase().includes(searchTerm) ||
            (c.block || '').toLowerCase().includes(searchTerm) ||
            (c.phone || '').includes(searchTerm) ||
            (c.role || '').toLowerCase().includes(searchTerm)
        );
    }

    contacts.sort((a, b) => (a.name || '').localeCompare(b.name || ''));

    // Stats
    const all = DB.get('contacts');
    const roles = {};
    all.forEach(c => { roles[c.role] = (roles[c.role] || 0) + 1; });

    document.getElementById('contactStats').innerHTML = `
        <div class="contact-stat-card"><div class="stat-value">${all.length}</div><div class="stat-label">Total</div></div>
        ${Object.entries(roles).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([role, count]) => `
            <div class="contact-stat-card"><div class="stat-value">${count}</div><div class="stat-label">${role}</div></div>
        `).join('')}
    `;

    const container = document.getElementById('contactsContainer');

    if (contacts.length === 0) {
        container.innerHTML = `<div class="contact-empty"><i class="fas fa-address-book"></i><h3>No contacts yet</h3><p>Add your key field contacts — HMs, BEOs, fellow RPs, mentors.</p></div>`;
        return;
    }

    const roleColors = {
        'Head Master': { bg: 'rgba(245,158,11,0.15)', color: '#f59e0b' },
        'Teacher': { bg: 'rgba(16,185,129,0.15)', color: '#10b981' },
        'BEO': { bg: 'rgba(239,68,68,0.15)', color: '#ef4444' },
        'DIET Faculty': { bg: 'rgba(139,92,246,0.15)', color: '#8b5cf6' },
        'CRP': { bg: 'rgba(59,130,246,0.15)', color: '#3b82f6' },
        'Fellow RP': { bg: 'rgba(6,182,212,0.15)', color: '#06b6d4' },
        'Mentor': { bg: 'rgba(236,72,153,0.15)', color: '#ec4899' },
        'Other': { bg: 'rgba(107,114,128,0.15)', color: '#6b7280' }
    };

    const avatarColors = ['#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ef4444', '#ec4899', '#06b6d4', '#f97316'];

    container.innerHTML = `<div class="contacts-grid">${contacts.map((c, i) => {
        const initials = c.name ? c.name.split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase() : '?';
        const rc = roleColors[c.role] || roleColors['Other'];
        const avatarColor = avatarColors[i % avatarColors.length];

        return `
            <div class="contact-card">
                <div class="contact-card-top">
                    <div class="contact-avatar" style="background:${avatarColor}">${initials}</div>
                    <div class="contact-card-info">
                        <h4>${escapeHtml(c.name)}</h4>
                        <span class="contact-card-role" style="background:${rc.bg};color:${rc.color};">${escapeHtml(c.role)}</span>
                    </div>
                </div>
                <div class="contact-card-details">
                    ${c.school ? `<div class="contact-detail-row"><i class="fas fa-building"></i> ${escapeHtml(c.school)}</div>` : ''}
                    ${c.block ? `<div class="contact-detail-row"><i class="fas fa-map-marker-alt"></i> ${escapeHtml(c.block)}</div>` : ''}
                    ${c.phone ? `<div class="contact-detail-row"><i class="fas fa-phone"></i> <a href="tel:${escapeHtml(c.phone)}">${escapeHtml(c.phone)}</a></div>` : ''}
                    ${c.email ? `<div class="contact-detail-row"><i class="fas fa-envelope"></i> <a href="mailto:${escapeHtml(c.email)}">${escapeHtml(c.email)}</a></div>` : ''}
                    ${c.notes ? `<div class="contact-detail-row"><i class="fas fa-sticky-note"></i> ${escapeHtml(c.notes)}</div>` : ''}
                </div>
                <div class="contact-card-actions">
                    ${c.phone ? `<button onclick="window.open('tel:${c.phone.replace(/[^\d+\-\s()]/g, '')}')"  ><i class="fas fa-phone"></i> Call</button>` : ''}
                    <button onclick="openContactModal('${c.id}')"><i class="fas fa-pen"></i> Edit</button>
                    <button class="delete-btn" onclick="deleteContact('${c.id}')"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        `;
    }).join('')}</div>`;
}

// ===== DATA & SECURITY =====
function renderBackupInfo() {
    // Data summary in encrypted file card
    const summaryEl = document.getElementById('encDataSummary');
    if (summaryEl) {
        const meta = [
            { key: 'visits', label: 'Visits', icon: 'fa-school', color: '#8b5cf6' },
            { key: 'trainings', label: 'Trainings', icon: 'fa-chalkboard-teacher', color: '#3b82f6' },
            { key: 'observations', label: 'Observations', icon: 'fa-eye', color: '#10b981' },
            { key: 'resources', label: 'Resources', icon: 'fa-book', color: '#f59e0b' },
            { key: 'notes', label: 'Notes', icon: 'fa-sticky-note', color: '#ec4899' },
            { key: 'ideas', label: 'Ideas', icon: 'fa-lightbulb', color: '#f97316' },
            { key: 'reflections', label: 'Reflections', icon: 'fa-journal-whills', color: '#06b6d4' },
            { key: 'contacts', label: 'Contacts', icon: 'fa-address-book', color: '#6366f1' },
            { key: 'plannerTasks', label: 'Tasks', icon: 'fa-tasks', color: '#14b8a6' },
            { key: 'goalTargets', label: 'Goals', icon: 'fa-bullseye', color: '#ef4444' },
            { key: 'followupStatus', label: 'Follow-ups', icon: 'fa-clipboard-check', color: '#84cc16' }
        ];
        let total = 0;
        const pills = meta.map(m => {
            const count = DB.get(m.key).length;
            total += count;
            return `<div class="enc-data-pill" style="--pill-color:${m.color}">
                <i class="fas ${m.icon}"></i>
                <span class="enc-pill-count">${count}</span>
                <span class="enc-pill-label">${m.label}</span>
            </div>`;
        }).join('');

        summaryEl.innerHTML = `
            <div class="enc-summary-header">
                <i class="fas fa-database"></i>
                <span>Data in Memory</span>
                <span class="enc-total-badge">${total} items</span>
            </div>
            <div class="enc-data-grid">${pills}</div>
        `;
    }

    updatePasswordUI();
    updateEncryptedFileStatus();
}

function downloadBackup() {
    try {
        const keys = ['visits', 'trainings', 'observations', 'resources', 'notes', 'ideas', 'reflections', 'contacts', 'plannerTasks', 'goalTargets', 'followupStatus'];
        const backup = { _meta: { version: 1, app: 'APF Dashboard', exportedAt: new Date().toISOString() } };
        keys.forEach(k => { backup[k] = DB.get(k); });

        const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const d = new Date();
        a.href = url;
        a.download = `APF_Backup_${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast('Backup downloaded successfully! 🛡️');
    } catch (err) {
        console.error('Backup download failed:', err);
        showToast('Backup download failed: ' + err.message, 'error');
    }
}

function restoreBackup(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (!confirm('⚠️ RESTORE BACKUP\n\nThis will REPLACE all your current data with the backup file.\n\nAre you sure? This cannot be undone!')) {
        event.target.value = '';
        return;
    }

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const backup = JSON.parse(e.target.result);
            if (!backup._meta || backup._meta.app !== 'APF Dashboard') {
                showToast('Invalid backup file — not an APF Dashboard backup', 'error');
                return;
            }

            const keys = ['visits', 'trainings', 'observations', 'resources', 'notes', 'ideas', 'reflections', 'contacts', 'plannerTasks', 'goalTargets', 'followupStatus'];
            keys.forEach(k => {
                if (backup[k] !== undefined) {
                    if (!Array.isArray(backup[k])) {
                        console.warn(`Backup key "${k}" is not an array, skipping`);
                        return;
                    }
                    DB.set(k, backup[k]);
                }
            });

            showToast('Data restored successfully! Refreshing...', 'success');
            setTimeout(() => {
                renderBackupInfo();
                navigateTo('dashboard');
            }, 1000);
        } catch (err) {
            showToast('Failed to restore — file may be corrupted', 'error');
        }
    };
    reader.readAsText(file);
    event.target.value = '';
}

function resetAllData() {
    if (!confirm('⚠️ DANGER: DELETE ALL DATA\n\nThis will permanently delete ALL your data including visits, trainings, observations, notes, ideas, contacts, reflections, and everything else.\n\nThis CANNOT be undone!\n\nAre you absolutely sure?')) return;
    const answer = prompt('Type DELETE to confirm permanent data removal:');
    if (answer !== 'DELETE') {
        showToast('Reset cancelled', 'info');
        return;
    }

    DB.clear();
    lastEncSaveTime = null;
    clearUnsavedChanges();
    stopPeriodicSave();
    SessionPersist.clear();
    EncryptedCache.clear();
    FileLink.unlink();
    showToast('All data has been reset', 'info');
    setTimeout(() => {
        renderBackupInfo();
        navigateTo('dashboard');
    }, 500);
}

// ===== EXPORT ALL DATA =====
function exportAllDataToExcel() {
    if (typeof XLSX === 'undefined') {
        showToast('Excel library not loaded. Please check your internet connection.', 'error');
        return;
    }
    const wb = XLSX.utils.book_new();

    const visits = DB.get('visits');
    const trainings = DB.get('trainings');
    const observations = DB.get('observations');
    const resources = DB.get('resources');
    const notes = DB.get('notes');

    if (visits.length > 0) {
        const ws = XLSX.utils.json_to_sheet(visits.map(v => ({
            Date: v.date, School: v.school, Block: v.block || '', Purpose: v.purpose || '', Status: v.status, Notes: v.notes || '', 'Follow-up': v.followUp || ''
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Visits');
    }

    if (trainings.length > 0) {
        const ws = XLSX.utils.json_to_sheet(trainings.map(t => ({
            Date: t.date, Title: t.title, Topic: t.topic || '', Duration: t.duration, Venue: t.venue || '', Status: t.status, Attendees: t.attendees || 0, Target: t.target || '', Notes: t.notes || '', Feedback: t.feedback || ''
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Trainings');
    }

    if (observations.length > 0) {
        const ws = XLSX.utils.json_to_sheet(observations.map(o => ({
            Date: o.date, School: o.school, Teacher: o.teacher || '', Class: o.class || '', Subject: o.subject, Topic: o.topic || '',
            'Engagement (1-5)': o.engagement || 0, 'Methodology (1-5)': o.methodology || 0, 'TLM Usage (1-5)': o.tlm || 0,
            Strengths: o.strengths || '', 'Areas for Improvement': o.areas || '', Suggestions: o.suggestions || ''
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Observations');
    }

    if (resources.length > 0) {
        const ws = XLSX.utils.json_to_sheet(resources.map(r => ({
            Title: r.title, Type: r.type, Subject: r.subject || '', Grade: r.grade || '', Source: r.source || '', Description: r.description || '', Tags: (r.tags || []).join(', ')
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Resources');
    }

    if (notes.length > 0) {
        const ws = XLSX.utils.json_to_sheet(notes.map(n => ({
            Title: n.title, Content: n.content, Created: n.createdAt
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Notes');
    }

    const ideas = DB.get('ideas');
    if (ideas.length > 0) {
        const ws = XLSX.utils.json_to_sheet(ideas.map(i => ({
            Title: i.title, Category: i.category || '', Status: i.status || '', Priority: i.priority || '', Description: i.description || '', Tags: (i.tags || []).join(', '), Inspiration: i.inspiration || '', Created: i.createdAt || ''
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Ideas');
    }

    const reflections = DB.get('reflections');
    if (reflections.length > 0) {
        const ws = XLSX.utils.json_to_sheet(reflections.map(r => ({
            Month: r.month || '', Mood: r.mood || '', 'What Went Well': r.wentWell || '', Challenges: r.challenges || '', Learnings: r.learnings || '', 'Next Steps': r.nextSteps || '', Gratitude: r.gratitude || ''
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Reflections');
    }

    const contacts = DB.get('contacts');
    if (contacts.length > 0) {
        const ws = XLSX.utils.json_to_sheet(contacts.map(c => ({
            Name: c.name, Role: c.role || '', School: c.school || '', Phone: c.phone || '', Email: c.email || '', Block: c.block || '', Notes: c.notes || ''
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Contacts');
    }

    // Summary sheet
    const summaryData = [
        { Metric: 'Total Visits', Value: visits.length },
        { Metric: 'Completed Visits', Value: visits.filter(v => v.status === 'completed').length },
        { Metric: 'Trainings', Value: trainings.length },
        { Metric: 'Teachers Reached', Value: trainings.reduce((s, t) => s + (t.attendees || 0), 0) },
        { Metric: 'Training Hours', Value: trainings.reduce((s, t) => s + (t.duration || 0), 0) },
        { Metric: 'Observations', Value: observations.length },
        { Metric: 'Resources', Value: resources.length },
        { Metric: 'Ideas', Value: ideas.length },
        { Metric: 'Reflections', Value: reflections.length },
        { Metric: 'Contacts', Value: contacts.length },
        { Metric: 'Schools Covered', Value: new Set([...visits.map(v => (v.school || '').toLowerCase().trim()), ...observations.map(o => (o.school || '').toLowerCase().trim())]).size },
        { Metric: 'Export Date', Value: new Date().toLocaleDateString('en-IN') },
    ];
    const summaryWs = XLSX.utils.json_to_sheet(summaryData);
    XLSX.utils.book_append_sheet(wb, summaryWs, 'Summary');

    XLSX.writeFile(wb, `APF_Dashboard_Export_${new Date().toISOString().split('T')[0]}.xlsx`);
    showToast('Data exported to Excel');
}

// ===== SAMPLE DATA =====
function loadSampleData() {
    // Load sample data into in-memory store (no localStorage)

    const sampleVisits = [
        { id: DB.generateId(), school: 'Govt. Primary School, Anekal', block: 'Anekal Block', date: '2026-02-12', status: 'planned', purpose: 'Classroom Observation', notes: '', followUp: 'Share fraction activity cards with maths teacher', createdAt: new Date().toISOString() },
        { id: DB.generateId(), school: 'Govt. Higher Primary School, Jigani', block: 'Anekal Block', date: '2026-02-14', status: 'planned', purpose: 'Teacher Support', notes: '', followUp: '', createdAt: new Date().toISOString() },
        { id: DB.generateId(), school: 'Govt. Primary School, Sarjapura', block: 'Anekal Block', date: '2026-02-06', status: 'completed', purpose: 'Workshop Facilitation', notes: 'Conducted session on activity-based learning for maths. Teachers showed interest in using TLMs.', followUp: 'Follow up after 2 weeks', createdAt: new Date(Date.now() - 5 * 86400000).toISOString() },
        { id: DB.generateId(), school: 'Govt. Primary School, Chandapura', block: 'Anekal Block', date: '2026-02-03', status: 'completed', purpose: 'Meeting with HM', notes: 'Discussed upcoming training calendar. HM is supportive.', followUp: '', createdAt: new Date(Date.now() - 8 * 86400000).toISOString() },
        { id: DB.generateId(), school: 'Govt. Model Primary School, Bommasandra', block: 'Anekal Block', date: '2026-02-18', status: 'planned', purpose: 'Follow-up', notes: '', followUp: '', createdAt: new Date().toISOString() },
    ];

    const sampleTrainings = [
        { id: DB.generateId(), title: 'Activity-Based Learning in Mathematics', topic: 'Foundational Numeracy', date: '2026-02-08', duration: 5, venue: 'Block Resource Centre, Anekal', status: 'completed', attendees: 28, target: 'Primary Teachers', notes: 'Covered number sense, place value with TLMs. Used Dienes blocks and number cards.', feedback: 'Teachers found the hands-on activities very useful. Requested more sessions.', createdAt: new Date(Date.now() - 3 * 86400000).toISOString() },
        { id: DB.generateId(), title: 'Storytelling for Language Development', topic: 'Foundational Literacy', date: '2026-02-20', duration: 3, venue: 'Cluster Centre, Jigani', status: 'upcoming', attendees: 0, target: 'Primary Teachers', notes: '', feedback: '', createdAt: new Date().toISOString() },
    ];

    const sampleObservations = [
        { id: DB.generateId(), school: 'Govt. Primary School, Sarjapura', teacher: 'Smt. Lakshmi K', date: '2026-02-06', class: 'Class 3', subject: 'Mathematics', topic: 'Addition of 2-digit numbers', engagement: 4, methodology: 3, tlm: 2, strengths: 'Good rapport with students. Encouraged questions.', areas: 'TLM usage was minimal. Could use more concrete materials.', suggestions: 'Suggested using base-10 blocks for place value understanding. Shared activity cards.', createdAt: new Date(Date.now() - 5 * 86400000).toISOString() },
        { id: DB.generateId(), school: 'Govt. Primary School, Chandapura', teacher: 'Sri. Ramesh B', date: '2026-02-03', class: 'Class 5', subject: 'Language', topic: 'Story reading — "The Lion and the Mouse"', engagement: 5, methodology: 4, tlm: 3, strengths: 'Excellent storytelling. Children were deeply engaged. Good use of voices and expressions.', areas: 'Post-reading comprehension could be strengthened.', suggestions: 'Suggested adding discussion questions and a short writing activity after the story.', createdAt: new Date(Date.now() - 8 * 86400000).toISOString() },
    ];

    const sampleResources = [
        { id: DB.generateId(), title: 'Fraction Activity Cards', type: 'TLM', subject: 'Mathematics', grade: 'Class 3-5', source: 'Self-created', description: 'Set of 24 cards for hands-on fraction activities. Includes comparing, equivalent, and simple operations.', tags: ['fractions', 'hands-on', 'card-activity'], createdAt: new Date().toISOString() },
        { id: DB.generateId(), title: 'Story Cards for Language Class', type: 'Activity', subject: 'Language', grade: 'Class 1-3', source: 'APF', description: 'Picture story cards for sequencing activities and oral narration practice.', tags: ['storytelling', 'sequencing', 'oral-language'], createdAt: new Date().toISOString() },
        { id: DB.generateId(), title: 'Lesson Plan — Place Value (Class 3)', type: 'Lesson Plan', subject: 'Mathematics', grade: 'Class 3', source: 'Self-created', description: 'Detailed lesson plan using Dienes blocks for teaching place value of 3-digit numbers.', tags: ['place-value', 'dienes-blocks', 'lesson-plan'], createdAt: new Date().toISOString() },
        { id: DB.generateId(), title: 'NCF 2023 — Key Highlights', type: 'Reference', subject: 'Other', grade: 'All', source: 'NCERT', description: 'Summary notes from the National Curriculum Framework 2023 with implications for classroom practice.', tags: ['NCF', 'policy', 'reference'], createdAt: new Date().toISOString() },
    ];

    const sampleNotes = [
        { id: DB.generateId(), title: 'Workshop Ideas', content: '• Hands-on fraction activities with paper folding\n• Number line games for addition/subtraction\n• Storytelling followed by comprehension mapping', color: 'amber', createdAt: new Date().toISOString() },
        { id: DB.generateId(), title: 'Follow-up: Sarjapura School', content: 'Check if Smt. Lakshmi started using base-10 blocks.\nShare the fraction worksheet set.\nSchedule next visit in 2 weeks.', color: 'blue', createdAt: new Date(Date.now() - 2 * 86400000).toISOString() },
        { id: DB.generateId(), title: 'Monthly Report Reminders', content: 'Submit February report by March 5th.\nInclude training attendance data.\nAdd photos from workshop.', color: 'red', createdAt: new Date(Date.now() - 4 * 86400000).toISOString() },
    ];

    DB.set('visits', sampleVisits);
    DB.set('trainings', sampleTrainings);
    DB.set('observations', sampleObservations);
    DB.set('resources', sampleResources);
    DB.set('notes', sampleNotes);
}

// ===== Utility Functions =====
function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function getTimeAgo(dateStr) {
    const now = new Date();
    const date = new Date(dateStr);
    const diff = Math.floor((now - date) / 1000);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return date.toLocaleDateString('en-IN');
}

// ===== Initialization =====
let appInitialized = false;

function initApp() {
    if (appInitialized) {
        renderDashboard();
        return;
    }
    appInitialized = true;

    // Nav clicks
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo(item.dataset.section);
        });
    });

    // Mobile menu
    document.getElementById('menuToggle').addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('open');
        document.getElementById('sidebarOverlay').classList.toggle('active');
    });

    document.getElementById('sidebarOverlay').addEventListener('click', closeMobileSidebar);

    // Restore desktop sidebar collapsed state
    restoreSidebarState();

    // Close modals on overlay click
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                overlay.classList.remove('active');
            }
        });
    });

    // Keyboard shortcut — Escape to close modals
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));
        }
    });

    // Star ratings
    initStarRatings();

    // Report year selector
    const yearSelect = document.getElementById('reportYearFilter');
    const currentYear = new Date().getFullYear();
    for (let y = currentYear; y >= currentYear - 5; y--) {
        const opt = document.createElement('option');
        opt.value = y;
        opt.textContent = y;
        yearSelect.appendChild(opt);
    }
    // Set current month
    document.getElementById('reportMonthFilter').value = new Date().getMonth();

    // Init goal tracker month selector
    initGoalMonthSelector();

    // Init reflection month filter
    initReflectionMonthFilter();

    // Update password UI
    updatePasswordUI();
    updateSidebarLockBtn();

    // Init auto-lock
    initAutoLock();

    // Render everything
    renderDashboard();
}

// ===== Welcome Screen (File-Only Storage) =====
function showWelcomeScreen() {
    const ws = document.getElementById('welcomeScreen');
    if (ws) ws.style.display = 'flex';
}

function hideWelcomeScreen() {
    const ws = document.getElementById('welcomeScreen');
    if (ws) ws.style.display = 'none';
}

async function welcomeLoadFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (!file.name.endsWith('.apf')) {
        showToast('Please select an .apf encrypted file', 'error');
        event.target.value = '';
        return;
    }

    const pwd = await getEncryptionPassword();
    if (!pwd) { event.target.value = ''; return; }

    try {
        const statusEl = document.getElementById('welcomeStatus');
        if (statusEl) { statusEl.style.display = ''; statusEl.textContent = 'Decrypting file...'; }

        const buffer = await file.arrayBuffer();
        const data = await CryptoEngine.decrypt(pwd, buffer);

        if (!data._meta || data._meta.app !== 'APF Dashboard') {
            showToast('Invalid file — not an APF Dashboard backup', 'error');
            if (statusEl) statusEl.style.display = 'none';
            event.target.value = '';
            return;
        }

        DB.clear();
        ENCRYPTED_DATA_KEYS.forEach(k => {
            if (data[k] !== undefined && Array.isArray(data[k])) {
                _originalDBSet(k, data[k]);
            }
        });

        // Set password from file's password if not already set
        if (!PasswordManager.isPasswordSet()) {
            const hash = await PasswordManager.hashPassword(pwd);
            PasswordManager.setHash(hash);
        }

        _sessionPassword = pwd;
        lastEncSaveTime = new Date().toISOString();
        // Cache encrypted data in browser
        await EncryptedCache.save(pwd);
        clearUnsavedChanges();
        hideWelcomeScreen();
        isAppUnlocked = true;
        initApp();
        startPeriodicSave();
        showToast('Data loaded from encrypted file! 🔓', 'success');

        // Offer to link a file for auto-save (if File System Access API supported)
        if (FileLink.isSupported() && !FileLink.isLinked()) {
            setTimeout(() => {
                if (confirm('Link a .apf file on your device for automatic read/write?\n\nThis means changes save directly to a file — no manual downloads needed.')) {
                    linkFile();
                }
            }, 1500);
        }
    } catch (err) {
        console.error('Decryption failed:', err);
        const statusEl = document.getElementById('welcomeStatus');
        if (statusEl) statusEl.style.display = 'none';
        if (err.message.includes('Not a valid')) {
            showToast('Not a valid APF encrypted file', 'error');
        } else {
            showToast('Decryption failed — wrong password or corrupted file', 'error');
        }
    }
    event.target.value = '';
}

function welcomeStartFresh(withSampleData) {
    DB.clear();
    if (withSampleData) {
        loadSampleData();
    }
    hideWelcomeScreen();
    isAppUnlocked = true;
    initApp();
    startPeriodicSave();
    if (!_sessionPassword && !withSampleData) {
        clearUnsavedChanges();
    }
    showToast(withSampleData ? 'Started with sample data — set a password to auto-save!' : 'Started fresh — add your data!', 'info');
}

// ===== Beforeunload — save to file + cache =====
window.addEventListener('beforeunload', (e) => {
    if (hasUnsavedChanges && _sessionPassword) {
        // Best-effort saves (fire-and-forget)
        if (FileLink.isLinked()) FileLink.writeToFile(_sessionPassword);
        EncryptedCache.save(_sessionPassword);
    }
});

document.addEventListener('DOMContentLoaded', async () => {
    // Restore persisted file handle from IndexedDB
    if (FileLink.isSupported()) {
        await FileLink.restoreHandle();
    }

    if (PasswordManager.isPasswordSet()) {
        // Try to auto-restore session (page refresh — skip lock screen)
        const savedPwd = SessionPersist.restore();
        if (savedPwd) {
            const hash = await PasswordManager.hashPassword(savedPwd);
            if (hash === PasswordManager.getStoredHash()) {
                _sessionPassword = savedPwd;
                // Auto-load data silently
                let loaded = false;
                if (FileLink.isLinked()) {
                    try {
                        const data = await FileLink.readFromFile(savedPwd);
                        if (data && data._meta && data._meta.app === 'APF Dashboard') {
                            DB.clear();
                            ENCRYPTED_DATA_KEYS.forEach(k => {
                                if (data[k] !== undefined && Array.isArray(data[k])) _originalDBSet(k, data[k]);
                            });
                            lastEncSaveTime = EncryptedCache.getLastSaveTime();
                            clearUnsavedChanges();
                            loaded = true;
                        }
                    } catch (err) { console.error('Auto-restore file read failed:', err); }
                }
                if (!loaded && EncryptedCache.exists()) {
                    try {
                        const data = await EncryptedCache.load(savedPwd);
                        if (data._meta && data._meta.app === 'APF Dashboard') {
                            DB.clear();
                            ENCRYPTED_DATA_KEYS.forEach(k => {
                                if (data[k] !== undefined && Array.isArray(data[k])) _originalDBSet(k, data[k]);
                            });
                            lastEncSaveTime = EncryptedCache.getLastSaveTime();
                            clearUnsavedChanges();
                            loaded = true;
                        }
                    } catch (err) { console.error('Auto-restore cache failed:', err); EncryptedCache.clear(); }
                }
                if (loaded) {
                    isAppUnlocked = true;
                    initApp();
                    startPeriodicSave();
                    return; // Session restored — no lock screen needed
                }
                // Session token invalid now, clear it
                SessionPersist.clear();
            } else {
                SessionPersist.clear();
            }
        }
        // No valid session — show lock screen
        showLockScreen('unlock');
    } else if (EncryptedCache.exists()) {
        EncryptedCache.clear();
        showWelcomeScreen();
    } else {
        showWelcomeScreen();
    }
});
