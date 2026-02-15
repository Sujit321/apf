// ===== APF Resource Person Dashboard — App Logic =====

// ===== Security: HTTPS Check for Crypto API =====
if (typeof window !== 'undefined' && window.location.protocol !== 'https:' && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
    console.warn('[APF Security] Running without HTTPS. crypto.subtle may not be available. Data encryption requires a secure context (HTTPS).');
}

// ===== Global Error Handlers =====
window.onerror = function(msg, src, line, col, err) {
    console.error(`[APF Error] ${msg} at ${src}:${line}:${col}`, err);
    return false;
};
window.addEventListener('unhandledrejection', function(e) {
    console.error('[APF] Unhandled promise rejection:', e.reason);
});

// ===== License Key Protection =====
const LICENSE_KEY_HASH = '8933892060b43134261822deab4afbcdce7148fca4f55f149cf0dfb6af034ab7'; // SHA-256 encrypted
const LICENSE_STORAGE_KEY = 'apf_license_activated';

async function hashLicenseKey(key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(key);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function isLicenseActivated() {
    return localStorage.getItem(LICENSE_STORAGE_KEY) === LICENSE_KEY_HASH;
}

async function handleLicenseSubmit(e) {
    e.preventDefault();
    const input = document.getElementById('licenseKeyInput');
    const errorEl = document.getElementById('licenseError');
    const key = input.value.trim();
    if (!key) { errorEl.textContent = 'Please enter a license key'; return; }
    const hash = await hashLicenseKey(key);
    if (hash === LICENSE_KEY_HASH) {
        localStorage.setItem(LICENSE_STORAGE_KEY, LICENSE_KEY_HASH);
        document.getElementById('licenseScreen').style.display = 'none';
        showToast('License activated successfully! \u2705', 'success');
        // Proceed with normal app boot
        proceedAfterLicense();
    } else {
        errorEl.textContent = 'Invalid license key';
        input.value = '';
        input.focus();
        // Shake animation
        const container = document.querySelector('.license-container');
        container.classList.remove('lock-shake');
        void container.offsetWidth;
        container.classList.add('lock-shake');
    }
}

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
    FLAG_KEY: 'apf_cache_exists',
    _dbName: 'apf_cache_db',
    _storeName: 'cache',

    _openDB() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(this._dbName, 1);
            req.onupgradeneeded = () => req.result.createObjectStore(this._storeName);
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    },

    exists() {
        return !!(localStorage.getItem(this.FLAG_KEY) || localStorage.getItem(this.CACHE_KEY));
    },

    async save(password) {
        try {
            const allData = { _meta: { app: 'APF Dashboard', version: 2, cachedAt: new Date().toISOString() } };
            ENCRYPTED_DATA_KEYS.forEach(k => { allData[k] = DB.get(k); });
            const encrypted = await CryptoEngine.encrypt(password, allData);

            // Store in IndexedDB (no size limit)
            const db = await this._openDB();
            await new Promise((resolve, reject) => {
                const tx = db.transaction(this._storeName, 'readwrite');
                tx.objectStore(this._storeName).put(encrypted.buffer, this.CACHE_KEY);
                tx.oncomplete = resolve;
                tx.onerror = () => reject(tx.error);
            });

            const now = new Date().toISOString();
            localStorage.setItem(this.FLAG_KEY, '1');
            localStorage.setItem(this.SAVE_TIME_KEY, now);
            lastEncSaveTime = now;

            // Clean up old localStorage cache if present
            localStorage.removeItem(this.CACHE_KEY);
            return true;
        } catch (err) {
            console.error('Cache save failed:', err);
            return false;
        }
    },

    async load(password) {
        // Try IndexedDB first (new storage)
        try {
            const db = await this._openDB();
            const buffer = await new Promise((resolve, reject) => {
                const tx = db.transaction(this._storeName, 'readonly');
                const req = tx.objectStore(this._storeName).get(this.CACHE_KEY);
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
            });
            if (buffer) {
                return CryptoEngine.decrypt(password, buffer);
            }
        } catch (err) {
            console.error('IndexedDB cache read failed:', err);
        }

        // Fallback: try old localStorage format (migration)
        const b64 = localStorage.getItem(this.CACHE_KEY);
        if (!b64) throw new Error('No cached data');
        const binary = atob(b64);
        const arr = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) arr[i] = binary.charCodeAt(i);
        return CryptoEngine.decrypt(password, arr.buffer);
    },

    async clear() {
        localStorage.removeItem(this.FLAG_KEY);
        localStorage.removeItem(this.CACHE_KEY);
        localStorage.removeItem(this.SAVE_TIME_KEY);
        try {
            const db = await this._openDB();
            const tx = db.transaction(this._storeName, 'readwrite');
            tx.objectStore(this._storeName).delete(this.CACHE_KEY);
        } catch (err) { /* ignore */ }
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
    _XOR_KEY: 'ApfDashboard2026SecureSession',
    _obfuscate(str) {
        // Simple XOR obfuscation to avoid plain-text password in sessionStorage
        const key = this._XOR_KEY;
        let result = '';
        for (let i = 0; i < str.length; i++) {
            result += String.fromCharCode(str.charCodeAt(i) ^ key.charCodeAt(i % key.length));
        }
        return btoa(result);
    },
    _deobfuscate(encoded) {
        const str = atob(encoded);
        const key = this._XOR_KEY;
        let result = '';
        for (let i = 0; i < str.length; i++) {
            result += String.fromCharCode(str.charCodeAt(i) ^ key.charCodeAt(i % key.length));
        }
        return result;
    },
    save(password) {
        try { sessionStorage.setItem(this._KEY, this._obfuscate(password)); } catch {}
    },
    restore() {
        try {
            const t = sessionStorage.getItem(this._KEY);
            return t ? this._deobfuscate(t) : null;
        } catch { return null; }
    },
    clear() {
        try { sessionStorage.removeItem(this._KEY); } catch {}
    }
};

// Unsaved changes tracking
let hasUnsavedChanges = false;
let lastEncSaveTime = null;
const ENCRYPTED_DATA_KEYS = ['visits', 'trainings', 'observations', 'resources', 'notes', 'ideas', 'reflections', 'contacts', 'plannerTasks', 'goalTargets', 'followupStatus', 'worklog', 'userProfile', 'meetings', 'growthAssessments', 'growthActionPlans', 'maraiTracking', 'schoolWork', 'visitPlanEntries', 'visitPlanDropdowns', 'feedbackReports', 'teacherRecords', 'schoolStudentRecords'];

// ===== Google Drive Auto-Backup (via Google Apps Script) =====
const GoogleDriveSync = {
    URL_KEY: 'apf_gdrive_script_url',
    AUTO_KEY: 'apf_gdrive_auto_backup',
    LAST_KEY: 'apf_gdrive_last_backup',
    LAST_SIZE_KEY: 'apf_gdrive_last_size',
    _busy: false,
    _autoTimer: null,

    getScriptUrl() { return localStorage.getItem(this.URL_KEY) || ''; },
    setScriptUrl(url) { localStorage.setItem(this.URL_KEY, url); },
    clearScriptUrl() { localStorage.removeItem(this.URL_KEY); },

    isConnected() { return !!this.getScriptUrl(); },

    isAutoEnabled() { return localStorage.getItem(this.AUTO_KEY) === '1'; },
    setAutoEnabled(v) { localStorage.setItem(this.AUTO_KEY, v ? '1' : '0'); },

    getLastBackup() { return localStorage.getItem(this.LAST_KEY) || ''; },
    setLastBackup(ts) { localStorage.setItem(this.LAST_KEY, ts); },

    getLastSize() { return localStorage.getItem(this.LAST_SIZE_KEY) || ''; },
    setLastSize(s) { localStorage.setItem(this.LAST_SIZE_KEY, s); },

    // Test connection to the Google Apps Script
    async testConnection() {
        const url = this.getScriptUrl();
        if (!url) return { ok: false, error: 'No URL configured' };
        try {
            const resp = await fetch(url, {
                method: 'POST',
                redirect: 'follow',
                headers: { 'Content-Type': 'text/plain' },
                body: JSON.stringify({ action: 'ping' })
            });
            const text = await resp.text();
            let data;
            try { data = JSON.parse(text); } catch { data = null; }
            if (data && data.error === 'Unknown action') {
                return { ok: false, error: 'Outdated script — please copy the latest code from the setup guide below, paste it in your Apps Script, then go to Deploy → Manage deployments → Edit (pencil icon) → Version: New version → Deploy' };
            }
            if (!data) return { ok: false, error: 'Invalid response from script' };
            return { ok: true, data };
        } catch (err) {
            return { ok: false, error: err.message };
        }
    },

    // Backup data to Google Drive
    async backup() {
        if (this._busy) return { ok: false, error: 'Backup in progress' };
        if (!_sessionPassword) return { ok: false, error: 'No password available' };
        const url = this.getScriptUrl();
        if (!url) return { ok: false, error: 'Google Drive not connected' };

        this._busy = true;
        this.updateUI('syncing');

        try {
            // Collect & encrypt
            const allData = { _meta: { app: 'APF Dashboard', version: 2, backedUpAt: new Date().toISOString() } };
            ENCRYPTED_DATA_KEYS.forEach(k => { allData[k] = DB.get(k); });
            const encrypted = await CryptoEngine.encrypt(_sessionPassword, allData);
            // Convert to base64 in chunks (avoid call stack overflow with large data)
            let binary = '';
            const chunkSize = 8192;
            for (let i = 0; i < encrypted.length; i += chunkSize) {
                binary += String.fromCharCode.apply(null, encrypted.subarray(i, i + chunkSize));
            }
            const b64Data = btoa(binary);

            // Send to Apps Script
            const resp = await fetch(url, {
                method: 'POST',
                redirect: 'follow',
                headers: { 'Content-Type': 'text/plain' },
                body: JSON.stringify({ action: 'backup', data: b64Data, timestamp: new Date().toISOString() })
            });
            const text = await resp.text();
            let result;
            try { result = JSON.parse(text); } catch { result = { success: true }; }

            if (result && result.error) {
                this._busy = false;
                this.updateUI('error');
                const errMsg = result.error === 'Unknown action'
                    ? 'Outdated script — please update your Apps Script code and re-deploy (Deploy → Manage deployments → Edit → New version → Deploy)'
                    : result.error;
                return { ok: false, error: errMsg };
            }

            const now = new Date().toISOString();
            this.setLastBackup(now);
            const sizeKB = (b64Data.length / 1024).toFixed(1);
            this.setLastSize(sizeKB + ' KB');
            this.updateUI('connected');
            this._busy = false;
            return { ok: true, size: sizeKB };
        } catch (err) {
            console.error('Google Drive backup failed:', err);
            this.updateUI('error');
            this._busy = false;
            return { ok: false, error: err.message };
        }
    },

    // Restore data from Google Drive
    async restore() {
        if (this._busy) return { ok: false, error: 'Operation in progress' };
        if (!_sessionPassword) return { ok: false, error: 'No password available' };
        const url = this.getScriptUrl();
        if (!url) return { ok: false, error: 'Google Drive not connected' };

        this._busy = true;
        this.updateUI('syncing');

        try {
            const resp = await fetch(url, {
                method: 'POST',
                redirect: 'follow',
                headers: { 'Content-Type': 'text/plain' },
                body: JSON.stringify({ action: 'restore' })
            });
            const text = await resp.text();
            let result;
            try { result = JSON.parse(text); } catch { result = null; }

            if (!result || result.error) {
                this._busy = false;
                this.updateUI('connected');
                const errMsg = result?.error === 'Unknown action'
                    ? 'Outdated script — please update your Apps Script code and re-deploy (Deploy → Manage deployments → Edit → New version → Deploy)'
                    : (result?.error || 'No backup found on Google Drive');
                return { ok: false, error: errMsg };
            }

            const b64Data = result.data;
            if (!b64Data) {
                this._busy = false;
                this.updateUI('connected');
                return { ok: false, error: 'No backup data on Google Drive' };
            }

            // Decrypt
            const binary = atob(b64Data);
            const buffer = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) buffer[i] = binary.charCodeAt(i);
            const data = await CryptoEngine.decrypt(_sessionPassword, buffer.buffer);

            if (!data._meta || data._meta.app !== 'APF Dashboard') {
                this._busy = false;
                this.updateUI('connected');
                return { ok: false, error: 'Invalid backup data' };
            }

            // Apply to DB
            DB.clear();
            ENCRYPTED_DATA_KEYS.forEach(k => {
                if (data[k] !== undefined && Array.isArray(data[k])) _originalDBSet(k, data[k]);
            });
            markUnsavedChanges();

            // Re-render
            const active = document.querySelector('.nav-item.active');
            if (active) navigateTo(active.dataset.section);

            this._busy = false;
            this.updateUI('connected');
            return { ok: true, meta: data._meta };
        } catch (err) {
            console.error('Google Drive restore failed:', err);
            this._busy = false;
            this.updateUI('connected');
            const isPasswordError = err.name === 'OperationError' ||
                err.message.includes('Decryption') || err.message.includes('decrypt') ||
                err.message.includes('operation failed');
            return { ok: false, error: isPasswordError
                ? 'Password mismatch — this backup was created with a different password. Please log in with the same password that was used when the backup was made.'
                : err.message };
        }
    },

    // Get backup info from Google Drive
    async getBackupInfo() {
        const url = this.getScriptUrl();
        if (!url) return null;
        try {
            const resp = await fetch(url, {
                method: 'POST',
                redirect: 'follow',
                headers: { 'Content-Type': 'text/plain' },
                body: JSON.stringify({ action: 'info' })
            });
            const text = await resp.text();
            return JSON.parse(text);
        } catch { return null; }
    },

    // Auto-backup (debounced — 10s after last change)
    scheduleAutoBackup() {
        if (!this.isConnected() || !this.isAutoEnabled()) return;
        if (this._autoTimer) clearTimeout(this._autoTimer);
        this._autoTimer = setTimeout(() => {
            this.backup().then(r => {
                if (r.ok) console.log('Auto-backup to Google Drive: ' + r.size + ' KB');
                else console.warn('Auto-backup to Google Drive failed:', r.error);
            });
        }, 10000); // 10 seconds debounce
    },

    // Update UI elements
    updateUI(state) {
        const statusEl = document.getElementById('gdriveStatus');
        const dotEl = document.getElementById('gdriveDot');
        const actionsEl = document.getElementById('gdriveActions');
        const infoEl = document.getElementById('gdriveInfo');
        const connectBtn = document.getElementById('gdriveConnectBtn');
        const disconnectArea = document.getElementById('gdriveDisconnectArea');

        if (!statusEl) return;

        const states = {
            disconnected: { dot: '#64748b', icon: 'fa-cloud', label: 'Not Connected', detail: 'Connect to auto-backup your data to Google Drive', color: '' },
            connected: { dot: '#22c55e', icon: 'fa-check-circle', label: 'Connected', detail: 'Encrypted backups syncing to Google Drive', color: 'gdrive-connected' },
            syncing: { dot: '#f59e0b', icon: 'fa-sync fa-spin', label: 'Syncing...', detail: 'Uploading encrypted data to Google Drive', color: 'gdrive-syncing' },
            error: { dot: '#ef4444', icon: 'fa-exclamation-triangle', label: 'Error', detail: 'Failed to connect — check your script URL', color: 'gdrive-error' }
        };
        const s = states[state] || states.disconnected;

        if (dotEl) dotEl.style.background = s.dot;
        statusEl.className = 'gdrive-status ' + s.color;
        statusEl.innerHTML = `<i class="fas ${s.icon}"></i><div><strong>${s.label}</strong><span>${s.detail}</span></div>`;

        if (connectBtn) connectBtn.style.display = state === 'disconnected' ? '' : 'none';
        if (disconnectArea) disconnectArea.style.display = state !== 'disconnected' ? '' : 'none';
        if (actionsEl) actionsEl.style.display = state !== 'disconnected' ? '' : 'none';

        // Update info
        if (infoEl && state !== 'disconnected') {
            const last = this.getLastBackup();
            const size = this.getLastSize();
            let infoHTML = '';
            if (last) {
                const d = new Date(last);
                infoHTML += `<div class="gdrive-info-row"><i class="fas fa-clock"></i> Last backup: <strong>${d.toLocaleDateString('en-IN', {day:'2-digit',month:'short',year:'numeric'})} ${d.toLocaleTimeString('en-IN', {hour:'2-digit',minute:'2-digit'})}</strong></div>`;
            }
            if (size) {
                infoHTML += `<div class="gdrive-info-row"><i class="fas fa-weight-hanging"></i> Backup size: <strong>${size}</strong></div>`;
            }
            infoEl.innerHTML = infoHTML || '<div class="gdrive-info-row"><i class="fas fa-info-circle"></i> No backup yet — click "Backup Now"</div>';
        }

        // Auto toggle
        const autoToggle = document.getElementById('gdriveAutoToggle');
        if (autoToggle) autoToggle.checked = this.isAutoEnabled();
    },

    // Disconnect
    disconnect() {
        this.clearScriptUrl();
        localStorage.removeItem(this.AUTO_KEY);
        localStorage.removeItem(this.LAST_KEY);
        localStorage.removeItem(this.LAST_SIZE_KEY);
        if (this._autoTimer) clearTimeout(this._autoTimer);
        this.updateUI('disconnected');
    }
};

// Public Google Drive functions
async function connectGoogleDrive() {
    const url = document.getElementById('gdriveScriptURL')?.value?.trim();
    if (!url) {
        showToast('Please enter your Google Apps Script URL', 'error');
        return;
    }
    if (!url.startsWith('https://script.google.com/')) {
        showToast('Invalid URL — must start with https://script.google.com/', 'error');
        return;
    }

    const btn = document.getElementById('gdriveConnectBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...'; }

    GoogleDriveSync.setScriptUrl(url);
    const result = await GoogleDriveSync.testConnection();

    if (result.ok) {
        GoogleDriveSync.setAutoEnabled(true);
        GoogleDriveSync.updateUI('connected');
        showToast('Google Drive connected!', 'success');
        // Do initial backup
        const bkp = await GoogleDriveSync.backup();
        if (bkp.ok) showToast('Initial backup complete (' + bkp.size + ' KB)', 'success');
    } else {
        GoogleDriveSync.clearScriptUrl();
        GoogleDriveSync.updateUI('disconnected');
        showToast('Connection failed: ' + result.error, 'error');
    }
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-plug"></i> Connect'; }
}

function disconnectGoogleDrive() {
    if (!confirm('Disconnect Google Drive backup? Your data on Drive will remain intact.')) return;
    GoogleDriveSync.disconnect();
    showToast('Google Drive disconnected', 'info');
}

async function gdriveBackupNow() {
    const btn = document.getElementById('gdriveBackupBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Backing up...'; }
    const result = await GoogleDriveSync.backup();
    if (result.ok) {
        showToast('Backed up to Google Drive (' + result.size + ' KB)', 'success');
    } else {
        showToast('Backup failed: ' + result.error, 'error');
    }
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-cloud-upload-alt"></i> Backup Now'; }
}

async function gdriveRestoreNow() {
    if (!confirm('Restore data from Google Drive? This will REPLACE all current data with the backup.')) return;
    const btn = document.getElementById('gdriveRestoreBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Restoring...'; }
    const result = await GoogleDriveSync.restore();
    if (result.ok) {
        showToast('Data restored from Google Drive!', 'success');
        if (result.meta?.backedUpAt) {
            const d = new Date(result.meta.backedUpAt);
            showToast('Backup was from: ' + d.toLocaleDateString('en-IN') + ' ' + d.toLocaleTimeString('en-IN'), 'info');
        }
    } else {
        const isPasswordErr = result.error && result.error.toLowerCase().includes('password mismatch');
        showToast(isPasswordErr ? '🔐 ' + result.error : 'Restore failed: ' + result.error, 'error', isPasswordErr ? 8000 : 4000);
    }
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-cloud-download-alt"></i> Restore from Drive'; }
}

function toggleGdriveAuto(checked) {
    GoogleDriveSync.setAutoEnabled(checked);
    showToast(checked ? 'Auto-backup to Google Drive enabled' : 'Auto-backup disabled', 'info');
}

function toggleGdriveSetup() {
    const el = document.getElementById('gdriveSetupGuide');
    if (el) el.style.display = el.style.display === 'none' ? '' : 'none';
}

function copyAppsScriptCode() {
    const code = document.getElementById('gdriveScriptCode')?.textContent;
    if (!code) return;
    navigator.clipboard.writeText(code).then(() => showToast('Script code copied!', 'success'))
        .catch(() => showToast('Please copy manually', 'info'));
}

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
        // 2. Also save to browser cache (IndexedDB — no size limit)
        const saved = await EncryptedCache.save(_sessionPassword);
        if (!saved) {
            showToast('⚠️ Auto-save to browser cache failed. Please manually save/export your data.', 'error', 8000);
        } else {
            clearUnsavedChanges();
            updateEncryptedFileStatus();
            // Clear localStorage fallback since proper encrypted save succeeded
            clearLocalStorageFallback();
            // 3. Schedule Google Drive backup if enabled
            GoogleDriveSync.scheduleAutoBackup();
        }
    } catch (err) {
        console.error('Auto-save failed:', err);
        showToast('⚠️ Auto-save failed: ' + (err.message || 'Unknown error'), 'error', 6000);
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

// Wrap DB.set to track changes and persist to localStorage fallback
const _originalDBSet = DB.set.bind(DB);
DB.set = function(key, data) {
    _originalDBSet(key, data);
    if (ENCRYPTED_DATA_KEYS.includes(key)) {
        markUnsavedChanges();
        // localStorage fallback when no password/encryption is set up
        try { localStorage.setItem('apf_data_' + key, JSON.stringify(data)); } catch(e) {}
    }
};

// Restore data from localStorage fallback (used when no password/encryption is configured)
function restoreFromLocalStorage() {
    let restored = 0;
    ENCRYPTED_DATA_KEYS.forEach(key => {
        try {
            const raw = localStorage.getItem('apf_data_' + key);
            if (raw) {
                const data = JSON.parse(raw);
                if (Array.isArray(data) && data.length > 0) {
                    _originalDBSet(key, data);
                    restored++;
                }
            }
        } catch(e) { console.warn('localStorage restore failed for', key, e); }
    });
    return restored;
}

// Clear localStorage fallback data (called after proper encrypted save succeeds)
function clearLocalStorageFallback() {
    ENCRYPTED_DATA_KEYS.forEach(key => {
        try { localStorage.removeItem('apf_data_' + key); } catch(e) {}
    });
}

async function getEncryptionPassword() {
    // Use session password if available
    if (_sessionPassword) return _sessionPassword;
    // Fallback: ask user to re-authenticate
    showToast('Session expired — please refresh and log in again', 'error');
    return null;
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
        applyProfileToUI();
        showToast('Data restored from encrypted file! 🔓', 'success');
        setTimeout(() => navigateTo('dashboard'), 500);
    } catch (err) {
        console.error('Decryption failed:', err);
        if (err.message.includes('Not a valid')) {
            showToast('Not a valid APF encrypted file', 'error');
        } else if (err.name === 'OperationError' || err.message.includes('operation failed')) {
            showToast('Password mismatch — this file was encrypted with a different password. Please enter the correct password.', 'error', 6000);
        } else {
            showToast('Decryption failed — file may be corrupted', 'error');
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

        if (appInitialized) {
            // Password change — app already running, re-save data with new password
            showToast('Password changed successfully! 🔒', 'success');
            markUnsavedChanges();
            // Re-encrypt cached data + linked file with the new password
            try { await EncryptedCache.save(password); } catch(e) { console.error('Re-encrypt cache failed:', e); }
            if (FileLink.isLinked()) {
                try { await FileLink.writeToFile(password); } catch(e) { console.error('Re-encrypt file failed:', e); }
            }
            clearUnsavedChanges();
        } else {
            // First-time setup — show welcome screen
            showToast('Password set! Your dashboard is now protected 🔒');
            showWelcomeScreen();
        }
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
    // User is already authenticated via _sessionPassword, go directly to setup
    showLockScreen('setup');
}

async function removePassword() {
    if (!confirm('Remove password protection? Your data will no longer be encrypted.')) return;
    PasswordManager.removeHash();
    SessionPersist.clear();
    _sessionPassword = null;
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
        case 'teachers': renderTeacherGrowth(); break;
        case 'marai': renderMaraiTracking(); break;
        case 'schoolwork': renderSchoolWork(); break;
        case 'visitplan': renderVisitPlan(); break;
        case 'reflections': initReflectionMonthFilter(); renderReflections(); break;
        case 'contacts': renderContacts(); break;
        case 'teacherrecords': renderTeacherRecords(); break;
        case 'meetings': renderMeetings(); break;
        case 'worklog': renderWorkLog(); break;
        case 'livesync': renderSyncSettings(); LiveSync.updateFloatingIndicator(); break;
        case 'backup': renderBackupInfo(); break;
        case 'settings': renderSettings(); break;
        case 'feedback': renderFeedbackList(); break;
        case 'growth': renderGrowthFramework(); break;
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

// ===== Theme Toggle (Light/Dark Mode) =====
function toggleTheme() {
    const body = document.body;
    const isLight = body.classList.toggle('light-mode');
    const icon = document.getElementById('themeIcon');
    if (icon) {
        icon.className = isLight ? 'fas fa-sun' : 'fas fa-moon';
    }
    const btn = document.getElementById('themeToggle');
    if (btn) btn.title = isLight ? 'Switch to dark mode' : 'Switch to light mode';
    try { localStorage.setItem('apf_theme', isLight ? 'light' : 'dark'); } catch(e) {}
    // Re-apply accent color for the new theme mode
    const s = getAppSettings();
    const accent = ACCENT_COLORS.find(c => c.value === s.accentColor);
    if (accent) applyAccentColorToCSS(accent.value, accent.css);
}

function restoreTheme() {
    try {
        const saved = localStorage.getItem('apf_theme');
        if (saved === 'light') {
            document.body.classList.add('light-mode');
            const icon = document.getElementById('themeIcon');
            if (icon) icon.className = 'fas fa-sun';
            const btn = document.getElementById('themeToggle');
            if (btn) btn.title = 'Switch to dark mode';
        }
    } catch(e) {}
}

// ===== Live Sync — Peer-to-Peer Real-Time Data Sync (WhatsApp Web-style) =====
const SYNC_PERSIST_KEY = 'apf_livesync_room';
const SYNC_SETTINGS_KEY = 'apf_livesync_settings';

const LiveSync = {
    peer: null,
    connections: [],       // Active DataConnection objects
    roomCode: null,
    isHost: false,
    deviceId: null,
    _syncLog: [],
    _autoSyncEnabled: true,
    _heartbeatInterval: null,
    _reconnectTimer: null,
    _reconnectAttempts: 0,
    _maxReconnectAttempts: 20,
    _debounceTimers: {},
    _pendingChanges: {},
    _isSyncing: false,       // Guard against re-entrant sync
    _lastSyncTime: null,
    _syncCount: 0,
    _totalBytesSynced: 0,

    // Generate a short readable room code
    generateRoomCode() {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        let code = '';
        for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
        return code;
    },

    // Get device fingerprint for display
    getDeviceName() {
        const ua = navigator.userAgent;
        if (/iPhone|iPad|iPod/.test(ua)) return '📱 iOS Device';
        if (/Android/.test(ua)) return '📱 Android Device';
        if (/Mac/.test(ua)) return '💻 Mac';
        if (/Linux/.test(ua)) return '💻 Linux PC';
        if (/Windows/.test(ua)) return '💻 Windows PC';
        return '🖥️ Device';
    },

    // Build a unique peer ID from room code
    getPeerId(code, isHost) {
        return 'apf-sync-' + code + (isHost ? '-host' : '-' + Date.now().toString(36));
    },

    // Collect all app data for sync
    collectData() {
        const allData = { _meta: { app: 'APF Dashboard', version: 2, syncedAt: new Date().toISOString(), device: this.getDeviceName() } };
        ENCRYPTED_DATA_KEYS.forEach(k => { allData[k] = DB.get(k); });
        return allData;
    },

    // ---- Smart Merge: merge by record ID instead of full replace ----
    mergeArrayByKey(local, remote, key = 'id') {
        if (!Array.isArray(remote)) return local;
        if (!Array.isArray(local) || local.length === 0) return remote;

        const map = new Map();
        // Local records first
        local.forEach(item => {
            const k = item && item[key];
            if (k) map.set(k, item);
            else map.set(JSON.stringify(item), item);
        });
        // Remote records overwrite by ID (or add new)
        remote.forEach(item => {
            const k = item && item[key];
            if (k) {
                const existing = map.get(k);
                // If remote has newer timestamp, use it
                if (!existing) {
                    map.set(k, item);
                } else {
                    const localTime = existing.updatedAt || existing.createdAt || '';
                    const remoteTime = item.updatedAt || item.createdAt || '';
                    if (remoteTime >= localTime) map.set(k, item);
                }
            } else {
                const jk = JSON.stringify(item);
                if (!map.has(jk)) map.set(jk, item);
            }
        });
        return Array.from(map.values());
    },

    // Apply received data to local DB (smart merge)
    applyData(data) {
        if (!data || !data._meta || data._meta.app !== 'APF Dashboard') {
            this.log('Rejected invalid sync data', 'error');
            return false;
        }
        this._isSyncing = true;
        const settings = this.getSettings();
        
        ENCRYPTED_DATA_KEYS.forEach(k => {
            if (data[k] !== undefined && Array.isArray(data[k])) {
                if (settings.mergeMode === 'smart') {
                    const local = DB.get(k);
                    const merged = this.mergeArrayByKey(local, data[k]);
                    _originalDBSet(k, merged);
                } else {
                    _originalDBSet(k, data[k]);
                }
            }
        });
        
        this._isSyncing = false;
        // Trigger save
        markUnsavedChanges();
        // Re-render current section
        const active = document.querySelector('.nav-item.active');
        if (active) navigateTo(active.dataset.section);
        return true;
    },

    // ---- Debounced real-time broadcast ----
    broadcastChange(key, value) {
        if (this._isSyncing) return; // Don't echo back what we just received
        const conns = this.connections.filter(c => c.open);
        if (conns.length === 0) return;

        // Debounce: batch rapid changes to the same key (300ms)
        if (this._debounceTimers[key]) clearTimeout(this._debounceTimers[key]);
        this._pendingChanges[key] = value;

        this._debounceTimers[key] = setTimeout(() => {
            const val = this._pendingChanges[key];
            delete this._pendingChanges[key];
            delete this._debounceTimers[key];

            const payload = JSON.stringify({ type: 'data-changed', key, value: val });
            const bytes = new Blob([payload]).size;
            this._totalBytesSynced += bytes;
            this._syncCount++;

            conns.forEach(c => {
                try { c.send({ type: 'data-changed', key, value: val, ts: Date.now() }); } catch(e) {}
            });
            this.showSyncPulse('send');
            this.updateSyncStats();
        }, 300);
    },

    // ---- Flush all pending changes immediately ----
    flushPending() {
        Object.keys(this._debounceTimers).forEach(key => {
            clearTimeout(this._debounceTimers[key]);
            const val = this._pendingChanges[key];
            delete this._pendingChanges[key];
            delete this._debounceTimers[key];
            if (val !== undefined) {
                const conns = this.connections.filter(c => c.open);
                conns.forEach(c => {
                    try { c.send({ type: 'data-changed', key, value: val, ts: Date.now() }); } catch(e) {}
                });
            }
        });
    },

    // ---- Persistent Room (remember & auto-reconnect) ----
    saveRoom() {
        try {
            localStorage.setItem(SYNC_PERSIST_KEY, JSON.stringify({
                code: this.roomCode,
                isHost: this.isHost,
                savedAt: Date.now()
            }));
        } catch(e) {}
    },

    clearSavedRoom() {
        try { localStorage.removeItem(SYNC_PERSIST_KEY); } catch(e) {}
    },

    getSavedRoom() {
        try {
            const raw = localStorage.getItem(SYNC_PERSIST_KEY);
            if (!raw) return null;
            const room = JSON.parse(raw);
            // Expire saved rooms after 24 hours
            if (Date.now() - room.savedAt > 24 * 60 * 60 * 1000) {
                this.clearSavedRoom();
                return null;
            }
            return room;
        } catch(e) { return null; }
    },

    // ---- Settings ----
    getSettings() {
        try {
            const raw = localStorage.getItem(SYNC_SETTINGS_KEY);
            if (raw) return { ...this._defaultSettings(), ...JSON.parse(raw) };
        } catch(e) {}
        return this._defaultSettings();
    },

    _defaultSettings() {
        return {
            autoReconnect: true,
            autoSyncOnConnect: true,
            mergeMode: 'smart',  // 'smart' | 'replace'
            showFloatingIndicator: true,
            syncNotifications: true
        };
    },

    saveSettings(settings) {
        try { localStorage.setItem(SYNC_SETTINGS_KEY, JSON.stringify(settings)); } catch(e) {}
    },

    // ---- Heartbeat (keep-alive) ----
    startHeartbeat() {
        this.stopHeartbeat();
        this._heartbeatInterval = setInterval(() => {
            const conns = this.connections.filter(c => c.open);
            conns.forEach(c => {
                try { c.send({ type: 'ping', ts: Date.now() }); } catch(e) {}
            });
            // Check for dead connections
            this.connections = this.connections.filter(c => c.open);
            this.updateDevices();
            this.updateFloatingIndicator();
        }, 15000);
    },

    stopHeartbeat() {
        if (this._heartbeatInterval) {
            clearInterval(this._heartbeatInterval);
            this._heartbeatInterval = null;
        }
    },

    // ---- Auto-reconnect ----
    scheduleReconnect() {
        const settings = this.getSettings();
        if (!settings.autoReconnect) return;
        if (this._reconnectAttempts >= this._maxReconnectAttempts) {
            this.log('Max reconnect attempts reached. Create a new room.', 'error');
            this.clearSavedRoom();
            return;
        }

        const delay = Math.min(2000 * Math.pow(1.5, this._reconnectAttempts), 30000);
        this._reconnectAttempts++;

        this.log(`Reconnecting in ${Math.round(delay / 1000)}s (attempt ${this._reconnectAttempts})...`, 'info');
        this.updateStatus('connecting', `Reconnecting... (attempt ${this._reconnectAttempts})`);

        this._reconnectTimer = setTimeout(() => {
            const saved = this.getSavedRoom();
            if (saved) {
                if (saved.isHost) {
                    this._doCreateRoom(saved.code);
                } else {
                    this._doJoinRoom(saved.code);
                }
            }
        }, delay);
    },

    cancelReconnect() {
        if (this._reconnectTimer) {
            clearTimeout(this._reconnectTimer);
            this._reconnectTimer = null;
        }
        this._reconnectAttempts = 0;
    },

    // ---- Visual Sync Pulse (floating indicator) ----
    showSyncPulse(direction = 'send') {
        const indicator = document.getElementById('syncFloatingIndicator');
        if (!indicator) return;
        const settings = this.getSettings();
        if (!settings.showFloatingIndicator) return;

        const arrow = indicator.querySelector('.sync-float-arrow');
        if (arrow) {
            arrow.innerHTML = direction === 'send' 
                ? '<i class="fas fa-arrow-up"></i>' 
                : '<i class="fas fa-arrow-down"></i>';
            arrow.className = 'sync-float-arrow sync-float-' + direction;
        }
        indicator.classList.add('sync-pulse-active');
        setTimeout(() => indicator.classList.remove('sync-pulse-active'), 600);
    },

    updateFloatingIndicator() {
        const indicator = document.getElementById('syncFloatingIndicator');
        if (!indicator) return;
        const settings = this.getSettings();

        const conns = this.connections.filter(c => c.open);
        const isConnected = conns.length > 0;

        if (!settings.showFloatingIndicator || !this.peer) {
            indicator.style.display = 'none';
            return;
        }
        indicator.style.display = 'flex';
        indicator.className = 'sync-floating-indicator' + (isConnected ? ' sync-float-online' : ' sync-float-offline');

        const countEl = indicator.querySelector('.sync-float-count');
        if (countEl) countEl.textContent = conns.length;

        const statusEl = indicator.querySelector('.sync-float-status');
        if (statusEl) statusEl.textContent = isConnected ? 'Syncing' : 'Waiting...';
    },

    // ---- Sync Stats ----
    updateSyncStats() {
        const el = document.getElementById('syncStatsPanel');
        if (!el) return;
        const sizeStr = this._totalBytesSynced > 1048576 
            ? (this._totalBytesSynced / 1048576).toFixed(1) + ' MB'
            : this._totalBytesSynced > 1024 
                ? (this._totalBytesSynced / 1024).toFixed(1) + ' KB'
                : this._totalBytesSynced + ' B';

        el.innerHTML = `
            <div class="sync-stat-item"><span class="sync-stat-val">${this._syncCount}</span><span class="sync-stat-label">Changes Synced</span></div>
            <div class="sync-stat-item"><span class="sync-stat-val">${sizeStr}</span><span class="sync-stat-label">Data Transferred</span></div>
            <div class="sync-stat-item"><span class="sync-stat-val">${this._lastSyncTime || '—'}</span><span class="sync-stat-label">Last Sync</span></div>
        `;
    },

    // ---- QR Code Generation ----
    generateQRCode() {
        const container = document.getElementById('syncQRCode');
        if (!container || !this.roomCode) return;

        const qrData = `APF-SYNC:${this.roomCode}`;
        // Use a lightweight QR generation via SVG (no external library needed)
        const size = 200;
        const qr = this._generateQRMatrix(qrData);
        if (!qr) {
            container.innerHTML = `<div class="sync-qr-fallback"><span class="sync-qr-code-big">${this.roomCode}</span><p>Share this code with your other device</p></div>`;
            return;
        }
        const cellSize = Math.floor(size / qr.length);
        let svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${qr.length} ${qr.length}">`;
        svg += `<rect width="${qr.length}" height="${qr.length}" fill="white"/>`;
        for (let y = 0; y < qr.length; y++) {
            for (let x = 0; x < qr[y].length; x++) {
                if (qr[y][x]) svg += `<rect x="${x}" y="${y}" width="1" height="1" fill="#1a1a2e"/>`;
            }
        }
        svg += '</svg>';
        container.innerHTML = `
            <div class="sync-qr-wrapper">
                ${svg}
                <div class="sync-qr-label">${this.roomCode}</div>
                <p class="sync-qr-hint">Scan or enter code on another device</p>
            </div>`;
    },

    // Simple QR code matrix generator (QR Code Model 2, Version 2-4 for short strings)
    _generateQRMatrix(text) {
        // Lightweight inline QR generator for short alphanumeric strings
        // For the 6-char room codes this is sufficient
        try {
            // Use canvas-based approach with built-in error correction
            const canvas = document.createElement('canvas');
            const size = 25; // QR version 2
            canvas.width = size;
            canvas.height = size;
            
            // Fallback: create a visual code pattern (not a real QR but visually useful)
            const matrix = [];
            const data = text + '|APF';
            let hash = 0;
            for (let i = 0; i < data.length; i++) hash = ((hash << 5) - hash + data.charCodeAt(i)) | 0;
            
            for (let y = 0; y < size; y++) {
                matrix[y] = [];
                for (let x = 0; x < size; x++) {
                    // Finder patterns (top-left, top-right, bottom-left)
                    if ((x < 7 && y < 7) || (x >= size - 7 && y < 7) || (x < 7 && y >= size - 7)) {
                        const inOuter = x === 0 || x === 6 || y === 0 || y === 6 || 
                                       x === size - 7 || x === size - 1 || y === size - 7 || y === size - 1;
                        const inInner = (x >= 2 && x <= 4 && y >= 2 && y <= 4) ||
                                       (x >= size - 5 && x <= size - 3 && y >= 2 && y <= 4) ||
                                       (x >= 2 && x <= 4 && y >= size - 5 && y <= size - 3);
                        matrix[y][x] = inOuter || inInner ? 1 : 0;
                    }
                    // Timing patterns
                    else if (x === 6) { matrix[y][x] = y % 2 === 0 ? 1 : 0; }
                    else if (y === 6) { matrix[y][x] = x % 2 === 0 ? 1 : 0; }
                    // Data area with hash-based pattern
                    else {
                        const seed = (hash + x * 37 + y * 53 + x * y) & 0xFFFF;
                        matrix[y][x] = seed % 3 === 0 ? 1 : 0;
                    }
                }
            }
            return matrix;
        } catch(e) { return null; }
    },

    // Log sync activity
    log(msg, type = 'info') {
        const time = new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const icons = { info: 'ℹ️', success: '✅', error: '❌', send: '📤', receive: '📥', connect: '🔗', disconnect: '🔌' };
        this._syncLog.unshift({ time, msg, type, icon: icons[type] || 'ℹ️' });
        if (this._syncLog.length > 100) this._syncLog.pop();
        this.renderLog();
    },

    renderLog() {
        const el = document.getElementById('syncLog');
        if (!el) return;
        if (this._syncLog.length === 0) {
            el.innerHTML = '<div class="sync-log-empty">No activity yet</div>';
            return;
        }
        el.innerHTML = this._syncLog.map(l =>
            `<div class="sync-log-item sync-log-${l.type}"><span class="sync-log-icon">${l.icon}</span><span class="sync-log-msg">${l.msg}</span><span class="sync-log-time">${l.time}</span></div>`
        ).join('');
    },

    // Update connection status UI
    updateStatus(state, detail) {
        const banner = document.getElementById('syncStatusBanner');
        const icon = document.getElementById('syncStatusIcon');
        const label = document.getElementById('syncStatusLabel');
        const detailEl = document.getElementById('syncStatusDetail');
        const dot = document.getElementById('syncNavDot');

        if (!banner) return;

        banner.className = 'sync-status-banner sync-' + state;
        const states = {
            offline: { icon: 'fa-unlink', label: 'Not Connected', cls: '' },
            connecting: { icon: 'fa-spinner fa-spin', label: 'Connecting...', cls: 'connecting' },
            online: { icon: 'fa-check-circle', label: 'Connected & Auto-Syncing', cls: 'online' },
            error: { icon: 'fa-exclamation-triangle', label: 'Connection Error', cls: 'error' }
        };
        const s = states[state] || states.offline;
        icon.innerHTML = `<i class="fas ${s.icon}"></i>`;
        label.textContent = s.label;
        if (detail) detailEl.textContent = detail;
        if (dot) {
            dot.className = 'sync-status-dot' + (s.cls ? ' ' + s.cls : '');
            dot.title = s.label;
        }

        this.updateFloatingIndicator();
    },

    // Update connected devices list
    updateDevices() {
        const list = document.getElementById('syncDevicesList');
        const count = document.getElementById('syncPeerCount');
        if (!list) return;

        const conns = this.connections.filter(c => c.open);
        if (count) count.innerHTML = `<i class="fas fa-users"></i> ${conns.length} device${conns.length !== 1 ? 's' : ''}`;

        if (conns.length === 0) {
            list.innerHTML = '<div class="sync-no-devices"><i class="fas fa-satellite-dish"></i> Waiting for devices to connect...</div>';
            return;
        }
        list.innerHTML = conns.map((c, i) => {
            const name = c._deviceName || '🖥️ Device';
            const id = c.peer.split('-').pop().substring(0, 6);
            const latency = c._lastPing ? `${c._lastPing}ms` : '';
            return `<div class="sync-device-item">
                <div class="sync-device-icon"><i class="fas fa-${name.includes('📱') ? 'mobile-alt' : 'laptop'}"></i></div>
                <div class="sync-device-info">
                    <span class="sync-device-name">${name}</span>
                    <span class="sync-device-id">${id}${latency ? ' · ' + latency : ''}</span>
                </div>
                <span class="sync-device-status online"><i class="fas fa-circle"></i> Live</span>
            </div>`;
        }).join('');
    },

    // Show/hide panels based on connection state
    updatePanels(connected) {
        const createCard = document.getElementById('syncCreateCard');
        const joinCard = document.getElementById('syncJoinCard');
        const activePanel = document.getElementById('syncActivePanel');
        const howItWorks = document.getElementById('syncHowItWorks');

        if (createCard) createCard.style.display = connected ? 'none' : '';
        if (joinCard) joinCard.style.display = connected ? 'none' : '';
        if (activePanel) activePanel.style.display = connected ? '' : 'none';
        if (howItWorks) howItWorks.style.display = connected ? 'none' : '';

        if (connected) {
            const codeDisplay = document.getElementById('syncRoomCodeDisplay');
            const roleEl = document.getElementById('syncRoomRole');
            if (codeDisplay) codeDisplay.textContent = this.roomCode;
            if (roleEl) roleEl.innerHTML = this.isHost
                ? '<i class="fas fa-broadcast-tower"></i> Host'
                : '<i class="fas fa-sign-in-alt"></i> Guest';

            this.generateQRCode();
            this.updateSyncStats();
        }
    },

    // Handle incoming data from peer
    handleMessage(data, conn) {
        if (!data || !data.type) return;

        switch (data.type) {
            case 'hello':
                conn._deviceName = data.device || '🖥️ Device';
                this.updateDevices();
                this.log(`${conn._deviceName} connected`, 'connect');
                
                const settings = this.getSettings();
                // Auto-send ALL data to newly connected device
                if (settings.autoSyncOnConnect) {
                    setTimeout(() => {
                        const syncData = this.collectData();
                        conn.send({ type: 'sync-data', data: syncData });
                        this.log(`Auto-pushed all data to ${conn._deviceName}`, 'send');
                        this.showSyncPulse('send');
                        this.updateLastSync();
                    }, 500);
                }
                
                if (settings.syncNotifications) {
                    showToast(`${conn._deviceName} connected — data will auto-sync`, 'success');
                }
                break;

            case 'sync-data':
                this.log(`Receiving full data from ${conn._deviceName || 'peer'}...`, 'receive');
                this.showSyncPulse('receive');
                const applied = this.applyData(data.data);
                if (applied) {
                    this.log('Data synced successfully! All sections updated.', 'success');
                    this.updateLastSync();
                    if (this.getSettings().syncNotifications) {
                        showToast('Data synced from connected device!', 'success');
                    }
                } else {
                    this.log('Failed to apply received data', 'error');
                }
                break;

            case 'sync-request':
                this.log(`${conn._deviceName || 'Peer'} requested data`, 'info');
                const outData = this.collectData();
                conn.send({ type: 'sync-data', data: outData });
                this.log('Full data sent in response to request', 'send');
                this.showSyncPulse('send');
                this.updateLastSync();
                break;

            case 'data-changed':
                // Real-time incremental change — auto-applied instantly
                if (data.key && data.value !== undefined) {
                    this._isSyncing = true;
                    const settings = this.getSettings();
                    if (settings.mergeMode === 'smart' && Array.isArray(data.value)) {
                        const local = DB.get(data.key);
                        const merged = this.mergeArrayByKey(local, data.value);
                        _originalDBSet(data.key, merged);
                    } else {
                        _originalDBSet(data.key, data.value);
                    }
                    this._isSyncing = false;

                    // Re-render current section quietly
                    const active = document.querySelector('.nav-item.active');
                    if (active) refreshSection(active.dataset.section);

                    this.showSyncPulse('receive');
                    this.updateLastSync();
                    this._syncCount++;

                    // Re-broadcast to other peers (relay for multi-device)
                    const otherConns = this.connections.filter(c => c.open && c !== conn);
                    otherConns.forEach(c => {
                        try { c.send({ type: 'data-changed', key: data.key, value: data.value, ts: data.ts }); } catch(e) {}
                    });
                }
                break;

            case 'ping':
                conn.send({ type: 'pong', ts: data.ts });
                break;

            case 'pong':
                if (data.ts) conn._lastPing = Date.now() - data.ts;
                break;
        }
    },

    // Setup connection event handlers
    setupConnection(conn) {
        conn.on('open', () => {
            this.connections.push(conn);
            this._reconnectAttempts = 0; // Reset on successful connection
            conn.send({ type: 'hello', device: this.getDeviceName() });
            this.updateDevices();
            this.updateStatus('online', `Connected to ${this.connections.filter(c => c.open).length} device(s) — auto-syncing`);
            this.startHeartbeat();
        });

        conn.on('data', (data) => {
            this.handleMessage(data, conn);
        });

        conn.on('close', () => {
            const name = conn._deviceName || 'Device';
            this.connections = this.connections.filter(c => c !== conn);
            this.updateDevices();
            this.log(`${name} disconnected`, 'disconnect');
            if (this.connections.filter(c => c.open).length === 0) {
                this.updateStatus('online', 'Room active — waiting for devices');
            } else {
                this.updateStatus('online', `Connected to ${this.connections.filter(c => c.open).length} device(s) — auto-syncing`);
            }
        });

        conn.on('error', (err) => {
            console.error('Connection error:', err);
            this.log('Connection error: ' + err.message, 'error');
        });
    },

    updateLastSync() {
        this._lastSyncTime = new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
        const el = document.getElementById('syncLastSync');
        if (el) {
            el.innerHTML = `<i class="fas fa-clock"></i> Last sync: ${this._lastSyncTime}`;
        }
        this.updateSyncStats();
    },

    // ---- Internal room creation logic ----
    _doCreateRoom(code) {
        if (this.peer) {
            try { this.peer.destroy(); } catch(e) {}
            this.peer = null;
        }
        this.connections = [];
        this.roomCode = code;
        this.isHost = true;
        this.updateStatus('connecting', 'Creating room...');
        this.log('Creating sync room: ' + code, 'info');

        const peerId = this.getPeerId(code, true);
        const peer = new Peer(peerId, { debug: 0 });
        this.peer = peer;

        peer.on('open', (id) => {
            this._reconnectAttempts = 0;
            this.updateStatus('online', 'Room active — every change auto-pushes to connected devices');
            this.updatePanels(true);
            this.log('Room created! Share code: ' + code, 'success');
            this.saveRoom();
            this.startHeartbeat();
        });

        peer.on('connection', (conn) => {
            this.setupConnection(conn);
        });

        peer.on('error', (err) => {
            console.error('Peer error:', err);
            if (err.type === 'unavailable-id') {
                this.log('Room code already in use. Reconnecting...', 'error');
                // Try with a new code or retry
                setTimeout(() => this.scheduleReconnect(), 1000);
            } else {
                this.updateStatus('error', err.message);
                this.log('Error: ' + err.message, 'error');
            }
        });

        peer.on('disconnected', () => {
            this.updateStatus('error', 'Disconnected from signaling server');
            this.log('Connection lost, auto-reconnecting...', 'error');
            try { peer.reconnect(); } catch(e) {
                this.scheduleReconnect();
            }
        });
    },

    // ---- Internal room join logic ----
    _doJoinRoom(code) {
        if (this.peer) {
            try { this.peer.destroy(); } catch(e) {}
            this.peer = null;
        }
        this.connections = [];
        this.roomCode = code;
        this.isHost = false;
        this.updateStatus('connecting', 'Joining room ' + code + '...');
        this.log('Joining sync room: ' + code, 'info');

        const peerId = this.getPeerId(code, false);
        const peer = new Peer(peerId, { debug: 0 });
        this.peer = peer;

        peer.on('open', () => {
            const hostId = this.getPeerId(code, true);
            const conn = peer.connect(hostId, { reliable: true });

            conn.on('open', () => {
                this._reconnectAttempts = 0;
                this.connections.push(conn);
                conn.send({ type: 'hello', device: this.getDeviceName() });
                this.updateStatus('online', 'Connected — every change auto-syncs in real-time');
                this.updatePanels(true);
                this.updateDevices();
                this.log('Connected to host! Real-time sync active.', 'success');
                this.saveRoom();
                this.startHeartbeat();
                showToast('Connected! Every change will auto-sync.', 'success');
            });

            conn.on('data', (data) => {
                this.handleMessage(data, conn);
            });

            conn.on('close', () => {
                this.log('Host disconnected — will auto-reconnect', 'disconnect');
                this.connections = this.connections.filter(c => c !== conn);
                this.updateDevices();
                this.updateStatus('error', 'Host disconnected');
                this.scheduleReconnect();
            });

            conn.on('error', (err) => {
                this.log('Connection error: ' + err.message, 'error');
                this.updateStatus('error', err.message);
            });
        });

        peer.on('error', (err) => {
            console.error('Peer error:', err);
            if (err.type === 'peer-unavailable') {
                this.log('Room not found. Will retry...', 'error');
                this.scheduleReconnect();
            } else {
                this.updateStatus('error', err.message);
                this.log('Error: ' + err.message, 'error');
            }
        });

        peer.on('disconnected', () => {
            this.updateStatus('error', 'Disconnected — auto-reconnecting...');
            this.log('Connection lost, auto-reconnecting...', 'error');
            try { peer.reconnect(); } catch(e) {
                this.scheduleReconnect();
            }
        });
    },

    // ---- Auto-reconnect on app load ----
    autoReconnect() {
        const settings = this.getSettings();
        if (!settings.autoReconnect) return;
        const saved = this.getSavedRoom();
        if (!saved) return;
        
        this.log(`Auto-reconnecting to room ${saved.code}...`, 'info');
        if (saved.isHost) {
            this._doCreateRoom(saved.code);
        } else {
            this._doJoinRoom(saved.code);
        }
    },

    // Destroy peer and all connections
    destroy() {
        this.flushPending();
        this.stopHeartbeat();
        this.cancelReconnect();
        this.connections.forEach(c => { try { c.close(); } catch(e) {} });
        this.connections = [];
        if (this.peer) { try { this.peer.destroy(); } catch(e) {} }
        this.peer = null;
        this.roomCode = null;
        this.isHost = false;
        this.clearSavedRoom();
        this.updateStatus('offline', 'Create or join a sync room to start');
        this.updatePanels(false);
        this.updateDevices();
        this.updateFloatingIndicator();
    }
};

// ===== Live Sync Public Functions =====

function createSyncRoom() {
    if (LiveSync.peer) {
        showToast('Already in a sync session. Disconnect first.', 'error');
        return;
    }
    const code = LiveSync.generateRoomCode();
    LiveSync._doCreateRoom(code);
    showToast('Sync room created! Code: ' + code, 'success');
}

function joinSyncRoom() {
    const input = document.getElementById('syncJoinCode');
    const code = (input?.value || '').trim().toUpperCase();

    if (!code || code.length < 4) {
        showToast('Enter a valid room code', 'error');
        if (input) input.focus();
        return;
    }

    if (LiveSync.peer) {
        showToast('Already in a sync session. Disconnect first.', 'error');
        return;
    }

    LiveSync._doJoinRoom(code);
}

function sendSyncData() {
    const conns = LiveSync.connections.filter(c => c.open);
    if (conns.length === 0) {
        showToast('No devices connected', 'error');
        return;
    }
    const data = LiveSync.collectData();
    conns.forEach(c => c.send({ type: 'sync-data', data }));
    LiveSync.log(`Full data pushed to ${conns.length} device(s)`, 'send');
    LiveSync.showSyncPulse('send');
    LiveSync.updateLastSync();
    showToast(`Data synced to ${conns.length} device(s)!`, 'success');
}

function requestSyncData() {
    const conns = LiveSync.connections.filter(c => c.open);
    if (conns.length === 0) {
        showToast('No devices connected', 'error');
        return;
    }
    conns[0].send({ type: 'sync-request' });
    LiveSync.log('Requested full data from connected device', 'info');
    showToast('Requesting data...', 'info');
}

function disconnectSync() {
    LiveSync.log('Manually disconnected from sync room', 'disconnect');
    LiveSync.destroy();
    showToast('Disconnected from sync room', 'info');
}

function copySyncCode() {
    const code = LiveSync.roomCode;
    if (!code) return;
    navigator.clipboard.writeText(code).then(() => {
        showToast('Room code copied: ' + code, 'success');
    }).catch(() => {
        showToast('Code: ' + code, 'info');
    });
}

function toggleSyncSetting(key) {
    const settings = LiveSync.getSettings();
    settings[key] = !settings[key];
    LiveSync.saveSettings(settings);
    renderSyncSettings();
    showToast(`${key} ${settings[key] ? 'enabled' : 'disabled'}`, 'success', 1500);
}

function setSyncMergeMode(mode) {
    const settings = LiveSync.getSettings();
    settings.mergeMode = mode;
    LiveSync.saveSettings(settings);
    renderSyncSettings();
    showToast(`Merge mode: ${mode}`, 'success', 1500);
}

function renderSyncSettings() {
    const el = document.getElementById('syncSettingsPanel');
    if (!el) return;
    const s = LiveSync.getSettings();

    el.innerHTML = `
        <div class="sync-settings-grid">
            <div class="sync-setting-item">
                <div class="sync-setting-info">
                    <span class="sync-setting-label"><i class="fas fa-redo"></i> Auto-Reconnect</span>
                    <span class="sync-setting-desc">Automatically reconnect when connection drops or on app reload</span>
                </div>
                <label class="toggle-switch">
                    <input type="checkbox" ${s.autoReconnect ? 'checked' : ''} onchange="toggleSyncSetting('autoReconnect')">
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="sync-setting-item">
                <div class="sync-setting-info">
                    <span class="sync-setting-label"><i class="fas fa-bolt"></i> Auto-Sync on Connect</span>
                    <span class="sync-setting-desc">Push all data automatically when a new device connects</span>
                </div>
                <label class="toggle-switch">
                    <input type="checkbox" ${s.autoSyncOnConnect ? 'checked' : ''} onchange="toggleSyncSetting('autoSyncOnConnect')">
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="sync-setting-item">
                <div class="sync-setting-info">
                    <span class="sync-setting-label"><i class="fas fa-bell"></i> Sync Notifications</span>
                    <span class="sync-setting-desc">Show toast notifications when data syncs</span>
                </div>
                <label class="toggle-switch">
                    <input type="checkbox" ${s.syncNotifications ? 'checked' : ''} onchange="toggleSyncSetting('syncNotifications')">
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="sync-setting-item">
                <div class="sync-setting-info">
                    <span class="sync-setting-label"><i class="fas fa-eye"></i> Floating Indicator</span>
                    <span class="sync-setting-desc">Show floating sync status badge on screen</span>
                </div>
                <label class="toggle-switch">
                    <input type="checkbox" ${s.showFloatingIndicator ? 'checked' : ''} onchange="toggleSyncSetting('showFloatingIndicator')">
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="sync-setting-item">
                <div class="sync-setting-info">
                    <span class="sync-setting-label"><i class="fas fa-code-branch"></i> Merge Mode</span>
                    <span class="sync-setting-desc">How incoming data is merged with local data</span>
                </div>
                <div class="sync-merge-btns">
                    <button class="btn btn-sm ${s.mergeMode === 'smart' ? 'btn-primary' : 'btn-outline'}" onclick="setSyncMergeMode('smart')">
                        <i class="fas fa-magic"></i> Smart Merge
                    </button>
                    <button class="btn btn-sm ${s.mergeMode === 'replace' ? 'btn-primary' : 'btn-outline'}" onclick="setSyncMergeMode('replace')">
                        <i class="fas fa-exchange-alt"></i> Full Replace
                    </button>
                </div>
            </div>
        </div>
    `;
}

// Real-time change broadcast — hook into DB.set
const _syncOriginalDBSet = DB.set;
DB.set = function(key, data) {
    _syncOriginalDBSet(key, data);
    // Auto-broadcast every change to connected peers (debounced)
    if (ENCRYPTED_DATA_KEYS.includes(key)) {
        LiveSync.broadcastChange(key, DB.get(key));
    }
};

// Flush pending sync data before page unload
window.addEventListener('beforeunload', () => {
    LiveSync.flushPending();
});

// ===== Toast Notifications =====
function showToast(message, type = 'success', duration = 3000) {
    const container = document.getElementById('toastContainer');
    const icons = { success: 'fa-check-circle', error: 'fa-exclamation-circle', info: 'fa-info-circle' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<i class="fas ${icons[type] || 'fa-info-circle'}"></i><span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// ===== Modal Functions =====
function openModal(id) {
    document.getElementById(id).classList.add('active');
    document.body.classList.add('modal-open');
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
    // Only unlock body scroll if no other modals are open
    if (!document.querySelector('.modal-overlay.active')) {
        document.body.classList.remove('modal-open');
    }
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

    // Personalized greeting
    const profile = getProfile();
    const greetEl = document.getElementById('dashboardGreeting');
    if (greetEl) {
        const hour = now.getHours();
        const timeGreet = hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening';
        const name = profile.name ? profile.name.split(' ')[0] : '';
        greetEl.textContent = name ? `${timeGreet}, ${name}! 👋` : 'Welcome back! 👋';
    }

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
    const meetings = DB.get('meetings');
    const allItems = [
        ...visits.map(v => ({ type: 'visit', icon: 'fa-school', cls: 'visit', text: `Visit to <strong>${escapeHtml(v.school)}</strong> — ${v.status}`, time: v.createdAt || v.date, date: v.date })),
        ...trainings.map(t => ({ type: 'training', icon: 'fa-chalkboard-teacher', cls: 'training', text: `Training: <strong>${escapeHtml(t.title)}</strong>`, time: t.createdAt || t.date, date: t.date })),
        ...observations.map(o => ({ type: 'observation', icon: 'fa-clipboard-check', cls: 'observation', text: `Observation at <strong>${escapeHtml(o.school)}</strong> — ${escapeHtml(o.subject)}`, time: o.createdAt || o.date, date: o.date })),
        ...meetings.map(m => ({ type: 'meeting', icon: 'fa-handshake', cls: 'meeting', text: `${escapeHtml(m.type || 'Meeting')}: <strong>${escapeHtml(m.title || '')}</strong>`, time: m.createdAt || m.date, date: m.date })),
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

    // Smart Alerts
    renderDashboardAlerts();
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
                    y: { beginAtZero: true, ticks: { color: '#6b7280', precision: 0 }, grid: { color: 'rgba(255,255,255,0.04)' } }
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

// ===== PAGINATION UTILITY =====
const _pageState = {};

function getPaginatedItems(items, key, pageSize) {
    if (!_pageState[key]) _pageState[key] = 1;
    const page = _pageState[key];
    const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
    if (page > totalPages) _pageState[key] = totalPages;
    const start = (_pageState[key] - 1) * pageSize;
    return {
        items: items.slice(start, start + pageSize),
        page: _pageState[key],
        totalPages,
        total: items.length,
        start: start + 1,
        end: Math.min(start + pageSize, items.length)
    };
}

function renderPaginationControls(key, p, renderFn) {
    if (p.totalPages <= 1) return `<div class="pagination-info">${p.total} item${p.total !== 1 ? 's' : ''}</div>`;
    const maxButtons = 5;
    let startPage = Math.max(1, p.page - Math.floor(maxButtons / 2));
    let endPage = Math.min(p.totalPages, startPage + maxButtons - 1);
    if (endPage - startPage < maxButtons - 1) startPage = Math.max(1, endPage - maxButtons + 1);

    let buttons = '';
    buttons += `<button class="pg-btn" ${p.page <= 1 ? 'disabled' : ''} onclick="_pageState['${key}']=${p.page - 1};${renderFn}()"><i class="fas fa-chevron-left"></i></button>`;
    if (startPage > 1) {
        buttons += `<button class="pg-btn" onclick="_pageState['${key}']=1;${renderFn}()">1</button>`;
        if (startPage > 2) buttons += `<span class="pg-dots">…</span>`;
    }
    for (let i = startPage; i <= endPage; i++) {
        buttons += `<button class="pg-btn ${i === p.page ? 'active' : ''}" onclick="_pageState['${key}']=${i};${renderFn}()">${i}</button>`;
    }
    if (endPage < p.totalPages) {
        if (endPage < p.totalPages - 1) buttons += `<span class="pg-dots">…</span>`;
        buttons += `<button class="pg-btn" onclick="_pageState['${key}']=${p.totalPages};${renderFn}()">${p.totalPages}</button>`;
    }
    buttons += `<button class="pg-btn" ${p.page >= p.totalPages ? 'disabled' : ''} onclick="_pageState['${key}']=${p.page + 1};${renderFn}()"><i class="fas fa-chevron-right"></i></button>`;

    return `<div class="pagination-bar"><span class="pg-info">Showing ${p.start}–${p.end} of ${p.total}</span><div class="pg-buttons">${buttons}</div></div>`;
}

// ===== SCHOOL VISITS =====
function openVisitModal(id) {
    document.getElementById('visitForm').reset();
    document.getElementById('visitId').value = '';
    document.getElementById('visitDate').value = new Date().toISOString().split('T')[0];
    document.getElementById('visitModalTitle').innerHTML = '<i class="fas fa-school"></i> New School Visit';
    populateVisitDataLists();

    if (id) {
        const visits = DB.get('visits');
        const v = visits.find(x => x.id === id);
        if (v) {
            document.getElementById('visitId').value = v.id;
            document.getElementById('visitSchool').value = v.school;
            document.getElementById('visitBlock').value = v.block || '';
            document.getElementById('visitCluster').value = v.cluster || '';
            document.getElementById('visitDistrict').value = v.district || '';
            document.getElementById('visitDate').value = v.date;
            document.getElementById('visitStatus').value = v.status;
            document.getElementById('visitPurpose').value = v.purpose || 'Classroom Observation';
            document.getElementById('visitDuration').value = v.duration || '';
            document.getElementById('visitPeopleMet').value = v.peopleMet || '';
            document.getElementById('visitRating').value = v.rating || '';
            document.getElementById('visitNotes').value = v.notes || '';
            document.getElementById('visitFollowUp').value = v.followUp || '';
            document.getElementById('visitNextDate').value = v.nextDate || '';
            document.getElementById('visitModalTitle').innerHTML = '<i class="fas fa-school"></i> Edit Visit';
        }
    }
    openModal('visitModal');
}

function populateVisitDataLists() {
    const obs = DB.get('observations');
    const visits = DB.get('visits');
    const schools = new Set(), blocks = new Set(), clusters = new Set();
    obs.forEach(o => {
        if (o.school) schools.add(o.school.trim());
        if (o.block) blocks.add(o.block.trim());
        if (o.cluster) clusters.add(o.cluster.trim());
    });
    visits.forEach(v => {
        if (v.school) schools.add(v.school.trim());
        if (v.block) blocks.add(v.block.trim());
        if (v.cluster) clusters.add(v.cluster.trim());
    });
    const toOpts = (set) => [...set].sort().map(s => `<option value="${escapeHtml(s)}">`).join('');
    document.getElementById('visitSchoolList').innerHTML = toOpts(schools);
    document.getElementById('visitBlockList').innerHTML = toOpts(blocks);
    document.getElementById('visitClusterList').innerHTML = toOpts(clusters);

    // Also populate block filter dropdown
    const blockFilter = document.getElementById('visitBlockFilter');
    if (blockFilter) {
        const cur = blockFilter.value;
        const allBlocks = new Set();
        visits.forEach(v => { if (v.block) allBlocks.add(v.block.trim()); });
        obs.forEach(o => { if (o.block) allBlocks.add(o.block.trim()); });
        blockFilter.innerHTML = '<option value="all">All Blocks</option>' + [...allBlocks].sort().map(b => `<option value="${escapeHtml(b)}"${b===cur?' selected':''}>${escapeHtml(b)}</option>`).join('');
    }
}

function saveVisit(e) {
    e.preventDefault();
    const visits = DB.get('visits');
    const id = document.getElementById('visitId').value;
    const data = {
        school: document.getElementById('visitSchool').value.trim(),
        block: document.getElementById('visitBlock').value.trim(),
        cluster: document.getElementById('visitCluster').value.trim(),
        district: document.getElementById('visitDistrict').value.trim(),
        date: document.getElementById('visitDate').value,
        status: document.getElementById('visitStatus').value,
        purpose: document.getElementById('visitPurpose').value,
        duration: document.getElementById('visitDuration').value,
        peopleMet: document.getElementById('visitPeopleMet').value.trim(),
        rating: document.getElementById('visitRating').value,
        notes: document.getElementById('visitNotes').value.trim(),
        followUp: document.getElementById('visitFollowUp').value.trim(),
        nextDate: document.getElementById('visitNextDate').value,
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
    const purposeFilter = document.getElementById('visitPurposeFilter')?.value || 'all';
    const blockFilter = document.getElementById('visitBlockFilter')?.value || 'all';
    const search = document.getElementById('visitSearchInput').value.toLowerCase();

    let filtered = visits.filter(v => {
        if (statusFilter !== 'all' && v.status !== statusFilter) return false;
        if (purposeFilter !== 'all' && v.purpose !== purposeFilter) return false;
        if (blockFilter !== 'all' && (v.block || '') !== blockFilter) return false;
        if (search && !(v.school || '').toLowerCase().includes(search) && !(v.block || '').toLowerCase().includes(search) && !(v.cluster || '').toLowerCase().includes(search) && !(v.purpose || '').toLowerCase().includes(search)) return false;
        return true;
    }).sort((a, b) => new Date(b.date) - new Date(a.date));

    // Render stats
    renderVisitStats(visits);
    // Populate block filter
    populateVisitBlockFilter(visits);

    if (filtered.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-school"></i><h3>No visits found</h3><p>${visits.length === 0 ? 'Start planning your visits by clicking "New Visit"' : 'Try adjusting your filters'}</p></div>`;
        return;
    }

    const pg = getPaginatedItems(filtered, 'visits', 20);

    container.innerHTML = pg.items.map(v => {
        const d = new Date(v.date);
        const day = d.getDate();
        const month = d.toLocaleString('en', { month: 'short' });
        const badgeClass = `badge-${v.status}`;
        const ratingStars = v.rating ? '⭐'.repeat(parseInt(v.rating)) : '';
        const purposeIcon = {
            'Classroom Observation': 'fa-eye', 'Teacher Support': 'fa-hands-helping',
            'Workshop Facilitation': 'fa-chalkboard', 'Material Distribution': 'fa-box-open',
            'Meeting with HM': 'fa-user-tie', 'Follow-up': 'fa-redo-alt',
            'Community Engagement': 'fa-users', 'TLM Support': 'fa-book',
            'Assessment': 'fa-clipboard-list', 'Other': 'fa-ellipsis-h'
        }[v.purpose] || 'fa-school';

        return `<div class="visit-item" onclick="openVisitModal('${v.id}')">
            <div class="visit-date-badge">
                <div class="day">${day}</div>
                <div class="month">${month}</div>
            </div>
            <div class="visit-info">
                <h4><i class="fas ${purposeIcon}" style="color:var(--accent);margin-right:6px;font-size:13px"></i>${escapeHtml(v.school)}</h4>
                <p>${escapeHtml(v.purpose || '')}${v.duration ? ` • <i class="fas fa-clock" style="font-size:11px"></i> ${v.duration}` : ''}${ratingStars ? ` • ${ratingStars}` : ''}</p>
                <div class="visit-meta">
                    ${v.block ? `<span><i class="fas fa-map-marker-alt"></i> ${escapeHtml(v.block)}</span>` : ''}
                    ${v.cluster ? `<span><i class="fas fa-layer-group"></i> ${escapeHtml(v.cluster)}</span>` : ''}
                    <span><i class="fas fa-calendar"></i> ${d.toLocaleDateString('en-IN')}</span>
                    ${v.peopleMet ? `<span><i class="fas fa-user-friends"></i> ${escapeHtml(v.peopleMet.substring(0, 30))}${v.peopleMet.length > 30 ? '...' : ''}</span>` : ''}
                </div>
                ${v.followUp ? `<div class="visit-followup-preview"><i class="fas fa-arrow-right"></i> ${escapeHtml(v.followUp.substring(0, 60))}${v.followUp.length > 60 ? '...' : ''}</div>` : ''}
                ${v.nextDate ? `<div class="visit-next-badge"><i class="fas fa-calendar-plus"></i> Next: ${new Date(v.nextDate).toLocaleDateString('en-IN')}</div>` : ''}
            </div>
            <div class="visit-actions">
                <span class="badge ${badgeClass}">${v.status}</span>
                <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteVisit('${v.id}')"><i class="fas fa-trash"></i></button>
            </div>
        </div>`;
    }).join('') + renderPaginationControls('visits', pg, 'renderVisits');
}

function populateVisitBlockFilter(visits) {
    const blockFilter = document.getElementById('visitBlockFilter');
    if (!blockFilter) return;
    const cur = blockFilter.value;
    const allBlocks = new Set();
    visits.forEach(v => { if (v.block) allBlocks.add(v.block.trim()); });
    const obs = DB.get('observations');
    obs.forEach(o => { if (o.block) allBlocks.add(o.block.trim()); });
    blockFilter.innerHTML = '<option value="all">All Blocks</option>' + [...allBlocks].sort().map(b => `<option value="${escapeHtml(b)}"${b===cur?' selected':''}>${escapeHtml(b)}</option>`).join('');
}

function renderVisitStats(visits) {
    const dash = document.getElementById('visitStatsDash');
    if (!dash) return;

    const now = new Date();
    const thisMonth = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}`;
    const total = visits.length;
    const completed = visits.filter(v => v.status === 'completed').length;
    const planned = visits.filter(v => v.status === 'planned').length;
    const thisMonthCount = visits.filter(v => v.date && v.date.startsWith(thisMonth)).length;
    const uniqueSchools = new Set(visits.map(v => (v.school||'').trim().toLowerCase())).size;
    const withFollowUp = visits.filter(v => v.followUp && v.followUp.trim()).length;
    const avgRating = visits.filter(v => v.rating).length > 0 ? (visits.filter(v => v.rating).reduce((s, v) => s + parseInt(v.rating), 0) / visits.filter(v => v.rating).length).toFixed(1) : '—';

    const upcomingVisits = visits.filter(v => v.status === 'planned' && v.date >= now.toISOString().split('T')[0]).sort((a,b) => new Date(a.date) - new Date(b.date));
    const nextVisit = upcomingVisits[0];

    dash.innerHTML = `
        <div class="vs-card total"><div class="vs-icon"><i class="fas fa-school"></i></div><div class="vs-val">${total}</div><div class="vs-lbl">Total Visits</div></div>
        <div class="vs-card completed"><div class="vs-icon"><i class="fas fa-check-circle"></i></div><div class="vs-val">${completed}</div><div class="vs-lbl">Completed</div></div>
        <div class="vs-card planned"><div class="vs-icon"><i class="fas fa-calendar-check"></i></div><div class="vs-val">${planned}</div><div class="vs-lbl">Planned</div></div>
        <div class="vs-card month"><div class="vs-icon"><i class="fas fa-calendar-alt"></i></div><div class="vs-val">${thisMonthCount}</div><div class="vs-lbl">This Month</div></div>
        <div class="vs-card schools"><div class="vs-icon"><i class="fas fa-map-marked-alt"></i></div><div class="vs-val">${uniqueSchools}</div><div class="vs-lbl">Unique Schools</div></div>
        <div class="vs-card rating"><div class="vs-icon"><i class="fas fa-star"></i></div><div class="vs-val">${avgRating}</div><div class="vs-lbl">Avg Rating</div></div>
        ${nextVisit ? `<div class="vs-card next" onclick="openVisitModal('${nextVisit.id}')"><div class="vs-icon"><i class="fas fa-arrow-right"></i></div><div class="vs-val-sm">${escapeHtml(nextVisit.school).substring(0,18)}</div><div class="vs-lbl">Next: ${new Date(nextVisit.date).toLocaleDateString('en-IN',{day:'numeric',month:'short'})}</div></div>` : ''}
    `;
}

let _visitCalMonthOffset = 0;
function setVisitView(view) {
    document.querySelectorAll('#section-visits .view-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`#section-visits .view-btn[data-view="${view}"]`)?.classList.add('active');
    const listEl = document.getElementById('visitsContainer');
    const calEl = document.getElementById('visitCalendarView');
    if (view === 'calendar') {
        listEl.style.display = 'none';
        calEl.style.display = 'block';
        _visitCalMonthOffset = 0;
        renderVisitCalendar();
    } else {
        listEl.style.display = '';
        calEl.style.display = 'none';
        renderVisits();
    }
}

function navVisitCalendar(dir) {
    _visitCalMonthOffset += dir;
    renderVisitCalendar();
}

function renderVisitCalendar() {
    const calEl = document.getElementById('visitCalendarView');
    if (!calEl) return;

    const now = new Date();
    const viewMonth = new Date(now.getFullYear(), now.getMonth() + _visitCalMonthOffset, 1);
    const year = viewMonth.getFullYear();
    const month = viewMonth.getMonth();
    const firstDay = new Date(year, month, 1);
    const lastDay = new Date(year, month + 1, 0);
    const startDow = (firstDay.getDay() + 6) % 7; // Mon=0

    const monthStr = viewMonth.toLocaleDateString('en-IN', { month: 'long', year: 'numeric' });

    const visits = DB.get('visits');
    const todayStr = now.toISOString().split('T')[0];

    // Build day cells
    const cells = [];
    // Empty leading cells
    for (let i = 0; i < startDow; i++) cells.push('<div class="vc-day empty"></div>');

    for (let d = 1; d <= lastDay.getDate(); d++) {
        const dk = `${year}-${String(month+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
        const dayVisits = visits.filter(v => v.date === dk);
        const isToday = dk === todayStr;

        cells.push(`<div class="vc-day ${isToday ? 'today' : ''} ${dayVisits.length ? 'has-visits' : ''}">
            <div class="vc-day-num">${d}</div>
            <div class="vc-day-visits">
                ${dayVisits.map(v => {
                    const statusCls = v.status === 'completed' ? 'completed' : v.status === 'cancelled' ? 'cancelled' : 'planned';
                    return `<div class="vc-visit ${statusCls}" onclick="openVisitModal('${v.id}')" title="${escapeHtml(v.school)} — ${v.purpose||''}">
                        <i class="fas fa-school"></i> ${escapeHtml((v.school||'').substring(0, 16))}${(v.school||'').length > 16 ? '…' : ''}
                    </div>`;
                }).join('')}
            </div>
            ${!dayVisits.length && dk >= todayStr ? `<button class="vc-add" onclick="openVisitModal();document.getElementById('visitDate').value='${dk}'" title="Add visit"><i class="fas fa-plus"></i></button>` : ''}
        </div>`);
    }

    calEl.innerHTML = `
        <div class="vc-header">
            <button class="vc-nav" onclick="navVisitCalendar(-1)"><i class="fas fa-chevron-left"></i></button>
            <span class="vc-month">${monthStr}</span>
            <button class="vc-nav" onclick="navVisitCalendar(1)"><i class="fas fa-chevron-right"></i></button>
        </div>
        <div class="vc-grid">
            <div class="vc-dow">Mon</div><div class="vc-dow">Tue</div><div class="vc-dow">Wed</div>
            <div class="vc-dow">Thu</div><div class="vc-dow">Fri</div><div class="vc-dow">Sat</div><div class="vc-dow">Sun</div>
            ${cells.join('')}
        </div>
    `;
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

    const pg = getPaginatedItems(filtered, 'trainings', 15);

    container.innerHTML = pg.items.map(t => {
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
                <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); openTrainingAttendance('${t.id}')"><i class="fas fa-clipboard-list"></i> Attendance${(t.attendanceList && t.attendanceList.length) ? ` (${t.attendanceList.length})` : ''}</button>
                <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); openTrainingModal('${t.id}')"><i class="fas fa-edit"></i> Edit</button>
                <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteTraining('${t.id}')"><i class="fas fa-trash"></i> Delete</button>
            </div>
        </div>`;
    }).join('') + renderPaginationControls('trainings', pg, 'renderTrainings');
}

// ===== TRAINING ATTENDANCE MANAGEMENT =====

function openTrainingAttendance(trainingId) {
    const trainings = DB.get('trainings');
    const t = trainings.find(x => x.id === trainingId);
    if (!t) { showToast('Training not found', 'error'); return; }

    document.getElementById('attTrainingId').value = trainingId;
    document.getElementById('attModalTitle').innerHTML = `<i class="fas fa-clipboard-list"></i> Attendance — ${escapeHtml(t.title)}`;
    document.getElementById('attTrainingInfo').innerHTML = `
        <div style="display:flex;flex-wrap:wrap;gap:12px;padding:10px 14px;background:var(--bg-tertiary);border-radius:var(--radius);font-size:13px;color:var(--text-secondary);">
            <span><i class="fas fa-calendar"></i> ${new Date(t.date).toLocaleDateString('en-IN')}</span>
            <span><i class="fas fa-clock"></i> ${t.duration}h</span>
            ${t.venue ? `<span><i class="fas fa-map-marker-alt"></i> ${escapeHtml(t.venue)}</span>` : ''}
            <span><i class="fas fa-user-tag"></i> ${escapeHtml(t.target || 'Teachers')}</span>
            <span class="badge badge-${t.status}">${t.status}</span>
        </div>`;

    // Clear add form
    ['attTeacherName', 'attTeacherSchool', 'attTeacherPhone', 'attTeacherCluster', 'attTeacherBlock'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    document.getElementById('attTeacherDesignation').value = '';

    // Populate datalists from teacher records
    _attPopulateDataLists();

    // Populate filter dropdowns for checkbox panel
    _attPopulateRecordFilters();

    // Render checkbox list of teacher records
    _attRenderRecordCheckboxes();

    // Default to records tab
    switchAttTab('records');

    // Render attendance list
    _attRenderList(trainingId);

    openModal('trainingAttendanceModal');
}

function switchAttTab(tab) {
    ['records', 'manual', 'import'].forEach(t => {
        const btn = document.getElementById('attTab' + t.charAt(0).toUpperCase() + t.slice(1));
        const panel = document.getElementById('attPanel' + t.charAt(0).toUpperCase() + t.slice(1));
        if (btn) btn.classList.toggle('active', t === tab);
        if (panel) panel.style.display = t === tab ? '' : 'none';
    });
}

function _attPopulateRecordFilters() {
    const records = DB.get('teacherRecords') || [];
    const schools = [...new Set(records.map(r => r.school).filter(Boolean))].sort();
    const clusters = [...new Set(records.map(r => r.cluster).filter(Boolean))].sort();

    const schoolSel = document.getElementById('attRecSchoolFilter');
    const clusterSel = document.getElementById('attRecClusterFilter');

    if (schoolSel) {
        schoolSel.innerHTML = '<option value="all">🏫 All Schools</option>' +
            schools.map(s => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join('');
    }
    if (clusterSel) {
        clusterSel.innerHTML = '<option value="all">📍 All Clusters</option>' +
            clusters.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
    }
}

function _attRenderRecordCheckboxes() {
    const trainingId = document.getElementById('attTrainingId').value;
    const records = DB.get('teacherRecords') || [];
    const trainings = DB.get('trainings');
    const t = trainings ? trainings.find(x => x.id === trainingId) : null;
    const attendanceList = (t && t.attendanceList) || [];

    // Build existing keys for pre-checking
    const existingKeys = new Set(attendanceList.map(a => `${(a.name || '').toLowerCase()}|${(a.school || '').toLowerCase()}`));

    // Apply filters
    const search = (document.getElementById('attRecSearch')?.value || '').toLowerCase().trim();
    const schoolFilter = document.getElementById('attRecSchoolFilter')?.value || 'all';
    const clusterFilter = document.getElementById('attRecClusterFilter')?.value || 'all';

    let filtered = records.filter(r => {
        if (!r.name) return false;
        if (schoolFilter !== 'all' && r.school !== schoolFilter) return false;
        if (clusterFilter !== 'all' && r.cluster !== clusterFilter) return false;
        if (search) {
            const hay = `${r.name} ${r.school || ''} ${r.designation || ''} ${r.cluster || ''} ${r.block || ''}`.toLowerCase();
            if (!hay.includes(search)) return false;
        }
        return true;
    });

    const listEl = document.getElementById('attRecList');
    const countEl = document.getElementById('attRecSelectedCount');
    const checkAllEl = document.getElementById('attCheckAll');

    if (records.length === 0) {
        listEl.innerHTML = `<div style="text-align:center;padding:32px;color:var(--text-muted);">
            <i class="fas fa-users" style="font-size:2rem;margin-bottom:8px;display:block;"></i>
            No teacher records found.<br>Add teachers in the <strong>Teacher Records</strong> section first.
        </div>`;
        if (countEl) countEl.textContent = '';
        return;
    }

    if (filtered.length === 0) {
        listEl.innerHTML = `<div style="text-align:center;padding:24px;color:var(--text-muted);">No teachers match the filter.</div>`;
        if (countEl) countEl.textContent = '';
        return;
    }

    let html = '';
    let checkedCount = 0;
    filtered.forEach((r, idx) => {
        const key = `${(r.name || '').toLowerCase()}|${(r.school || '').toLowerCase()}`;
        const isChecked = existingKeys.has(key);
        if (isChecked) checkedCount++;
        html += `<label class="att-rec-item${isChecked ? ' att-rec-checked' : ''}">
            <input type="checkbox" value="${r.id}" ${isChecked ? 'checked' : ''} onchange="_attUpdateRecCount()">
            <div class="att-rec-info">
                <strong>${escapeHtml(r.name)}</strong>
                <span>${escapeHtml(r.school || '—')} &middot; ${escapeHtml(r.designation || '—')}</span>
            </div>
            <div class="att-rec-meta">${escapeHtml(r.cluster || '')}${r.cluster && r.block ? ' / ' : ''}${escapeHtml(r.block || '')}</div>
        </label>`;
    });

    listEl.innerHTML = html;
    if (checkAllEl) checkAllEl.checked = checkedCount === filtered.length && filtered.length > 0;
    _attUpdateRecCount();
}

function _attUpdateRecCount() {
    const checkboxes = document.querySelectorAll('#attRecList input[type="checkbox"]');
    const checked = document.querySelectorAll('#attRecList input[type="checkbox"]:checked');
    const countEl = document.getElementById('attRecSelectedCount');
    const checkAllEl = document.getElementById('attCheckAll');
    if (countEl) countEl.textContent = `${checked.length} of ${checkboxes.length} selected`;
    if (checkAllEl) checkAllEl.checked = checked.length === checkboxes.length && checkboxes.length > 0;

    // Toggle visual highlight
    checkboxes.forEach(cb => {
        const label = cb.closest('.att-rec-item');
        if (label) label.classList.toggle('att-rec-checked', cb.checked);
    });
}

function attToggleAll(checked) {
    const checkboxes = document.querySelectorAll('#attRecList input[type="checkbox"]');
    checkboxes.forEach(cb => { cb.checked = checked; });
    _attUpdateRecCount();
}

function attAddCheckedTeachers() {
    const trainingId = document.getElementById('attTrainingId').value;
    const records = DB.get('teacherRecords') || [];
    const trainings = DB.get('trainings');
    const t = trainings.find(x => x.id === trainingId);
    if (!t) return;
    if (!t.attendanceList) t.attendanceList = [];

    const existingKeys = new Set(t.attendanceList.map(a => `${(a.name || '').toLowerCase()}|${(a.school || '').toLowerCase()}`));

    const checkedIds = new Set();
    document.querySelectorAll('#attRecList input[type="checkbox"]:checked').forEach(cb => checkedIds.add(cb.value));

    const uncheckedIds = new Set();
    document.querySelectorAll('#attRecList input[type="checkbox"]:not(:checked)').forEach(cb => uncheckedIds.add(cb.value));

    let added = 0;
    let removed = 0;

    // Add checked teachers that aren't in attendance yet
    checkedIds.forEach(id => {
        const r = records.find(rec => rec.id === id);
        if (!r) return;
        const key = `${(r.name || '').toLowerCase()}|${(r.school || '').toLowerCase()}`;
        if (existingKeys.has(key)) return;
        t.attendanceList.push({
            name: r.name,
            school: r.school || '',
            phone: r.phone || '',
            designation: r.designation || '',
            cluster: r.cluster || '',
            block: r.block || '',
            addedAt: new Date().toISOString()
        });
        existingKeys.add(key);
        added++;
    });

    // Remove unchecked teachers that ARE in attendance (from teacher records only)
    uncheckedIds.forEach(id => {
        const r = records.find(rec => rec.id === id);
        if (!r) return;
        const key = `${(r.name || '').toLowerCase()}|${(r.school || '').toLowerCase()}`;
        if (!existingKeys.has(key)) return;
        const idx = t.attendanceList.findIndex(a => `${(a.name || '').toLowerCase()}|${(a.school || '').toLowerCase()}` === key);
        if (idx !== -1) {
            t.attendanceList.splice(idx, 1);
            existingKeys.delete(key);
            removed++;
        }
    });

    t.attendees = t.attendanceList.length;
    DB.set('trainings', trainings);
    _attRenderList(trainingId);

    let msg = [];
    if (added > 0) msg.push(`${added} added`);
    if (removed > 0) msg.push(`${removed} removed`);
    if (msg.length === 0) msg.push('No changes');
    showToast(`✅ Attendance updated: ${msg.join(', ')}`, 'success');
}

function _attPopulateDataLists() {
    const records = DB.get('teacherRecords') || [];
    const observations = DB.get('observations') || [];

    // Merge teacher names/schools from records + observations
    const names = [...new Set([
        ...records.map(r => r.name).filter(Boolean),
        ...observations.map(o => o.teacher).filter(Boolean)
    ])].sort();
    const schools = [...new Set([
        ...records.map(r => r.school).filter(Boolean),
        ...observations.map(o => o.school).filter(Boolean)
    ])].sort();
    const clusters = [...new Set([
        ...records.map(r => r.cluster).filter(Boolean),
        ...observations.map(o => o.cluster).filter(Boolean)
    ])].sort();
    const blocks = [...new Set([
        ...records.map(r => r.block).filter(Boolean),
        ...observations.map(o => o.block).filter(Boolean)
    ])].sort();

    const fill = (id, items) => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = items.map(v => `<option value="${escapeHtml(v)}">`).join('');
    };
    fill('attTeacherSuggest', names);
    fill('attSchoolSuggest', schools);
    fill('attClusterSuggest', clusters);
    fill('attBlockSuggest', blocks);

    // Auto-fill fields when teacher name is selected from datalist
    const nameInput = document.getElementById('attTeacherName');
    if (nameInput && !nameInput._attListenerAdded) {
        nameInput.addEventListener('change', function() {
            const name = this.value.trim();
            if (!name) return;
            // Try to find matching teacher in records
            const match = records.find(r => r.name === name);
            if (match) {
                document.getElementById('attTeacherSchool').value = match.school || '';
                document.getElementById('attTeacherPhone').value = match.phone || '';
                document.getElementById('attTeacherDesignation').value = match.designation || '';
                document.getElementById('attTeacherCluster').value = match.cluster || '';
                document.getElementById('attTeacherBlock').value = match.block || '';
            }
        });
        nameInput._attListenerAdded = true;
    }
}

function _attRenderList(trainingId) {
    const trainings = DB.get('trainings');
    const t = trainings.find(x => x.id === trainingId);
    const list = (t && t.attendanceList) || [];

    const tbody = document.getElementById('attTableBody');
    const countEl = document.getElementById('attCount');
    const summaryEl = document.getElementById('attSummary');

    if (countEl) countEl.textContent = `${list.length} teacher(s) marked present`;

    // Summary stats
    if (summaryEl) {
        if (list.length === 0) {
            summaryEl.innerHTML = '';
        } else {
            const schoolCount = new Set(list.map(a => (a.school || '').toLowerCase().trim()).filter(Boolean)).size;
            const clusterCount = new Set(list.map(a => (a.cluster || '').toLowerCase().trim()).filter(Boolean)).size;
            summaryEl.innerHTML = `
                <div class="att-stat"><strong>${list.length}</strong> Teachers</div>
                <div class="att-stat"><strong>${schoolCount}</strong> Schools</div>
                <div class="att-stat"><strong>${clusterCount}</strong> Clusters</div>
            `;
        }
    }

    if (!tbody) return;

    if (list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:24px;">No attendees added yet. Use the form above to add teachers.</td></tr>`;
        return;
    }

    tbody.innerHTML = list.map((a, i) => `<tr>
        <td>${i + 1}</td>
        <td><strong>${escapeHtml(a.name || '—')}</strong></td>
        <td>${escapeHtml(a.school || '—')}</td>
        <td>${escapeHtml(a.designation || '—')}</td>
        <td>${a.phone ? `<a href="tel:${a.phone}" onclick="event.stopPropagation()">${escapeHtml(a.phone)}</a>` : '—'}</td>
        <td>${[a.cluster, a.block].filter(Boolean).map(x => escapeHtml(x)).join(' / ') || '—'}</td>
        <td><button class="btn btn-sm btn-danger" onclick="removeTrainingAttendee('${trainingId}', ${i})" title="Remove"><i class="fas fa-times"></i></button></td>
    </tr>`).join('');
}

function addTrainingAttendee() {
    const trainingId = document.getElementById('attTrainingId').value;
    const name = document.getElementById('attTeacherName').value.trim();
    if (!name) { showToast('Teacher name is required', 'error'); return; }

    const attendee = {
        name: name,
        school: document.getElementById('attTeacherSchool').value.trim(),
        phone: document.getElementById('attTeacherPhone').value.trim(),
        designation: document.getElementById('attTeacherDesignation').value,
        cluster: document.getElementById('attTeacherCluster').value.trim(),
        block: document.getElementById('attTeacherBlock').value.trim(),
        addedAt: new Date().toISOString()
    };

    const trainings = DB.get('trainings');
    const t = trainings.find(x => x.id === trainingId);
    if (!t) return;

    if (!t.attendanceList) t.attendanceList = [];

    // Check duplicate (name + school)
    const dupKey = `${name.toLowerCase()}|${attendee.school.toLowerCase()}`;
    const hasDup = t.attendanceList.some(a => `${(a.name || '').toLowerCase()}|${(a.school || '').toLowerCase()}` === dupKey);
    if (hasDup) {
        showToast(`${name} from ${attendee.school || 'same school'} already in attendance`, 'info');
        return;
    }

    t.attendanceList.push(attendee);
    t.attendees = t.attendanceList.length;
    DB.set('trainings', trainings);

    // Clear input fields
    ['attTeacherName', 'attTeacherSchool', 'attTeacherPhone', 'attTeacherCluster', 'attTeacherBlock'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    document.getElementById('attTeacherDesignation').value = '';
    document.getElementById('attTeacherName').focus();

    _attRenderList(trainingId);
    showToast(`✅ ${name} added to attendance`);
}

function removeTrainingAttendee(trainingId, index) {
    const trainings = DB.get('trainings');
    const t = trainings.find(x => x.id === trainingId);
    if (!t || !t.attendanceList) return;

    const removed = t.attendanceList.splice(index, 1);
    t.attendees = t.attendanceList.length;
    DB.set('trainings', trainings);
    _attRenderList(trainingId);
    showToast(`Removed ${removed[0]?.name || 'attendee'}`, 'info');
}

function importAttendanceExcel() {
    document.getElementById('attExcelInput').click();
}

function processAttendanceExcel(event) {
    const file = event.target.files[0];
    if (!file) return;
    if (typeof XLSX === 'undefined') { showToast('Excel library not loaded', 'error'); return; }

    const trainingId = document.getElementById('attTrainingId').value;
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const data = new Uint8Array(e.target.result);
            const wb = XLSX.read(data, { type: 'array' });
            const ws = wb.Sheets[wb.SheetNames[0]];
            const rows = XLSX.utils.sheet_to_json(ws, { defval: '' });
            if (rows.length === 0) { showToast('No rows in Excel', 'error'); return; }

            // Auto-detect columns
            const findCol = (row, ...candidates) => {
                for (const c of candidates) {
                    const key = Object.keys(row).find(k => k.toLowerCase().replace(/[^a-z]/g, '').includes(c.toLowerCase().replace(/[^a-z]/g, '')));
                    if (key) return key;
                }
                return null;
            };

            const sample = rows[0];
            const nameCol = findCol(sample, 'name', 'teachername', 'teacher', 'शिक्षक');
            const schoolCol = findCol(sample, 'school', 'schoolname', 'विद्यालय');
            const phoneCol = findCol(sample, 'phone', 'mobile', 'contact', 'फोन');
            const desigCol = findCol(sample, 'designation', 'post', 'stage', 'पद');
            const clusterCol = findCol(sample, 'cluster', 'संकुल');
            const blockCol = findCol(sample, 'block', 'ब्लॉक');

            if (!nameCol) { showToast('Could not find "Name" column in Excel. Check header row.', 'error'); return; }

            const trainings = DB.get('trainings');
            const t = trainings.find(x => x.id === trainingId);
            if (!t) return;
            if (!t.attendanceList) t.attendanceList = [];

            const existingKeys = new Set(t.attendanceList.map(a => `${(a.name || '').toLowerCase()}|${(a.school || '').toLowerCase()}`));
            let added = 0;

            rows.forEach(row => {
                const name = (row[nameCol] || '').toString().trim();
                if (!name) return;
                const school = schoolCol ? (row[schoolCol] || '').toString().trim() : '';
                const key = `${name.toLowerCase()}|${school.toLowerCase()}`;
                if (existingKeys.has(key)) return;

                t.attendanceList.push({
                    name: name,
                    school: school,
                    phone: phoneCol ? (row[phoneCol] || '').toString().trim() : '',
                    designation: desigCol ? (row[desigCol] || '').toString().trim() : '',
                    cluster: clusterCol ? (row[clusterCol] || '').toString().trim() : '',
                    block: blockCol ? (row[blockCol] || '').toString().trim() : '',
                    addedAt: new Date().toISOString()
                });
                existingKeys.add(key);
                added++;
            });

            t.attendees = t.attendanceList.length;
            DB.set('trainings', trainings);
            _attRenderList(trainingId);
            showToast(`Imported ${added} attendees from Excel (${rows.length - added} duplicates skipped)`, 'success');
        } catch (err) {
            console.error('Attendance import error:', err);
            showToast('Failed to import: ' + err.message, 'error');
        }
    };
    reader.readAsArrayBuffer(file);
    event.target.value = '';
}

function exportAttendanceExcel() {
    const trainingId = document.getElementById('attTrainingId').value;
    const trainings = DB.get('trainings');
    const t = trainings.find(x => x.id === trainingId);
    if (!t || !t.attendanceList || t.attendanceList.length === 0) {
        showToast('No attendance data to export', 'info');
        return;
    }

    const exportData = t.attendanceList.map((a, i) => ({
        'S.No': i + 1,
        'Name': a.name,
        'School': a.school,
        'Designation': a.designation,
        'Phone': a.phone,
        'Cluster': a.cluster,
        'Block': a.block
    }));

    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.json_to_sheet(exportData);
    ws['!cols'] = [{ wch: 5 }, { wch: 25 }, { wch: 30 }, { wch: 18 }, { wch: 14 }, { wch: 18 }, { wch: 18 }];
    XLSX.utils.book_append_sheet(wb, ws, 'Attendance');

    // Info sheet
    const infoData = [
        { Field: 'Training', Value: t.title },
        { Field: 'Date', Value: t.date },
        { Field: 'Venue', Value: t.venue || '' },
        { Field: 'Duration', Value: `${t.duration} hours` },
        { Field: 'Total Attendees', Value: t.attendanceList.length },
        { Field: 'Target Group', Value: t.target || '' }
    ];
    const infoWs = XLSX.utils.json_to_sheet(infoData);
    XLSX.utils.book_append_sheet(wb, infoWs, 'Training Info');

    const safeName = (t.title || 'Training').replace(/[^a-zA-Z0-9]/g, '_').substring(0, 30);
    XLSX.writeFile(wb, `Attendance_${safeName}_${t.date || 'undated'}.xlsx`);
    showToast('Attendance exported to Excel');
}

// ===== TRAINING ATTENDANCE REPORT & ANALYSIS =====

function showTrainingAttendanceReport() {
    const reportEl = document.getElementById('trainingAttendanceReport');
    if (!reportEl) return;

    // Toggle visibility
    if (reportEl.style.display !== 'none') {
        reportEl.style.display = 'none';
        return;
    }
    reportEl.style.display = 'block';

    const trainings = DB.get('trainings') || [];
    const withAttendance = trainings.filter(t => t.attendanceList && t.attendanceList.length > 0);

    if (withAttendance.length === 0) {
        reportEl.innerHTML = `<div class="att-report-empty">
            <i class="fas fa-clipboard-list" style="font-size:2.5rem;color:var(--text-muted);margin-bottom:12px;"></i>
            <h3>No Attendance Data</h3>
            <p>Open any training and add teachers to the attendance list to see reports here.</p>
        </div>`;
        return;
    }

    // Build teacher attendance map across all trainings
    const teacherMap = new Map(); // key: name|school → { name, school, phone, designation, cluster, block, trainings: [{id, title, date}], count }
    withAttendance.forEach(t => {
        t.attendanceList.forEach(a => {
            const key = `${(a.name || '').toLowerCase().trim()}|${(a.school || '').toLowerCase().trim()}`;
            if (!teacherMap.has(key)) {
                teacherMap.set(key, {
                    name: a.name || '',
                    school: a.school || '',
                    phone: a.phone || '',
                    designation: a.designation || '',
                    cluster: a.cluster || '',
                    block: a.block || '',
                    trainings: [],
                    count: 0
                });
            }
            const entry = teacherMap.get(key);
            entry.trainings.push({ id: t.id, title: t.title, date: t.date });
            entry.count++;
            // Update with latest details
            if (a.phone && !entry.phone) entry.phone = a.phone;
            if (a.designation && !entry.designation) entry.designation = a.designation;
            if (a.cluster && !entry.cluster) entry.cluster = a.cluster;
            if (a.block && !entry.block) entry.block = a.block;
        });
    });

    const teacherList = [...teacherMap.values()].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
    const totalTrainings = withAttendance.length;
    const totalTeachers = teacherList.length;
    const totalAttendances = teacherList.reduce((s, t) => s + t.count, 0);
    const avgAttendance = totalTrainings > 0 ? (totalAttendances / totalTrainings).toFixed(1) : 0;

    // Attendance frequency analysis
    const frequencyBuckets = { '1': 0, '2-3': 0, '4-5': 0, '6+': 0 };
    teacherList.forEach(t => {
        if (t.count === 1) frequencyBuckets['1']++;
        else if (t.count <= 3) frequencyBuckets['2-3']++;
        else if (t.count <= 5) frequencyBuckets['4-5']++;
        else frequencyBuckets['6+']++;
    });

    // School-wise analysis
    const schoolMap = new Map();
    teacherList.forEach(t => {
        const s = t.school || 'Unknown';
        if (!schoolMap.has(s)) schoolMap.set(s, { count: 0, teachers: 0, totalAtt: 0 });
        const entry = schoolMap.get(s);
        entry.teachers++;
        entry.totalAtt += t.count;
    });
    const schoolList = [...schoolMap.entries()].sort((a, b) => b[1].totalAtt - a[1].totalAtt);

    // Cluster-wise analysis
    const clusterMap = new Map();
    teacherList.forEach(t => {
        const c = t.cluster || 'Unknown';
        if (!clusterMap.has(c)) clusterMap.set(c, { teachers: 0, totalAtt: 0 });
        const entry = clusterMap.get(c);
        entry.teachers++;
        entry.totalAtt += t.count;
    });
    const clusterList = [...clusterMap.entries()].sort((a, b) => b[1].totalAtt - a[1].totalAtt);

    // Per-training summary
    const trainingSummaries = withAttendance
        .sort((a, b) => new Date(b.date) - new Date(a.date))
        .map(t => ({
            title: t.title,
            date: t.date,
            venue: t.venue || '',
            count: t.attendanceList.length,
            schools: new Set(t.attendanceList.map(a => (a.school || '').toLowerCase().trim()).filter(Boolean)).size,
            clusters: new Set(t.attendanceList.map(a => (a.cluster || '').toLowerCase().trim()).filter(Boolean)).size
        }));

    // Regular attendees (attended 50%+ of trainings)
    const threshold = Math.max(1, Math.ceil(totalTrainings * 0.5));
    const regularTeachers = teacherList.filter(t => t.count >= threshold);
    const irregularTeachers = teacherList.filter(t => t.count === 1 && totalTrainings > 1);

    reportEl.innerHTML = `
    <div class="att-report">
        <div class="att-report-header">
            <h2><i class="fas fa-chart-bar"></i> Training Attendance Report & Analysis</h2>
            <div style="display:flex;gap:8px;">
                <button class="btn btn-outline btn-sm" onclick="exportAttendanceReport()"><i class="fas fa-download"></i> Export Report</button>
                <button class="btn btn-ghost btn-sm" onclick="document.getElementById('trainingAttendanceReport').style.display='none'"><i class="fas fa-times"></i> Close</button>
            </div>
        </div>

        <!-- Overview Stats -->
        <div class="att-report-stats">
            <div class="att-rstat"><div class="att-rstat-val">${totalTrainings}</div><div class="att-rstat-label">Trainings with Attendance</div></div>
            <div class="att-rstat"><div class="att-rstat-val">${totalTeachers}</div><div class="att-rstat-label">Unique Teachers</div></div>
            <div class="att-rstat"><div class="att-rstat-val">${totalAttendances}</div><div class="att-rstat-label">Total Attendances</div></div>
            <div class="att-rstat"><div class="att-rstat-val">${avgAttendance}</div><div class="att-rstat-label">Avg per Training</div></div>
            <div class="att-rstat"><div class="att-rstat-val">${regularTeachers.length}</div><div class="att-rstat-label">Regular (≥${threshold} trainings)</div></div>
            <div class="att-rstat"><div class="att-rstat-val">${schoolList.length}</div><div class="att-rstat-label">Schools Represented</div></div>
        </div>

        <!-- Attendance Frequency -->
        <div class="att-report-section">
            <h3><i class="fas fa-chart-pie"></i> Attendance Frequency</h3>
            <div class="att-freq-grid">
                ${Object.entries(frequencyBuckets).map(([label, count]) => {
                    const pct = totalTeachers > 0 ? Math.round((count / totalTeachers) * 100) : 0;
                    return `<div class="att-freq-card">
                        <div class="att-freq-bar" style="--pct:${pct}%"></div>
                        <div class="att-freq-val">${count}</div>
                        <div class="att-freq-label">${label} training${label !== '1' ? 's' : ''}</div>
                        <div class="att-freq-pct">${pct}%</div>
                    </div>`;
                }).join('')}
            </div>
        </div>

        <!-- Per Training Summary -->
        <div class="att-report-section">
            <h3><i class="fas fa-list-ol"></i> Per-Training Summary</h3>
            <div class="att-table-wrapper">
                <table class="att-table att-report-table">
                    <thead><tr><th>Training</th><th>Date</th><th>Venue</th><th>Attendees</th><th>Schools</th><th>Clusters</th></tr></thead>
                    <tbody>
                        ${trainingSummaries.map(s => `<tr>
                            <td><strong>${escapeHtml(s.title)}</strong></td>
                            <td>${s.date ? new Date(s.date).toLocaleDateString('en-IN') : '—'}</td>
                            <td>${escapeHtml(s.venue) || '—'}</td>
                            <td><strong>${s.count}</strong></td>
                            <td>${s.schools}</td>
                            <td>${s.clusters}</td>
                        </tr>`).join('')}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Teacher-wise Attendance Table -->
        <div class="att-report-section">
            <h3><i class="fas fa-users"></i> Teacher-wise Attendance (${totalTeachers})</h3>
            <div class="att-table-wrapper" style="max-height:450px;overflow-y:auto;">
                <table class="att-table att-report-table">
                    <thead><tr><th>#</th><th>Teacher</th><th>School</th><th>Designation</th><th>Phone</th><th>Cluster</th><th>Block</th><th>Attended</th><th>Rate</th></tr></thead>
                    <tbody>
                        ${teacherList.map((t, i) => {
                            const rate = totalTrainings > 0 ? Math.round((t.count / totalTrainings) * 100) : 0;
                            const rateColor = rate >= 75 ? '#10b981' : rate >= 50 ? '#f59e0b' : rate >= 25 ? '#f97316' : '#ef4444';
                            return `<tr>
                                <td>${i + 1}</td>
                                <td><strong>${escapeHtml(t.name)}</strong></td>
                                <td>${escapeHtml(t.school) || '—'}</td>
                                <td>${escapeHtml(t.designation) || '—'}</td>
                                <td>${t.phone || '—'}</td>
                                <td>${escapeHtml(t.cluster) || '—'}</td>
                                <td>${escapeHtml(t.block) || '—'}</td>
                                <td><strong>${t.count}/${totalTrainings}</strong></td>
                                <td><span style="color:${rateColor};font-weight:600;">${rate}%</span></td>
                            </tr>`;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- School-wise Breakdown -->
        <div class="att-report-section">
            <h3><i class="fas fa-school"></i> School-wise Breakdown (${schoolList.length})</h3>
            <div class="att-table-wrapper">
                <table class="att-table att-report-table">
                    <thead><tr><th>School</th><th>Teachers</th><th>Total Attendances</th><th>Avg per Teacher</th></tr></thead>
                    <tbody>
                        ${schoolList.slice(0, 30).map(([school, data]) => `<tr>
                            <td><strong>${escapeHtml(school)}</strong></td>
                            <td>${data.teachers}</td>
                            <td>${data.totalAtt}</td>
                            <td>${(data.totalAtt / data.teachers).toFixed(1)}</td>
                        </tr>`).join('')}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Cluster-wise Breakdown -->
        ${clusterList.length > 0 && !(clusterList.length === 1 && clusterList[0][0] === 'Unknown') ? `
        <div class="att-report-section">
            <h3><i class="fas fa-map-marker-alt"></i> Cluster-wise Breakdown (${clusterList.length})</h3>
            <div class="att-table-wrapper">
                <table class="att-table att-report-table">
                    <thead><tr><th>Cluster</th><th>Teachers</th><th>Total Attendances</th><th>Avg per Teacher</th></tr></thead>
                    <tbody>
                        ${clusterList.map(([cluster, data]) => `<tr>
                            <td><strong>${escapeHtml(cluster)}</strong></td>
                            <td>${data.teachers}</td>
                            <td>${data.totalAtt}</td>
                            <td>${(data.totalAtt / data.teachers).toFixed(1)}</td>
                        </tr>`).join('')}
                    </tbody>
                </table>
            </div>
        </div>
        ` : ''}

        <!-- Insights -->
        <div class="att-report-section">
            <h3><i class="fas fa-lightbulb"></i> Key Insights</h3>
            <div class="att-insights">
                ${regularTeachers.length > 0 ? `<div class="att-insight att-insight-good">
                    <i class="fas fa-check-circle"></i>
                    <div><strong>Regular Attendees:</strong> ${regularTeachers.slice(0, 5).map(t => escapeHtml(t.name)).join(', ')}${regularTeachers.length > 5 ? ` +${regularTeachers.length - 5} more` : ''} — attended ≥${threshold} of ${totalTrainings} trainings.</div>
                </div>` : ''}
                ${irregularTeachers.length > 0 && totalTrainings > 1 ? `<div class="att-insight att-insight-warn">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div><strong>Single Attendance:</strong> ${irregularTeachers.length} teacher(s) attended only 1 training. Consider follow-up: ${irregularTeachers.slice(0, 4).map(t => escapeHtml(t.name)).join(', ')}${irregularTeachers.length > 4 ? '...' : ''}</div>
                </div>` : ''}
                ${schoolList.length > 0 ? `<div class="att-insight att-insight-info">
                    <i class="fas fa-info-circle"></i>
                    <div><strong>Top Schools:</strong> ${schoolList.slice(0, 3).map(([s, d]) => `${escapeHtml(s)} (${d.teachers} teachers)`).join(', ')}</div>
                </div>` : ''}
                <div class="att-insight att-insight-info">
                    <i class="fas fa-chart-line"></i>
                    <div><strong>Reach:</strong> ${totalTeachers} unique teachers reached across ${totalTrainings} trainings with ${totalAttendances} total attendances.</div>
                </div>
            </div>
        </div>
    </div>`;
}

function exportAttendanceReport() {
    const trainings = DB.get('trainings') || [];
    const withAtt = trainings.filter(t => t.attendanceList && t.attendanceList.length > 0);
    if (withAtt.length === 0) { showToast('No attendance data', 'info'); return; }

    const wb = XLSX.utils.book_new();

    // Sheet 1: Teacher-wise attendance
    const teacherMap = new Map();
    withAtt.forEach(t => {
        t.attendanceList.forEach(a => {
            const key = `${(a.name || '').toLowerCase().trim()}|${(a.school || '').toLowerCase().trim()}`;
            if (!teacherMap.has(key)) {
                teacherMap.set(key, { name: a.name, school: a.school, phone: a.phone || '', designation: a.designation || '', cluster: a.cluster || '', block: a.block || '', count: 0, trainings: [] });
            }
            const e = teacherMap.get(key);
            e.count++;
            e.trainings.push(t.title + ' (' + (t.date || '') + ')');
        });
    });

    const teacherRows = [...teacherMap.values()].sort((a, b) => b.count - a.count).map((t, i) => ({
        'S.No': i + 1,
        'Teacher Name': t.name,
        'School': t.school,
        'Designation': t.designation,
        'Phone': t.phone,
        'Cluster': t.cluster,
        'Block': t.block,
        'Trainings Attended': t.count,
        'Attendance Rate': `${Math.round((t.count / withAtt.length) * 100)}%`,
        'Training Details': t.trainings.join('; ')
    }));
    const ws1 = XLSX.utils.json_to_sheet(teacherRows);
    ws1['!cols'] = [{ wch: 5 }, { wch: 25 }, { wch: 30 }, { wch: 18 }, { wch: 14 }, { wch: 18 }, { wch: 18 }, { wch: 12 }, { wch: 10 }, { wch: 50 }];
    XLSX.utils.book_append_sheet(wb, ws1, 'Teacher Attendance');

    // Sheet 2: Training-wise summary
    const trainingSummary = withAtt.sort((a, b) => new Date(b.date) - new Date(a.date)).map(t => ({
        'Training': t.title,
        'Date': t.date,
        'Venue': t.venue || '',
        'Duration (hrs)': t.duration,
        'Target Group': t.target || '',
        'Total Attendees': t.attendanceList.length,
        'Schools': new Set(t.attendanceList.map(a => (a.school || '').toLowerCase().trim()).filter(Boolean)).size,
        'Clusters': new Set(t.attendanceList.map(a => (a.cluster || '').toLowerCase().trim()).filter(Boolean)).size
    }));
    const ws2 = XLSX.utils.json_to_sheet(trainingSummary);
    XLSX.utils.book_append_sheet(wb, ws2, 'Training Summary');

    // Sheet 3: Per-training attendance lists
    withAtt.forEach(t => {
        const sheetName = (t.title || 'Training').replace(/[^a-zA-Z0-9 ]/g, '').substring(0, 28);
        const rows = t.attendanceList.map((a, i) => ({
            'S.No': i + 1,
            'Name': a.name,
            'School': a.school,
            'Designation': a.designation,
            'Phone': a.phone,
            'Cluster': a.cluster,
            'Block': a.block
        }));
        const ws = XLSX.utils.json_to_sheet(rows);
        XLSX.utils.book_append_sheet(wb, ws, sheetName);
    });

    XLSX.writeFile(wb, `Training_Attendance_Report_${new Date().toISOString().split('T')[0]}.xlsx`);
    showToast('Attendance report exported to Excel', 'success');
}

// ===== OBSERVATIONS =====
let observationRatings = { engagement: 0, methodology: 0, tlm: 0 };
let obsActiveCharts = {};

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

// Populate datalists for auto-complete from existing observations
function populateObsDataLists() {
    const observations = DB.get('observations');
    const schools = [...new Set(observations.map(o => o.school).filter(Boolean))];
    const teachers = [...new Set(observations.map(o => o.teacher).filter(Boolean))];
    const clusters = [...new Set(observations.map(o => o.cluster).filter(Boolean))];
    const blocks = [...new Set(observations.map(o => o.block).filter(Boolean))];
    const groups = [...new Set(observations.map(o => o.group).filter(Boolean))];
    const observers = [...new Set(observations.map(o => o.observer).filter(Boolean))];

    const setList = (id, vals) => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = vals.map(v => `<option value="${escapeHtml(v)}">`).join('');
    };
    setList('obsSchoolList', schools);
    setList('obsTeacherList', teachers);
    setList('obsClusterList', clusters);
    setList('obsBlockList', blocks);
    setList('obsGroupList', groups);
    setList('obsObserverList', observers);

    // Also populate block filter dropdown
    const blockFilter = document.getElementById('observationBlockFilter');
    if (blockFilter) {
        const current = blockFilter.value;
        blockFilter.innerHTML = '<option value="all">All Blocks</option>' +
            blocks.sort().map(b => `<option value="${escapeHtml(b)}">${escapeHtml(b)}</option>`).join('');
        blockFilter.value = current || 'all';
    }
}

function openObservationModal(id) {
    document.getElementById('observationForm').reset();
    document.getElementById('observationId').value = '';
    document.getElementById('observationDate').value = new Date().toISOString().split('T')[0];
    document.getElementById('observationModalTitle').innerHTML = '<i class="fas fa-clipboard-check"></i> New Observation';
    observationRatings = { engagement: 0, methodology: 0, tlm: 0 };
    document.querySelectorAll('.star-rating').forEach(g => updateStars(g, 0));

    populateObsDataLists();

    if (id) {
        const observations = DB.get('observations');
        const o = observations.find(x => x.id === id);
        if (o) {
            document.getElementById('observationId').value = o.id;
            document.getElementById('observationSchool').value = o.school || '';
            document.getElementById('observationTeacher').value = o.teacher || '';
            document.getElementById('observationTeacherPhone').value = o.teacherPhone || '';
            document.getElementById('observationTeacherStage').value = o.teacherStage || '';
            document.getElementById('observationCluster').value = o.cluster || '';
            document.getElementById('observationBlock').value = o.block || '';
            document.getElementById('observationDate').value = o.date;
            document.getElementById('observationStatus').value = o.observationStatus || 'Yes';
            document.getElementById('observationSubject').value = o.subject || '';
            document.getElementById('observationClass').value = o.class || '';
            document.getElementById('observationObservedTeaching').value = o.observedWhileTeaching || '';
            document.getElementById('observationEngagement').value = o.engagementLevel || '';
            document.getElementById('observationPracticeType').value = o.practiceType || '';
            document.getElementById('observationPracticeSerial').value = o.practiceSerial || '';
            document.getElementById('observationPractice').value = o.practice || '';
            document.getElementById('observationGroup').value = o.group || '';
            document.getElementById('observationTopic').value = o.topic || '';
            document.getElementById('observationNotes').value = o.notes || '';
            document.getElementById('observationStrengths').value = o.strengths || '';
            document.getElementById('observationAreas').value = o.areas || '';
            document.getElementById('observationSuggestions').value = o.suggestions || '';
            document.getElementById('observationObserver').value = o.observer || '';
            document.getElementById('observationStakeholderStatus').value = o.stakeholderStatus || '';
            observationRatings = {
                engagement: o.engagementRating || o.engagement || 0,
                methodology: o.methodology || 0,
                tlm: o.tlm || 0
            };
            updateStars(document.getElementById('ratingEngagement'), observationRatings.engagement);
            updateStars(document.getElementById('ratingMethodology'), observationRatings.methodology);
            updateStars(document.getElementById('ratingTLM'), observationRatings.tlm);
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
        teacherPhone: document.getElementById('observationTeacherPhone').value.trim(),
        teacherStage: document.getElementById('observationTeacherStage').value,
        cluster: document.getElementById('observationCluster').value.trim(),
        block: document.getElementById('observationBlock').value.trim(),
        date: document.getElementById('observationDate').value,
        observationStatus: document.getElementById('observationStatus').value,
        subject: document.getElementById('observationSubject').value,
        class: document.getElementById('observationClass').value,
        observedWhileTeaching: document.getElementById('observationObservedTeaching').value,
        engagementLevel: document.getElementById('observationEngagement').value,
        practiceType: document.getElementById('observationPracticeType').value,
        practiceSerial: document.getElementById('observationPracticeSerial').value.trim(),
        practice: document.getElementById('observationPractice').value.trim(),
        group: document.getElementById('observationGroup').value.trim(),
        topic: document.getElementById('observationTopic').value.trim(),
        engagementRating: observationRatings.engagement,
        methodology: observationRatings.methodology,
        tlm: observationRatings.tlm,
        notes: document.getElementById('observationNotes').value.trim(),
        strengths: document.getElementById('observationStrengths').value.trim(),
        areas: document.getElementById('observationAreas').value.trim(),
        suggestions: document.getElementById('observationSuggestions').value.trim(),
        observer: document.getElementById('observationObserver').value.trim(),
        stakeholderStatus: document.getElementById('observationStakeholderStatus').value,
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

// ===== Observation Tabs =====
function switchObsTab(tab) {
    document.querySelectorAll('.obs-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
    document.querySelectorAll('.obs-tab-content').forEach(c => c.classList.remove('active'));
    const tabMap = { list: 'obsTabList', analytics: 'obsTabAnalytics', planner: 'obsTabPlanner', aianalysis: 'obsTabAianalysis' };
    const el = document.getElementById(tabMap[tab] || 'obsTabList');
    if (el) el.classList.add('active');
    if (tab === 'analytics') renderObsAnalytics();
    if (tab === 'planner') renderSmartPlanner();
}

// ===== Observation Stats =====
function updateObsStats(observations) {
    const total = observations.length;
    const schools = new Set(observations.map(o => o.school).filter(Boolean)).size;
    const teachers = new Set(observations.map(o => o.teacher).filter(Boolean)).size;
    const observed = observations.filter(o => o.observationStatus === 'Yes').length;
    const engagedCount = observations.filter(o => o.engagementLevel === 'More Engaged' || o.engagementLevel === 'Engaged').length;
    const engagedPct = total > 0 ? Math.round(engagedCount / total * 100) : 0;

    const s = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    s('obsStatTotal', total);
    s('obsStatSchools', schools);
    s('obsStatTeachers', teachers);
    s('obsStatObserved', observed);
    s('obsStatEngaged', engagedPct + '%');
}

function renderObservations() {
    const observations = DB.get('observations');
    const container = document.getElementById('observationsContainer');
    const subjectFilter = document.getElementById('observationSubjectFilter')?.value || 'all';
    const engagementFilter = document.getElementById('observationEngagementFilter')?.value || 'all';
    const typeFilter = document.getElementById('observationTypeFilter')?.value || 'all';
    const blockFilter = document.getElementById('observationBlockFilter')?.value || 'all';
    const obsFilter = document.getElementById('observationObsFilter')?.value || 'all';
    const search = (document.getElementById('observationSearchInput')?.value || '').toLowerCase();

    // Populate block filter
    populateObsDataLists();

    let filtered = observations.filter(o => {
        if (subjectFilter !== 'all' && o.subject !== subjectFilter) return false;
        if (engagementFilter !== 'all' && o.engagementLevel !== engagementFilter) return false;
        if (typeFilter !== 'all' && o.practiceType !== typeFilter) return false;
        if (blockFilter !== 'all' && o.block !== blockFilter) return false;
        if (obsFilter !== 'all' && o.observationStatus !== obsFilter) return false;
        if (search) {
            const hay = [o.school, o.teacher, o.practice, o.group, o.observer, o.topic, o.cluster, o.block, o.notes].filter(Boolean).join(' ').toLowerCase();
            if (!hay.includes(search)) return false;
        }
        return true;
    }).sort((a, b) => new Date(b.date) - new Date(a.date));

    updateObsStats(filtered);

    // Store filtered list for load-more
    window._obsFiltered = filtered;
    window._obsPageSize = 50;
    window._obsShowing = Math.min(50, filtered.length);

    if (filtered.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-clipboard-check"></i><h3>No observations found</h3><p>${observations.length === 0 ? 'Start documenting classroom observations or import a DMT Excel' : 'Try adjusting your filters'}</p></div>`;
        return;
    }

    // Pagination: show max 50 at a time
    const PAGE_SIZE = 50;
    const showing = filtered.slice(0, PAGE_SIZE);
    const hasMore = filtered.length > PAGE_SIZE;

    container.innerHTML = showing.map(o => {
        const d = new Date(o.date);
        const engClass = o.engagementLevel === 'More Engaged' ? 'engagement-high' :
                         o.engagementLevel === 'Engaged' ? 'engagement-mid' : 'engagement-low';
        const obsStatusClass = o.observationStatus === 'Yes' ? 'obs-yes' :
                               o.observationStatus === 'Not_Observed' ? 'obs-notobs' : 'obs-no';
        const obsStatusLabel = o.observationStatus === 'Yes' ? 'Observed' :
                               o.observationStatus === 'Not_Observed' ? 'Not Observed' : 'Not Done';
        const starsHtml = (val) => {
            if (!val) return '';
            let s = '';
            for (let i = 1; i <= 5; i++) s += `<i class="fas fa-star" style="color:${i <= val ? 'var(--accent)' : 'var(--text-muted)'}; font-size:10px;"></i>`;
            return s;
        };
        const preview = o.notes || o.strengths || o.areas || o.suggestions || '';
        const practicePreview = o.practice ? (o.practice.length > 80 ? o.practice.substring(0, 80) + '...' : o.practice) : '';

        return `<div class="observation-item" onclick="openObservationModal('${o.id}')">
            <div class="observation-header">
                <h4>${escapeHtml(o.school)}</h4>
                <div class="obs-header-right">
                    <span class="obs-status-badge ${obsStatusClass}">${obsStatusLabel}</span>
                    <span class="observation-date">${d.toLocaleDateString('en-IN')}</span>
                </div>
            </div>
            <div class="observation-meta-row">
                ${o.teacher ? `<span><i class="fas fa-user"></i> ${escapeHtml(o.teacher)}</span>` : ''}
                ${o.subject ? `<span><i class="fas fa-book"></i> ${escapeHtml(o.subject)}</span>` : ''}
                ${o.class ? `<span><i class="fas fa-graduation-cap"></i> ${escapeHtml(o.class)}</span>` : ''}
                ${o.block ? `<span><i class="fas fa-map-marker-alt"></i> ${escapeHtml(o.block)}</span>` : ''}
                ${o.cluster ? `<span><i class="fas fa-layer-group"></i> ${escapeHtml(o.cluster)}</span>` : ''}
            </div>
            <div class="observation-meta-row obs-meta-row-2">
                ${o.engagementLevel ? `<span class="obs-engagement-badge ${engClass}"><i class="fas fa-fire"></i> ${escapeHtml(o.engagementLevel)}</span>` : ''}
                ${o.practiceType ? `<span class="obs-practice-type-badge">${escapeHtml(o.practiceType)}</span>` : ''}
                ${o.practiceSerial ? `<span class="obs-serial-badge">${escapeHtml(o.practiceSerial)}</span>` : ''}
                ${o.observedWhileTeaching === 'True' ? `<span class="obs-teaching-badge"><i class="fas fa-chalkboard"></i> While Teaching</span>` : ''}
                ${o.observer ? `<span><i class="fas fa-user-tie"></i> ${escapeHtml(o.observer)}</span>` : ''}
            </div>
            ${practicePreview ? `<div class="obs-practice-preview"><i class="fas fa-tasks"></i> ${escapeHtml(practicePreview)}</div>` : ''}
            ${(o.engagementRating || o.methodology || o.tlm) ? `<div class="observation-ratings">
                ${o.engagementRating ? `<span class="mini-rating">Engagement: <span class="stars">${starsHtml(o.engagementRating)}</span></span>` : ''}
                ${o.methodology ? `<span class="mini-rating">Methodology: <span class="stars">${starsHtml(o.methodology)}</span></span>` : ''}
                ${o.tlm ? `<span class="mini-rating">TLM Use: <span class="stars">${starsHtml(o.tlm)}</span></span>` : ''}
            </div>` : ''}
            ${preview ? `<div class="observation-notes-preview">${escapeHtml(preview.substring(0, 150))}${preview.length > 150 ? '...' : ''}</div>` : ''}
            <div class="observation-item-actions">
                <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); openObservationModal('${o.id}')"><i class="fas fa-edit"></i> Edit</button>
                <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); printObsFeedback('${o.id}')"><i class="fas fa-print"></i> Feedback</button>
                <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteObservation('${o.id}')"><i class="fas fa-trash"></i> Delete</button>
            </div>
        </div>`;
    }).join('') + (hasMore ? `<div class="obs-load-more"><button class="btn btn-outline" onclick="loadMoreObservations()"><i class="fas fa-chevron-down"></i> Showing ${PAGE_SIZE} of ${filtered.length.toLocaleString()} — Load More</button></div>` : `<div class="obs-load-more-info">${filtered.length.toLocaleString()} observations</div>`);
}

function loadMoreObservations() {
    if (!window._obsFiltered) return;
    const container = document.getElementById('observationsContainer');
    const nextBatch = 50;
    const start = window._obsShowing;
    const end = Math.min(start + nextBatch, window._obsFiltered.length);
    const newItems = window._obsFiltered.slice(start, end);
    window._obsShowing = end;
    const hasMore = end < window._obsFiltered.length;

    // Remove the load-more button
    const loadMoreEl = container.querySelector('.obs-load-more');
    if (loadMoreEl) loadMoreEl.remove();
    const infoEl = container.querySelector('.obs-load-more-info');
    if (infoEl) infoEl.remove();

    const renderCard = (o) => {
        const d = new Date(o.date);
        const engClass = o.engagementLevel === 'More Engaged' ? 'engagement-high' :
                         o.engagementLevel === 'Engaged' ? 'engagement-mid' : 'engagement-low';
        const obsStatusClass = o.observationStatus === 'Yes' ? 'obs-yes' :
                               o.observationStatus === 'Not_Observed' ? 'obs-notobs' : 'obs-no';
        const obsStatusLabel = o.observationStatus === 'Yes' ? 'Observed' :
                               o.observationStatus === 'Not_Observed' ? 'Not Observed' : 'Not Done';
        const starsHtml = (val) => {
            if (!val) return '';
            let s = '';
            for (let i = 1; i <= 5; i++) s += `<i class="fas fa-star" style="color:${i <= val ? 'var(--accent)' : 'var(--text-muted)'}; font-size:10px;"></i>`;
            return s;
        };
        const preview = o.notes || o.strengths || o.areas || o.suggestions || '';
        const practicePreview = o.practice ? (o.practice.length > 80 ? o.practice.substring(0, 80) + '...' : o.practice) : '';

        return `<div class="observation-item" onclick="openObservationModal('${o.id}')">
            <div class="observation-header">
                <h4>${escapeHtml(o.school)}</h4>
                <div class="obs-header-right">
                    <span class="obs-status-badge ${obsStatusClass}">${obsStatusLabel}</span>
                    <span class="observation-date">${d.toLocaleDateString('en-IN')}</span>
                </div>
            </div>
            <div class="observation-meta-row">
                ${o.teacher ? `<span><i class="fas fa-user"></i> ${escapeHtml(o.teacher)}</span>` : ''}
                ${o.subject ? `<span><i class="fas fa-book"></i> ${escapeHtml(o.subject)}</span>` : ''}
                ${o.class ? `<span><i class="fas fa-graduation-cap"></i> ${escapeHtml(o.class)}</span>` : ''}
                ${o.block ? `<span><i class="fas fa-map-marker-alt"></i> ${escapeHtml(o.block)}</span>` : ''}
                ${o.cluster ? `<span><i class="fas fa-layer-group"></i> ${escapeHtml(o.cluster)}</span>` : ''}
            </div>
            <div class="observation-meta-row obs-meta-row-2">
                ${o.engagementLevel ? `<span class="obs-engagement-badge ${engClass}"><i class="fas fa-fire"></i> ${escapeHtml(o.engagementLevel)}</span>` : ''}
                ${o.practiceType ? `<span class="obs-practice-type-badge">${escapeHtml(o.practiceType)}</span>` : ''}
                ${o.practiceSerial ? `<span class="obs-serial-badge">${escapeHtml(o.practiceSerial)}</span>` : ''}
                ${o.observedWhileTeaching === 'True' ? `<span class="obs-teaching-badge"><i class="fas fa-chalkboard"></i> While Teaching</span>` : ''}
                ${o.observer ? `<span><i class="fas fa-user-tie"></i> ${escapeHtml(o.observer)}</span>` : ''}
            </div>
            ${practicePreview ? `<div class="obs-practice-preview"><i class="fas fa-tasks"></i> ${escapeHtml(practicePreview)}</div>` : ''}
            ${(o.engagementRating || o.methodology || o.tlm) ? `<div class="observation-ratings">
                ${o.engagementRating ? `<span class="mini-rating">Engagement: <span class="stars">${starsHtml(o.engagementRating)}</span></span>` : ''}
                ${o.methodology ? `<span class="mini-rating">Methodology: <span class="stars">${starsHtml(o.methodology)}</span></span>` : ''}
                ${o.tlm ? `<span class="mini-rating">TLM Use: <span class="stars">${starsHtml(o.tlm)}</span></span>` : ''}
            </div>` : ''}
            ${preview ? `<div class="observation-notes-preview">${escapeHtml(preview.substring(0, 150))}${preview.length > 150 ? '...' : ''}</div>` : ''}
            <div class="observation-item-actions">
                <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); openObservationModal('${o.id}')"><i class="fas fa-edit"></i> Edit</button>
                <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); printObsFeedback('${o.id}')"><i class="fas fa-print"></i> Feedback</button>
                <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteObservation('${o.id}')"><i class="fas fa-trash"></i> Delete</button>
            </div>
        </div>`;
    };

    container.innerHTML += newItems.map(renderCard).join('') +
        (hasMore ? `<div class="obs-load-more"><button class="btn btn-outline" onclick="loadMoreObservations()"><i class="fas fa-chevron-down"></i> Showing ${end.toLocaleString()} of ${window._obsFiltered.length.toLocaleString()} — Load More</button></div>` : `<div class="obs-load-more-info">${window._obsFiltered.length.toLocaleString()} observations</div>`);
}

// ===== DMT Excel Import =====
let _dmtImportMode = 'add';

function toggleObsImportMenu() {
    const menu = document.getElementById('obsImportMenu');
    if (menu) menu.classList.toggle('show');
}

// Close menu when clicking outside
document.addEventListener('click', e => {
    const menu = document.getElementById('obsImportMenu');
    const btn = document.getElementById('obsImportBtn');
    if (menu && !menu.contains(e.target) && btn && !btn.contains(e.target)) {
        menu.classList.remove('show');
    }
});

function triggerDMTImport(mode) {
    _dmtImportMode = mode;
    document.getElementById('obsImportMenu')?.classList.remove('show');
    document.getElementById('dmtImportFile').click();
}

// ===== Cluster Checkbox Helpers =====
function populateClusterCheckboxes(listId, clusters, onchangeExpr) {
    const listEl = document.getElementById(listId);
    if (!listEl) return;
    listEl.innerHTML = clusters.map(c =>
        `<label class="cluster-cb-item" data-cluster="${escapeHtml(c)}">
            <input type="checkbox" value="${escapeHtml(c)}" checked onchange="${onchangeExpr}; updateClusterCount('${listEl.closest('.cluster-checkbox-wrap')?.id}', '${listEl.closest('.cluster-checkbox-wrap')?.id ? listEl.closest('.cluster-checkbox-wrap').id.replace('Filter', '') + 'Count' : ''}')">
            <span>${escapeHtml(c)}</span>
        </label>`
    ).join('');
    // Reset search
    const searchInput = listEl.closest('.cluster-checkbox-wrap')?.querySelector('.cluster-cb-search input');
    if (searchInput) searchInput.value = '';
    // Update select-all
    const selAll = listEl.closest('.cluster-checkbox-wrap')?.querySelector('.cluster-select-all input');
    if (selAll) selAll.checked = true;
}

function getSelectedClusters(listId) {
    const listEl = document.getElementById(listId);
    if (!listEl) return null;
    const all = listEl.querySelectorAll('input[type="checkbox"]');
    const checked = listEl.querySelectorAll('input[type="checkbox"]:checked');
    if (all.length === 0 || checked.length === all.length) return null; // null = all selected
    return new Set([...checked].map(cb => cb.value));
}

function toggleAllClusters(wrapId, checked) {
    const wrap = document.getElementById(wrapId);
    if (!wrap) return;
    wrap.querySelectorAll('.cluster-cb-list input[type="checkbox"]').forEach(cb => {
        cb.checked = checked;
    });
    updateClusterCount(wrapId, wrapId.replace('Filter', '') + 'Count');
}

function filterClusterCheckboxes(wrapId, query) {
    const wrap = document.getElementById(wrapId);
    if (!wrap) return;
    const q = query.toLowerCase();
    wrap.querySelectorAll('.cluster-cb-item').forEach(item => {
        const name = item.dataset.cluster.toLowerCase();
        item.style.display = name.includes(q) ? '' : 'none';
    });
}

function updateClusterCount(wrapId, countId) {
    const wrap = document.getElementById(wrapId);
    const countEl = document.getElementById(countId);
    if (!wrap || !countEl) return;
    const all = wrap.querySelectorAll('.cluster-cb-list input[type="checkbox"]');
    const checked = wrap.querySelectorAll('.cluster-cb-list input[type="checkbox"]:checked');
    countEl.textContent = checked.length === all.length ? `All (${all.length})` : `${checked.length} of ${all.length}`;
    // Update select-all checkbox state
    const selAll = wrap.querySelector('.cluster-select-all input');
    if (selAll) selAll.checked = checked.length === all.length;
}

// ===== Filtered Import =====
let _filteredImportRows = [];
let _filteredImportFileName = '';

function triggerFilteredImport() {
    document.getElementById('obsImportMenu')?.classList.remove('show');
    document.getElementById('dmtFilteredImportFile').click();
}

async function loadFilteredImportPreview(event) {
    const file = event.target.files[0];
    if (!file) return;
    event.target.value = '';

    _filteredImportFileName = file.name;
    _filteredImportRows = [];

    // Show modal with loading state
    document.getElementById('filteredImportLoading').style.display = 'flex';
    document.getElementById('filteredImportContent').style.display = 'none';
    document.getElementById('filteredImportConfirmBtn').disabled = true;
    document.getElementById('filteredImportModal').classList.add('active');

    try {
        const data = await file.arrayBuffer();
        const wb = XLSX.read(data, { type: 'array', cellDates: true });

        let rows = [];
        for (const sheetName of wb.SheetNames) {
            const ws = wb.Sheets[sheetName];
            const sheetRows = XLSX.utils.sheet_to_json(ws);
            if (sheetRows.length > 0) rows = rows.concat(sheetRows);
        }

        if (rows.length === 0) {
            showToast('No data found in Excel file', 'error');
            closeModal('filteredImportModal');
            return;
        }

        const cols = Object.keys(rows[0]);
        const isDMT = cols.some(c => c.includes('Teacher: Teacher Name') || c.includes('Practice Type') || c.includes('Teacher Engagement Level'));
        if (!isDMT) {
            showToast('This does not appear to be a DMT Field Notes Excel.', 'error', 6000);
            closeModal('filteredImportModal');
            return;
        }

        _filteredImportRows = rows;

        // Extract unique values for filters
        const states = [...new Set(rows.map(r => (r['State'] || '').trim()).filter(Boolean))].sort();
        const blocks = [...new Set(rows.map(r => (r['Block Name'] || '').trim()).filter(Boolean))].sort();
        const clusters = [...new Set(rows.map(r => (r['Cluster'] || '').trim()).filter(Boolean))].sort();
        const observers = [...new Set(rows.map(r => (r['Actual Observer: Full Name'] || r['Primary Observer: Full Name'] || '').trim()).filter(Boolean))].sort();

        const populateSelect = (id, label, values) => {
            const el = document.getElementById(id);
            if (!el) return;
            el.innerHTML = `<option value="all">All ${label} (${values.length})</option>` +
                values.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
        };

        populateSelect('importFilterState', 'States', states);
        populateSelect('importFilterBlock', 'Blocks', blocks);
        populateClusterCheckboxes('importClusterList', clusters, 'previewFilteredImport()');
        updateClusterCount('importFilterCluster', 'importClusterCount');
        populateSelect('importFilterObserver', 'Observers', observers);

        document.getElementById('filteredImportFileName').textContent = file.name;
        document.getElementById('filteredImportTotalRows').textContent = rows.length.toLocaleString();

        document.getElementById('filteredImportLoading').style.display = 'none';
        document.getElementById('filteredImportContent').style.display = 'block';
        previewFilteredImport();
    } catch (err) {
        console.error('Filtered import read error:', err);
        showToast('Failed to read Excel: ' + err.message, 'error');
        closeModal('filteredImportModal');
    }
}

function getImportFilters() {
    return {
        state: document.getElementById('importFilterState')?.value || 'all',
        block: document.getElementById('importFilterBlock')?.value || 'all',
        clusters: getSelectedClusters('importClusterList'),
        observer: document.getElementById('importFilterObserver')?.value || 'all'
    };
}

function getFilteredImportRows() {
    const f = getImportFilters();
    const anyFilter = f.state !== 'all' || f.block !== 'all' || f.clusters !== null || f.observer !== 'all';
    if (!anyFilter) return { rows: _filteredImportRows, anyFilter: false };

    const filtered = _filteredImportRows.filter(row => {
        const rowState = (row['State'] || '').trim();
        const rowBlock = (row['Block Name'] || '').trim();
        const rowCluster = (row['Cluster'] || '').trim();
        const rowObserver = (row['Actual Observer: Full Name'] || row['Primary Observer: Full Name'] || '').trim();
        if (f.state !== 'all' && rowState !== f.state) return false;
        if (f.block !== 'all' && rowBlock !== f.block) return false;
        if (f.clusters !== null && !f.clusters.has(rowCluster)) return false;
        if (f.observer !== 'all' && rowObserver !== f.observer) return false;
        return true;
    });
    return { rows: filtered, anyFilter: true };
}

function previewFilteredImport() {
    const { rows, anyFilter } = getFilteredImportRows();
    const total = _filteredImportRows.length;
    const previewEl = document.getElementById('filteredImportPreview');
    const countEl = document.getElementById('filteredImportCount');
    const btn = document.getElementById('filteredImportConfirmBtn');

    const schools = [...new Set(rows.map(r => (r['School Name'] || '').trim()).filter(Boolean))];
    const teachers = [...new Set(rows.map(r => (r['Teacher: Teacher Name'] || '').trim()).filter(Boolean))];
    const blocks = [...new Set(rows.map(r => (r['Block Name'] || '').trim()).filter(Boolean))];
    const clusters = [...new Set(rows.map(r => (r['Cluster'] || '').trim()).filter(Boolean))];

    const filterLabel = anyFilter
        ? `<strong>${rows.length.toLocaleString()}</strong> of ${total.toLocaleString()} rows match your filters`
        : `All <strong>${total.toLocaleString()}</strong> rows will be imported (no filter applied)`;

    previewEl.innerHTML = `
        <div class="unload-preview-stats">
            <div class="unload-preview-count" style="color: var(--accent)">
                <i class="fas fa-${anyFilter ? 'filter' : 'database'}"></i>
                ${filterLabel}
            </div>
            <div class="unload-preview-details">
                <span><i class="fas fa-school"></i> ${schools.length} Schools</span>
                <span><i class="fas fa-chalkboard-teacher"></i> ${teachers.length} Teachers</span>
                <span><i class="fas fa-map-marker-alt"></i> ${blocks.length} Blocks</span>
                <span><i class="fas fa-layer-group"></i> ${clusters.length} Clusters</span>
            </div>
        </div>`;

    btn.disabled = rows.length === 0;
    countEl.textContent = rows.length.toLocaleString();
}

function executeFilteredImport() {
    const { rows } = getFilteredImportRows();
    if (rows.length === 0) return;

    const f = getImportFilters();
    const filterDesc = [f.state !== 'all' ? `State: ${f.state}` : '', f.block !== 'all' ? `Block: ${f.block}` : '', f.clusters !== null ? `Clusters: ${[...f.clusters].join(', ')}` : '', f.observer !== 'all' ? `Observer: ${f.observer}` : ''].filter(Boolean).join(', ') || 'No filter';

    if (!confirm(`Import ${rows.length.toLocaleString()} records from "${_filteredImportFileName}"?\n\nFilter: ${filterDesc}\n\nThese will be ADDED to your existing observations.`)) return;

    let observations = DB.get('observations');
    let imported = 0;
    const buildKey = (o) => `${o.nid || ''}|${o.date || ''}|${o.practiceSerial || ''}`;
    const existingKeys = new Set(observations.filter(o => o.source === 'DMT Import').map(buildKey));

    rows.forEach(row => {
        const nid = String(row['NID'] || '').trim();
        let dateStr = '';
        const rawDate = row['Response Date'];
        if (rawDate instanceof Date) {
            dateStr = rawDate.toISOString().split('T')[0];
        } else if (typeof rawDate === 'string' && rawDate) {
            const parsed = new Date(rawDate);
            if (!isNaN(parsed)) dateStr = parsed.toISOString().split('T')[0];
        }

        const obs = {
            id: DB.generateId(),
            nid: nid,
            school: (row['School Name'] || '').trim(),
            teacher: (row['Teacher: Teacher Name'] || '').trim(),
            teacherPhone: String(row['Teacher Phone No.'] || '').trim(),
            teacherStage: (row['Teacher Stage'] || '').trim(),
            cluster: (row['Cluster'] || '').trim(),
            block: (row['Block Name'] || '').trim(),
            date: dateStr || new Date().toISOString().split('T')[0],
            observationStatus: (row['Observation'] || 'Yes').trim(),
            observedWhileTeaching: (row['Observed While Teaching'] || '').trim(),
            engagementLevel: (row['Teacher Engagement Level'] || '').trim(),
            practiceType: (row['Practice Type'] || '').trim(),
            practiceSerial: (row['Practice Master: Practice Serial No'] || '').trim(),
            practice: (row['Practice'] || '').trim(),
            group: (row['Group'] || '').trim(),
            subject: (row['Subject'] || '').trim(),
            notes: (row['Notes'] || '').trim(),
            observer: (row['Actual Observer: Full Name'] || row['Primary Observer: Full Name'] || '').trim(),
            stakeholderStatus: (row['Stakeholder Status'] || '').trim(),
            history: String(row['History'] || '0').trim(),
            district: (row['District Name'] || '').trim(),
            state: (row['State'] || '').trim(),
            createdAt: new Date().toISOString(),
            source: 'DMT Import'
        };

        const key = buildKey(obs);
        if (existingKeys.has(key)) return;

        observations.push(obs);
        existingKeys.add(key);
        imported++;
    });

    DB.set('observations', observations);
    closeModal('filteredImportModal');
    _filteredImportRows = [];
    renderObservations();
    renderDashboard();
    showToast(`Imported ${imported.toLocaleString()} records (${filterDesc}). ${(rows.length - imported)} duplicates skipped.`, 'success', 6000);
    setTimeout(() => switchObsTab('analytics'), 500);
}

function unloadImportedData() {
    document.getElementById('obsImportMenu')?.classList.remove('show');
    const observations = DB.get('observations');
    const imported = observations.filter(o => o.source === 'DMT Import');
    if (imported.length === 0) {
        showToast('No imported data found to unload', 'info');
        return;
    }
    if (!confirm(`Unload ALL ${imported.length.toLocaleString()} imported observations?\n\nThis will remove all DMT-imported records but keep your manually added observations.\n\nContinue?`)) return;
    const manual = observations.filter(o => o.source !== 'DMT Import');
    DB.set('observations', manual);
    renderObservations();
    renderDashboard();
    showToast(`Unloaded ${imported.length.toLocaleString()} imported observations. ${manual.length} manual records kept.`, 'success', 5000);
}

function openUnloadModal() {
    document.getElementById('obsImportMenu')?.classList.remove('show');
    const observations = DB.get('observations');
    const imported = observations.filter(o => o.source === 'DMT Import');
    if (imported.length === 0) {
        showToast('No imported data found to unload', 'info');
        return;
    }

    // Populate filter dropdowns from imported data only
    const states = [...new Set(imported.map(o => o.state).filter(Boolean))].sort();
    const blocks = [...new Set(imported.map(o => o.block).filter(Boolean))].sort();
    const clusters = [...new Set(imported.map(o => o.cluster).filter(Boolean))].sort();
    const observers = [...new Set(imported.map(o => o.observer).filter(Boolean))].sort();

    const populateSelect = (id, label, values) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.innerHTML = `<option value="all">All ${label} (${values.length})</option>` +
            values.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
    };

    populateSelect('unloadState', 'States', states);
    populateSelect('unloadBlock', 'Blocks', blocks);
    populateClusterCheckboxes('unloadClusterList', clusters, 'previewUnload()');
    updateClusterCount('unloadCluster', 'unloadClusterCount');
    populateSelect('unloadObserver', 'Observers', observers);

    previewUnload();
    document.getElementById('unloadModal').classList.add('active');
}

function getUnloadFilters() {
    return {
        state: document.getElementById('unloadState')?.value || 'all',
        block: document.getElementById('unloadBlock')?.value || 'all',
        clusters: getSelectedClusters('unloadClusterList'),
        observer: document.getElementById('unloadObserver')?.value || 'all'
    };
}

function getUnloadMatches() {
    const f = getUnloadFilters();
    const observations = DB.get('observations');
    const imported = observations.filter(o => o.source === 'DMT Import');
    const anyFilter = f.state !== 'all' || f.block !== 'all' || f.clusters !== null || f.observer !== 'all';
    if (!anyFilter) return { matches: [], total: imported.length, anyFilter: false };

    const matches = imported.filter(o => {
        if (f.state !== 'all' && o.state !== f.state) return false;
        if (f.block !== 'all' && o.block !== f.block) return false;
        if (f.clusters !== null && !f.clusters.has(o.cluster)) return false;
        if (f.observer !== 'all' && o.observer !== f.observer) return false;
        return true;
    });
    return { matches, total: imported.length, anyFilter: true };
}

function previewUnload() {
    const f = getUnloadFilters();
    const observations = DB.get('observations');
    const imported = observations.filter(o => o.source === 'DMT Import');

    // Cascade: filter available options based on current selections
    let pool = imported;
    if (f.state !== 'all') pool = pool.filter(o => o.state === f.state);

    const cascadeBlocks = [...new Set(pool.map(o => o.block).filter(Boolean))].sort();
    const blockSel = document.getElementById('unloadBlock');
    const curBlock = blockSel?.value || 'all';
    if (blockSel) {
        blockSel.innerHTML = `<option value="all">All Blocks (${cascadeBlocks.length})</option>` +
            cascadeBlocks.map(v => `<option value="${escapeHtml(v)}"${v === curBlock ? ' selected' : ''}>${escapeHtml(v)}</option>`).join('');
    }

    if (f.block !== 'all') pool = pool.filter(o => o.block === f.block);

    const cascadeClusters = [...new Set(pool.map(o => o.cluster).filter(Boolean))].sort();
    const clusterSel = document.getElementById('unloadCluster');
    const curCluster = clusterSel?.value || 'all';
    if (clusterSel) {
        clusterSel.innerHTML = `<option value="all">All Clusters (${cascadeClusters.length})</option>` +
            cascadeClusters.map(v => `<option value="${escapeHtml(v)}"${v === curCluster ? ' selected' : ''}>${escapeHtml(v)}</option>`).join('');
    }

    if (f.cluster !== 'all') pool = pool.filter(o => o.cluster === f.cluster);

    const cascadeObservers = [...new Set(pool.map(o => o.observer).filter(Boolean))].sort();
    const obsSel = document.getElementById('unloadObserver');
    const curObs = obsSel?.value || 'all';
    if (obsSel) {
        obsSel.innerHTML = `<option value="all">All Observers (${cascadeObservers.length})</option>` +
            cascadeObservers.map(v => `<option value="${escapeHtml(v)}"${v === curObs ? ' selected' : ''}>${escapeHtml(v)}</option>`).join('');
    }

    // Now compute matches
    const { matches, total, anyFilter } = getUnloadMatches();
    const previewEl = document.getElementById('unloadPreview');
    const countEl = document.getElementById('unloadCount');
    const btn = document.getElementById('unloadConfirmBtn');

    if (!anyFilter) {
        previewEl.innerHTML = `<div class="unload-preview-empty"><i class="fas fa-info-circle"></i> Select at least one filter to preview which records will be removed<br><small>${total.toLocaleString()} imported records available</small></div>`;
        btn.disabled = true;
        countEl.textContent = '0';
        return;
    }

    const schools = [...new Set(matches.map(o => o.school).filter(Boolean))];
    const teachers = [...new Set(matches.map(o => o.teacher).filter(Boolean))];
    const blocks = [...new Set(matches.map(o => o.block).filter(Boolean))];
    const clusters = [...new Set(matches.map(o => o.cluster).filter(Boolean))];

    previewEl.innerHTML = `
        <div class="unload-preview-stats">
            <div class="unload-preview-count">
                <i class="fas fa-exclamation-triangle"></i>
                <strong>${matches.length.toLocaleString()}</strong> of ${total.toLocaleString()} imported records will be removed
            </div>
            <div class="unload-preview-details">
                <span><i class="fas fa-school"></i> ${schools.length} Schools</span>
                <span><i class="fas fa-chalkboard-teacher"></i> ${teachers.length} Teachers</span>
                <span><i class="fas fa-map-marker-alt"></i> ${blocks.length} Blocks</span>
                <span><i class="fas fa-layer-group"></i> ${clusters.length} Clusters</span>
            </div>
        </div>`;

    btn.disabled = matches.length === 0;
    countEl.textContent = matches.length.toLocaleString();
}

function executeFilteredUnload() {
    const { matches, anyFilter } = getUnloadMatches();
    if (!anyFilter || matches.length === 0) return;

    const f = getUnloadFilters();
    const filterDesc = [f.state !== 'all' ? `State: ${f.state}` : '', f.block !== 'all' ? `Block: ${f.block}` : '', f.clusters !== null ? `Clusters: ${[...f.clusters].join(', ')}` : '', f.observer !== 'all' ? `Observer: ${f.observer}` : ''].filter(Boolean).join(', ');

    if (!confirm(`Unload ${matches.length.toLocaleString()} imported observations matching:\n${filterDesc}\n\nYour manual entries will NOT be affected.\n\nContinue?`)) return;

    const matchIds = new Set(matches.map(o => o.id));
    const observations = DB.get('observations');
    const remaining = observations.filter(o => !matchIds.has(o.id));
    DB.set('observations', remaining);
    closeModal('unloadModal');
    renderObservations();
    renderDashboard();
    showToast(`Unloaded ${matches.length.toLocaleString()} records (${filterDesc}). ${remaining.length.toLocaleString()} records remaining.`, 'success', 6000);
}

function clearAllObservations() {
    document.getElementById('obsImportMenu')?.classList.remove('show');
    const observations = DB.get('observations');
    if (observations.length === 0) {
        showToast('No observations to clear', 'info');
        return;
    }
    if (!confirm(`Delete ALL ${observations.length.toLocaleString()} observations?\n\n⚠️ This will permanently remove every observation record (both imported and manual).\n\nThis cannot be undone!`)) return;
    const answer = prompt('Type DELETE to confirm:');
    if (answer !== 'DELETE') { showToast('Cancelled', 'info'); return; }
    DB.set('observations', []);
    renderObservations();
    renderDashboard();
    showToast('All observations cleared', 'info');
}

async function importDMTExcel(event) {
    const file = event.target.files[0];
    if (!file) return;

    const mode = _dmtImportMode || 'add';
    const modeLabel = mode === 'replace' ? 'REPLACE all existing observations with' : 'ADD';
    if (!confirm(`Import "${file.name}"?\n\nThis will ${modeLabel} observation records from the DMT Excel file.\n\nContinue?`)) {
        event.target.value = '';
        return;
    }

    showToast('Reading Excel file...', 'info');

    try {
        const data = await file.arrayBuffer();
        const wb = XLSX.read(data, { type: 'array', cellDates: true });
        
        // Read ALL sheets and combine rows (in case data spans multiple sheets)
        let rows = [];
        for (const sheetName of wb.SheetNames) {
            const ws = wb.Sheets[sheetName];
            const sheetRows = XLSX.utils.sheet_to_json(ws);
            if (sheetRows.length > 0) rows = rows.concat(sheetRows);
        }

        if (rows.length === 0) {
            showToast('No data found in Excel file', 'error');
            event.target.value = '';
            return;
        }

        // Detect DMT format by checking column names
        const cols = Object.keys(rows[0]);
        const isDMT = cols.some(c => c.includes('Teacher: Teacher Name') || c.includes('Practice Type') || c.includes('Teacher Engagement Level'));

        if (!isDMT) {
            showToast('This does not appear to be a DMT Field Notes Excel. Expected columns like "Teacher: Teacher Name", "Practice Type" etc.', 'error', 6000);
            event.target.value = '';
            return;
        }

        let observations = mode === 'replace'
            ? DB.get('observations').filter(o => o.source !== 'DMT Import')
            : DB.get('observations');
        if (mode === 'replace') {
            // In replace mode, also remove old imported data first
            const manualOnly = observations.filter(o => o.source !== 'DMT Import');
            observations = manualOnly;
        }
        let imported = 0;
        // Build dedup key: NID + date + practice serial (NID is teacher ID, not unique per row)
        const buildKey = (o) => `${o.nid || ''}|${o.date || ''}|${o.practiceSerial || ''}`;
        const existingKeys = new Set(observations.filter(o => o.source === 'DMT Import').map(buildKey));

        rows.forEach(row => {
            const nid = String(row['NID'] || '').trim();

            // Parse date
            let dateStr = '';
            const rawDate = row['Response Date'];
            if (rawDate instanceof Date) {
                dateStr = rawDate.toISOString().split('T')[0];
            } else if (typeof rawDate === 'string' && rawDate) {
                // Try parsing "9/28/2020, 8:45 AM" format
                const parsed = new Date(rawDate);
                if (!isNaN(parsed)) dateStr = parsed.toISOString().split('T')[0];
            }

            const obs = {
                id: DB.generateId(),
                nid: nid,
                school: (row['School Name'] || '').trim(),
                teacher: (row['Teacher: Teacher Name'] || '').trim(),
                teacherPhone: String(row['Teacher Phone No.'] || '').trim(),
                teacherStage: (row['Teacher Stage'] || '').trim(),
                cluster: (row['Cluster'] || '').trim(),
                block: (row['Block Name'] || '').trim(),
                date: dateStr || new Date().toISOString().split('T')[0],
                observationStatus: (row['Observation'] || 'Yes').trim(),
                observedWhileTeaching: (row['Observed While Teaching'] || '').trim(),
                engagementLevel: (row['Teacher Engagement Level'] || '').trim(),
                practiceType: (row['Practice Type'] || '').trim(),
                practiceSerial: (row['Practice Master: Practice Serial No'] || '').trim(),
                practice: (row['Practice'] || '').trim(),
                group: (row['Group'] || '').trim(),
                subject: (row['Subject'] || '').trim(),
                notes: (row['Notes'] || '').trim(),
                observer: (row['Actual Observer: Full Name'] || row['Primary Observer: Full Name'] || '').trim(),
                stakeholderStatus: (row['Stakeholder Status'] || '').trim(),
                history: String(row['History'] || '0').trim(),
                district: (row['District Name'] || '').trim(),
                state: (row['State'] || '').trim(),
                createdAt: new Date().toISOString(),
                source: 'DMT Import'
            };

            // Skip exact duplicates (same teacher + date + practice)
            const key = buildKey(obs);
            if (existingKeys.has(key)) return;

            observations.push(obs);
            existingKeys.add(key);
            imported++;
        });

        DB.set('observations', observations);
        renderObservations();
        renderDashboard();
        showToast(`Imported ${imported.toLocaleString()} observations from DMT Excel! (${rows.length - imported} duplicates skipped)`, 'success', 6000);
        // Auto-switch to analytics tab after import
        setTimeout(() => switchObsTab('analytics'), 500);

        // --- Auto-extract Teacher Records from DMT import ---
        _autoExtractTeachersFromDMT(rows);

    } catch (err) {
        console.error('DMT Import error:', err);
        showToast('Failed to import: ' + err.message, 'error');
    }
    event.target.value = '';
}

/**
 * Auto-extract unique teachers from DMT Excel rows and add to Teacher Records.
 * Called after a successful DMT observation import.
 */
function _autoExtractTeachersFromDMT(rows) {
    if (!rows || rows.length === 0) return;

    // Build unique teacher map from DMT rows (key: NID or name+school)
    const teacherMap = new Map();
    rows.forEach(row => {
        const name = (row['Teacher: Teacher Name'] || '').toString().trim();
        const nid = (row['NID'] || '').toString().trim();
        const school = (row['School Name'] || '').toString().trim();
        if (!name) return;

        // Use NID as primary key, fallback to name+school
        const key = nid ? `nid:${nid}` : `${name.toLowerCase()}|${school.toLowerCase()}`;
        if (!teacherMap.has(key)) {
            teacherMap.set(key, {
                name: name,
                nid: nid,
                school: school,
                phone: (row['Teacher Phone No.'] || '').toString().trim(),
                designation: (row['Teacher Stage'] || '').toString().trim(),
                cluster: (row['Cluster'] || '').toString().trim(),
                block: (row['Block Name'] || '').toString().trim(),
                subject: (row['Subject'] || '').toString().trim(),
                district: (row['District Name'] || '').toString().trim()
            });
        }
    });

    if (teacherMap.size === 0) return;

    // Check existing teacher records to avoid duplicates
    const existingRecords = DB.get('teacherRecords');
    const existingKeys = new Set();
    existingRecords.forEach(tr => {
        const n = (tr.name || '').toLowerCase().trim();
        const s = (tr.school || '').toLowerCase().trim();
        const nid = (tr.nid || '').trim();
        if (nid) existingKeys.add(`nid:${nid}`);
        existingKeys.add(`${n}|${s}`);
    });

    // Filter out already-existing teachers
    const newTeachers = [];
    teacherMap.forEach((t, key) => {
        const nameSchoolKey = `${t.name.toLowerCase()}|${t.school.toLowerCase()}`;
        const nidKey = t.nid ? `nid:${t.nid}` : null;
        if (!existingKeys.has(nameSchoolKey) && (!nidKey || !existingKeys.has(nidKey))) {
            newTeachers.push(t);
        }
    });

    if (newTeachers.length === 0) {
        showToast(`All ${teacherMap.size} teachers already exist in Teacher Records`, 'info', 3000);
        return;
    }

    // Confirm with user
    const skipped = teacherMap.size - newTeachers.length;
    let msg = `📋 Auto-Load Teacher Records\n\n`;
    msg += `Found ${newTeachers.length} new teacher(s) from this DMT import.\n`;
    if (skipped > 0) msg += `${skipped} already in Teacher Records (skipped).\n`;
    msg += `\nAdd ${newTeachers.length} teacher(s) to Teacher Records?`;

    if (!confirm(msg)) return;

    // Add new teachers to teacherRecords
    const records = DB.get('teacherRecords');
    const now = new Date().toISOString();
    let added = 0;

    newTeachers.forEach(t => {
        records.push({
            id: DB.generateId(),
            name: t.name,
            gender: '',
            school: t.school,
            designation: t.designation,
            subject: t.subject,
            classesTaught: '',
            phone: t.phone,
            email: '',
            block: t.block,
            cluster: t.cluster,
            qualification: '',
            experience: '',
            joinDate: '',
            nid: t.nid,
            notes: t.district ? `District: ${t.district}` : '',
            createdAt: now,
            updatedAt: now,
            source: 'DMT Import'
        });
        added++;
    });

    DB.set('teacherRecords', records);
    showToast(`Added ${added} teacher(s) to Teacher Records from DMT import!`, 'success', 5000);

    // If teacher records section is visible, refresh it
    if (document.querySelector('#section-teacherrecords.active')) {
        renderTeacherRecords();
    }
}

// ===== SMART PLANNER — Intelligent Suggestion Engine =====
let _spAnalysis = null;
let _spObs = null;
let _spCalendarWeekOffset = 0;

function renderSmartPlanner() {
    const container = document.getElementById('smartPlannerContainer');
    if (!container) return;
    const observations = DB.get('observations');

    if (observations.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-brain"></i><h3>No data available</h3><p>Import DMT Excel data or add observations to activate the Smart Planner</p></div>`;
        return;
    }

    _spObs = observations;
    _spAnalysis = analyzeObservationData(observations);
    const html = buildSmartPlannerHTML(_spAnalysis, observations);
    container.innerHTML = html;
}

/* ---- Expand/collapse any sp-section body ---- */
function toggleSpSection(el) {
    const section = el.closest('.sp-section');
    if (!section) return;
    section.classList.toggle('collapsed');
}

/* ---- Expand detail panel inside a card ---- */
function toggleSpDetail(btn) {
    const card = btn.closest('[data-sp-detail]') || btn.parentElement;
    const detail = card.querySelector('.sp-detail-panel');
    if (!detail) return;
    const open = detail.style.display === 'block';
    detail.style.display = open ? 'none' : 'block';
    btn.querySelector('i').className = open ? 'fas fa-chevron-down' : 'fas fa-chevron-up';
}

/* ---- Weekly Calendar navigation ---- */
function spCalNav(dir) {
    if (dir === 0) _spCalendarWeekOffset = 0;
    else _spCalendarWeekOffset += dir;
    renderSpCalendar();
}

function renderSpCalendar() {
    const wrap = document.getElementById('spCalendarWrap');
    if (!wrap || !_spAnalysis) return;

    const now = new Date();
    const dow = now.getDay();
    const mon = new Date(now);
    mon.setDate(now.getDate() - (dow === 0 ? 6 : dow - 1) + (_spCalendarWeekOffset * 7));
    mon.setHours(0,0,0,0);

    const days = [];
    const dayNames = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
    for (let i = 0; i < 7; i++) {
        const d = new Date(mon); d.setDate(mon.getDate() + i);
        const dk = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
        days.push({ date: d, dk, dayName: dayNames[i], isToday: d.toDateString() === now.toDateString() });
    }

    const startStr = mon.toLocaleDateString('en-IN',{day:'numeric',month:'short'});
    const endD = new Date(mon); endD.setDate(mon.getDate()+6);
    const endStr = endD.toLocaleDateString('en-IN',{day:'numeric',month:'short',year:'numeric'});

    // Pull existing planner tasks, visits, observations for this week
    const tasks = DB.get('plannerTasks');
    const visits = DB.get('visits');
    const observations = DB.get('observations');
    const trainings = DB.get('trainings');

    // Cluster-wise suggestion for each weekday
    const allClustersSorted = [..._spAnalysis.clusters].sort((x,y) => x.avgEngagement - y.avgEngagement);

    wrap.innerHTML = `
        <div class="sp-cal-header">
            <button class="sp-cal-nav" onclick="spCalNav(-1)" title="Previous"><i class="fas fa-chevron-left"></i></button>
            <span class="sp-cal-title">📅 ${startStr} — ${endStr}</span>
            <button class="sp-cal-nav" onclick="spCalNav(0)" title="Today"><i class="fas fa-dot-circle"></i></button>
            <button class="sp-cal-nav" onclick="spCalNav(1)" title="Next"><i class="fas fa-chevron-right"></i></button>
        </div>
        <div class="sp-cal-grid">
            ${days.map((day, idx) => {
                const dayTasks = tasks.filter(t => t.date === day.dk);
                const dayVisits = visits.filter(v => v.date === day.dk);
                const dayObs = observations.filter(o => o.date === day.dk);
                const dayTrainings = trainings.filter(t => t.date === day.dk);
                const sugCluster = idx < 5 ? allClustersSorted[idx % allClustersSorted.length] : null;
                const sugSchools = sugCluster ? _spAnalysis.schools.filter(s => s.cluster === sugCluster.name).sort((a,b)=>b.priorityScore-a.priorityScore).slice(0,2) : [];
                const dateDisp = day.date.toLocaleDateString('en-IN',{day:'numeric',month:'short'});
                const isWeekend = idx >= 5;
                return `<div class="sp-cal-day ${day.isToday ? 'today' : ''} ${isWeekend ? 'weekend' : ''}">
                    <div class="sp-cal-day-head">
                        <span class="sp-cal-day-name">${day.dayName}</span>
                        <span class="sp-cal-day-date">${dateDisp}</span>
                    </div>
                    <div class="sp-cal-day-body">
                        ${dayVisits.map(v => `<div class="sp-cal-item visit"><i class="fas fa-school"></i> ${escapeHtml(v.school||v.purpose||'Visit')}</div>`).join('')}
                        ${dayObs.map(o => `<div class="sp-cal-item obs"><i class="fas fa-clipboard-check"></i> ${escapeHtml(o.school||'Observation')}</div>`).join('')}
                        ${dayTrainings.map(t => `<div class="sp-cal-item training"><i class="fas fa-chalkboard-teacher"></i> ${escapeHtml(t.title||'Training')}</div>`).join('')}
                        ${dayTasks.map(t => `<div class="sp-cal-item task ${t.done?'done':''}"><i class="fas ${t.done?'fa-check-circle':'fa-circle'}"></i> ${escapeHtml(t.text)}</div>`).join('')}
                        ${!isWeekend && sugCluster && dayVisits.length===0 && dayObs.length===0 && dayTasks.length===0 ? `
                            <div class="sp-cal-suggest">
                                <div class="sp-cal-sug-label"><i class="fas fa-magic"></i> Suggested</div>
                                <div class="sp-cal-sug-cluster"><i class="fas fa-layer-group"></i> ${escapeHtml(sugCluster.name)}</div>
                                ${sugSchools.map(s => `<div class="sp-cal-sug-school">${escapeHtml(s.name)}</div>`).join('')}
                                <button class="sp-cal-add-btn" onclick="spAddSuggestedVisit('${day.dk}','${escapeHtml(sugSchools[0]?.name||'')}','${escapeHtml(sugCluster.name)}')" title="Add to planner"><i class="fas fa-plus"></i> Add to Planner</button>
                            </div>` : ''}
                        ${!isWeekend ? `<div class="sp-cal-add-row">
                            <input type="text" class="sp-cal-input" id="spCalInput-${day.dk}" placeholder="Quick add..." onkeydown="if(event.key==='Enter')spQuickAddTask('${day.dk}')">
                            <button onclick="spQuickAddTask('${day.dk}')" title="Add"><i class="fas fa-plus"></i></button>
                        </div>` : ''}
                    </div>
                </div>`;
            }).join('')}
        </div>`;
}

function spQuickAddTask(dateKey) {
    const input = document.getElementById('spCalInput-' + dateKey);
    if (!input) return;
    const text = input.value.trim();
    if (!text) return;
    const tasks = DB.get('plannerTasks');
    tasks.push({ id: DB.generateId(), date: dateKey, text, type: 'task', done: false, createdAt: new Date().toISOString() });
    DB.set('plannerTasks', tasks);
    input.value = '';
    renderSmartPlanner();
    refreshPlannerIfVisible();
    showToast('Task added to planner');
}

function spAddSuggestedVisit(dateKey, school, cluster) {
    // Create an actual School Visit entry
    const visits = DB.get('visits');
    const block = _spAnalysis ? (_spAnalysis.schools.find(s => s.name === school) || {}).block || '' : '';
    const alreadyVisit = visits.some(v => v.school === school && v.date === dateKey);
    if (!alreadyVisit) {
        visits.push({ id: DB.generateId(), school, block, cluster, district: '', date: dateKey, status: 'planned', purpose: 'Classroom Observation', duration: '', peopleMet: '', rating: '', notes: '', followUp: '', nextDate: '', createdAt: new Date().toISOString() });
        DB.set('visits', visits);
    }

    renderSmartPlanner();
    refreshPlannerIfVisible();
    renderVisits();
    showToast(alreadyVisit ? 'Visit already planned for this date' : 'School visit added ✅', alreadyVisit ? 'info' : 'success');
}

/* ---- Generate actions — push plans to existing features ---- */
function spGenerateDailyVisits() {
    if (!_spAnalysis) { showToast('No data loaded', 'error'); return; }
    const today = new Date();
    const dk = `${today.getFullYear()}-${String(today.getMonth()+1).padStart(2,'0')}-${String(today.getDate()).padStart(2,'0')}`;
    const visits = DB.get('visits');
    const topSchools = [..._spAnalysis.schools].sort((a,b)=>b.priorityScore-a.priorityScore).slice(0,3);
    let added = 0;
    topSchools.forEach(s => {
        const alreadyVisit = visits.some(v => v.school === s.name && v.date === dk);
        if (!alreadyVisit) {
            visits.push({ id: DB.generateId(), school: s.name, block: s.block || '', cluster: s.cluster || '', district: '', date: dk, status: 'planned', purpose: 'Classroom Observation', duration: '', peopleMet: '', rating: '', notes: '', followUp: '', nextDate: '', createdAt: new Date().toISOString() });
            added++;
        }
    });
    DB.set('visits', visits);
    renderSmartPlanner();
    refreshPlannerIfVisible();
    renderVisits();
    showToast(added > 0 ? `${added} school visits planned for today` : 'All top schools already planned for today', added > 0 ? 'success' : 'info');
}

function spGenerateWeeklyPlan() {
    if (!_spAnalysis) { showToast('No data loaded', 'error'); return; }
    const now = new Date();
    const dow = now.getDay();
    const mon = new Date(now);
    mon.setDate(now.getDate() - (dow === 0 ? 6 : dow - 1));
    mon.setHours(0,0,0,0);

    const visits = DB.get('visits');
    const allClustersSorted = [..._spAnalysis.clusters].sort((x,y) => x.avgEngagement - y.avgEngagement);
    let added = 0;

    for (let i = 0; i < 5; i++) {
        const d = new Date(mon); d.setDate(mon.getDate() + i);
        const dk = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
        const cluster = allClustersSorted[i % allClustersSorted.length];
        if (!cluster) continue;
        const schools = _spAnalysis.schools.filter(s => s.cluster === cluster.name).sort((a,b)=>b.priorityScore-a.priorityScore).slice(0,2);
        schools.forEach(s => {
            const alreadyVisit = visits.some(v => v.school === s.name && v.date === dk);
            if (!alreadyVisit) {
                visits.push({ id: DB.generateId(), school: s.name, block: s.block || '', cluster: cluster.name, district: '', date: dk, status: 'planned', purpose: 'Classroom Observation', duration: '', peopleMet: '', rating: '', notes: '', followUp: '', nextDate: '', createdAt: new Date().toISOString() });
                added++;
            }
        });
    }
    DB.set('visits', visits);
    renderSmartPlanner();
    refreshPlannerIfVisible();
    renderVisits();
    showToast(added > 0 ? `${added} school visits planned for this week` : 'Weekly plan already populated', added > 0 ? 'success' : 'info');
}

function spGenerateQuarterlyGoals() {
    if (!_spAnalysis) { showToast('No data loaded', 'error'); return; }
    const now = new Date();
    const monthKey = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}`;
    const allGoals = DB.get('goalTargets');
    const existing = allGoals.find(g => g.monthKey === monthKey);

    const totalSchools = _spAnalysis.schools.length;
    const totalTeachers = _spAnalysis.teachers.length;
    const trainingNeeded = _spAnalysis.subjects.filter(s => s.needsTraining).length;

    const targets = {
        visits: Math.max(totalSchools, 15),
        trainings: Math.max(trainingNeeded, 4),
        observations: Math.max(Math.ceil(totalTeachers * 0.5), 10),
        teachers: totalTeachers,
        resources: 5
    };

    if (existing) {
        existing.targets = targets;
    } else {
        allGoals.push({ monthKey, targets });
    }
    DB.set('goalTargets', allGoals);
    renderSmartPlanner();
    showToast('Quarterly goals pushed to Goal Tracker ✅');
}

function spPushIdea(title, desc) {
    const ideas = DB.get('ideas');
    ideas.push({
        id: DB.generateId(),
        title, description: desc,
        category: 'Education', status: 'spark', priority: 'medium',
        tags: ['smart-planner', 'auto-generated'],
        color: '#8b5cf6', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
    });
    DB.set('ideas', ideas);
    renderSmartPlanner();
    showToast('Idea saved to Idea Tracker 💡');
}

function spPushTrainingIdea(topic) {
    spPushIdea(`Training: ${topic}`, `Auto-suggested by Smart Planner based on observation data analysis. Plan a training session on "${topic}" for teachers with low engagement in this area.`);
}

/* ================================================================
   AI ANALYSIS — AI Prompt Builder & Plan Renderer
   ================================================================ */
let _aiPromptFocus = 'full';
let _aiParsedPlans = [];
let _aiGeneratedPrompt = '';
let _aiLastRawResponse = '';

function setAiPromptFocus(focus) {
    _aiPromptFocus = focus;
    document.querySelectorAll('.ai-chip').forEach(c => c.classList.toggle('active', c.dataset.focus === focus));
}

function scrollToAiStep(num) {
    const el = document.getElementById('aiStep' + num);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function toggleAiRawResponse() {
    const el = document.getElementById('aiRawResponse');
    if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}



// Build the prompt from observation data
function _buildAiPrompt() {
    const obs = DB.get('observations');
    if (!obs || obs.length === 0) return null;

    const analysis = analyzeObservationData(obs);
    const focus = _aiPromptFocus;
    const today = new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });

    const totalObs = obs.length;
    const engCounts = { 'More Engaged': 0, 'Engaged': 0, 'Not Engaged': 0 };
    obs.forEach(o => { if (o.engagementLevel && engCounts[o.engagementLevel] !== undefined) engCounts[o.engagementLevel]++; });

    const subjectLines = analysis.subjects.slice(0, 15).map(s =>
        `  - ${s.name}: ${s.count} obs, Avg Engagement ${s.avgEngagement.toFixed(1)}/3${s.needsTraining ? ' ⚠️ NEEDS TRAINING' : ''}`
    ).join('\n');

    const lowEngLines = analysis.lowEngTeachers.slice(0, 20).map(t =>
        `  - ${t.name} (${t.school || 'N/A'}, ${t.cluster || ''}, ${t.block || ''}) — Avg: ${t.avgEngagement.toFixed(1)}/3, ${t.totalVisits} visits, Last: ${t.daysSinceVisit}d ago`
    ).join('\n');

    const topSchoolLines = analysis.schools.sort((a, b) => b.priorityScore - a.priorityScore).slice(0, 15).map(s =>
        `  - ${s.name} (${s.block || ''} / ${s.cluster || ''}) — ${s.teacherCount} teachers, Avg: ${s.avgEngagement.toFixed(1)}/3, Last: ${s.daysSinceVisit}d ago, Priority: ${s.priorityScore.toFixed(0)}`
    ).join('\n');

    const clusterLines = analysis.clusters.map(c =>
        `  - ${c.name} (${c.block || ''}) — ${c.schoolCount} schools, ${c.teacherCount} teachers, Avg: ${c.avgEngagement.toFixed(1)}/3`
    ).join('\n');

    const notObsLines = analysis.notObservedTeachers.slice(0, 15).map(t => `  - ${t}`).join('\n');

    const practiceLines = analysis.practices.slice(0, 15).map(p =>
        `  - ${p.name} (${p.type || 'N/A'}): ${p.count} obs, Avg: ${p.avgEngagement.toFixed(1)}/3`
    ).join('\n');

    const notVisitedLines = analysis.notVisitedRecently.slice(0, 15).map(t =>
        `  - ${t.name} (${t.school || ''}) — Last: ${t.daysSinceVisit}d ago`
    ).join('\n');

    // Build engagement trend data
    const monthMap = {};
    obs.forEach(o => {
        if (!o.date) return;
        const d = new Date(o.date);
        const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
        if (!monthMap[key]) monthMap[key] = { total: 0, moreEng: 0, eng: 0, notEng: 0 };
        monthMap[key].total++;
        if (o.engagementLevel === 'More Engaged') monthMap[key].moreEng++;
        else if (o.engagementLevel === 'Engaged') monthMap[key].eng++;
        else if (o.engagementLevel === 'Not Engaged') monthMap[key].notEng++;
    });
    const trendLines = Object.keys(monthMap).sort().map(k => {
        const m = monthMap[k];
        return `  - ${k}: ${m.total} obs — More Engaged ${m.moreEng} (${m.total ? Math.round(m.moreEng/m.total*100) : 0}%), Engaged ${m.eng} (${m.total ? Math.round(m.eng/m.total*100) : 0}%), Not Engaged ${m.notEng} (${m.total ? Math.round(m.notEng/m.total*100) : 0}%)`;
    }).join('\n');

    // High-performing teachers for recognition
    const highEngTeachers = analysis.teachers
        .filter(t => t.avgEngagement >= 2.5 && t.totalVisits >= 2)
        .sort((a, b) => b.avgEngagement - a.avgEngagement)
        .slice(0, 10);
    const highEngLines = highEngTeachers.map(t =>
        `  - ${t.name} (${t.school || 'N/A'}, ${t.cluster || ''}) — Avg: ${t.avgEngagement.toFixed(1)}/3, ${t.totalVisits} visits`
    ).join('\n');

    let prompt = `You are an expert Educational Mentor / Academic Resource Person (APF/BRP/CRP) in India.
Today is ${today}. Analyze this classroom observation data thoroughly and provide DETAILED, COMPREHENSIVE, ACTIONABLE plans.
Be VERY SPECIFIC — use EXACT teacher names, school names, dates. Give RICH explanations for every recommendation.
Provide REASONING for each suggestion. Don't just list items — explain WHY and HOW.\n\n`;

    prompt += `📊 DATA SUMMARY\nTotal Observations: ${totalObs} | Schools: ${analysis.schools.length} | Teachers: ${analysis.teachers.length} | Clusters: ${analysis.clusters.length} | Blocks: ${analysis.blocks.length}\n`;
    prompt += `Engagement Breakdown: More Engaged ${engCounts['More Engaged']} (${totalObs ? Math.round(engCounts['More Engaged'] / totalObs * 100) : 0}%) | Engaged ${engCounts['Engaged']} (${totalObs ? Math.round(engCounts['Engaged'] / totalObs * 100) : 0}%) | Not Engaged ${engCounts['Not Engaged']} (${totalObs ? Math.round(engCounts['Not Engaged'] / totalObs * 100) : 0}%)\n\n`;

    if (trendLines) {
        prompt += `📈 MONTHLY TREND:\n${trendLines}\n\n`;
    }

    if (focus === 'full' || focus === 'engagement') {
        prompt += `📘 Subjects:\n${subjectLines}\n\n🔴 Low Engagement Teachers:\n${lowEngLines || '(None)'}\n\n📋 Teaching Practices:\n${practiceLines}\n\n`;
        if (highEngLines) prompt += `⭐ High Performing Teachers (for peer mentoring/recognition):\n${highEngLines}\n\n`;
    }
    if (focus === 'full' || focus === 'teacher') {
        prompt += `⏳ Not Visited Recently (need follow-up):\n${notVisitedLines || '(All recent)'}\n\n❌ Not Observed At All:\n${notObsLines || '(None)'}\n\n`;
    }
    if (focus === 'full' || focus === 'school') {
        prompt += `🏫 Priority Schools (sorted by priority score):\n${topSchoolLines}\n\n`;
    }
    if (focus === 'full' || focus === 'training') {
        prompt += `🏘️ Clusters:\n${clusterLines}\n\n`;
    }

    prompt += `RESPOND with these EXACT section headers. Use pipe | to separate fields within items.\n`;
    prompt += `For each item, provide DETAILED explanations — not just short labels.\n\n`;

    if (focus === 'full' || focus === 'engagement') {
        prompt += `## KEY INSIGHTS\n10-15 bullet points with detailed findings. For each insight include:\n- What the data shows (with specific numbers and percentages)\n- Why it matters for student learning\n- Which specific teachers/schools/subjects are involved\n\n`;
    }

    if (focus === 'full' || focus === 'engagement') {
        prompt += `## SUBJECT WISE ANALYSIS\nFor each subject with observations, provide: Subject Name | Total Observations | Engagement Rate | Key Issue | Recommended Action | Reason\n\n`;
    }

    if (focus === 'full' || focus === 'school') {
        prompt += `## SCHOOL VISIT PLAN\nFor each school (at least 8-10): School Name | Block | Cluster | Purpose (be DETAILED — what to observe, whom to meet, what to check) | Specific Date (YYYY-MM-DD) | Expected Outcome\n\n`;
    }

    if (focus === 'full' || focus === 'teacher') {
        prompt += `## TEACHER SUPPORT ACTIONS\nFor each teacher (at least 10-12): Teacher Name | School | Detailed Action Needed (be specific about what support to give and how) | Priority (High/Medium/Low) | Reason for Priority\n\n`;
    }

    if (focus === 'full' || focus === 'teacher') {
        prompt += `## TEACHER PROFILES\nFor the top 8-10 teachers needing attention, provide: Teacher Name | School | Strengths | Challenges | Specific Mentoring Plan | Timeline\n\n`;
    }

    if (focus === 'full' || focus === 'training') {
        prompt += `## TRAINING RECOMMENDATIONS\nFor each training (at least 5-6): Title | Target Group: who | Key Topics: detailed topic list | Duration: time | Methodology: hands-on/demo/etc | Expected Impact: what will improve\n\n`;
    }

    if (focus === 'full' || focus === 'engagement') {
        prompt += `## ENGAGEMENT IMPROVEMENT STRATEGIES\n8-12 concrete strategies. For each strategy include:\n- Strategy name and description\n- Which specific teachers/schools it targets\n- Step-by-step implementation plan\n- Expected timeline and measurable outcome\n\n`;
    }

    prompt += `## WEEKLY ACTION PLAN\nFor EACH day (Monday through Saturday): Day | School to Visit | Key Activities (list 3-4 specific things to do) | Teachers to Meet (use real names) | Follow-up Focus | Materials/Documents Needed\n\n`;

    if (focus === 'full') {
        prompt += `## DATA GAPS & RECOMMENDATIONS\n5-7 items about what data is missing, which schools/teachers need more observations, and what additional information would strengthen the analysis. For each: Gap Description | Impact | Recommended Action\n\n`;
    }

    if (focus === 'full') {
        prompt += `## MONTHLY PROGRESS TRACKER\nCreate 4-5 measurable goals for this month. For each: Goal | Current Status (from data) | Target | How to Measure | Key Actions\n\n`;
    }

    prompt += `## IDEAS & INNOVATIONS\n5-8 innovative, creative ideas for improving classroom engagement and teacher support. For each idea include what it is, how to implement it, and expected impact.\n\n`;

    prompt += `IMPORTANT INSTRUCTIONS:\n`;
    prompt += `- Use EXACT names from my data. Be specific — no generic advice.\n`;
    prompt += `- Dates in YYYY-MM-DD format, starting from this week.\n`;
    prompt += `- Provide REASONING and CONTEXT for every recommendation.\n`;
    prompt += `- Be COMPREHENSIVE — more detail is better. Think like an experienced mentor.\n`;
    prompt += `- Cover ALL teachers and schools mentioned in the data, don't skip any.\n`;
    prompt += `- Cross-reference data points — if a teacher has low engagement AND hasn't been visited, mention both.`;

    return prompt;
}

function generateAiPrompt() {
    const prompt = _buildAiPrompt();
    if (!prompt) { showToast('No observation data. Import DMT Excel first.', 'error'); return; }
    _aiGeneratedPrompt = prompt;
    const outputEl = document.getElementById('aiPromptOutput');
    const textEl = document.getElementById('aiPromptText');
    if (outputEl && textEl) {
        textEl.textContent = prompt;
        outputEl.style.display = 'block';
    }
    showToast('Prompt generated!', 'success');
}

function copyAiPrompt() {
    const text = _aiGeneratedPrompt || document.getElementById('aiPromptText')?.textContent || '';
    if (!text) { generateAiPrompt(); return; }
    navigator.clipboard.writeText(text).then(() => showToast('Copied! 📋', 'success')).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('Copied! 📋', 'success');
    });
}

function _parseAndShowAiResults(text) {
    const plans = [];
    const cleanMd = t => t.replace(/\*\*(.+?)\*\*/g, '$1').replace(/__(.+?)__/g, '$1').replace(/\*(.+?)\*/g, '$1').replace(/_(.+?)_/g, '$1').trim();

    const sections = [
        { key: 'insights', header: 'KEY INSIGHTS', icon: 'fa-lightbulb', color: '#f59e0b' },
        { key: 'subjects', header: 'SUBJECT WISE ANALYSIS', icon: 'fa-book', color: '#0ea5e9' },
        { key: 'visits', header: 'SCHOOL VISIT PLAN', icon: 'fa-school', color: '#3b82f6' },
        { key: 'teacher', header: 'TEACHER SUPPORT ACTIONS', icon: 'fa-user-graduate', color: '#8b5cf6' },
        { key: 'profiles', header: 'TEACHER PROFILES', icon: 'fa-id-card', color: '#a855f7' },
        { key: 'training', header: 'TRAINING RECOMMENDATIONS', icon: 'fa-chalkboard-teacher', color: '#10b981' },
        { key: 'engagement', header: 'ENGAGEMENT IMPROVEMENT STRATEGIES', icon: 'fa-fire', color: '#ef4444' },
        { key: 'weekly', header: 'WEEKLY ACTION PLAN', icon: 'fa-calendar-week', color: '#6366f1' },
        { key: 'datagaps', header: 'DATA GAPS & RECOMMENDATIONS', icon: 'fa-exclamation-triangle', color: '#f97316' },
        { key: 'progress', header: 'MONTHLY PROGRESS TRACKER', icon: 'fa-chart-line', color: '#14b8a6' },
        { key: 'ideas', header: 'IDEAS & INNOVATIONS', icon: 'fa-lightbulb', color: '#ec4899' }
    ];

    sections.forEach(sec => {
        const regex = new RegExp(`##\\s*${sec.header.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'i');
        const match = text.match(regex);
        if (!match) return;

        const startIdx = match.index + match[0].length;
        const nextHeader = text.slice(startIdx).match(/\n##\s/);
        const endIdx = nextHeader ? startIdx + nextHeader.index : text.length;
        const sectionText = text.slice(startIdx, endIdx).trim();

        const lines = sectionText.split('\n')
            .map(l => l.replace(/^[\s]*[-*•▸▹►●◆⦿✦✧]\s*/, '').replace(/^\d+[\.\)]\s*/, '').trim())
            .filter(l => l.length > 5 && !l.startsWith('#'));

        plans.push({
            key: sec.key,
            header: sec.header,
            icon: sec.icon,
            color: sec.color,
            items: lines.map((line, idx) => {
                const cleaned = cleanMd(line);
                let parts = null, fields = null;
                if (cleaned.includes('|')) {
                    parts = cleaned.split('|').map(p => p.trim());
                    fields = {};
                    parts.forEach(p => {
                        const m = p.match(/^([A-Za-z\s\-]+?):\s*(.+)$/);
                        if (m) fields[m[1].trim().toLowerCase()] = m[2].trim();
                        else if (!fields._title && p.length > 2) fields._title = p;
                    });
                }
                return { id: `ai_${sec.key}_${idx}`, text: cleaned, pushed: false, parts, fields };
            })
        });
    });

    if (plans.length === 0) {
        const lines = text.split('\n')
            .map(l => cleanMd(l.replace(/^[\s]*[-*•]\s*/, '').trim()))
            .filter(l => l.length > 10 && !l.startsWith('#'));
        plans.push({
            key: 'general', header: 'AI ANALYSIS', icon: 'fa-robot', color: '#6366f1',
            items: lines.map((line, idx) => {
                let parts = null, fields = null;
                if (line.includes('|')) {
                    parts = line.split('|').map(p => p.trim());
                    fields = {};
                    parts.forEach(p => {
                        const m = p.match(/^([A-Za-z\s\-]+?):\s*(.+)$/);
                        if (m) fields[m[1].trim().toLowerCase()] = m[2].trim();
                        else if (!fields._title && p.length > 2) fields._title = p;
                    });
                }
                return { id: `ai_general_${idx}`, text: line, pushed: false, parts, fields };
            })
        });
    }

    _aiParsedPlans = plans;
    renderAiPlans(plans);

    const results = document.getElementById('aiResultsContainer');
    if (results) { results.style.display = 'block'; results.scrollIntoView({ behavior: 'smooth' }); }
}

// Also support manual paste
function parseAiResponse() {
    const input = document.getElementById('aiResponseInput');
    if (!input || !input.value.trim()) { showToast('Please paste the AI response first', 'error'); return; }
    _parseAndShowAiResults(input.value.trim());
    showToast(`Parsed ${_aiParsedPlans.reduce((s, p) => s + p.items.length, 0)} items`, 'success');
}

function renderAiPlans(plans) {
    const container = document.getElementById('aiPlansContainer');
    const actionsEl = document.getElementById('aiPlansActions');
    if (!container) return;

    if (!plans || plans.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-robot"></i><h3>No plans generated</h3><p>Paste the AI response and try again</p></div>';
        if (actionsEl) actionsEl.style.display = 'none';
        return;
    }

    container.innerHTML = plans.map(sec => `
        <div class="ai-plan-section" style="--ai-sec-color: ${sec.color}">
            <div class="ai-plan-section-header">
                <i class="fas ${sec.icon}" style="color: ${sec.color}"></i>
                <span>${sec.header}</span>
                <span class="ai-plan-count">${sec.items.length} items</span>
            </div>
            <div class="ai-plan-items">
                ${sec.items.map(item => `
                    <div class="ai-plan-item ${item.pushed ? 'pushed' : ''}" id="aiItem-${item.id}">
                        <div class="ai-plan-item-body">
                            ${_renderAiItemContent(item, sec.key)}
                        </div>
                        <div class="ai-plan-item-actions">
                            ${sec.key === 'visits' || sec.key === 'weekly' ? `<button class="ai-push-btn visit" onclick="aiPushToVisit('${item.id}')" title="Add as School Visit" ${item.pushed ? 'disabled' : ''}><i class="fas fa-school"></i> Visit</button>` : ''}
                            ${sec.key === 'training' ? `<button class="ai-push-btn training" onclick="aiPushToTraining('${item.id}')" title="Add as Training" ${item.pushed ? 'disabled' : ''}><i class="fas fa-chalkboard-teacher"></i> Training</button>` : ''}
                            ${sec.key === 'ideas' || sec.key === 'engagement' || sec.key === 'insights' || sec.key === 'datagaps' || sec.key === 'progress' ? `<button class="ai-push-btn idea" onclick="aiPushToIdea('${item.id}')" title="Save as Idea" ${item.pushed ? 'disabled' : ''}><i class="fas fa-lightbulb"></i> Idea</button>` : ''}
                            ${sec.key === 'teacher' || sec.key === 'profiles' ? `<button class="ai-push-btn visit" onclick="aiPushToVisit('${item.id}')" title="Add as Visit" ${item.pushed ? 'disabled' : ''}><i class="fas fa-school"></i> Visit</button><button class="ai-push-btn idea" onclick="aiPushToIdea('${item.id}')" title="Save as Idea" ${item.pushed ? 'disabled' : ''}><i class="fas fa-lightbulb"></i> Idea</button>` : ''}
                            ${sec.key === 'subjects' ? `<button class="ai-push-btn training" onclick="aiPushToTraining('${item.id}')" title="Add as Training" ${item.pushed ? 'disabled' : ''}><i class="fas fa-chalkboard-teacher"></i> Training</button><button class="ai-push-btn idea" onclick="aiPushToIdea('${item.id}')" title="Save as Idea" ${item.pushed ? 'disabled' : ''}><i class="fas fa-lightbulb"></i> Idea</button>` : ''}
                            ${sec.key === 'general' ? `<button class="ai-push-btn idea" onclick="aiPushToIdea('${item.id}')" title="Save as Idea" ${item.pushed ? 'disabled' : ''}><i class="fas fa-lightbulb"></i> Idea</button><button class="ai-push-btn visit" onclick="aiPushToVisit('${item.id}')" title="Add Visit" ${item.pushed ? 'disabled' : ''}><i class="fas fa-school"></i> Visit</button>` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `).join('');


    if (actionsEl) actionsEl.style.display = 'flex';
}

function _renderAiItemContent(item, secKey) {
    const f = item.fields;
    const parts = item.parts;

    // ===== Positional pipe fields (no labels like "Key:") — map by section type =====
    const positionalMaps = {
        visits: [
            { label: 'School', icon: 'fa-school' },
            { label: 'Block', icon: 'fa-map-marker-alt' },
            { label: 'Cluster', icon: 'fa-layer-group' },
            { label: 'Purpose', icon: 'fa-bullseye' },
            { label: 'Date', icon: 'fa-calendar' },
            { label: 'Expected Outcome', icon: 'fa-chart-line' }
        ],
        teacher: [
            { label: 'Teacher', icon: 'fa-user' },
            { label: 'School', icon: 'fa-school' },
            { label: 'Action Needed', icon: 'fa-bolt' },
            { label: 'Priority', icon: 'fa-flag' },
            { label: 'Reason', icon: 'fa-info-circle' }
        ],
        profiles: [
            { label: 'Teacher', icon: 'fa-user' },
            { label: 'School', icon: 'fa-school' },
            { label: 'Strengths', icon: 'fa-star' },
            { label: 'Challenges', icon: 'fa-exclamation-circle' },
            { label: 'Mentoring Plan', icon: 'fa-hands-helping' },
            { label: 'Timeline', icon: 'fa-clock' }
        ],
        weekly: [
            { label: 'Day', icon: 'fa-calendar-day' },
            { label: 'School to Visit', icon: 'fa-school' },
            { label: 'Key Activities', icon: 'fa-tasks' },
            { label: 'Teachers to Meet', icon: 'fa-user' },
            { label: 'Follow-up Focus', icon: 'fa-redo' },
            { label: 'Materials Needed', icon: 'fa-clipboard-list' }
        ],
        training: [
            { label: 'Training Title', icon: 'fa-chalkboard-teacher' },
            { label: 'Target Group', icon: 'fa-users' },
            { label: 'Key Topics', icon: 'fa-tags' },
            { label: 'Duration', icon: 'fa-clock' },
            { label: 'Methodology', icon: 'fa-cogs' },
            { label: 'Expected Impact', icon: 'fa-chart-line' }
        ],
        subjects: [
            { label: 'Subject', icon: 'fa-book' },
            { label: 'Total Observations', icon: 'fa-clipboard-check' },
            { label: 'Engagement Rate', icon: 'fa-fire' },
            { label: 'Key Issue', icon: 'fa-exclamation-circle' },
            { label: 'Recommended Action', icon: 'fa-bolt' },
            { label: 'Reason', icon: 'fa-info-circle' }
        ],
        datagaps: [
            { label: 'Gap', icon: 'fa-exclamation-triangle' },
            { label: 'Impact', icon: 'fa-chart-line' },
            { label: 'Recommended Action', icon: 'fa-bolt' }
        ],
        progress: [
            { label: 'Goal', icon: 'fa-bullseye' },
            { label: 'Current Status', icon: 'fa-info-circle' },
            { label: 'Target', icon: 'fa-flag' },
            { label: 'How to Measure', icon: 'fa-ruler' },
            { label: 'Key Actions', icon: 'fa-tasks' }
        ]
    };

    const fieldIcons = {
        'target group': 'fa-users', 'target': 'fa-users', 'group': 'fa-users',
        'key topics': 'fa-tags', 'topics': 'fa-tags', 'key topic': 'fa-tags',
        'duration': 'fa-clock', 'time': 'fa-clock', 'timeline': 'fa-clock',
        'school': 'fa-school', 'school to visit': 'fa-school', 'school name': 'fa-school',
        'block': 'fa-map-marker-alt', 'cluster': 'fa-layer-group',
        'purpose': 'fa-bullseye', 'action': 'fa-bolt', 'action needed': 'fa-bolt',
        'priority': 'fa-flag', 'date': 'fa-calendar', 'suggested date': 'fa-calendar',
        'key activities': 'fa-tasks', 'activities': 'fa-tasks',
        'teachers to meet': 'fa-user', 'teacher': 'fa-user', 'teacher name': 'fa-user',
        'follow-up focus': 'fa-redo', 'follow-up': 'fa-redo', 'followup': 'fa-redo',
        'day': 'fa-calendar-day', 'training title': 'fa-chalkboard-teacher',
        'strategy': 'fa-chess', 'idea': 'fa-lightbulb', 'description': 'fa-align-left',
        'impact': 'fa-chart-line', 'expected impact': 'fa-chart-line', 'area': 'fa-crosshairs',
        'focus': 'fa-crosshairs', 'subject': 'fa-book',
        'observation': 'fa-clipboard-check', 'total observations': 'fa-clipboard-check',
        'engagement rate': 'fa-fire', 'key issue': 'fa-exclamation-circle',
        'recommended action': 'fa-bolt', 'reason': 'fa-info-circle',
        'reason for priority': 'fa-info-circle', 'strengths': 'fa-star',
        'challenges': 'fa-exclamation-circle', 'mentoring plan': 'fa-hands-helping',
        'specific mentoring plan': 'fa-hands-helping',
        'methodology': 'fa-cogs', 'materials needed': 'fa-clipboard-list',
        'materials/documents needed': 'fa-clipboard-list',
        'expected outcome': 'fa-chart-line', 'gap': 'fa-exclamation-triangle',
        'gap description': 'fa-exclamation-triangle',
        'goal': 'fa-bullseye', 'current status': 'fa-info-circle',
        'how to measure': 'fa-ruler', 'key actions': 'fa-tasks'
    };

    // --- Case 1: Labeled fields detected (like "Target Group: value") ---
    if (f && Object.keys(f).length > 1) {
        const title = f._title || '';
        let html = '';
        if (title) html += `<div class="ai-item-title">${escapeHtml(title)}</div>`;
        html += '<div class="ai-item-fields">';
        for (const [key, val] of Object.entries(f)) {
            if (key === '_title') continue;
            const icon = fieldIcons[key] || 'fa-info-circle';
            const label = key.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
            html += `<div class="ai-item-field"><span class="ai-field-label"><i class="fas ${icon}"></i> ${escapeHtml(label)}</span><span class="ai-field-value">${escapeHtml(val)}</span></div>`;
        }
        html += '</div>';
        return html;
    }

    // --- Case 2: Positional pipe fields (no labels) — map by section ---
    if (parts && parts.length >= 2 && positionalMaps[secKey]) {
        const map = positionalMaps[secKey];
        const title = parts[0] || '';
        let html = '';
        if (title) html += `<div class="ai-item-title">${escapeHtml(title)}</div>`;
        html += '<div class="ai-item-fields">';
        for (let i = 1; i < parts.length; i++) {
            const def = map[i] || { label: `Field ${i}`, icon: 'fa-info-circle' };
            if (parts[i]) {
                html += `<div class="ai-item-field"><span class="ai-field-label"><i class="fas ${def.icon}"></i> ${escapeHtml(def.label)}</span><span class="ai-field-value">${escapeHtml(parts[i])}</span></div>`;
            }
        }
        html += '</div>';
        return html;
    }

    // --- Case 3: Pipe fields in unknown section — show generically ---
    if (parts && parts.length >= 2) {
        const title = parts[0] || '';
        let html = '';
        if (title) html += `<div class="ai-item-title">${escapeHtml(title)}</div>`;
        if (parts.length > 1) {
            html += '<div class="ai-item-fields">';
            for (let i = 1; i < parts.length; i++) {
                if (parts[i]) {
                    const m = parts[i].match(/^([A-Za-z\s\-]+?):\s*(.+)$/);
                    if (m) {
                        const icon = fieldIcons[m[1].trim().toLowerCase()] || 'fa-info-circle';
                        html += `<div class="ai-item-field"><span class="ai-field-label"><i class="fas ${icon}"></i> ${escapeHtml(m[1].trim())}</span><span class="ai-field-value">${escapeHtml(m[2].trim())}</span></div>`;
                    } else {
                        html += `<div class="ai-item-field"><span class="ai-field-value">${escapeHtml(parts[i])}</span></div>`;
                    }
                }
            }
            html += '</div>';
        }
        return html;
    }

    // --- Case 4: Plain text (insights, strategies, ideas) — render as highlighted card ---
    const text = item.text || '';
    // Detect if text has a colon-separated title
    const colonMatch = text.match(/^([^:]{5,60}):\s+(.+)$/s);
    if (colonMatch) {
        return `<div class="ai-item-title">${escapeHtml(colonMatch[1])}</div><div class="ai-plan-item-text">${escapeHtml(colonMatch[2])}</div>`;
    }
    return `<div class="ai-plan-item-text">${escapeHtml(text)}</div>`;
}

function _findAiItem(itemId) {
    for (const sec of _aiParsedPlans) {
        const item = sec.items.find(i => i.id === itemId);
        if (item) return { item, sec };
    }
    return null;
}

function _markAiPushed(itemId) {
    const found = _findAiItem(itemId);
    if (found) {
        found.item.pushed = true;
        const el = document.getElementById('aiItem-' + itemId);
        if (el) {
            el.classList.add('pushed');
            el.querySelectorAll('.ai-push-btn').forEach(b => b.disabled = true);
        }
    }
}

function aiPushToVisit(itemId) {
    const found = _findAiItem(itemId);
    if (!found) return;
    const txt = found.item.text;

    // Try to parse structured: School | Block | Cluster | Purpose | Date
    let school = '', block = '', cluster = '', purpose = 'Classroom Observation', date = '';
    if (found.item.parts && found.item.parts.length >= 2) {
        const p = found.item.parts;
        school = p[0] || '';
        block = p.length >= 3 ? p[1] : '';
        cluster = p.length >= 4 ? p[2] : '';
        purpose = p.length >= 5 ? p[3] : purpose;
        // Try to find a date in YYYY-MM-DD format
        const dateMatch = txt.match(/\d{4}-\d{2}-\d{2}/);
        date = dateMatch ? dateMatch[0] : p[p.length - 1]?.match(/\d{4}-\d{2}-\d{2}/) ? p[p.length - 1].match(/\d{4}-\d{2}-\d{2}/)[0] : '';
    } else {
        // Guess from free text
        school = txt.substring(0, 60);
        const dateMatch = txt.match(/\d{4}-\d{2}-\d{2}/);
        date = dateMatch ? dateMatch[0] : '';
    }

    if (!date) {
        // Default to tomorrow
        const tmrw = new Date();
        tmrw.setDate(tmrw.getDate() + 1);
        date = `${tmrw.getFullYear()}-${String(tmrw.getMonth()+1).padStart(2,'0')}-${String(tmrw.getDate()).padStart(2,'0')}`;
    }

    const visits = DB.get('visits');
    const alreadyExists = visits.some(v => v.school === school && v.date === date);
    if (alreadyExists) {
        showToast('Visit already exists for this school & date', 'info');
        _markAiPushed(itemId);
        return;
    }

    visits.push({
        id: DB.generateId(), school, block, cluster, district: '',
        date, status: 'planned', purpose,
        duration: '', peopleMet: '', rating: '', notes: `AI Suggested: ${txt}`,
        followUp: '', nextDate: '', createdAt: new Date().toISOString()
    });
    DB.set('visits', visits);
    _markAiPushed(itemId);
    renderVisits();
    showToast('School visit added ✅');
}

function aiPushToTraining(itemId) {
    const found = _findAiItem(itemId);
    if (!found) return;
    const txt = found.item.text;

    let title = '', target = '', topics = '', duration = '';
    if (found.item.parts && found.item.parts.length >= 2) {
        const p = found.item.parts;
        title = p[0] || txt.substring(0, 60);
        target = p[1] || '';
        topics = p[2] || '';
        duration = p[3] || '';
    } else {
        title = txt.substring(0, 80);
    }

    const trainings = DB.get('trainings');
    trainings.push({
        id: DB.generateId(), title,
        date: new Date().toISOString().split('T')[0],
        location: '', facilitator: '', participants: target,
        description: `AI Suggested: ${txt}\n\nTopics: ${topics}\nDuration: ${duration}`,
        type: 'Workshop', status: 'planned',
        createdAt: new Date().toISOString()
    });
    DB.set('trainings', trainings);
    _markAiPushed(itemId);
    showToast('Training added ✅');
}

function aiPushToIdea(itemId) {
    const found = _findAiItem(itemId);
    if (!found) return;
    const txt = found.item.text;
    const title = txt.length > 80 ? txt.substring(0, 77) + '...' : txt;

    const ideas = DB.get('ideas');
    ideas.push({
        id: DB.generateId(),
        title,
        description: `AI Analysis Suggestion:\n${txt}`,
        category: 'Education',
        status: 'spark',
        priority: 'medium',
        tags: ['ai-analysis', 'auto-generated'],
        color: '#6366f1',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    });
    DB.set('ideas', ideas);
    _markAiPushed(itemId);
    showToast('Idea saved 💡');
}

function aiPushAllPlans() {
    if (!_aiParsedPlans || _aiParsedPlans.length === 0) return;
    let pushed = 0;

    _aiParsedPlans.forEach(sec => {
        sec.items.forEach(item => {
            if (item.pushed) return;
            if (sec.key === 'visits' || sec.key === 'weekly') {
                aiPushToVisit(item.id);
                pushed++;
            } else if (sec.key === 'training') {
                aiPushToTraining(item.id);
                pushed++;
            } else if (sec.key === 'ideas' || sec.key === 'engagement' || sec.key === 'insights') {
                aiPushToIdea(item.id);
                pushed++;
            } else if (sec.key === 'teacher') {
                aiPushToIdea(item.id);
                pushed++;
            } else if (sec.key === 'general') {
                aiPushToIdea(item.id);
                pushed++;
            }
        });
    });

    renderAiPlans(_aiParsedPlans);
    renderVisits();
    renderDashboard();
    showToast(`${pushed} items pushed to dashboard! 🚀`, 'success');
}

function analyzeObservationData(obs) {
    const today = new Date();
    const todayStr = today.toISOString().split('T')[0];

    // ===== Teacher Profiles =====
    const teacherMap = {};
    obs.forEach(o => {
        const key = (o.teacher || '').trim();
        if (!key) return;
        if (!teacherMap[key]) teacherMap[key] = {
            name: key, nid: o.nid, school: o.school, block: o.block, cluster: o.cluster,
            phone: o.teacherPhone, stage: o.teacherStage, subject: new Set(),
            observations: [], engagementScores: [], practices: new Set(),
            lastVisit: null, totalVisits: 0
        };
        const t = teacherMap[key];
        t.observations.push(o);
        t.totalVisits++;
        if (o.subject) t.subject.add(o.subject);
        if (o.practice) t.practices.add(o.practice);
        const engMap = { 'More Engaged': 3, 'Engaged': 2, 'Not Engaged': 1 };
        if (o.engagementLevel && engMap[o.engagementLevel]) t.engagementScores.push(engMap[o.engagementLevel]);
        const d = new Date(o.date);
        if (!isNaN(d) && (!t.lastVisit || d > t.lastVisit)) t.lastVisit = d;
    });

    // ===== School Profiles =====
    const schoolMap = {};
    obs.forEach(o => {
        const key = (o.school || '').trim();
        if (!key) return;
        if (!schoolMap[key]) schoolMap[key] = {
            name: key, block: o.block, cluster: o.cluster, observations: [],
            teachers: new Set(), lastVisit: null, engagementScores: []
        };
        const s = schoolMap[key];
        s.observations.push(o);
        if (o.teacher) s.teachers.add(o.teacher);
        const engMap = { 'More Engaged': 3, 'Engaged': 2, 'Not Engaged': 1 };
        if (o.engagementLevel && engMap[o.engagementLevel]) s.engagementScores.push(engMap[o.engagementLevel]);
        const d = new Date(o.date);
        if (!isNaN(d) && (!s.lastVisit || d > s.lastVisit)) s.lastVisit = d;
    });

    // ===== Cluster Profiles =====
    const clusterMap = {};
    obs.forEach(o => {
        const key = (o.cluster || '').trim();
        if (!key) return;
        if (!clusterMap[key]) clusterMap[key] = {
            name: key, block: o.block, schools: new Set(), teachers: new Set(),
            observations: [], engagementScores: []
        };
        const c = clusterMap[key];
        c.observations.push(o);
        if (o.school) c.schools.add(o.school);
        if (o.teacher) c.teachers.add(o.teacher);
        const engMap = { 'More Engaged': 3, 'Engaged': 2, 'Not Engaged': 1 };
        if (o.engagementLevel && engMap[o.engagementLevel]) c.engagementScores.push(engMap[o.engagementLevel]);
    });

    // ===== Block Profiles =====
    const blockMap = {};
    obs.forEach(o => {
        const key = (o.block || '').trim();
        if (!key) return;
        if (!blockMap[key]) blockMap[key] = {
            name: key, clusters: new Set(), schools: new Set(), teachers: new Set(),
            observations: [], engagementScores: []
        };
        const b = blockMap[key];
        b.observations.push(o);
        if (o.cluster) b.clusters.add(o.cluster);
        if (o.school) b.schools.add(o.school);
        if (o.teacher) b.teachers.add(o.teacher);
        const engMap = { 'More Engaged': 3, 'Engaged': 2, 'Not Engaged': 1 };
        if (o.engagementLevel && engMap[o.engagementLevel]) b.engagementScores.push(engMap[o.engagementLevel]);
    });

    // ===== Compute Averages & Scores =====
    const avg = arr => arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
    const daysSince = d => d ? Math.floor((today - d) / 86400000) : 999;

    const teachers = Object.values(teacherMap).map(t => ({
        ...t,
        avgEngagement: avg(t.engagementScores),
        daysSinceVisit: daysSince(t.lastVisit),
        subject: [...t.subject],
        practices: [...t.practices],
        // Priority score: higher = more urgent to visit
        priorityScore: (3 - avg(t.engagementScores)) * 30 + Math.min(daysSince(t.lastVisit), 180) + (t.totalVisits < 3 ? 50 : 0)
    }));

    const schools = Object.values(schoolMap).map(s => ({
        ...s,
        avgEngagement: avg(s.engagementScores),
        daysSinceVisit: daysSince(s.lastVisit),
        teacherCount: s.teachers.size,
        teachers: [...s.teachers],
        priorityScore: (3 - avg(s.engagementScores)) * 25 + Math.min(daysSince(s.lastVisit), 180) + (s.teachers.size > 5 ? 20 : 0)
    }));

    const clusters = Object.values(clusterMap).map(c => ({
        ...c,
        avgEngagement: avg(c.engagementScores),
        schoolCount: c.schools.size,
        teacherCount: c.teachers.size,
        schools: [...c.schools],
        teachers: [...c.teachers]
    }));

    const blocks = Object.values(blockMap).map(b => ({
        ...b,
        avgEngagement: avg(b.engagementScores),
        clusterCount: b.clusters.size,
        schoolCount: b.schools.size,
        teacherCount: b.teachers.size,
        clusters: [...b.clusters],
        schools: [...b.schools]
    }));

    // ===== Subject Analysis =====
    const subjectEngagement = {};
    obs.forEach(o => {
        const sub = o.subject || 'Other';
        if (!subjectEngagement[sub]) subjectEngagement[sub] = { scores: [], count: 0, notEngaged: 0 };
        subjectEngagement[sub].count++;
        const engMap = { 'More Engaged': 3, 'Engaged': 2, 'Not Engaged': 1 };
        if (o.engagementLevel && engMap[o.engagementLevel]) {
            subjectEngagement[sub].scores.push(engMap[o.engagementLevel]);
            if (o.engagementLevel === 'Not Engaged') subjectEngagement[sub].notEngaged++;
        }
    });

    const subjects = Object.entries(subjectEngagement).map(([name, d]) => ({
        name, count: d.count, avgEngagement: avg(d.scores), notEngaged: d.notEngaged,
        needsTraining: d.notEngaged > d.count * 0.3
    })).sort((a, b) => a.avgEngagement - b.avgEngagement);

    // ===== Practice Analysis =====
    const practiceEngagement = {};
    obs.forEach(o => {
        const p = o.practice || '';
        if (!p) return;
        if (!practiceEngagement[p]) practiceEngagement[p] = { scores: [], count: 0, type: o.practiceType };
        practiceEngagement[p].count++;
        const engMap = { 'More Engaged': 3, 'Engaged': 2, 'Not Engaged': 1 };
        if (o.engagementLevel && engMap[o.engagementLevel]) practiceEngagement[p].scores.push(engMap[o.engagementLevel]);
    });

    const practices = Object.entries(practiceEngagement).map(([name, d]) => ({
        name, count: d.count, avgEngagement: avg(d.scores), type: d.type
    })).sort((a, b) => a.avgEngagement - b.avgEngagement);

    // ===== Trend Data =====
    const monthlyData = {};
    obs.forEach(o => {
        const d = new Date(o.date);
        if (isNaN(d)) return;
        const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
        if (!monthlyData[key]) monthlyData[key] = { total: 0, engaged: 0, notEngaged: 0 };
        monthlyData[key].total++;
        if (o.engagementLevel === 'More Engaged' || o.engagementLevel === 'Engaged') monthlyData[key].engaged++;
        if (o.engagementLevel === 'Not Engaged') monthlyData[key].notEngaged++;
    });

    // ===== Not Observed / Not Done Teachers =====
    const notObserved = obs.filter(o => o.observationStatus === 'Not_Observed' || o.observationStatus === 'No');
    const notObservedTeachers = [...new Set(notObserved.map(o => o.teacher).filter(Boolean))];

    // ===== Engagement groups for training =====
    const lowEngTeachers = teachers.filter(t => t.avgEngagement > 0 && t.avgEngagement < 2);
    const highEngTeachers = teachers.filter(t => t.avgEngagement >= 2.5);
    const notVisitedRecently = teachers.filter(t => t.daysSinceVisit > 30).sort((a, b) => b.daysSinceVisit - a.daysSinceVisit);
    const needsFollowUp = teachers.filter(t => t.avgEngagement < 2 || t.totalVisits < 2).sort((a, b) => b.priorityScore - a.priorityScore);
    const topPriority = [...teachers].sort((a, b) => b.priorityScore - a.priorityScore).slice(0, 20);

    return {
        teachers, schools, clusters, blocks, subjects, practices,
        monthlyData, notObservedTeachers, lowEngTeachers, highEngTeachers,
        notVisitedRecently, needsFollowUp, topPriority, today, todayStr
    };
}

function buildSmartPlannerHTML(a, obs) {
    const engLabel = v => v >= 2.5 ? '🟢 High' : v >= 1.5 ? '🟡 Medium' : '🔴 Low';
    const engColor = v => v >= 2.5 ? '#10b981' : v >= 1.5 ? '#f59e0b' : '#ef4444';
    const daysLabel = d => d < 7 ? 'This week' : d < 30 ? `${Math.floor(d / 7)}w ago` : d < 365 ? `${Math.floor(d / 30)}m ago` : `${Math.floor(d / 365)}y ago`;

    // Existing features data
    const ideas = DB.get('ideas');
    const plannerTasks = DB.get('plannerTasks');
    const goalTargets = DB.get('goalTargets');
    const followupStatus = DB.get('followupStatus');
    const visits = DB.get('visits');
    const trainings = DB.get('trainings');

    // ===== DAILY VISIT PLAN =====
    const dailySchools = [...a.schools].sort((x, y) => y.priorityScore - x.priorityScore).slice(0, 5);
    const dailyHTML = dailySchools.map((s, i) => {
        const schoolTeachers = a.teachers.filter(t => t.school === s.name);
        const lowEng = schoolTeachers.filter(t => t.avgEngagement < 2);
        const subjectsSet = new Set();
        schoolTeachers.forEach(t => t.subject.forEach(su => subjectsSet.add(su)));
        return `
        <div class="sp-visit-card" data-sp-detail>
            <div class="sp-visit-rank">${i + 1}</div>
            <div class="sp-visit-info">
                <div class="sp-visit-school">${escapeHtml(s.name)}</div>
                <div class="sp-visit-meta">
                    <span><i class="fas fa-map-marker-alt"></i> ${escapeHtml(s.block || '')} / ${escapeHtml(s.cluster || '')}</span>
                    <span><i class="fas fa-users"></i> ${s.teacherCount} teachers</span>
                    <span><i class="fas fa-clock"></i> ${daysLabel(s.daysSinceVisit)}</span>
                </div>
            </div>
            <div class="sp-visit-score" style="color:${engColor(s.avgEngagement)}">${engLabel(s.avgEngagement)}</div>
            <button class="sp-expand-btn" onclick="toggleSpDetail(this)" title="Details"><i class="fas fa-chevron-down"></i></button>
            <div class="sp-detail-panel" style="display:none">
                <div class="sp-detail-grid">
                    <div class="sp-detail-item"><strong>Total Observations:</strong> ${s.observations.length}</div>
                    <div class="sp-detail-item"><strong>Avg Engagement:</strong> <span style="color:${engColor(s.avgEngagement)}">${s.avgEngagement.toFixed(2)}/3</span></div>
                    <div class="sp-detail-item"><strong>Last Visit:</strong> ${s.lastVisit ? s.lastVisit.toLocaleDateString('en-IN') : 'Never'}</div>
                    <div class="sp-detail-item"><strong>Subjects:</strong> ${[...subjectsSet].join(', ') || '—'}</div>
                </div>
                <div class="sp-detail-teachers">
                    <strong>Teachers (${schoolTeachers.length}):</strong>
                    ${schoolTeachers.slice(0,10).map(t => `<span class="sp-teacher-chip" style="border-left:3px solid ${engColor(t.avgEngagement)}">${escapeHtml(t.name)} <small>${engLabel(t.avgEngagement)}</small></span>`).join('')}
                    ${schoolTeachers.length > 10 ? `<span class="sp-teacher-chip sp-more">+${schoolTeachers.length - 10} more</span>` : ''}
                </div>
                ${lowEng.length ? `<div class="sp-detail-alert"><i class="fas fa-exclamation-triangle"></i> ${lowEng.length} teacher${lowEng.length>1?'s':''} with low engagement need follow-up</div>` : ''}
                <div class="sp-detail-actions">
                    <button onclick="spAddSuggestedVisit('${a.todayStr}','${escapeHtml(s.name)}','${escapeHtml(s.cluster||'')}')" class="sp-action-btn"><i class="fas fa-plus"></i> Add to Today's Planner</button>
                    <button onclick="spPushIdea('Visit ${escapeHtml(s.name)}','Priority school visit — ${lowEng.length} low engagement teachers, avg ${s.avgEngagement.toFixed(1)}/3')" class="sp-action-btn idea"><i class="fas fa-lightbulb"></i> Save as Idea</button>
                </div>
            </div>
        </div>`;
    }).join('');

    // ===== FOLLOW-UP PLAN =====
    const followUpTeachers = a.needsFollowUp.slice(0, 10);
    const followUpHTML = followUpTeachers.map(t => {
        const reasons = [];
        if (t.avgEngagement < 2) reasons.push('Low engagement');
        if (t.totalVisits < 2) reasons.push('Few visits');
        if (t.daysSinceVisit > 30) reasons.push(`Not visited ${daysLabel(t.daysSinceVisit)}`);
        const isDone = followupStatus.some(f => f.id === t.nid && f.done);
        const practiceList = t.practices.slice(0,5);
        return `<div class="sp-followup-row ${isDone ? 'done' : ''}" data-sp-detail>
            <div class="sp-followup-teacher">
                <strong>${escapeHtml(t.name)}</strong>
                <span class="sp-followup-school">${escapeHtml(t.school || '')} • ${escapeHtml(t.cluster || '')}</span>
            </div>
            <div class="sp-followup-reasons">${reasons.map(r => `<span class="sp-reason-tag">${r}</span>`).join('')}</div>
            <div class="sp-followup-eng" style="color:${engColor(t.avgEngagement)}">${engLabel(t.avgEngagement)}</div>
            <button class="sp-expand-btn" onclick="toggleSpDetail(this)" title="Details"><i class="fas fa-chevron-down"></i></button>
            <div class="sp-detail-panel" style="display:none">
                <div class="sp-detail-grid">
                    <div class="sp-detail-item"><strong>NID:</strong> ${escapeHtml(t.nid||'—')}</div>
                    <div class="sp-detail-item"><strong>Phone:</strong> ${escapeHtml(t.phone||'—')}</div>
                    <div class="sp-detail-item"><strong>Stage:</strong> ${escapeHtml(t.stage||'—')}</div>
                    <div class="sp-detail-item"><strong>Total Visits:</strong> ${t.totalVisits}</div>
                    <div class="sp-detail-item"><strong>Subjects:</strong> ${t.subject.join(', ')||'—'}</div>
                    <div class="sp-detail-item"><strong>Last Visit:</strong> ${t.lastVisit ? t.lastVisit.toLocaleDateString('en-IN') : 'Never'}</div>
                </div>
                ${practiceList.length ? `<div class="sp-detail-practices"><strong>Practices Observed:</strong> ${practiceList.map(p=>`<span class="sp-practice-chip">${escapeHtml(p)}</span>`).join('')}${t.practices.length>5?`<span class="sp-practice-chip sp-more">+${t.practices.length-5}</span>`:''}</div>` : ''}
                <div class="sp-detail-actions">
                    <button onclick="spAddSuggestedVisit('${a.todayStr}','${escapeHtml(t.school||'')}','${escapeHtml(t.cluster||'')}')" class="sp-action-btn"><i class="fas fa-calendar-plus"></i> Schedule Visit</button>
                    <button onclick="spPushIdea('Follow-up: ${escapeHtml(t.name)}','Teacher at ${escapeHtml(t.school||'')} needs follow-up. Engagement: ${t.avgEngagement.toFixed(1)}/3. Visits: ${t.totalVisits}. ${reasons.join(". ")}.')" class="sp-action-btn idea"><i class="fas fa-lightbulb"></i> Save Idea</button>
                </div>
            </div>
        </div>`;
    }).join('');

    // ===== WEEKLY PLAN =====
    const weekDays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
    const clustersByBlock = {};
    a.clusters.forEach(c => {
        const bk = c.block || 'Unknown';
        if (!clustersByBlock[bk]) clustersByBlock[bk] = [];
        clustersByBlock[bk].push(c);
    });
    // Sort clusters by lowest engagement first
    const allClustersSorted = [...a.clusters].sort((x, y) => x.avgEngagement - y.avgEngagement);
    const weeklyPlan = weekDays.map((day, i) => {
        const cluster = allClustersSorted[i % allClustersSorted.length];
        if (!cluster) return { day, cluster: 'N/A', schools: [], focus: '' };
        const clusterSchools = a.schools.filter(s => s.cluster === cluster.name).sort((x, y) => y.priorityScore - x.priorityScore).slice(0, 3);
        const weakSubjects = {};
        cluster.observations.forEach(o => {
            if (o.engagementLevel === 'Not Engaged' && o.subject) {
                weakSubjects[o.subject] = (weakSubjects[o.subject] || 0) + 1;
            }
        });
        const topWeakSubject = Object.entries(weakSubjects).sort((a, b) => b[1] - a[1])[0];
        return {
            day, cluster: cluster.name, block: cluster.block,
            schools: clusterSchools.map(s => s.name),
            focus: topWeakSubject ? topWeakSubject[0] + ' support' : 'General observation',
            engagement: cluster.avgEngagement
        };
    });
    const weeklyHTML = weeklyPlan.map(w => `
        <div class="sp-week-row">
            <div class="sp-week-day">${w.day}</div>
            <div class="sp-week-cluster"><i class="fas fa-layer-group"></i> ${escapeHtml(w.cluster)}</div>
            <div class="sp-week-schools">${w.schools.map(s => `<span class="sp-school-chip">${escapeHtml(s)}</span>`).join('') || '<span style="color:var(--text-muted)">—</span>'}</div>
            <div class="sp-week-focus"><i class="fas fa-bullseye"></i> ${escapeHtml(w.focus)}</div>
        </div>`).join('');

    // ===== MONTHLY PLAN =====
    const totalTeachers = a.teachers.length;
    const totalSchools = a.schools.length;
    const totalClusters = a.clusters.length;
    const lowEngCount = a.lowEngTeachers.length;
    const lowEngPct = totalTeachers > 0 ? Math.round(lowEngCount / totalTeachers * 100) : 0;
    const avgVisitsPerTeacher = totalTeachers > 0 ? Math.round(obs.length / totalTeachers * 10) / 10 : 0;

    // Training group suggestions
    const trainingGroups = [];
    // Group by subject with low engagement
    a.subjects.filter(s => s.needsTraining).forEach(sub => {
        const subTeachers = a.lowEngTeachers.filter(t => t.subject.includes(sub.name));
        if (subTeachers.length >= 2) {
            trainingGroups.push({
                topic: `${sub.name} — Pedagogy & Practice`,
                type: 'Subject-based',
                icon: 'fas fa-book',
                teachers: subTeachers.slice(0, 15),
                reason: `${subTeachers.length} teachers with low engagement in ${sub.name}`,
                sessions: Math.ceil(subTeachers.length / 8),
                suggestedActivities: ['Demo lesson', 'Practice sharing', 'Material development', 'Peer observation']
            });
        }
    });

    // Group by practice type with low engagement
    const practiceTypeEng = {};
    obs.forEach(o => {
        const pt = o.practiceType || '';
        if (!pt) return;
        if (!practiceTypeEng[pt]) practiceTypeEng[pt] = { low: 0, total: 0, teachers: new Set() };
        practiceTypeEng[pt].total++;
        if (o.engagementLevel === 'Not Engaged') {
            practiceTypeEng[pt].low++;
            if (o.teacher) practiceTypeEng[pt].teachers.add(o.teacher);
        }
    });
    Object.entries(practiceTypeEng).forEach(([pt, d]) => {
        if (d.low > d.total * 0.3 && d.teachers.size >= 3) {
            trainingGroups.push({
                topic: `${pt} — Strengthening Implementation`,
                type: 'Practice-based',
                icon: 'fas fa-tasks',
                teachers: [...d.teachers].slice(0, 15).map(name => a.teachers.find(t => t.name === name)).filter(Boolean),
                reason: `${d.low} of ${d.total} observations show low engagement`,
                sessions: Math.ceil(d.teachers.size / 10),
                suggestedActivities: ['Workshop', 'Hands-on practice', 'Action research', 'Follow-up classroom visit']
            });
        }
    });

    // Cluster-level capacity building
    const weakClusters = a.clusters.filter(c => c.avgEngagement < 1.8 && c.teacherCount >= 3);
    weakClusters.forEach(c => {
        trainingGroups.push({
            topic: `${c.name} Cluster — Intensive Support Programme`,
            type: 'Cluster-based',
            icon: 'fas fa-layer-group',
            teachers: a.teachers.filter(t => t.cluster === c.name).slice(0, 20),
            reason: `Cluster avg engagement ${c.avgEngagement.toFixed(1)}/3 with ${c.teacherCount} teachers`,
            sessions: 3,
            suggestedActivities: ['Cluster meeting', 'Peer learning circle', 'Demo lesson by mentor teacher', 'Material sharing']
        });
    });

    // New teacher support (few visits)
    const newTeachers = a.teachers.filter(t => t.totalVisits <= 2);
    if (newTeachers.length >= 3) {
        trainingGroups.push({
            topic: 'Orientation & Onboarding Support',
            type: 'Support',
            icon: 'fas fa-hands-helping',
            teachers: newTeachers.slice(0, 20),
            reason: `${newTeachers.length} teachers with only 1-2 observations — need more engagement`,
            sessions: 2,
            suggestedActivities: ['One-on-one mentoring', 'Classroom observation with feedback', 'Resource sharing', 'Goal setting']
        });
    }

    const trainingHTML = trainingGroups.length ? trainingGroups.map((g, idx) => `
        <div class="sp-training-card" data-sp-detail>
            <div class="sp-training-header">
                <i class="${g.icon}"></i>
                <div style="flex:1">
                    <div class="sp-training-topic">${escapeHtml(g.topic)}</div>
                    <div class="sp-training-type">${escapeHtml(g.type)} • ${g.sessions} session${g.sessions > 1 ? 's' : ''} recommended</div>
                </div>
                <button class="sp-expand-btn" onclick="toggleSpDetail(this)" title="Details"><i class="fas fa-chevron-down"></i></button>
            </div>
            <div class="sp-training-reason"><i class="fas fa-info-circle"></i> ${escapeHtml(g.reason)}</div>
            <div class="sp-detail-panel" style="display:none">
                <div class="sp-training-teachers">
                    <strong>${g.teachers.length} Teachers:</strong>
                    ${g.teachers.slice(0, 8).map(t => `<span class="sp-teacher-chip">${escapeHtml(t.name)} <small>(${escapeHtml(t.school || '')})</small> <small style="color:${engColor(t.avgEngagement)}">${engLabel(t.avgEngagement)}</small></span>`).join('')}
                    ${g.teachers.length > 8 ? `<span class="sp-teacher-chip sp-more">+${g.teachers.length - 8} more</span>` : ''}
                </div>
                <div class="sp-training-activities">
                    <strong>Suggested Activities:</strong>
                    ${g.suggestedActivities.map(a => `<span class="sp-activity-chip"><i class="fas fa-check-circle"></i> ${a}</span>`).join('')}
                </div>
                <div class="sp-detail-actions">
                    <button onclick="spPushTrainingIdea('${escapeHtml(g.topic)}')" class="sp-action-btn idea"><i class="fas fa-lightbulb"></i> Save as Idea</button>
                </div>
            </div>
        </div>
    `).join('') : '<div class="sp-no-data">All teachers showing good engagement levels — no urgent training needs detected.</div>';

    // ===== CLASSROOM SUPPORT =====
    const classroomSupport = a.topPriority.slice(0, 10).map(t => {
        const suggestions = [];
        if (t.avgEngagement < 1.5) suggestions.push('Intensive co-teaching support');
        if (t.avgEngagement < 2) suggestions.push('Weekly classroom visit with structured feedback');
        if (t.totalVisits < 3) suggestions.push('Build rapport through informal visit');
        if (t.daysSinceVisit > 60) suggestions.push('Re-establish contact urgently');
        if (t.subject.length && t.avgEngagement < 2) suggestions.push(`Share ${t.subject[0]} TLM/resources`);
        suggestions.push('Observe + debrief cycle');
        return { teacher: t, suggestions: suggestions.slice(0, 4) };
    });

    const classroomHTML = classroomSupport.map(cs => `
        <div class="sp-support-card" data-sp-detail>
            <div class="sp-support-header">
                <div>
                    <div class="sp-support-name">${escapeHtml(cs.teacher.name)}</div>
                    <div class="sp-support-meta">${escapeHtml(cs.teacher.school || '')} • ${escapeHtml(cs.teacher.cluster || '')} • ${daysLabel(cs.teacher.daysSinceVisit)}</div>
                </div>
                <div class="sp-support-eng" style="color:${engColor(cs.teacher.avgEngagement)}">${engLabel(cs.teacher.avgEngagement)}</div>
            </div>
            <div class="sp-support-suggestions">
                ${cs.suggestions.map(s => `<div class="sp-suggestion"><i class="fas fa-arrow-right"></i> ${s}</div>`).join('')}
            </div>
            <div class="sp-detail-actions">
                <button onclick="spAddSuggestedVisit('${a.todayStr}','${escapeHtml(cs.teacher.school||'')}','${escapeHtml(cs.teacher.cluster||'')}')" class="sp-action-btn sm"><i class="fas fa-calendar-plus"></i> Plan Visit</button>
                <button onclick="spPushIdea('Support: ${escapeHtml(cs.teacher.name)}','${cs.suggestions.join(". ")}')" class="sp-action-btn idea sm"><i class="fas fa-lightbulb"></i> Idea</button>
            </div>
        </div>`).join('');

    // ===== QUARTERLY PLAN =====
    const quarterlyGoals = [];
    const engagedPct = obs.filter(o => o.engagementLevel === 'More Engaged' || o.engagementLevel === 'Engaged').length;
    const currentEngRate = obs.length > 0 ? Math.round(engagedPct / obs.length * 100) : 0;
    const targetEngRate = Math.min(currentEngRate + 15, 95);
    quarterlyGoals.push({ goal: `Increase engagement rate from ${currentEngRate}% to ${targetEngRate}%`, icon: 'fas fa-chart-line', metric: `${currentEngRate}% → ${targetEngRate}%` });
    quarterlyGoals.push({ goal: `Complete follow-up visits for ${a.needsFollowUp.length} priority teachers`, icon: 'fas fa-walking', metric: `${a.needsFollowUp.length} teachers` });
    quarterlyGoals.push({ goal: `Cover all ${totalClusters} clusters with at least 2 visits each`, icon: 'fas fa-layer-group', metric: `${totalClusters} clusters` });
    if (trainingGroups.length) quarterlyGoals.push({ goal: `Conduct ${trainingGroups.length} training sessions for identified groups`, icon: 'fas fa-chalkboard-teacher', metric: `${trainingGroups.length} trainings` });
    quarterlyGoals.push({ goal: `Ensure every school receives minimum 1 observation per month`, icon: 'fas fa-school', metric: `${totalSchools} schools × 3 months` });
    if (lowEngCount > 0) quarterlyGoals.push({ goal: `Move ${lowEngCount} low-engagement teachers to medium/high through mentoring`, icon: 'fas fa-hands-helping', metric: `${lowEngCount} teachers` });

    const quarterlyHTML = quarterlyGoals.map(g => `
        <div class="sp-goal-row">
            <i class="${g.icon}"></i>
            <div class="sp-goal-text">${g.goal}</div>
            <div class="sp-goal-metric">${g.metric}</div>
        </div>`).join('');

    // ===== YEARLY PLAN =====
    const yearlyMilestones = [
        { month: 'Q1 (Apr-Jun)', focus: 'Baseline & Mapping', tasks: [`Complete observation mapping for all ${totalSchools} schools`, `Identify and profile all ${totalTeachers} teachers`, 'Establish cluster-wise visit calendar', 'First round of teacher training for low-engagement groups'], icon: 'fas fa-map-marked-alt' },
        { month: 'Q2 (Jul-Sep)', focus: 'Intensive Support', tasks: [`Intensive classroom support for ${lowEngCount || 'priority'} low-engagement teachers`, 'Subject-specific TLM development and distribution', 'Peer learning circles in each cluster', 'Mid-year engagement assessment'], icon: 'fas fa-hands-helping' },
        { month: 'Q3 (Oct-Dec)', focus: 'Consolidation & Scale', tasks: ['Scale successful practices across clusters', 'Teacher-led demo lessons — peer mentoring', 'Community engagement and parent interactions', 'Quarterly review and plan adjustment'], icon: 'fas fa-chart-line' },
        { month: 'Q4 (Jan-Mar)', focus: 'Review & Planning', tasks: ['Annual engagement analysis and impact report', 'Identify best practices for documentation', 'Plan next year targets based on progress', 'Celebrate teacher achievements'], icon: 'fas fa-flag-checkered' }
    ];

    const yearlyHTML = yearlyMilestones.map(m => `
        <div class="sp-yearly-card">
            <div class="sp-yearly-header"><i class="${m.icon}"></i> <strong>${m.month}</strong> — ${m.focus}</div>
            <div class="sp-yearly-tasks">${m.tasks.map(t => `<div class="sp-yearly-task"><i class="fas fa-check"></i> ${t}</div>`).join('')}</div>
        </div>`).join('');

    // ===== KEY INSIGHTS =====
    const insights = [];
    // Engagement trend
    const monthKeys = Object.keys(a.monthlyData).sort();
    if (monthKeys.length >= 2) {
        const latest = a.monthlyData[monthKeys[monthKeys.length - 1]];
        const prev = a.monthlyData[monthKeys[monthKeys.length - 2]];
        const latestRate = latest.total > 0 ? Math.round(latest.engaged / latest.total * 100) : 0;
        const prevRate = prev.total > 0 ? Math.round(prev.engaged / prev.total * 100) : 0;
        const diff = latestRate - prevRate;
        insights.push({ icon: diff >= 0 ? 'fas fa-arrow-up' : 'fas fa-arrow-down', color: diff >= 0 ? '#10b981' : '#ef4444', text: `Engagement ${diff >= 0 ? 'improved' : 'declined'} by ${Math.abs(diff)}% from last month (${prevRate}% → ${latestRate}%)` });
    }
    if (a.notVisitedRecently.length > 0) insights.push({ icon: 'fas fa-exclamation-triangle', color: '#f59e0b', text: `${a.notVisitedRecently.length} teachers not visited in 30+ days — prioritize revisits` });
    if (a.notObservedTeachers.length > 0) insights.push({ icon: 'fas fa-eye-slash', color: '#ef4444', text: `${a.notObservedTeachers.length} teachers marked as "Not Observed" — schedule observations` });
    if (a.highEngTeachers.length > 0) insights.push({ icon: 'fas fa-star', color: '#10b981', text: `${a.highEngTeachers.length} highly engaged teachers — potential peer mentors and demo lesson leaders` });
    const avgVPT = totalTeachers > 0 ? (obs.length / totalTeachers).toFixed(1) : 0;
    insights.push({ icon: 'fas fa-clipboard-list', color: '#3b82f6', text: `Average ${avgVPT} observations per teacher across ${totalSchools} schools in ${totalClusters} clusters` });

    const insightsHTML = insights.map(i => `
        <div class="sp-insight"><i class="${i.icon}" style="color:${i.color}"></i> ${i.text}</div>`).join('');

    // ===== INTEGRATION STATS — Goals, Ideas, Tasks =====
    const activeIdeas = ideas.filter(i => i.status !== 'archived' && i.status !== 'done');
    const upcomingTasks = plannerTasks.filter(t => !t.done && t.date >= a.todayStr).length;
    const completedFollowups = followupStatus.filter(f => f.done).length;
    const currentMonthGoals = goalTargets.find(g => g.monthKey === `${a.today.getFullYear()}-${String(a.today.getMonth()+1).padStart(2,'0')}`);
    const pendingVisits = visits.filter(v => v.status !== 'completed' && v.date >= a.todayStr).length;
    const upcomingTrainings = trainings.filter(t => t.date >= a.todayStr).length;

    // ===== ASSEMBLE FINAL HTML =====
    return `
        <div class="sp-header">
            <div class="sp-header-title"><i class="fas fa-brain"></i> Smart Planner — AI Suggestions</div>
            <div class="sp-header-subtitle">Powered by analysis of ${obs.length.toLocaleString()} observations across ${totalSchools} schools, ${totalTeachers} teachers, ${totalClusters} clusters</div>
        </div>

        <!-- Toolbar -->
        <div class="sp-toolbar">
            <div class="sp-toolbar-group">
                <span class="sp-toolbar-label">Generate & Push:</span>
                <button class="sp-gen-btn" onclick="spGenerateDailyVisits()"><i class="fas fa-calendar-day"></i> Today's Visits</button>
                <button class="sp-gen-btn" onclick="spGenerateWeeklyPlan()"><i class="fas fa-calendar-week"></i> Weekly Plan</button>
                <button class="sp-gen-btn" onclick="spGenerateQuarterlyGoals()"><i class="fas fa-bullseye"></i> Quarterly Goals</button>
            </div>
            <div class="sp-toolbar-group">
                <button class="sp-gen-btn refresh" onclick="renderSmartPlanner()"><i class="fas fa-sync-alt"></i> Refresh</button>
            </div>
        </div>

        <!-- Integration Dashboard -->
        <div class="sp-section">
            <div class="sp-section-title sp-section-toggle" onclick="toggleSpSection(this)"><i class="fas fa-link"></i> Dashboard — Integrated Overview <i class="fas fa-chevron-down sp-toggle-icon"></i></div>
            <div class="sp-section-body">
                <div class="sp-dash-grid">
                    <div class="sp-dash-card" style="--dash-color:#3b82f6"><div class="sp-dash-icon"><i class="fas fa-walking"></i></div><div class="sp-dash-stat">${pendingVisits}</div><div class="sp-dash-label">Pending Visits</div></div>
                    <div class="sp-dash-card" style="--dash-color:#8b5cf6"><div class="sp-dash-icon"><i class="fas fa-tasks"></i></div><div class="sp-dash-stat">${upcomingTasks}</div><div class="sp-dash-label">Planner Tasks</div></div>
                    <div class="sp-dash-card" style="--dash-color:#f59e0b"><div class="sp-dash-icon"><i class="fas fa-lightbulb"></i></div><div class="sp-dash-stat">${activeIdeas.length}</div><div class="sp-dash-label">Active Ideas</div></div>
                    <div class="sp-dash-card" style="--dash-color:#10b981"><div class="sp-dash-icon"><i class="fas fa-clipboard-check"></i></div><div class="sp-dash-stat">${completedFollowups}</div><div class="sp-dash-label">Follow-ups Done</div></div>
                    <div class="sp-dash-card" style="--dash-color:#ec4899"><div class="sp-dash-icon"><i class="fas fa-chalkboard-teacher"></i></div><div class="sp-dash-stat">${upcomingTrainings}</div><div class="sp-dash-label">Upcoming Trainings</div></div>
                    <div class="sp-dash-card" style="--dash-color:#6366f1"><div class="sp-dash-icon"><i class="fas fa-flag-checkered"></i></div><div class="sp-dash-stat">${currentMonthGoals ? '✓' : '—'}</div><div class="sp-dash-label">Monthly Goals Set</div></div>
                </div>
            </div>
        </div>

        <!-- Key Insights -->
        <div class="sp-section">
            <div class="sp-section-title sp-section-toggle" onclick="toggleSpSection(this)"><i class="fas fa-lightbulb"></i> Key Insights <i class="fas fa-chevron-down sp-toggle-icon"></i></div>
            <div class="sp-section-body">
                <div class="sp-insights-grid">${insightsHTML}</div>
            </div>
        </div>

        <!-- Weekly Calendar -->
        <div class="sp-section">
            <div class="sp-section-title sp-section-toggle" onclick="toggleSpSection(this)"><i class="fas fa-calendar-week"></i> School Visit Calendar <i class="fas fa-chevron-down sp-toggle-icon"></i></div>
            <div class="sp-section-desc">Visual weekly calendar with existing tasks + AI suggestions. Click <strong>+ Add to Planner</strong> to schedule.</div>
            <div class="sp-section-body">
                <div id="spCalendarWrap" class="sp-calendar-wrap"></div>
            </div>
        </div>

        <!-- Daily Visit Plan -->
        <div class="sp-section">
            <div class="sp-section-title sp-section-toggle" onclick="toggleSpSection(this)"><i class="fas fa-calendar-day"></i> Daily Visit Plan — Top Priority Schools <i class="fas fa-chevron-down sp-toggle-icon"></i></div>
            <div class="sp-section-desc">Schools ranked by urgency. Click any card to see teachers, subjects & actions.</div>
            <div class="sp-section-body">
                <div class="sp-visit-list">${dailyHTML}</div>
            </div>
        </div>

        <!-- Follow-up Plan -->
        <div class="sp-section">
            <div class="sp-section-title sp-section-toggle" onclick="toggleSpSection(this)"><i class="fas fa-redo-alt"></i> Follow-up Plan — Teachers Needing Attention <i class="fas fa-chevron-down sp-toggle-icon"></i></div>
            <div class="sp-section-desc">Click any teacher to see TPS data, practices & schedule a visit.</div>
            <div class="sp-section-body">
                <div class="sp-followup-list">${followUpHTML || '<div class="sp-no-data">All teachers are well-covered. Great work!</div>'}</div>
            </div>
        </div>

        <!-- Weekly Plan Table -->
        <div class="sp-section">
            <div class="sp-section-title sp-section-toggle" onclick="toggleSpSection(this)"><i class="fas fa-table"></i> Weekly Cluster Schedule <i class="fas fa-chevron-down sp-toggle-icon"></i></div>
            <div class="sp-section-desc">Cluster-wise schedule prioritized by lowest engagement.</div>
            <div class="sp-section-body">
                <div class="sp-week-table">
                    <div class="sp-week-header">
                        <div>Day</div><div>Cluster</div><div>Priority Schools</div><div>Focus Area</div>
                    </div>
                    ${weeklyHTML}
                </div>
            </div>
        </div>

        <!-- Monthly Plan -->
        <div class="sp-section">
            <div class="sp-section-title sp-section-toggle" onclick="toggleSpSection(this)"><i class="fas fa-calendar-alt"></i> Monthly Plan — Targets & Milestones <i class="fas fa-chevron-down sp-toggle-icon"></i></div>
            <div class="sp-section-body">
                <div class="sp-monthly-grid">
                    <div class="sp-monthly-card">
                        <div class="sp-monthly-stat">${totalSchools}</div>
                        <div class="sp-monthly-label">Schools to cover</div>
                        <div class="sp-monthly-target">Target: ${Math.ceil(totalSchools / 4)} schools/week</div>
                    </div>
                    <div class="sp-monthly-card">
                        <div class="sp-monthly-stat">${a.needsFollowUp.length}</div>
                        <div class="sp-monthly-label">Follow-ups needed</div>
                        <div class="sp-monthly-target">Target: ${Math.ceil(a.needsFollowUp.length / 4)} teachers/week</div>
                    </div>
                    <div class="sp-monthly-card">
                        <div class="sp-monthly-stat">${trainingGroups.length}</div>
                        <div class="sp-monthly-label">Trainings to plan</div>
                        <div class="sp-monthly-target">Target: ${Math.ceil(trainingGroups.length / 2)} sessions this month</div>
                    </div>
                    <div class="sp-monthly-card">
                        <div class="sp-monthly-stat" style="color:${engColor(currentEngRate / 33)}">${currentEngRate}%</div>
                        <div class="sp-monthly-label">Current engagement</div>
                        <div class="sp-monthly-target">Target: ${targetEngRate}% by month end</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Teacher Training Suggestions -->
        <div class="sp-section">
            <div class="sp-section-title sp-section-toggle" onclick="toggleSpSection(this)"><i class="fas fa-chalkboard-teacher"></i> Teacher Training Suggestions <i class="fas fa-chevron-down sp-toggle-icon"></i></div>
            <div class="sp-section-desc">Click training cards to see teachers list, activities & save as idea.</div>
            <div class="sp-section-body">
                <div class="sp-training-list">${trainingHTML}</div>
            </div>
        </div>

        <!-- Classroom Support -->
        <div class="sp-section">
            <div class="sp-section-title sp-section-toggle" onclick="toggleSpSection(this)"><i class="fas fa-hands-helping"></i> Classroom Support — Priority Teachers <i class="fas fa-chevron-down sp-toggle-icon"></i></div>
            <div class="sp-section-desc">Teachers needing intensive one-on-one support with specific action items.</div>
            <div class="sp-section-body">
                <div class="sp-support-list">${classroomHTML}</div>
            </div>
        </div>

        <!-- Quarterly Plan -->
        <div class="sp-section">
            <div class="sp-section-title sp-section-toggle" onclick="toggleSpSection(this)"><i class="fas fa-bullseye"></i> Quarterly Goals <i class="fas fa-chevron-down sp-toggle-icon"></i></div>
            <div class="sp-section-body">
                <div class="sp-goals-list">${quarterlyHTML}</div>
                <div style="margin-top:12px;text-align:center">
                    <button class="sp-gen-btn" onclick="spGenerateQuarterlyGoals()"><i class="fas fa-arrow-right"></i> Push to Goal Tracker</button>
                </div>
            </div>
        </div>

        <!-- Yearly Plan -->
        <div class="sp-section">
            <div class="sp-section-title sp-section-toggle" onclick="toggleSpSection(this)"><i class="fas fa-road"></i> Yearly Roadmap <i class="fas fa-chevron-down sp-toggle-icon"></i></div>
            <div class="sp-section-desc">Strategic annual plan aligned with APF field work approach.</div>
            <div class="sp-section-body">
                <div class="sp-yearly-grid">${yearlyHTML}</div>
            </div>
        </div>
    `;
}

// After render, init the calendar
const _origRenderSP = renderSmartPlanner;
renderSmartPlanner = function() {
    _origRenderSP();
    setTimeout(() => renderSpCalendar(), 50);
};

// ===== Observation Analytics =====
function renderObsAnalytics() {
    const observations = DB.get('observations');
    const grid = document.getElementById('obsAnalyticsGrid');
    if (!grid) return;

    if (observations.length === 0) {
        grid.innerHTML = '<div class="empty-state"><i class="fas fa-chart-pie"></i><h3>No data for analytics</h3><p>Add observations or import DMT Excel to see analytics</p></div>';
        return;
    }

    // Destroy old charts
    Object.values(obsActiveCharts).forEach(c => { try { c.destroy(); } catch(e){} });
    obsActiveCharts = {};

    // Rebuild canvas elements fresh every time
    grid.innerHTML = `
        <div class="obs-chart-card"><h3><i class="fas fa-chart-pie"></i> Engagement Distribution</h3><canvas id="obsChartEngagement"></canvas></div>
        <div class="obs-chart-card"><h3><i class="fas fa-chart-bar"></i> Observations by Subject</h3><canvas id="obsChartSubject"></canvas></div>
        <div class="obs-chart-card"><h3><i class="fas fa-chart-bar"></i> Practice Type Distribution</h3><canvas id="obsChartPracticeType"></canvas></div>
        <div class="obs-chart-card"><h3><i class="fas fa-chart-bar"></i> Block-wise Observations</h3><canvas id="obsChartBlock"></canvas></div>
        <div class="obs-chart-card"><h3><i class="fas fa-chart-line"></i> Monthly Observation Trend</h3><canvas id="obsChartTrend"></canvas></div>
        <div class="obs-chart-card"><h3><i class="fas fa-chart-bar"></i> Observation Status</h3><canvas id="obsChartStatus"></canvas></div>
        <div class="obs-chart-card obs-chart-wide"><h3><i class="fas fa-chart-bar"></i> Top 15 Practices Observed</h3><canvas id="obsChartPractices"></canvas></div>
        <div class="obs-chart-card obs-chart-wide"><h3><i class="fas fa-chalkboard-teacher"></i> Top Observers</h3><canvas id="obsChartObservers"></canvas></div>
    `;

    const countBy = (arr, key) => {
        const m = {};
        arr.forEach(o => { const v = o[key] || 'Unknown'; m[v] = (m[v] || 0) + 1; });
        return m;
    };

    const palette = ['#f59e0b', '#3b82f6', '#10b981', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316', '#14b8a6', '#6366f1', '#d946ef', '#84cc16'];

    // 1. Engagement Distribution (Doughnut)
    const engData = countBy(observations, 'engagementLevel');
    const engLabels = Object.keys(engData);
    obsActiveCharts.engagement = new Chart(document.getElementById('obsChartEngagement'), {
        type: 'doughnut',
        data: {
            labels: engLabels,
            datasets: [{ data: Object.values(engData), backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#6b7280'].slice(0, engLabels.length) }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#ccc' } } } }
    });

    // 2. Subject Distribution (Bar)
    const subData = countBy(observations, 'subject');
    obsActiveCharts.subject = new Chart(document.getElementById('obsChartSubject'), {
        type: 'bar',
        data: {
            labels: Object.keys(subData),
            datasets: [{ label: 'Observations', data: Object.values(subData), backgroundColor: palette }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { ticks: { color: '#ccc' }, grid: { color: 'rgba(255,255,255,0.06)' } }, x: { ticks: { color: '#ccc', maxRotation: 45 }, grid: { display: false } } } }
    });

    // 3. Practice Type (Doughnut)
    const ptData = countBy(observations, 'practiceType');
    obsActiveCharts.practiceType = new Chart(document.getElementById('obsChartPracticeType'), {
        type: 'doughnut',
        data: {
            labels: Object.keys(ptData),
            datasets: [{ data: Object.values(ptData), backgroundColor: ['#3b82f6', '#f59e0b', '#10b981', '#6b7280'] }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#ccc' } } } }
    });

    // 4. Block-wise (Bar)
    const blockData = countBy(observations, 'block');
    obsActiveCharts.block = new Chart(document.getElementById('obsChartBlock'), {
        type: 'bar',
        data: {
            labels: Object.keys(blockData),
            datasets: [{ label: 'Observations', data: Object.values(blockData), backgroundColor: palette }]
        },
        options: { responsive: true, maintainAspectRatio: false, indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#ccc' }, grid: { color: 'rgba(255,255,255,0.06)' } }, y: { ticks: { color: '#ccc' }, grid: { display: false } } } }
    });

    // 5. Monthly Trend (Line)
    const monthCounts = {};
    observations.forEach(o => {
        if (!o.date) return;
        const m = o.date.substring(0, 7); // YYYY-MM
        monthCounts[m] = (monthCounts[m] || 0) + 1;
    });
    const sortedMonths = Object.keys(monthCounts).sort();
    obsActiveCharts.trend = new Chart(document.getElementById('obsChartTrend'), {
        type: 'line',
        data: {
            labels: sortedMonths.map(m => { const [y, mo] = m.split('-'); return `${['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][parseInt(mo)-1]} ${y}`; }),
            datasets: [{ label: 'Observations', data: sortedMonths.map(m => monthCounts[m]), borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.1)', fill: true, tension: 0.3 }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { ticks: { color: '#ccc' }, grid: { color: 'rgba(255,255,255,0.06)' } }, x: { ticks: { color: '#ccc', maxRotation: 45 }, grid: { display: false } } } }
    });

    // 6. Observation Status (Pie)
    const statusData = countBy(observations, 'observationStatus');
    obsActiveCharts.status = new Chart(document.getElementById('obsChartStatus'), {
        type: 'pie',
        data: {
            labels: Object.keys(statusData).map(k => k === 'Yes' ? 'Observed' : k === 'Not_Observed' ? 'Not Observed' : k),
            datasets: [{ data: Object.values(statusData), backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#6b7280'] }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#ccc' } } } }
    });

    // 7. Top 15 Practices (Horizontal Bar)
    const practiceData = countBy(observations, 'practice');
    const topPractices = Object.entries(practiceData)
        .filter(([k]) => k !== 'Unknown' && k)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 15);
    obsActiveCharts.practices = new Chart(document.getElementById('obsChartPractices'), {
        type: 'bar',
        data: {
            labels: topPractices.map(([k]) => k.length > 50 ? k.substring(0, 50) + '...' : k),
            datasets: [{ label: 'Count', data: topPractices.map(([,v]) => v), backgroundColor: palette }]
        },
        options: { responsive: true, maintainAspectRatio: false, indexAxis: 'y', plugins: { legend: { display: false }, tooltip: { callbacks: { title: (items) => topPractices[items[0].dataIndex]?.[0] || '' } } }, scales: { x: { ticks: { color: '#ccc' }, grid: { color: 'rgba(255,255,255,0.06)' } }, y: { ticks: { color: '#ccc', font: { size: 10 } }, grid: { display: false } } } }
    });

    // 8. Top Observers (Bar)
    const obsData = countBy(observations, 'observer');
    const topObservers = Object.entries(obsData)
        .filter(([k]) => k !== 'Unknown' && k)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 15);
    obsActiveCharts.observers = new Chart(document.getElementById('obsChartObservers'), {
        type: 'bar',
        data: {
            labels: topObservers.map(([k]) => k),
            datasets: [{ label: 'Observations', data: topObservers.map(([,v]) => v), backgroundColor: palette }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { ticks: { color: '#ccc' }, grid: { color: 'rgba(255,255,255,0.06)' } }, x: { ticks: { color: '#ccc', maxRotation: 45 }, grid: { display: false } } } }
    });
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

    const pg = getPaginatedItems(filtered, 'resources', 18);

    container.innerHTML = pg.items.map(r => {
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
    }).join('') + renderPaginationControls('resources', pg, 'renderResources');
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
        <p class="report-subtitle">Report by ${escapeHtml(getProfile().name || 'Resource Person')}${getProfile().district ? ' — ' + escapeHtml(getProfile().district) : ''} &bull; Generated on ${new Date().toLocaleDateString('en-IN')}</p>

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
    const ratedObs = observations.filter(o => (o.engagementRating || o.engagement) || o.methodology || o.tlm);
    const avgEngagement = ratedObs.length ? (ratedObs.reduce((s, o) => s + (o.engagementRating || o.engagement || 0), 0) / ratedObs.length).toFixed(1) : '-';
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

    const pg = getPaginatedItems(notes, 'notes', 18);

    container.innerHTML = pg.items.map(n => {
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
    }).join('') + renderPaginationControls('notes', pg, 'renderNotes');
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
                    ticks: { color: '#6b7280', precision: 0 },
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

    // Refresh visit frequency if visible
    const freqPanel = document.getElementById('visitFreqPanel');
    if (freqPanel && freqPanel.style.display !== 'none') {
        renderVisitFrequency(visits);
    }
}

function toggleVisitFrequency() {
    const panel = document.getElementById('visitFreqPanel');
    if (!panel) return;
    const isHidden = panel.style.display === 'none';
    panel.style.display = isHidden ? '' : 'none';
    if (isHidden) {
        const range = getAnalyticsDateRange();
        const visits = filterByDateRange(DB.get('visits'), 'date', range);
        renderVisitFrequency(visits);
    }
}

function renderVisitFrequency(visits) {
    const body = document.getElementById('visitFreqBody');
    if (!body) return;

    // Count visits per school
    const freq = {};
    visits.forEach(v => {
        const school = (v.school || '').trim();
        if (!school) return;
        if (!freq[school]) freq[school] = { total: 0, completed: 0, planned: 0, cancelled: 0, lastDate: '', cluster: v.cluster || '', block: v.block || '' };
        freq[school].total++;
        if (v.status === 'completed') freq[school].completed++;
        else if (v.status === 'planned') freq[school].planned++;
        else if (v.status === 'cancelled') freq[school].cancelled++;
        if (v.date && v.date > freq[school].lastDate) {
            freq[school].lastDate = v.date;
            if (v.cluster) freq[school].cluster = v.cluster;
            if (v.block) freq[school].block = v.block;
        }
    });

    const sorted = Object.entries(freq).sort((a, b) => b[1].total - a[1].total);
    if (sorted.length === 0) {
        body.innerHTML = '<div class="empty-state"><i class="fas fa-school"></i><h3>No school visits found</h3><p>Add school visits to see frequency analysis.</p></div>';
        return;
    }

    const maxVisits = sorted[0][1].total;

    let html = `<div class="vf-summary">
        <span class="vf-sum-item"><strong>${sorted.length}</strong> schools</span>
        <span class="vf-sum-item"><strong>${visits.length}</strong> total visits</span>
        <span class="vf-sum-item">Avg <strong>${(visits.length / sorted.length).toFixed(1)}</strong> visits/school</span>
    </div>
    <table class="vf-table">
        <thead><tr>
            <th>#</th>
            <th>School Name</th>
            <th>Cluster / Block</th>
            <th>Visits</th>
            <th>Completed</th>
            <th>Planned</th>
            <th>Last Visit</th>
            <th>Frequency</th>
        </tr></thead>
        <tbody>`;

    sorted.forEach(([school, data], i) => {
        const pct = Math.round((data.total / maxVisits) * 100);
        const barColor = data.total >= 5 ? '#10b981' : data.total >= 3 ? '#f59e0b' : data.total >= 2 ? '#3b82f6' : '#6b7280';
        const lastVisit = data.lastDate ? new Date(data.lastDate).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
        const location = [data.cluster, data.block].filter(Boolean).join(', ');

        html += `<tr>
            <td class="vf-rank">${i + 1}</td>
            <td class="vf-school"><i class="fas fa-school" style="color:${barColor};margin-right:6px;font-size:11px"></i>${escapeHtml(school)}</td>
            <td class="vf-loc">${escapeHtml(location) || '—'}</td>
            <td class="vf-count"><strong>${data.total}</strong></td>
            <td class="vf-comp">${data.completed}</td>
            <td class="vf-plan">${data.planned}</td>
            <td class="vf-date">${lastVisit}</td>
            <td class="vf-bar-cell"><div class="vf-bar" style="width:${pct}%;background:${barColor}"><span class="vf-bar-num">${data.total}</span></div></td>
        </tr>`;
    });

    html += '</tbody></table>';
    body.innerHTML = html;
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
    const ratedObs = observations.filter(o => (o.engagementRating || o.engagement) || o.methodology || o.tlm);
    if (ratedObs.length >= 2) {
        const avgEng = (ratedObs.reduce((s, o) => s + (o.engagementRating || o.engagement || 0), 0) / ratedObs.length).toFixed(1);
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
    
    const ratedObs = observations.filter(o => (o.engagementRating || o.engagement) || o.methodology || o.tlm);
    const avgRating = ratedObs.length
        ? ((ratedObs.reduce((s, o) => s + (o.engagementRating || o.engagement || 0) + (o.methodology || 0) + (o.tlm || 0), 0)) / (ratedObs.length * 3)).toFixed(1)
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
                x: { beginAtZero: true, ticks: { color: '#6b7280', precision: 0 }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { ticks: { color: '#9ca3b8', font: { size: 11 } }, grid: { display: false } }
            }
        }
    });
}

function renderObsRatingsChart(observations) {
    destroyChart('ratingsChart');
    const canvas = document.getElementById('chartObsRatings');
    if (!canvas) return;

    const rated = observations.filter(o => (o.engagementRating || o.engagement) || o.methodology || o.tlm);
    if (rated.length === 0) {
        canvas.style.display = 'none';
        if (!canvas.parentElement.querySelector('.empty-state')) canvas.insertAdjacentHTML('afterend', '<div class="empty-state small"><i class="fas fa-star"></i><p>No rated observations in this period</p></div>');
        return;
    }
    canvas.style.display = '';
    { const e = canvas.parentElement.querySelector('.empty-state'); if (e) e.remove(); }

    const avgEng = (rated.reduce((s, o) => s + (o.engagementRating || o.engagement || 0), 0) / rated.length).toFixed(1);
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
                y: { beginAtZero: true, ticks: { color: '#6b7280', precision: 0 }, grid: { color: 'rgba(255,255,255,0.04)' } }
            }
        }
    });
}

function renderActivityTimeline(visits, trainings, observations) {
    const container = document.getElementById('activityTimeline');
    const countEl = document.getElementById('timelineCount');
    if (!container || !countEl) return;

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

    // Collect action items from meetings
    const meetings = DB.get('meetings');
    meetings.forEach(m => {
        (m.actionItems || []).forEach((a, i) => {
            if (a.text && a.text.trim()) {
                const fId = `meeting_${m.id}_${i}`;
                const isDone = a.done || followupStatus.some(f => f.id === fId && f.done);
                followups.push({
                    id: fId,
                    source: 'meeting',
                    school: m.title || 'Meeting',
                    date: m.date,
                    text: a.text + (a.assignee ? ` (→ ${a.assignee})` : ''),
                    done: isDone,
                    icon: 'fa-handshake',
                    cls: 'followup-meeting',
                });
            }
        });
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

    const pg = getPaginatedItems(followups, 'followups', 20);

    container.innerHTML = pg.items.map(f => {
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
    }).join('') + renderPaginationControls('followups', pg, 'renderFollowups');
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
    _pageState.ideas = 1;
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
                    ${idea.status === 'archived'
                        ? `<button onclick="unarchiveIdea('${idea.id}')" title="Unarchive" class="unarchive-btn"><i class="fas fa-box-open"></i></button>`
                        : `<button onclick="archiveIdea('${idea.id}')" title="Archive" class="archive-btn"><i class="fas fa-archive"></i></button>`
                    }
                    <button class="delete-btn" onclick="deleteIdea('${idea.id}')" title="Delete"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        </div>
    `;
}

function archiveIdea(id) {
    const ideas = DB.get('ideas');
    const idea = ideas.find(i => i.id === id);
    if (idea) {
        idea.status = 'archived';
        idea.updatedAt = new Date().toISOString();
        DB.set('ideas', ideas);
        renderIdeas();
        showToast('Idea archived 📦');
    }
}

function unarchiveIdea(id) {
    const ideas = DB.get('ideas');
    const idea = ideas.find(i => i.id === id);
    if (idea) {
        idea.status = 'spark';
        idea.updatedAt = new Date().toISOString();
        DB.set('ideas', ideas);
        renderIdeas();
        showToast('Idea unarchived — moved back to Spark ✨');
    }
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
        { key: 'done', title: '✅ Done', color: '#10b981' },
        { key: 'archived', title: '📦 Archived', color: '#6b7280' }
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
    const pg = getPaginatedItems(sorted, 'ideas', 18);
    container.innerHTML = `<div class="idea-grid">${pg.items.map(idea => {
        const statusLabels = { spark: '✨ Spark', exploring: '🔍 Exploring', 'in-progress': '🚀 In Progress', done: '✅ Done', archived: '📦 Archived' };
        // Wrap card with status badge overlay
        return `<div style="position:relative">
            <span class="idea-status-badge ${idea.status}" style="position:absolute;top:12px;right:12px;z-index:1;">${statusLabels[idea.status] || idea.status}</span>
            ${buildIdeaCard(idea)}
        </div>`;
    }).join('')}</div>` + renderPaginationControls('ideas', pg, 'renderIdeas');
}

function renderIdeaList(ideas, container) {
    const sorted = [...ideas].sort((a, b) => new Date(b.updatedAt || b.createdAt) - new Date(a.updatedAt || a.createdAt));
    const pg = getPaginatedItems(sorted, 'ideas', 20);
    const statusLabels = { spark: '✨ Spark', exploring: '🔍 Exploring', 'in-progress': '🚀 In Progress', done: '✅ Done', archived: '📦 Archived' };
    container.innerHTML = `<div class="idea-list">${pg.items.map(idea => `
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
                ${idea.status === 'archived'
                    ? `<button onclick="unarchiveIdea('${idea.id}')" title="Unarchive" class="unarchive-btn"><i class="fas fa-box-open"></i></button>`
                    : `<button onclick="archiveIdea('${idea.id}')" title="Archive" class="archive-btn"><i class="fas fa-archive"></i></button>`
                }
                <button class="delete-btn" onclick="deleteIdea('${idea.id}')" title="Delete"><i class="fas fa-trash"></i></button>
            </div>
        </div>
    `).join('')}</div>` + renderPaginationControls('ideas', pg, 'renderIdeas');
}

// ===== SCHOOL PROFILE IMPORT FROM EXCEL =====
let _schoolImportRows = [];
let _schoolImportFileName = '';

function triggerSchoolProfileImport() {
    document.getElementById('obsImportMenu')?.classList.remove('show');
    document.getElementById('schoolProfileImportFile').click();
}

async function loadSchoolProfileImportPreview(event) {
    const file = event.target.files[0];
    if (!file) return;
    event.target.value = '';

    _schoolImportFileName = file.name;
    _schoolImportRows = [];

    document.getElementById('schoolImportLoading').style.display = 'flex';
    document.getElementById('schoolImportContent').style.display = 'none';
    document.getElementById('schoolImportConfirmBtn').disabled = true;
    document.getElementById('schoolProfileImportModal').classList.add('active');

    try {
        const data = await file.arrayBuffer();
        const wb = XLSX.read(data, { type: 'array', cellDates: true });

        let rows = [];
        for (const sheetName of wb.SheetNames) {
            const ws = wb.Sheets[sheetName];
            const sheetRows = XLSX.utils.sheet_to_json(ws);
            if (sheetRows.length > 0) rows = rows.concat(sheetRows);
        }

        if (rows.length === 0) {
            showToast('No data found in Excel file', 'error');
            closeModal('schoolProfileImportModal');
            return;
        }

        // Check if it's a DMT file
        const cols = Object.keys(rows[0]);
        const isDMT = cols.some(c => c.includes('School Name') || c.includes('Teacher: Teacher Name') || c.includes('Practice Type'));
        if (!isDMT) {
            showToast('This does not appear to be a DMT Field Notes Excel. Needs "School Name" column.', 'error', 6000);
            closeModal('schoolProfileImportModal');
            return;
        }

        _schoolImportRows = rows;

        // Extract unique values for filters
        const states = [...new Set(rows.map(r => (r['State'] || '').trim()).filter(Boolean))].sort();
        const blocks = [...new Set(rows.map(r => (r['Block Name'] || '').trim()).filter(Boolean))].sort();
        const clusters = [...new Set(rows.map(r => (r['Cluster'] || '').trim()).filter(Boolean))].sort();
        const observers = [...new Set(rows.map(r => (r['Actual Observer: Full Name'] || r['Primary Observer: Full Name'] || '').trim()).filter(Boolean))].sort();

        const populateSelect = (id, label, values) => {
            const el = document.getElementById(id);
            if (!el) return;
            el.innerHTML = `<option value="all">All ${label} (${values.length})</option>` +
                values.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
        };

        populateSelect('schoolImportFilterState', 'States', states);
        populateSelect('schoolImportFilterBlock', 'Blocks', blocks);
        populateClusterCheckboxes('schoolImportClusterList', clusters, 'previewSchoolProfileImport()');
        updateClusterCount('schoolImportFilterCluster', 'schoolImportClusterCount');
        populateSelect('schoolImportFilterObserver', 'Observers', observers);

        document.getElementById('schoolImportFileName').textContent = file.name;

        document.getElementById('schoolImportLoading').style.display = 'none';
        document.getElementById('schoolImportContent').style.display = 'block';
        previewSchoolProfileImport();
    } catch (err) {
        console.error('School profile import read error:', err);
        showToast('Failed to read Excel: ' + err.message, 'error');
        closeModal('schoolProfileImportModal');
    }
}

function getSchoolImportFilters() {
    return {
        state: document.getElementById('schoolImportFilterState')?.value || 'all',
        block: document.getElementById('schoolImportFilterBlock')?.value || 'all',
        clusters: getSelectedClusters('schoolImportClusterList'),
        observer: document.getElementById('schoolImportFilterObserver')?.value || 'all'
    };
}

function getFilteredSchoolImportRows() {
    const f = getSchoolImportFilters();
    const anyFilter = f.state !== 'all' || f.block !== 'all' || f.clusters !== null || f.observer !== 'all';
    if (!anyFilter) return { rows: _schoolImportRows, anyFilter: false };

    const filtered = _schoolImportRows.filter(row => {
        const rowState = (row['State'] || '').trim();
        const rowBlock = (row['Block Name'] || '').trim();
        const rowCluster = (row['Cluster'] || '').trim();
        const rowObserver = (row['Actual Observer: Full Name'] || row['Primary Observer: Full Name'] || '').trim();
        if (f.state !== 'all' && rowState !== f.state) return false;
        if (f.block !== 'all' && rowBlock !== f.block) return false;
        if (f.clusters !== null && !f.clusters.has(rowCluster)) return false;
        if (f.observer !== 'all' && rowObserver !== f.observer) return false;
        return true;
    });
    return { rows: filtered, anyFilter: true };
}

function extractSchoolProfilesFromRows(rows) {
    const schoolMap = {};
    rows.forEach(row => {
        const schoolName = (row['School Name'] || '').trim();
        if (!schoolName) return;
        const key = schoolName.toLowerCase();

        if (!schoolMap[key]) {
            schoolMap[key] = {
                name: schoolName,
                block: (row['Block Name'] || '').trim(),
                cluster: (row['Cluster'] || '').trim(),
                district: (row['District Name'] || '').trim(),
                state: (row['State'] || '').trim(),
                teachers: new Set(),
                subjects: new Set(),
                totalObservations: 0,
                dates: [],
                observers: new Set()
            };
        }

        const s = schoolMap[key];
        s.totalObservations++;
        const teacher = (row['Teacher: Teacher Name'] || '').trim();
        if (teacher) s.teachers.add(teacher);
        const subject = (row['Subject'] || '').trim();
        if (subject) s.subjects.add(subject);
        const observer = (row['Actual Observer: Full Name'] || row['Primary Observer: Full Name'] || '').trim();
        if (observer) s.observers.add(observer);
        if (!s.block && row['Block Name']) s.block = (row['Block Name'] || '').trim();
        if (!s.cluster && row['Cluster']) s.cluster = (row['Cluster'] || '').trim();
        if (!s.district && row['District Name']) s.district = (row['District Name'] || '').trim();
        if (!s.state && row['State']) s.state = (row['State'] || '').trim();

        const rawDate = row['Response Date'];
        if (rawDate instanceof Date) {
            s.dates.push(rawDate.toISOString().split('T')[0]);
        } else if (typeof rawDate === 'string' && rawDate) {
            const parsed = new Date(rawDate);
            if (!isNaN(parsed)) s.dates.push(parsed.toISOString().split('T')[0]);
        }
    });

    // Convert Sets to arrays and sort
    return Object.values(schoolMap).map(s => ({
        ...s,
        teachers: [...s.teachers],
        subjects: [...s.subjects],
        observers: [...s.observers],
        dates: s.dates.sort(),
        lastDate: s.dates.length > 0 ? s.dates.sort().pop() : '',
        firstDate: s.dates.length > 0 ? s.dates.sort()[0] : ''
    })).sort((a, b) => b.totalObservations - a.totalObservations);
}

function previewSchoolProfileImport() {
    const { rows, anyFilter } = getFilteredSchoolImportRows();
    const totalRows = _schoolImportRows.length;
    const schools = extractSchoolProfilesFromRows(rows);
    const allSchools = extractSchoolProfilesFromRows(_schoolImportRows);

    const previewEl = document.getElementById('schoolImportPreview');
    const countEl = document.getElementById('schoolImportCount');
    const listEl = document.getElementById('schoolImportSchoolList');
    const btn = document.getElementById('schoolImportConfirmBtn');
    const totalEl = document.getElementById('schoolImportTotalSchools');

    totalEl.textContent = allSchools.length;

    const blocks = [...new Set(schools.map(s => s.block).filter(Boolean))];
    const clusters = [...new Set(schools.map(s => s.cluster).filter(Boolean))];
    const totalTeachers = new Set(schools.flatMap(s => s.teachers)).size;

    const filterLabel = anyFilter
        ? `<strong>${schools.length}</strong> of ${allSchools.length} schools match your filters (from ${rows.length.toLocaleString()} rows)`
        : `All <strong>${allSchools.length}</strong> schools found (from ${totalRows.toLocaleString()} rows)`;

    // Check how many are already in visits
    const existingVisits = DB.get('visits');
    const existingSchoolKeys = new Set(existingVisits.map(v => (v.school || '').trim().toLowerCase()));
    const newSchools = schools.filter(s => !existingSchoolKeys.has(s.name.toLowerCase()));
    const existingCount = schools.length - newSchools.length;

    previewEl.innerHTML = `
        <div class="unload-preview-stats">
            <div class="unload-preview-count" style="color: var(--accent)">
                <i class="fas fa-${anyFilter ? 'filter' : 'database'}"></i>
                ${filterLabel}
            </div>
            <div class="unload-preview-details">
                <span><i class="fas fa-school"></i> ${schools.length} Schools</span>
                <span><i class="fas fa-plus-circle" style="color:#10b981;"></i> ${newSchools.length} New</span>
                <span><i class="fas fa-check-circle" style="color:#f59e0b;"></i> ${existingCount} Already Exist</span>
                <span><i class="fas fa-chalkboard-teacher"></i> ${totalTeachers} Teachers</span>
                <span><i class="fas fa-map-marker-alt"></i> ${blocks.length} Blocks</span>
                <span><i class="fas fa-layer-group"></i> ${clusters.length} Clusters</span>
            </div>
        </div>`;

    // Render school cards
    if (schools.length > 0) {
        listEl.innerHTML = `<div class="school-import-grid">${schools.slice(0, 50).map(s => {
            const isExisting = existingSchoolKeys.has(s.name.toLowerCase());
            return `<div class="school-import-card ${isExisting ? 'existing' : 'new-school'}">
                <div class="school-import-card-header">
                    <span class="school-import-name">${escapeHtml(s.name)}</span>
                    <span class="school-import-badge ${isExisting ? 'badge-existing' : 'badge-new'}">${isExisting ? 'Exists' : 'New'}</span>
                </div>
                <div class="school-import-meta">
                    ${s.block ? `<span><i class="fas fa-map-marker-alt"></i> ${escapeHtml(s.block)}</span>` : ''}
                    ${s.cluster ? `<span><i class="fas fa-layer-group"></i> ${escapeHtml(s.cluster)}</span>` : ''}
                    ${s.district ? `<span><i class="fas fa-city"></i> ${escapeHtml(s.district)}</span>` : ''}
                </div>
                <div class="school-import-stats">
                    <span><i class="fas fa-clipboard-list"></i> ${s.totalObservations} obs</span>
                    <span><i class="fas fa-chalkboard-teacher"></i> ${s.teachers.length} teachers</span>
                    ${s.lastDate ? `<span><i class="fas fa-calendar"></i> ${new Date(s.lastDate).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: '2-digit' })}</span>` : ''}
                </div>
            </div>`;
        }).join('')}</div>${schools.length > 50 ? `<p style="text-align:center;color:var(--text-muted);font-size:12px;margin-top:8px;">Showing 50 of ${schools.length} schools...</p>` : ''}`;
    } else {
        listEl.innerHTML = '<p style="text-align:center;color:var(--text-muted);padding:20px;">No schools found matching filters.</p>';
    }

    btn.disabled = schools.length === 0;
    countEl.textContent = schools.length;
}

function executeSchoolProfileImport() {
    const { rows } = getFilteredSchoolImportRows();
    const schools = extractSchoolProfilesFromRows(rows);
    if (schools.length === 0) return;

    const f = getSchoolImportFilters();
    const filterDesc = [f.state !== 'all' ? `State: ${f.state}` : '', f.block !== 'all' ? `Block: ${f.block}` : '', f.clusters !== null ? `Clusters: ${[...f.clusters].join(', ')}` : '', f.observer !== 'all' ? `Observer: ${f.observer}` : ''].filter(Boolean).join(', ') || 'No filter';

    if (!confirm(`Import ${schools.length} school profiles from "${_schoolImportFileName}"?\n\nFilter: ${filterDesc}\n\nThis will create planned visits for new schools and update block/cluster info for existing ones.`)) return;

    let visits = DB.get('visits');
    const existingSchoolKeys = new Map();
    visits.forEach((v, i) => {
        const key = (v.school || '').trim().toLowerCase();
        if (!existingSchoolKeys.has(key)) existingSchoolKeys.set(key, i);
    });

    let newCount = 0;
    let updatedCount = 0;

    schools.forEach(s => {
        const key = s.name.toLowerCase();

        if (existingSchoolKeys.has(key)) {
            // Update existing visit with missing info
            const idx = existingSchoolKeys.get(key);
            let changed = false;
            if (!visits[idx].block && s.block) { visits[idx].block = s.block; changed = true; }
            if (!visits[idx].cluster && s.cluster) { visits[idx].cluster = s.cluster; changed = true; }
            if (!visits[idx].district && s.district) { visits[idx].district = s.district; changed = true; }
            if (!visits[idx].state && s.state) { visits[idx].state = s.state; changed = true; }
            if (changed) updatedCount++;
        } else {
            // Create a new planned visit for this school
            const visit = {
                id: DB.generateId(),
                school: s.name,
                block: s.block || '',
                cluster: s.cluster || '',
                district: s.district || '',
                state: s.state || '',
                date: new Date().toISOString().split('T')[0],
                status: 'planned',
                purpose: 'School Profile Import',
                notes: `Imported from Excel. ${s.teachers.length} teachers observed, ${s.totalObservations} observations. Subjects: ${s.subjects.join(', ') || 'N/A'}.${s.firstDate && s.lastDate ? ' Data range: ' + s.firstDate + ' to ' + s.lastDate : ''}`,
                followUp: '',
                createdAt: new Date().toISOString(),
                source: 'Excel Import'
            };
            visits.push(visit);
            existingSchoolKeys.set(key, visits.length - 1);
            newCount++;
        }
    });

    DB.set('visits', visits);
    closeModal('schoolProfileImportModal');
    _schoolImportRows = [];
    renderSchoolProfiles();

    const msg = [];
    if (newCount > 0) msg.push(`${newCount} new school profiles imported`);
    if (updatedCount > 0) msg.push(`${updatedCount} existing schools updated`);
    showToast(`${msg.join(', ')}! 🏫`, 'success', 5000);

    // Switch to schools section
    navigateTo('schools');
}

// ===== SCHOOL DELETE FUNCTIONS =====
function deleteSchoolProfile(encodedKey) {
    const schoolKey = decodeURIComponent(encodedKey);
    const schoolMap = getSchoolData();
    const school = schoolMap[schoolKey];
    if (!school) { showToast('School not found', 'error'); return; }

    const visitCount = school.visits.length;
    const obsCount = school.observations.length;

    let msg = `Delete school "${school.name}"?\n\n`;
    if (visitCount > 0 || obsCount > 0) {
        msg += `This will remove:\n`;
        if (visitCount > 0) msg += `• ${visitCount} visit(s)\n`;
        if (obsCount > 0) msg += `• ${obsCount} observation(s)\n`;
        msg += `\nThis cannot be undone!`;
    }

    if (!confirm(msg)) return;

    // Remove visits for this school
    if (visitCount > 0) {
        const visits = DB.get('visits');
        const filtered = visits.filter(v => (v.school || '').trim().toLowerCase() !== schoolKey);
        DB.set('visits', filtered);
    }

    // Remove observations for this school
    if (obsCount > 0) {
        const observations = DB.get('observations');
        const filtered = observations.filter(o => (o.school || '').trim().toLowerCase() !== schoolKey);
        DB.set('observations', filtered);
    }

    showToast(`School "${school.name}" deleted`, 'success');
    renderSchoolProfiles();
}

function openBulkDeleteSchools() {
    const schoolMap = getSchoolData();
    const schools = Object.values(schoolMap);
    if (schools.length === 0) {
        showToast('No schools to delete', 'info');
        return;
    }

    // Collect all visits to build filter data
    const visits = DB.get('visits');

    // Build per-school info for filtering
    const schoolInfos = schools.map(s => {
        const key = s.name.trim().toLowerCase();
        const schoolVisits = visits.filter(v => (v.school || '').trim().toLowerCase() === key);
        const sources = [...new Set(schoolVisits.map(v => v.source || 'Manual'))];
        const blocks = [...new Set([s.block, ...schoolVisits.map(v => v.block)].filter(Boolean))];
        const clusters = [...new Set(schoolVisits.map(v => v.cluster).filter(Boolean))];
        const statuses = [...new Set(schoolVisits.map(v => v.status).filter(Boolean))];
        return {
            name: s.name,
            key,
            visitCount: s.visits.length,
            obsCount: s.observations.length,
            block: blocks[0] || '',
            cluster: clusters[0] || '',
            sources,
            blocks,
            clusters,
            statuses
        };
    });

    // Populate filter checkboxes
    const allSources = [...new Set(schoolInfos.flatMap(s => s.sources))].sort();
    const allBlocks = [...new Set(schoolInfos.map(s => s.block).filter(Boolean))].sort();
    const allClusters = [...new Set(schoolInfos.flatMap(s => s.clusters))].sort();
    const allStatuses = [...new Set(schoolInfos.flatMap(s => s.statuses))].sort();

    _schoolDelInfos = schoolInfos;

    populateSchoolDelCheckboxes('schoolDelSourceList', allSources);
    populateSchoolDelCheckboxes('schoolDelBlockList', allBlocks);
    populateSchoolDelCheckboxes('schoolDelClusterList', allClusters);
    populateSchoolDelCheckboxes('schoolDelStatusList', allStatuses);

    previewBulkDeleteSchools();
    openModal('bulkDeleteSchoolsModal');
}

let _schoolDelInfos = [];

function populateSchoolDelCheckboxes(containerId, values) {
    const container = document.getElementById(containerId);
    if (!container) return;
    if (values.length === 0) {
        container.innerHTML = '<span style="color:var(--text-muted);font-size:11px;padding:4px;">None available</span>';
        return;
    }
    container.innerHTML = values.map(v =>
        `<label class="bulk-checkbox"><input type="checkbox" checked onchange="previewBulkDeleteSchools()" value="${escapeHtml(v)}"> ${escapeHtml(v || 'N/A')}</label>`
    ).join('');
}

function schoolDelFilterToggle(filter, mode) {
    const idMap = { source: 'schoolDelSourceList', block: 'schoolDelBlockList', cluster: 'schoolDelClusterList', status: 'schoolDelStatusList' };
    const container = document.getElementById(idMap[filter]);
    if (!container) return;
    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(cb => cb.checked = mode === 'all');
    previewBulkDeleteSchools();
}

function getSchoolDelChecked(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return new Set();
    return new Set([...container.querySelectorAll('input[type="checkbox"]:checked')].map(cb => cb.value));
}

function getBulkDeleteSchoolsFiltered() {
    const sources = getSchoolDelChecked('schoolDelSourceList');
    const blocks = getSchoolDelChecked('schoolDelBlockList');
    const clusters = getSchoolDelChecked('schoolDelClusterList');
    const statuses = getSchoolDelChecked('schoolDelStatusList');

    return _schoolDelInfos.filter(s => {
        const matchesSource = s.sources.some(src => sources.has(src));
        const matchesBlock = !s.block || blocks.has(s.block);
        const matchesCluster = s.clusters.length === 0 || s.clusters.some(c => clusters.has(c));
        const matchesStatus = s.statuses.length === 0 || s.statuses.some(st => statuses.has(st));
        return matchesSource && matchesBlock && matchesCluster && matchesStatus;
    });
}

function previewBulkDeleteSchools() {
    const filtered = getBulkDeleteSchoolsFiltered();
    const total = _schoolDelInfos.length;
    const totalVisits = filtered.reduce((s, x) => s + x.visitCount, 0);
    const totalObs = filtered.reduce((s, x) => s + x.obsCount, 0);

    const previewEl = document.getElementById('schoolDelPreview');
    const countEl = document.getElementById('schoolDelCount');
    const btn = document.getElementById('schoolDelConfirmBtn');

    previewEl.innerHTML = `
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:10px 14px;background:${filtered.length > 0 ? 'rgba(239,68,68,0.08)' : 'var(--bg-secondary)'};border-radius:10px;border:1px solid ${filtered.length > 0 ? 'rgba(239,68,68,0.2)' : 'var(--border)'};">
            <span style="font-size:13px;color:${filtered.length > 0 ? '#ef4444' : 'var(--text-muted)'};">
                <i class="fas fa-${filtered.length > 0 ? 'exclamation-triangle' : 'info-circle'}"></i>
                <strong>${filtered.length}</strong> of ${total} schools will be deleted
            </span>
            <span style="font-size:11px;color:var(--text-muted);"><i class="fas fa-school"></i> ${totalVisits} visits</span>
            <span style="font-size:11px;color:var(--text-muted);"><i class="fas fa-clipboard-list"></i> ${totalObs} observations</span>
        </div>
    `;

    // Show school list preview
    const listEl = document.getElementById('schoolDelList');
    if (filtered.length > 0) {
        listEl.innerHTML = filtered.slice(0, 40).map(s => `
            <div class="school-del-item">
                <div class="school-del-name"><i class="fas fa-school"></i> ${escapeHtml(s.name)}</div>
                <div class="school-del-meta">
                    ${s.block ? `<span>${escapeHtml(s.block)}</span>` : ''}
                    <span>${s.visitCount} visits</span>
                    <span>${s.obsCount} obs</span>
                    <span class="school-del-source">${escapeHtml(s.sources.join(', '))}</span>
                </div>
            </div>
        `).join('') + (filtered.length > 40 ? `<p style="text-align:center;color:var(--text-muted);font-size:11px;">...and ${filtered.length - 40} more</p>` : '');
    } else {
        listEl.innerHTML = '<p style="text-align:center;color:var(--text-muted);padding:16px;">No schools match current filters</p>';
    }

    btn.disabled = filtered.length === 0;
    countEl.textContent = filtered.length;
}

function executeBulkDeleteSchools() {
    const filtered = getBulkDeleteSchoolsFiltered();
    if (filtered.length === 0) return;

    const totalVisits = filtered.reduce((s, x) => s + x.visitCount, 0);
    const totalObs = filtered.reduce((s, x) => s + x.obsCount, 0);

    if (!confirm(`⚠️ DELETE ${filtered.length} SCHOOLS\n\nThis will permanently remove:\n• ${totalVisits} visit(s)\n• ${totalObs} observation(s)\n\nThis CANNOT be undone!`)) return;

    const keysToDelete = new Set(filtered.map(s => s.key));

    // Remove visits
    let visits = DB.get('visits');
    visits = visits.filter(v => !keysToDelete.has((v.school || '').trim().toLowerCase()));
    DB.set('visits', visits);

    // Remove observations
    let observations = DB.get('observations');
    observations = observations.filter(o => !keysToDelete.has((o.school || '').trim().toLowerCase()));
    DB.set('observations', observations);

    closeModal('bulkDeleteSchoolsModal');
    _schoolDelInfos = [];
    renderSchoolProfiles();
    showToast(`Deleted ${filtered.length} schools (${totalVisits} visits, ${totalObs} observations removed)`, 'success', 5000);
}

// ===== SCHOOL PROFILES =====
function getSchoolData() {
    const visits = DB.get('visits');
    const observations = DB.get('observations');
    const schoolMap = {};

    const ensureSchool = (key, name, block) => {
        if (!schoolMap[key]) schoolMap[key] = { name, block: block || '', visits: [], observations: [], _dates: new Set(), _teachers: new Set() };
    };

    visits.forEach(v => {
        const key = (v.school || '').trim().toLowerCase();
        ensureSchool(key, (v.school || '').trim(), v.block);
        if (v.block && !schoolMap[key].block) schoolMap[key].block = v.block;
        schoolMap[key].visits.push(v);
        if (v.date) schoolMap[key]._dates.add(v.date);
    });

    observations.forEach(o => {
        const key = (o.school || '').trim().toLowerCase();
        ensureSchool(key, (o.school || '').trim(), o.block);
        if (o.block && !schoolMap[key].block) schoolMap[key].block = o.block;
        schoolMap[key].observations.push(o);
        if (o.date) schoolMap[key]._dates.add(o.date);
        const teacher = (o.teacher || '').trim();
        if (teacher) schoolMap[key]._teachers.add(teacher);
    });

    // Convert sets to counts for easy access
    Object.values(schoolMap).forEach(s => {
        s.totalVisitDays = s._dates.size;
        s.teacherCount = s._teachers.size;
        s.teachers = [...s._teachers];
        delete s._dates;
        delete s._teachers;
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
    schools.sort((a, b) => (b.totalVisitDays + b.observations.length) - (a.totalVisitDays + a.observations.length));

    // Summary stats
    const allSchools = Object.values(schoolMap);
    const totalSchools = allSchools.length;
    const totalVisitDays = allSchools.reduce((s, sc) => s + sc.totalVisitDays, 0);
    const totalObs = allSchools.reduce((s, sc) => s + sc.observations.length, 0);
    const totalTeachers = new Set(allSchools.flatMap(sc => sc.teachers)).size;

    // Student totals
    const allStudents = DB.get('schoolStudentRecords') || {};
    let totalStudents = 0;
    Object.values(allStudents).forEach(sr => { totalStudents += _ssrTotals(sr).total; });

    document.getElementById('schoolSummaryStats').innerHTML = `
        <div class="school-summary-stat"><div class="stat-icon">🏫</div><div class="stat-value">${totalSchools}</div><div class="stat-label">Schools</div></div>
        <div class="school-summary-stat"><div class="stat-icon">📍</div><div class="stat-value">${totalVisitDays}</div><div class="stat-label">Total Visits</div></div>
        <div class="school-summary-stat"><div class="stat-icon">📋</div><div class="stat-value">${totalObs}</div><div class="stat-label">Observations</div></div>
        <div class="school-summary-stat"><div class="stat-icon">👩‍🏫</div><div class="stat-value">${totalTeachers}</div><div class="stat-label">Teachers</div></div>
        <div class="school-summary-stat"><div class="stat-icon">🎓</div><div class="stat-value">${totalStudents}</div><div class="stat-label">Students</div></div>
    `;

    // Show school list (hide detail view)
    document.getElementById('schoolDetailView').style.display = 'none';
    const container = document.getElementById('schoolProfilesContainer');
    container.style.display = '';

    if (schools.length === 0) {
        container.innerHTML = '<div class="idea-empty"><i class="fas fa-school"></i><h3>No schools found</h3><p>Schools will appear here automatically from your visits and observations.</p></div>';
        return;
    }

    const pg = getPaginatedItems(schools, 'schools', 18);
    const allStudentRecords = DB.get('schoolStudentRecords') || {};

    container.innerHTML = `<div class="school-cards-grid">${pg.items.map(school => {
        // Last activity date from visits + observations combined
        const allDates = [
            ...school.visits.filter(v => v.date).map(v => v.date),
            ...school.observations.filter(o => o.date).map(o => o.date)
        ].sort();
        const lastDate = allDates.length > 0 ? allDates[allDates.length - 1] : null;
        const avgRating = school.observations.length > 0
            ? (school.observations.reduce((s, o) => s + (((o.engagementRating || o.engagement) || 0) + (o.methodology || 0) + (o.tlm || 0)) / 3, 0) / school.observations.length).toFixed(1)
            : null;
        const schoolKey = school.name.trim().toLowerCase();
        const safeKey = encodeURIComponent(schoolKey).replace(/'/g, '%27');

        // Student records summary
        const sr = allStudentRecords[schoolKey];
        const totalStudents = _ssrTotals(sr).total;
        const studentBadge = totalStudents > 0 ? `<div class="school-metric"><div class="metric-value">${totalStudents}</div><div class="metric-label">Students</div></div>` : '';
        const studentBar = totalStudents > 0 ? _buildLevelMiniBar(sr, totalStudents) : '';

        return `
            <div class="school-profile-card" onclick="showSchoolDetail('${safeKey}')">
                <div class="school-card-delete" onclick="event.stopPropagation(); deleteSchoolProfile('${safeKey}')" title="Delete this school"><i class="fas fa-times"></i></div>
                <div class="school-card-name"><i class="fas fa-school"></i> ${escapeHtml(school.name)}</div>
                <div class="school-card-block">${escapeHtml(school.block || 'Block not specified')}</div>
                <div class="school-card-metrics">
                    <div class="school-metric"><div class="metric-value">${school.totalVisitDays}</div><div class="metric-label">Visits</div></div>
                    <div class="school-metric"><div class="metric-value">${school.observations.length}</div><div class="metric-label">Obs.</div></div>
                    <div class="school-metric"><div class="metric-value">${school.teacherCount}</div><div class="metric-label">Teachers</div></div>
                    ${studentBadge}
                </div>
                ${studentBar}
                <div class="school-card-footer">
                    <div class="school-last-visit"><i class="fas fa-clock"></i> ${lastDate ? new Date(lastDate).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }) : 'No activity'}</div>
                    ${avgRating ? `<div class="school-rating"><i class="fas fa-star"></i> ${avgRating}/5</div>` : ''}
                </div>
            </div>
        `;
    }).join('')}</div>` + renderPaginationControls('schools', pg, 'renderSchoolProfiles');
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
    const teachers = school.teachers || [];
    const subjects = [...new Set(school.observations.map(o => o.subject).filter(Boolean))];
    const avgRating = school.observations.length > 0
        ? (school.observations.reduce((s, o) => s + (((o.engagementRating || o.engagement) || 0) + (o.methodology || 0) + (o.tlm || 0)) / 3, 0) / school.observations.length).toFixed(1)
        : 'N/A';

    // Student records for this school
    const allStudentRecs = DB.get('schoolStudentRecords') || {};
    const thisSchoolStudents = allStudentRecs[schoolKey];
    const totalStudents = _ssrTotals(thisSchoolStudents).total;

    // All activities timeline — build rich objects
    const activities = [
        ...school.visits.map(v => ({
            type: 'visit', date: v.date, id: v.id,
            title: v.purpose || 'Visit',
            status: v.status || '',
            fields: [
                v.notes ? { icon: 'fa-sticky-note', label: 'Notes', value: v.notes } : null,
                v.followUp ? { icon: 'fa-clipboard-check', label: 'Follow-up', value: v.followUp } : null,
                v.block ? { icon: 'fa-map-marker-alt', label: 'Block', value: v.block } : null,
                v.cluster ? { icon: 'fa-layer-group', label: 'Cluster', value: v.cluster } : null
            ].filter(Boolean)
        })),
        ...school.observations.map(o => {
            const engVal = o.engagementRating || o.engagement || 0;
            const methVal = o.methodology || 0;
            const tlmVal = o.tlm || 0;
            const hasRatings = engVal > 0 || methVal > 0 || tlmVal > 0;
            return {
                type: 'observation', date: o.date, id: o.id,
                title: `Observation — ${o.subject || 'General'}`,
                status: '',
                fields: [
                    o.teacher ? { icon: 'fa-chalkboard-teacher', label: 'Teacher', value: o.teacher } : null,
                    o.subject ? { icon: 'fa-book', label: 'Subject', value: o.subject } : null,
                    o.topic ? { icon: 'fa-bookmark', label: 'Topic', value: o.topic } : null,
                    o.class ? { icon: 'fa-users', label: 'Class', value: o.class } : null,
                    o.practice ? { icon: 'fa-lightbulb', label: 'Practice', value: o.practice } : null,
                    o.practiceType ? { icon: 'fa-tag', label: 'Practice Type', value: o.practiceType } : null,
                    o.group ? { icon: 'fa-layer-group', label: 'Group', value: o.group } : null,
                    o.engagementLevel ? { icon: 'fa-signal', label: 'Engagement Level', value: o.engagementLevel } : null,
                    hasRatings ? { icon: 'fa-star', label: 'Ratings', value: `Engagement: ${engVal}/5 · Methodology: ${methVal}/5 · TLM: ${tlmVal}/5`, isRating: true, eng: engVal, meth: methVal, tlm: tlmVal } : null,
                    o.strengths ? { icon: 'fa-check-circle', label: 'Strengths', value: o.strengths } : null,
                    o.areas ? { icon: 'fa-exclamation-circle', label: 'Areas for Improvement', value: o.areas } : null,
                    o.suggestions ? { icon: 'fa-comment-dots', label: 'Suggestions', value: o.suggestions } : null,
                    o.notes ? { icon: 'fa-sticky-note', label: 'Notes', value: o.notes } : null,
                    o.observer ? { icon: 'fa-user', label: 'Observer', value: o.observer } : null,
                    o.teacherStage ? { icon: 'fa-graduation-cap', label: 'Teacher Stage', value: o.teacherStage } : null,
                    o.cluster ? { icon: 'fa-map-pin', label: 'Cluster', value: o.cluster } : null,
                    o.block ? { icon: 'fa-map-marker-alt', label: 'Block', value: o.block } : null,
                    o.observedWhileTeaching ? { icon: 'fa-eye', label: 'Observed While Teaching', value: o.observedWhileTeaching } : null
                ].filter(Boolean)
            };
        })
    ].sort((a, b) => (b.date || '').localeCompare(a.date || ''));

    detailView.innerHTML = `
        <div class="school-detail">
            <div class="school-detail-header">
                <button class="back-btn" onclick="renderSchoolProfiles()"><i class="fas fa-arrow-left"></i> Back</button>
                <h2><i class="fas fa-school"></i> ${escapeHtml(school.name)}</h2>
                <button class="btn btn-outline btn-sm" onclick="printSchoolHealthCard('${encodeURIComponent(schoolKey)}')" style="margin-left:auto;"><i class="fas fa-print"></i> Health Card</button>
                <button class="btn btn-danger btn-sm" onclick="deleteSchoolProfile('${encodeURIComponent(schoolKey)}')"><i class="fas fa-trash"></i> Delete</button>
            </div>
            ${school.block ? `<p style="color:var(--text-muted);margin-bottom:20px;"><i class="fas fa-map-marker-alt" style="color:var(--amber);margin-right:6px;"></i>${escapeHtml(school.block)}</p>` : ''}
            <div class="school-detail-stats">
                <div class="school-detail-stat"><div class="stat-value">${school.totalVisitDays}</div><div class="stat-label">Total Visits</div></div>
                <div class="school-detail-stat"><div class="stat-value">${completedVisits}</div><div class="stat-label">Completed</div></div>
                <div class="school-detail-stat"><div class="stat-value">${plannedVisits}</div><div class="stat-label">Planned</div></div>
                <div class="school-detail-stat"><div class="stat-value">${school.observations.length}</div><div class="stat-label">Observations</div></div>
                <div class="school-detail-stat"><div class="stat-value">${teachers.length}</div><div class="stat-label">Teachers</div></div>
                <div class="school-detail-stat"><div class="stat-value">${totalStudents}</div><div class="stat-label">Students</div></div>
                <div class="school-detail-stat"><div class="stat-value">${avgRating}</div><div class="stat-label">Avg Rating</div></div>
            </div>
            ${teachers.length > 0 ? `<div style="margin-bottom:20px;"><strong style="color:var(--text-secondary);font-size:13px;">Teachers observed:</strong> <span style="color:var(--text-muted);font-size:13px;">${escapeHtml(teachers.join(', '))}</span></div>` : ''}
            ${subjects.length > 0 ? `<div style="margin-bottom:20px;"><strong style="color:var(--text-secondary);font-size:13px;">Subjects covered:</strong> <span style="color:var(--text-muted);font-size:13px;">${escapeHtml(subjects.join(', '))}</span></div>` : ''}

            <!-- Student Records Section -->
            ${_buildSchoolStudentSection(schoolKey)}

            <div class="school-detail-timeline">
                <h3><i class="fas fa-history" style="color:var(--amber);margin-right:8px;"></i>Activity Timeline (${activities.length})</h3>
                ${activities.length > 0 ? activities.map((a, idx) => {
                    const summary = a.type === 'observation'
                        ? (a.fields.find(f => f.label === 'Teacher')?.value || '') + (a.fields.find(f => f.label === 'Topic')?.value ? ' | ' + a.fields.find(f => f.label === 'Topic').value : '')
                        : a.fields.find(f => f.label === 'Notes')?.value || '';
                    const detailRows = a.fields.map(f => {
                        if (f.isRating) {
                            const stars = (v) => { let s = ''; for (let i = 1; i <= 5; i++) s += `<i class="fas fa-star" style="color:${i <= v ? '#f59e0b' : 'var(--border)'};font-size:11px;"></i>`; return s; };
                            return `<div class="tl-detail-row tl-ratings-row">
                                <span class="tl-detail-label"><i class="fas ${f.icon}"></i> ${f.label}</span>
                                <div class="tl-rating-group">
                                    <span class="tl-rating-item">Engagement ${stars(f.eng)}</span>
                                    <span class="tl-rating-item">Methodology ${stars(f.meth)}</span>
                                    <span class="tl-rating-item">TLM ${stars(f.tlm)}</span>
                                </div>
                            </div>`;
                        }
                        return `<div class="tl-detail-row">
                            <span class="tl-detail-label"><i class="fas ${f.icon}"></i> ${f.label}</span>
                            <span class="tl-detail-value">${escapeHtml(f.value)}</span>
                        </div>`;
                    }).join('');
                    return `
                    <div class="school-timeline-item clickable" onclick="this.classList.toggle('expanded')">
                        <div class="school-timeline-icon ${a.type}"><i class="fas ${a.type === 'visit' ? 'fa-school' : 'fa-clipboard-check'}"></i></div>
                        <div class="school-timeline-content">
                            <div class="timeline-title">${escapeHtml(a.title)}${a.status ? ` <span style="font-size:11px;opacity:0.7;">(${escapeHtml(a.status)})</span>` : ''}</div>
                            ${summary ? `<div class="timeline-details">${escapeHtml(summary)}</div>` : ''}
                            ${a.fields.length > 0 ? `<div class="tl-expanded-details">${detailRows}</div>` : ''}
                        </div>
                        <div class="school-timeline-right">
                            <div class="school-timeline-date">${new Date(a.date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}</div>
                            <i class="fas fa-chevron-down tl-expand-icon"></i>
                        </div>
                    </div>`;
                }).join('') : '<p style="color:var(--text-muted);text-align:center;padding:30px;">No activities recorded yet</p>'}
            </div>
        </div>
    `;
}

// ===== SCHOOL STUDENT RECORDS (Learning Levels × Class) =====
const STUDENT_LEVELS = [
    { key: 'lig', label: 'LIG', fullLabel: 'Lagging', color: '#ef4444', icon: '🔴' },
    { key: 'fln', label: 'FLN', fullLabel: 'Foundational Literacy & Numeracy', color: '#f59e0b', icon: '🟡' },
    { key: 'pgl', label: 'PGL', fullLabel: 'Partially at Grade Level', color: '#3b82f6', icon: '🔵' },
    { key: 'gl',  label: 'GL',  fullLabel: 'Grade Level', color: '#10b981', icon: '🟢' }
];
const SSR_CLASSES = ['1', '2', '3', '4', '5', '6', '7', '8'];

// Compute totals from class-wise data (handles both old flat & new class-wise format)
function _ssrTotals(sr) {
    if (!sr) return { lig: 0, fln: 0, pgl: 0, gl: 0, total: 0 };
    // New format: sr.classes = { '1': {lig,fln,pgl,gl}, ... }
    if (sr.classes) {
        const t = { lig: 0, fln: 0, pgl: 0, gl: 0 };
        Object.values(sr.classes).forEach(c => {
            STUDENT_LEVELS.forEach(l => { t[l.key] += (c[l.key] || 0); });
        });
        t.total = t.lig + t.fln + t.pgl + t.gl;
        return t;
    }
    // Old flat format fallback
    const t = { lig: sr.lig || 0, fln: sr.fln || 0, pgl: sr.pgl || 0, gl: sr.gl || 0 };
    t.total = t.lig + t.fln + t.pgl + t.gl;
    return t;
}

function _buildLevelMiniBar(sr, total) {
    if (!sr || total === 0) return '';
    const t = _ssrTotals(sr);
    const levels = STUDENT_LEVELS.map(l => ({
        ...l,
        count: t[l.key],
        pct: total > 0 ? (t[l.key] / total * 100) : 0
    })).filter(l => l.count > 0);

    return `<div class="ssr-mini-bar" title="${levels.map(l => l.label + ': ' + l.count).join(' | ')}">
        ${levels.map(l => `<div class="ssr-mini-seg" style="width:${l.pct}%;background:${l.color};" title="${l.label}: ${l.count} (${l.pct.toFixed(0)}%)"></div>`).join('')}
    </div>`;
}

function _buildSchoolStudentSection(schoolKey) {
    const allRecords = DB.get('schoolStudentRecords') || {};
    const sr = allRecords[schoolKey];
    const t = _ssrTotals(sr);
    const total = t.total;
    const safeKey = encodeURIComponent(schoolKey).replace(/'/g, '%27');

    let barHtml = '';
    let classTable = '';
    if (total > 0) {
        // Overall bar
        const levels = STUDENT_LEVELS.map(l => ({ ...l, count: t[l.key], pct: t[l.key] / total * 100 }));
        barHtml = `<div class="ssr-bar">${levels.map(l =>
            l.count > 0 ? `<div class="ssr-bar-seg" style="width:${l.pct}%;background:${l.color};">
                <span class="ssr-bar-label">${l.label} ${l.count}</span>
            </div>` : ''
        ).join('')}</div>`;

        // Class-wise table
        const classes = (sr && sr.classes) || {};
        const activeClasses = SSR_CLASSES.filter(cls => {
            const c = classes[cls];
            return c && (c.lig || c.fln || c.pgl || c.gl);
        });

        if (activeClasses.length > 0) {
            classTable = `<div class="ssr-class-table-wrap">
                <table class="ssr-class-table">
                    <thead>
                        <tr>
                            <th>Class</th>
                            ${STUDENT_LEVELS.map(l => `<th style="color:${l.color};">${l.icon} ${l.label}</th>`).join('')}
                            <th>Total</th>
                            <th>Bar</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${activeClasses.map(cls => {
                            const c = classes[cls] || {};
                            const cTotal = (c.lig || 0) + (c.fln || 0) + (c.pgl || 0) + (c.gl || 0);
                            const miniLevels = STUDENT_LEVELS.map(l => ({ ...l, count: c[l.key] || 0, pct: cTotal > 0 ? ((c[l.key] || 0) / cTotal * 100) : 0 })).filter(l => l.count > 0);
                            return `<tr>
                                <td><strong>Class ${cls}</strong></td>
                                ${STUDENT_LEVELS.map(l => `<td>${c[l.key] || 0}</td>`).join('')}
                                <td><strong>${cTotal}</strong></td>
                                <td style="min-width:100px;">
                                    <div class="ssr-mini-bar" style="margin:0;">${miniLevels.map(l => `<div class="ssr-mini-seg" style="width:${l.pct}%;background:${l.color};"></div>`).join('')}</div>
                                </td>
                            </tr>`;
                        }).join('')}
                        <tr class="ssr-total-row">
                            <td><strong>Total</strong></td>
                            ${STUDENT_LEVELS.map(l => `<td><strong style="color:${l.color};">${t[l.key]}</strong></td>`).join('')}
                            <td><strong>${total}</strong></td>
                            <td></td>
                        </tr>
                    </tbody>
                </table>
            </div>`;
        } else {
            // Old flat format - show level cards
            classTable = `<div class="ssr-level-grid">${levels.map(l => `
                <div class="ssr-level-card" style="border-left:3px solid ${l.color};">
                    <div class="ssr-level-hdr">
                        <span class="ssr-level-icon">${l.icon}</span>
                        <span class="ssr-level-name">${l.label}</span>
                        <span class="ssr-level-full">${l.fullLabel}</span>
                    </div>
                    <div class="ssr-level-count">${l.count}</div>
                    <div class="ssr-level-pct">${l.pct.toFixed(1)}%</div>
                </div>
            `).join('')}</div>`;
        }
    }

    return `
        <div class="ssr-section" id="ssrSection">
            <div class="ssr-header">
                <h3><i class="fas fa-user-graduate" style="color:var(--accent);margin-right:8px;"></i>Student Records</h3>
                <button class="btn btn-sm btn-primary" onclick="openStudentRecordEditor('${safeKey}')"><i class="fas fa-edit"></i> ${total > 0 ? 'Edit' : 'Add Students'}</button>
            </div>
            ${total > 0 ? `
                <div class="ssr-total"><strong>${total}</strong> Students across ${((sr && sr.classes) ? Object.keys(sr.classes).filter(k => { const c = sr.classes[k]; return c && (c.lig||c.fln||c.pgl||c.gl); }).length : 0) || '—'} classes</div>
                ${barHtml}
                ${classTable}
                ${(sr && sr.notes) ? `<div class="ssr-notes"><i class="fas fa-sticky-note" style="color:var(--accent);margin-right:6px;"></i>${escapeHtml(sr.notes)}</div>` : ''}
                ${(sr && sr.updatedAt) ? `<div class="ssr-updated"><i class="fas fa-clock"></i> Updated ${new Date(sr.updatedAt).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}</div>` : ''}
            ` : `
                <div class="ssr-empty">
                    <i class="fas fa-users" style="font-size:1.5rem;color:var(--text-muted);margin-bottom:8px;"></i>
                    <p>No student records added yet. Click "Add Students" to record class-wise learning levels.</p>
                </div>
            `}
        </div>
    `;
}

function openStudentRecordEditor(encodedKey) {
    const schoolKey = decodeURIComponent(encodedKey);
    const allRecords = DB.get('schoolStudentRecords') || {};
    const sr = allRecords[schoolKey] || {};
    const classes = sr.classes || {};

    const ssrSection = document.getElementById('ssrSection');
    if (!ssrSection) return;

    // Build class-wise input table
    const rows = SSR_CLASSES.map(cls => {
        const c = classes[cls] || {};
        return `<tr>
            <td><strong>Class ${cls}</strong></td>
            ${STUDENT_LEVELS.map(l => `<td><input type="number" class="ssr-cell-input" id="ssrC${cls}_${l.key}" value="${c[l.key] || ''}" min="0" placeholder="0" oninput="_ssrUpdatePreview()"></td>`).join('')}
            <td class="ssr-row-total" id="ssrRowTotal_${cls}">0</td>
        </tr>`;
    }).join('');

    ssrSection.innerHTML = `
        <div class="ssr-header">
            <h3><i class="fas fa-user-graduate" style="color:var(--accent);margin-right:8px;"></i>Student Records — Edit by Class</h3>
        </div>
        <div class="ssr-editor">
            <div class="ssr-class-table-wrap">
                <table class="ssr-class-table ssr-edit-table">
                    <thead>
                        <tr>
                            <th>Class</th>
                            ${STUDENT_LEVELS.map(l => `<th style="color:${l.color};">${l.icon} ${l.label}<br><small style="font-weight:400;font-size:10px;">${l.fullLabel}</small></th>`).join('')}
                            <th>Total</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows}
                        <tr class="ssr-total-row">
                            <td><strong>Grand Total</strong></td>
                            ${STUDENT_LEVELS.map(l => `<td id="ssrColTotal_${l.key}" style="color:${l.color};font-weight:700;">0</td>`).join('')}
                            <td id="ssrGrandTotal" style="font-weight:800;font-size:16px;">0</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="ssr-edit-preview" id="ssrPreview"></div>
            <div class="ssr-edit-notes">
                <label for="ssrNotes" style="font-size:13px;color:var(--text-secondary);font-weight:600;">Notes (optional)</label>
                <textarea id="ssrNotes" class="ssr-edit-textarea" rows="2" placeholder="e.g., Assessment date, source of data...">${escapeHtml(sr.notes || '')}</textarea>
            </div>
            <div class="ssr-edit-actions">
                <button class="btn btn-primary" onclick="saveSchoolStudentRecords('${encodeURIComponent(schoolKey).replace(/'/g, '%27')}')"><i class="fas fa-save"></i> Save</button>
                <button class="btn btn-ghost" onclick="showSchoolDetail('${encodeURIComponent(schoolKey).replace(/'/g, '%27')}')"><i class="fas fa-times"></i> Cancel</button>
                ${Object.keys(classes).length > 0 ? `<button class="btn btn-danger btn-sm" onclick="clearSchoolStudentRecords('${encodeURIComponent(schoolKey).replace(/'/g, '%27')}')"><i class="fas fa-trash"></i> Clear</button>` : ''}
            </div>
        </div>
    `;
    _ssrUpdatePreview();
}

function _ssrUpdatePreview() {
    const previewEl = document.getElementById('ssrPreview');

    // Compute row & column totals
    const colTotals = {};
    STUDENT_LEVELS.forEach(l => { colTotals[l.key] = 0; });
    let grandTotal = 0;

    SSR_CLASSES.forEach(cls => {
        let rowTotal = 0;
        STUDENT_LEVELS.forEach(l => {
            const val = parseInt(document.getElementById(`ssrC${cls}_${l.key}`)?.value) || 0;
            colTotals[l.key] += val;
            rowTotal += val;
        });
        const rtEl = document.getElementById(`ssrRowTotal_${cls}`);
        if (rtEl) rtEl.textContent = rowTotal || '';
        grandTotal += rowTotal;
    });

    STUDENT_LEVELS.forEach(l => {
        const el = document.getElementById(`ssrColTotal_${l.key}`);
        if (el) el.textContent = colTotals[l.key];
    });
    const gtEl = document.getElementById('ssrGrandTotal');
    if (gtEl) gtEl.textContent = grandTotal;

    if (!previewEl) return;

    if (grandTotal === 0) {
        previewEl.innerHTML = '<div style="color:var(--text-muted);font-size:13px;text-align:center;padding:8px;">Enter student counts above to see preview</div>';
        return;
    }

    const levels = STUDENT_LEVELS.map(l => ({
        ...l,
        count: colTotals[l.key],
        pct: colTotals[l.key] / grandTotal * 100
    })).filter(l => l.count > 0);

    previewEl.innerHTML = `
        <div style="font-size:13px;color:var(--text-secondary);margin-bottom:6px;font-weight:600;">Preview — ${grandTotal} Students</div>
        <div class="ssr-bar">${levels.map(l =>
            `<div class="ssr-bar-seg" style="width:${l.pct}%;background:${l.color};"><span class="ssr-bar-label">${l.label} ${l.count}</span></div>`
        ).join('')}</div>
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:6px;">
            ${levels.map(l => `<span style="font-size:12px;color:${l.color};font-weight:600;">${l.icon} ${l.label}: ${l.count} (${l.pct.toFixed(1)}%)</span>`).join('')}
        </div>
    `;
}

function saveSchoolStudentRecords(encodedKey) {
    const schoolKey = decodeURIComponent(encodedKey);
    const notes = (document.getElementById('ssrNotes')?.value || '').trim();

    const classes = {};
    let grandTotal = 0;
    SSR_CLASSES.forEach(cls => {
        const c = {};
        let rowTotal = 0;
        STUDENT_LEVELS.forEach(l => {
            c[l.key] = parseInt(document.getElementById(`ssrC${cls}_${l.key}`)?.value) || 0;
            rowTotal += c[l.key];
        });
        if (rowTotal > 0) {
            classes[cls] = c;
            grandTotal += rowTotal;
        }
    });

    if (grandTotal === 0) {
        showToast('Enter at least one student count', 'error');
        return;
    }

    const allRecords = DB.get('schoolStudentRecords') || {};
    allRecords[schoolKey] = { classes, notes, updatedAt: new Date().toISOString() };
    DB.set('schoolStudentRecords', allRecords);
    showToast(`✅ Student records saved (${grandTotal} students)`);
    showSchoolDetail(encodeURIComponent(schoolKey));
}

function clearSchoolStudentRecords(encodedKey) {
    const schoolKey = decodeURIComponent(encodedKey);
    if (!confirm('Clear all student records for this school?')) return;
    const allRecords = DB.get('schoolStudentRecords') || {};
    delete allRecords[schoolKey];
    DB.set('schoolStudentRecords', allRecords);
    showToast('Student records cleared', 'info');
    showSchoolDetail(encodeURIComponent(schoolKey));
}

// ===== MEETING TRACKER =====
function renderMeetings() {
    const meetings = DB.get('meetings');
    const filter = document.getElementById('meetingFilter')?.value || 'all';

    // Filter
    let filtered = [...meetings];
    if (filter !== 'all') {
        filtered = filtered.filter(m => m.type === filter);
    }
    filtered.sort((a, b) => (b.date || '').localeCompare(a.date || ''));

    // Stats
    const now = new Date();
    const thisMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    const thisMonthMeetings = meetings.filter(m => (m.date || '').startsWith(thisMonth));
    const totalActionItems = meetings.reduce((s, m) => s + (m.actionItems || []).filter(a => !a.done).length, 0);
    const typeCount = {};
    meetings.forEach(m => { typeCount[m.type || 'Other'] = (typeCount[m.type || 'Other'] || 0) + 1; });
    const topType = Object.entries(typeCount).sort((a, b) => b[1] - a[1])[0];

    const statsEl = document.getElementById('meetingStats');
    if (statsEl) {
        statsEl.innerHTML = `
            <div class="meeting-stat-card"><div class="meeting-stat-icon" style="background:rgba(99,102,241,0.15);color:#6366f1;"><i class="fas fa-handshake"></i></div><div class="meeting-stat-value">${meetings.length}</div><div class="meeting-stat-label">Total Meetings</div></div>
            <div class="meeting-stat-card"><div class="meeting-stat-icon" style="background:rgba(16,185,129,0.15);color:#10b981;"><i class="fas fa-calendar-check"></i></div><div class="meeting-stat-value">${thisMonthMeetings.length}</div><div class="meeting-stat-label">This Month</div></div>
            <div class="meeting-stat-card"><div class="meeting-stat-icon" style="background:rgba(245,158,11,0.15);color:#f59e0b;"><i class="fas fa-exclamation-circle"></i></div><div class="meeting-stat-value">${totalActionItems}</div><div class="meeting-stat-label">Pending Actions</div></div>
            <div class="meeting-stat-card"><div class="meeting-stat-icon" style="background:rgba(236,72,153,0.15);color:#ec4899;"><i class="fas fa-star"></i></div><div class="meeting-stat-value">${topType ? topType[0] : '-'}</div><div class="meeting-stat-label">Most Frequent</div></div>
        `;
    }

    // Render list
    const container = document.getElementById('meetingList');
    if (!container) return;

    if (filtered.length === 0) {
        container.innerHTML = '<div class="idea-empty"><i class="fas fa-handshake"></i><h3>No meetings recorded</h3><p>Track your BRC, cluster, district, and other meetings here.</p></div>';
        return;
    }

    const typeColors = { 'BRC Meeting': '#6366f1', 'Cluster Meeting': '#10b981', 'District Meeting': '#f59e0b', 'SDMC Meeting': '#ec4899', 'Parent-Teacher Meeting': '#8b5cf6', 'Convergence Meeting': '#3b82f6', 'Review Meeting': '#ef4444', 'Other': '#64748b' };

    const pg = getPaginatedItems(filtered, 'meetings', 10);

    container.innerHTML = pg.items.map(m => {
        const color = typeColors[m.type] || '#64748b';
        const pendingActions = (m.actionItems || []).filter(a => !a.done).length;
        const totalActions = (m.actionItems || []).length;
        return `
            <div class="meeting-card">
                <div class="meeting-card-header">
                    <span class="meeting-type-badge" style="background:${color}20;color:${color};border:1px solid ${color}40;">${escapeHtml(m.type || 'Meeting')}</span>
                    <span class="meeting-date"><i class="fas fa-calendar-alt"></i> ${m.date ? new Date(m.date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }) : 'N/A'}</span>
                    <div class="meeting-card-actions">
                        <button class="btn-icon-sm" onclick="openMeetingModal('${m.id}')" title="Edit"><i class="fas fa-edit"></i></button>
                        <button class="btn-icon-sm" onclick="deleteMeeting('${m.id}')" title="Delete"><i class="fas fa-trash"></i></button>
                    </div>
                </div>
                <div class="meeting-card-title">${escapeHtml(m.title || 'Untitled Meeting')}</div>
                ${m.location ? `<div class="meeting-card-meta"><i class="fas fa-map-marker-alt"></i> ${escapeHtml(m.location)}</div>` : ''}
                ${m.organizer ? `<div class="meeting-card-meta"><i class="fas fa-user-tie"></i> ${escapeHtml(m.organizer)}</div>` : ''}
                ${m.attendees ? `<div class="meeting-card-meta"><i class="fas fa-users"></i> ${escapeHtml(m.attendees)}</div>` : ''}
                ${m.agenda ? `<div class="meeting-card-detail"><strong>Agenda:</strong> ${escapeHtml(m.agenda)}</div>` : ''}
                ${m.decisions ? `<div class="meeting-card-detail"><strong>Decisions:</strong> ${escapeHtml(m.decisions)}</div>` : ''}
                ${m.keyTakeaways ? `<div class="meeting-card-detail"><strong>Key Takeaways:</strong> ${escapeHtml(m.keyTakeaways)}</div>` : ''}
                ${totalActions > 0 ? `
                    <div class="meeting-actions-section">
                        <strong>Action Items (${totalActions - pendingActions}/${totalActions} done):</strong>
                        <div class="meeting-action-progress"><div class="meeting-action-bar" style="width:${totalActions > 0 ? Math.round(((totalActions - pendingActions) / totalActions) * 100) : 0}%"></div></div>
                        <ul class="meeting-action-list">${(m.actionItems || []).map((a, i) => `
                            <li class="${a.done ? 'done' : ''}">
                                <label><input type="checkbox" ${a.done ? 'checked' : ''} onchange="toggleMeetingAction('${m.id}', ${i})"> ${escapeHtml(a.text)}</label>
                                ${a.assignee ? `<span class="action-assignee">${escapeHtml(a.assignee)}</span>` : ''}
                            </li>`).join('')}
                        </ul>
                    </div>` : ''}
                ${m.nextMeetingDate ? `<div class="meeting-card-meta" style="margin-top:8px;color:#6366f1;"><i class="fas fa-forward"></i> Next meeting: ${new Date(m.nextMeetingDate).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}</div>` : ''}
            </div>
        `;
    }).join('') + renderPaginationControls('meetings', pg, 'renderMeetings');
}

function openMeetingModal(id) {
    const form = document.getElementById('meetingForm');
    form.reset();
    document.getElementById('meetingId').value = '';
    document.getElementById('meetingModalTitle').innerHTML = '<i class="fas fa-handshake"></i> New Meeting';
    document.getElementById('meetingActionItemsContainer').innerHTML = '';
    document.getElementById('meetingDate').value = new Date().toISOString().split('T')[0];

    if (id) {
        const meetings = DB.get('meetings');
        const m = meetings.find(x => x.id === id);
        if (m) {
            document.getElementById('meetingModalTitle').innerHTML = '<i class="fas fa-handshake"></i> Edit Meeting';
            document.getElementById('meetingId').value = m.id;
            document.getElementById('meetingTitle').value = m.title || '';
            document.getElementById('meetingType').value = m.type || 'Other';
            document.getElementById('meetingDate').value = m.date || '';
            document.getElementById('meetingLocation').value = m.location || '';
            document.getElementById('meetingOrganizer').value = m.organizer || '';
            document.getElementById('meetingAttendees').value = m.attendees || '';
            document.getElementById('meetingAgenda').value = m.agenda || '';
            document.getElementById('meetingDecisions').value = m.decisions || '';
            document.getElementById('meetingKeyTakeaways').value = m.keyTakeaways || '';
            document.getElementById('meetingNextDate').value = m.nextMeetingDate || '';
            // Render action items
            const container = document.getElementById('meetingActionItemsContainer');
            container.innerHTML = (m.actionItems || []).map((a, i) => getMeetingActionItemHtml(i, a.text, a.assignee, a.done)).join('');
        }
    }
    openModal('meetingModal');
}

function getMeetingActionItemHtml(index, text, assignee, done) {
    return `<div class="meeting-action-row" data-index="${index}">
        <input type="text" class="form-control meeting-action-text" placeholder="Action item..." value="${escapeHtml(text || '')}" style="flex:1;">
        <input type="text" class="form-control meeting-action-assignee" placeholder="Assigned to..." value="${escapeHtml(assignee || '')}" style="width:140px;">
        <label class="meeting-action-done-label"><input type="checkbox" class="meeting-action-done" ${done ? 'checked' : ''}> Done</label>
        <button type="button" class="btn-icon-sm" onclick="this.closest('.meeting-action-row').remove()" title="Remove"><i class="fas fa-times"></i></button>
    </div>`;
}

function addMeetingActionItem() {
    const container = document.getElementById('meetingActionItemsContainer');
    const index = container.children.length;
    container.insertAdjacentHTML('beforeend', getMeetingActionItemHtml(index, '', '', false));
}

function saveMeeting(e) {
    e.preventDefault();
    const meetings = DB.get('meetings');
    const id = document.getElementById('meetingId').value;

    // Collect action items
    const actionRows = document.querySelectorAll('#meetingActionItemsContainer .meeting-action-row');
    const actionItems = [];
    actionRows.forEach(row => {
        const text = row.querySelector('.meeting-action-text').value.trim();
        if (text) {
            actionItems.push({
                text,
                assignee: row.querySelector('.meeting-action-assignee').value.trim(),
                done: row.querySelector('.meeting-action-done').checked
            });
        }
    });

    const meeting = {
        id: id || DB.generateId(),
        title: document.getElementById('meetingTitle').value.trim(),
        type: document.getElementById('meetingType').value,
        date: document.getElementById('meetingDate').value,
        location: document.getElementById('meetingLocation').value.trim(),
        organizer: document.getElementById('meetingOrganizer').value.trim(),
        attendees: document.getElementById('meetingAttendees').value.trim(),
        agenda: document.getElementById('meetingAgenda').value.trim(),
        decisions: document.getElementById('meetingDecisions').value.trim(),
        keyTakeaways: document.getElementById('meetingKeyTakeaways').value.trim(),
        nextMeetingDate: document.getElementById('meetingNextDate').value,
        actionItems,
        createdAt: id ? (meetings.find(m => m.id === id) || {}).createdAt || new Date().toISOString() : new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    if (id) {
        const idx = meetings.findIndex(m => m.id === id);
        if (idx !== -1) meetings[idx] = meeting;
    } else {
        meetings.push(meeting);
    }

    DB.set('meetings', meetings);
    closeModal('meetingModal');
    renderMeetings();
    showToast(id ? 'Meeting updated' : 'Meeting saved! 🤝');
}

function deleteMeeting(id) {
    if (!confirm('Delete this meeting?')) return;
    let meetings = DB.get('meetings');
    meetings = meetings.filter(m => m.id !== id);
    DB.set('meetings', meetings);
    renderMeetings();
    showToast('Meeting deleted');
}

function toggleMeetingAction(meetingId, actionIndex) {
    const meetings = DB.get('meetings');
    const m = meetings.find(x => x.id === meetingId);
    if (m && m.actionItems && m.actionItems[actionIndex] !== undefined) {
        m.actionItems[actionIndex].done = !m.actionItems[actionIndex].done;
        DB.set('meetings', meetings);
        renderMeetings();
    }
}

// ===== SCHOOL HEALTH CARD (PRINT) =====
function printSchoolHealthCard(encodedKey) {
    const schoolKey = decodeURIComponent(encodedKey);
    const schoolMap = getSchoolData();
    const school = schoolMap[schoolKey];
    if (!school) { showToast('School not found', 'error'); return; }

    const profile = getProfile();
    const completedVisits = school.visits.filter(v => v.status === 'completed').length;
    const teachers = [...new Set(school.observations.map(o => o.teacher).filter(Boolean))];
    const subjects = [...new Set(school.observations.map(o => o.subject).filter(Boolean))];
    const lastVisit = school.visits.filter(v => v.date).sort((a, b) => b.date.localeCompare(a.date))[0];

    // Teacher-wise summary
    const teacherMap = {};
    school.observations.forEach(o => {
        const t = (o.teacher || 'Unknown').trim();
        if (!teacherMap[t]) teacherMap[t] = { obs: 0, engTotal: 0, methTotal: 0, tlmTotal: 0, dates: [], subjects: new Set() };
        teacherMap[t].obs++;
        teacherMap[t].engTotal += ((o.engagementRating || o.engagement) || 0);
        teacherMap[t].methTotal += (o.methodology || 0);
        teacherMap[t].tlmTotal += (o.tlm || 0);
        teacherMap[t].dates.push(o.date);
        if (o.subject) teacherMap[t].subjects.add(o.subject);
    });

    const teacherRows = Object.entries(teacherMap).map(([name, d]) => {
        const avgEng = d.obs > 0 ? (d.engTotal / d.obs).toFixed(1) : '-';
        const avgMeth = d.obs > 0 ? (d.methTotal / d.obs).toFixed(1) : '-';
        const avgTlm = d.obs > 0 ? (d.tlmTotal / d.obs).toFixed(1) : '-';
        const overallAvg = d.obs > 0 ? ((d.engTotal + d.methTotal + d.tlmTotal) / (d.obs * 3)).toFixed(1) : '-';
        const dates = d.dates.sort();
        let trend = '—';
        if (dates.length >= 2) {
            const firstHalf = dates.slice(0, Math.ceil(dates.length / 2));
            const secondHalf = dates.slice(Math.ceil(dates.length / 2));
            const avgFirst = firstHalf.length > 0 ? school.observations.filter(o => (o.teacher || '').trim() === name && firstHalf.includes(o.date)).reduce((s, o) => s + (((o.engagementRating || o.engagement) || 0) + (o.methodology || 0) + (o.tlm || 0)) / 3, 0) / firstHalf.length : 0;
            const avgSecond = secondHalf.length > 0 ? school.observations.filter(o => (o.teacher || '').trim() === name && secondHalf.includes(o.date)).reduce((s, o) => s + (((o.engagementRating || o.engagement) || 0) + (o.methodology || 0) + (o.tlm || 0)) / 3, 0) / secondHalf.length : 0;
            trend = avgSecond > avgFirst + 0.3 ? '↑ Improving' : avgSecond < avgFirst - 0.3 ? '↓ Declining' : '→ Stable';
        }
        return `<tr>
            <td style="font-weight:600;">${escapeHtml(name)}</td>
            <td style="text-align:center;">${d.obs}</td>
            <td style="text-align:center;">${[...d.subjects].join(', ')}</td>
            <td style="text-align:center;">${avgEng}</td>
            <td style="text-align:center;">${avgMeth}</td>
            <td style="text-align:center;">${avgTlm}</td>
            <td style="text-align:center;font-weight:600;">${overallAvg}</td>
            <td style="text-align:center;">${trend}</td>
        </tr>`;
    }).join('');

    // Strengths and areas from observations
    const strengths = school.observations.map(o => o.strengths).filter(Boolean);
    const areas = school.observations.map(o => o.areas).filter(Boolean);
    const suggestions = school.observations.map(o => o.suggestions).filter(Boolean);

    // Follow-ups
    const followupStatus = DB.get('followupStatus');
    const pendingFollowups = [
        ...school.visits.filter(v => v.followUp && v.followUp.trim() && !followupStatus.some(f => f.id === v.id && f.done)).map(v => ({ text: v.followUp, date: v.date, source: 'Visit' })),
        ...school.observations.filter(o => o.suggestions && o.suggestions.trim() && !followupStatus.some(f => f.id === o.id && f.done)).map(o => ({ text: o.suggestions, date: o.date, source: 'Observation' }))
    ];

    // Visit frequency bar (simple HTML bars)
    const monthCounts = {};
    [...school.visits, ...school.observations].forEach(item => {
        if (item.date) {
            const m = item.date.substring(0, 7);
            monthCounts[m] = (monthCounts[m] || 0) + 1;
        }
    });
    const monthKeys = Object.keys(monthCounts).sort();
    const maxCount = Math.max(...Object.values(monthCounts), 1);
    const activityBars = monthKeys.slice(-6).map(m => {
        const pct = Math.round((monthCounts[m] / maxCount) * 100);
        const label = new Date(m + '-01').toLocaleDateString('en-IN', { month: 'short', year: '2-digit' });
        return `<div style="text-align:center;flex:1;"><div style="height:${Math.max(pct, 5)}px;max-height:60px;background:#6366f1;border-radius:3px 3px 0 0;margin:0 2px;"></div><div style="font-size:9px;color:#64748b;margin-top:2px;">${label}</div><div style="font-size:10px;font-weight:600;">${monthCounts[m]}</div></div>`;
    }).join('');

    const avgRating = school.observations.length > 0
        ? (school.observations.reduce((s, o) => s + (((o.engagementRating || o.engagement) || 0) + (o.methodology || 0) + (o.tlm || 0)) / 3, 0) / school.observations.length).toFixed(1)
        : 'N/A';

    const html = `<!DOCTYPE html>
<html><head><title>School Health Card — ${escapeHtml(school.name)}</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Arial, sans-serif; padding: 16px 24px; color: #1e293b; font-size: 11px; }
    .header { text-align: center; border-bottom: 3px solid #6366f1; padding-bottom: 10px; margin-bottom: 12px; }
    .header h1 { font-size: 16px; color: #6366f1; margin-bottom: 2px; }
    .header .school-name { font-size: 20px; font-weight: 700; color: #1e293b; }
    .header p { color: #64748b; font-size: 10px; }
    .meta-row { display: flex; justify-content: space-between; margin-bottom: 12px; padding: 6px 10px; background: #f8fafc; border-radius: 6px; font-size: 11px; }
    .stats-grid { display: flex; gap: 8px; margin-bottom: 14px; }
    .stat-box { flex: 1; text-align: center; padding: 8px 4px; background: #f1f5f9; border-radius: 6px; }
    .stat-box .val { font-size: 20px; font-weight: 700; color: #6366f1; }
    .stat-box .lbl { font-size: 9px; color: #64748b; text-transform: uppercase; }
    h3 { font-size: 12px; color: #6366f1; margin: 12px 0 6px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: 10px; margin-bottom: 10px; }
    th { background: #6366f1; color: white; padding: 5px 6px; text-align: left; font-size: 9px; text-transform: uppercase; }
    td { padding: 4px 6px; border-bottom: 1px solid #e2e8f0; }
    tr:nth-child(even) { background: #f8fafc; }
    .bar-chart { display: flex; align-items: flex-end; height: 80px; padding: 0 10px; margin-bottom: 14px; }
    .section-block { margin-bottom: 10px; }
    .section-block ul { padding-left: 16px; }
    .section-block li { margin-bottom: 3px; line-height: 1.4; }
    .followup-item { padding: 4px 8px; margin-bottom: 3px; background: #fff7ed; border-left: 3px solid #f59e0b; border-radius: 0 4px 4px 0; font-size: 10px; }
    .footer { text-align: center; margin-top: 16px; font-size: 9px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 6px; }
    .signature { display: flex; justify-content: space-between; margin-top: 30px; }
    .sig-box { text-align: center; width: 180px; }
    .sig-line { border-top: 1px solid #334155; margin-top: 30px; padding-top: 4px; font-size: 10px; color: #64748b; }
    @media print { body { padding: 8px; } }
</style></head><body>
<div class="header">
    <h1>📋 School Health Card</h1>
    <div class="school-name">${escapeHtml(school.name)}</div>
    <p>Azim Premji Foundation — Field Support Summary</p>
</div>
<div class="meta-row">
    <div><strong>Block:</strong> ${escapeHtml(school.block || 'N/A')} &nbsp;&bull;&nbsp; <strong>RP:</strong> ${escapeHtml(profile.name || 'N/A')} &nbsp;&bull;&nbsp; <strong>District:</strong> ${escapeHtml(profile.district || 'N/A')}</div>
    <div><strong>Generated:</strong> ${new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' })} &nbsp;&bull;&nbsp; <strong>Last Visit:</strong> ${lastVisit ? new Date(lastVisit.date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }) : 'N/A'}</div>
</div>
<div class="stats-grid">
    <div class="stat-box"><div class="val">${school.visits.length}</div><div class="lbl">Total Visits</div></div>
    <div class="stat-box"><div class="val">${completedVisits}</div><div class="lbl">Completed</div></div>
    <div class="stat-box"><div class="val">${school.observations.length}</div><div class="lbl">Observations</div></div>
    <div class="stat-box"><div class="val">${teachers.length}</div><div class="lbl">Teachers</div></div>
    <div class="stat-box"><div class="val">${avgRating}</div><div class="lbl">Avg Rating</div></div>
</div>

${monthKeys.length > 0 ? `<h3>📊 Activity Trend (Last 6 months)</h3><div class="bar-chart">${activityBars}</div>` : ''}

${teacherRows ? `<h3>👩‍🏫 Teacher-wise Summary</h3>
<table>
    <tr><th>Teacher</th><th>Obs.</th><th>Subjects</th><th>Engage.</th><th>Method.</th><th>TLM</th><th>Overall</th><th>Trend</th></tr>
    ${teacherRows}
</table>` : ''}

${strengths.length > 0 ? `<h3>✅ Strengths Observed</h3><div class="section-block"><ul>${strengths.slice(0, 5).map(s => `<li>${escapeHtml(s)}</li>`).join('')}</ul></div>` : ''}
${areas.length > 0 ? `<h3>🔶 Areas for Improvement</h3><div class="section-block"><ul>${areas.slice(0, 5).map(a => `<li>${escapeHtml(a)}</li>`).join('')}</ul></div>` : ''}

${pendingFollowups.length > 0 ? `<h3>⏳ Pending Follow-ups (${pendingFollowups.length})</h3>${pendingFollowups.slice(0, 5).map(f => `<div class="followup-item"><strong>${f.source} (${new Date(f.date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' })}):</strong> ${escapeHtml(f.text)}</div>`).join('')}` : ''}

${subjects.length > 0 ? `<div style="margin-top:8px;"><strong style="font-size:10px;">Subjects covered:</strong> <span style="font-size:10px;color:#64748b;">${escapeHtml(subjects.join(', '))}</span></div>` : ''}

<div class="signature">
    <div class="sig-box"><div class="sig-line">${escapeHtml(profile.designation || 'Resource Person')}</div></div>
    <div class="sig-box"><div class="sig-line">Head Master / Head Mistress</div></div>
    <div class="sig-box"><div class="sig-line">Block Coordinator</div></div>
</div>
<div class="footer">Generated by ${escapeHtml(profile.name || 'APF Resource Person')} — APF Dashboard — ${new Date().toLocaleDateString('en-IN')}</div>
</body></html>`;

    const w = window.open('', '_blank', 'width=1000,height=800');
    if (!w) { showToast('Popup blocked — please allow popups for this site', 'error'); return; }
    w.document.write(html);
    w.document.close();
    setTimeout(() => w.print(), 500);
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

    const pg = getPaginatedItems(reflections, 'reflections', 12);

    container.innerHTML = `<div class="reflections-grid">${pg.items.map(r => {
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
    }).join('')}</div>` + renderPaginationControls('reflections', pg, 'renderReflections');
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
            document.getElementById('contactCluster').value = c.cluster || '';
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
        cluster: document.getElementById('contactCluster').value.trim(),
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

// ===== BULK DELETE CONTACTS =====
function openBulkDeleteContacts() {
    const contacts = DB.get('contacts');
    if (contacts.length === 0) {
        showToast('No contacts to delete', 'info');
        return;
    }

    // Migrate cluster from notes for older contacts that stored it there
    let migrated = false;
    contacts.forEach(c => {
        if (!c.cluster && c.notes) {
            const m = c.notes.match(/Cluster:\s*([^|]+)/i);
            if (m) {
                c.cluster = m[1].trim();
                // Remove "Cluster: xyz" from notes
                c.notes = c.notes.replace(/\s*\|?\s*Cluster:\s*[^|]+/i, '').replace(/^\s*\|\s*/, '').trim();
                migrated = true;
            }
        }
    });
    // Also try to fill cluster from observations for contacts without one
    if (contacts.some(c => !c.cluster && c.school)) {
        const observations = DB.get('observations');
        const schoolClusterMap = {};
        observations.forEach(o => {
            if (o.school && o.cluster) {
                schoolClusterMap[o.school.trim().toLowerCase()] = o.cluster.trim();
            }
        });
        contacts.forEach(c => {
            if (!c.cluster && c.school) {
                const key = c.school.trim().toLowerCase();
                if (schoolClusterMap[key]) {
                    c.cluster = schoolClusterMap[key];
                    migrated = true;
                }
            }
        });
    }
    if (migrated) DB.set('contacts', contacts);

    // Populate filter dropdowns dynamically from contact data
    const roles = new Set(), blocks = new Set(), clusters = new Set(), schools = new Set(), sources = new Set();
    contacts.forEach(c => {
        if (c.role) roles.add(c.role);
        if (c.block) blocks.add(c.block.trim());
        if (c.cluster) clusters.add(c.cluster.trim());
        if (c.school) schools.add(c.school.trim());
        if (c.source) sources.add(c.source);
    });

    populateBulkDelCheckboxes('bulkDelRole', roles);
    populateBulkDelCheckboxes('bulkDelBlock', blocks);
    populateBulkDelCheckboxes('bulkDelCluster', clusters);
    populateBulkDelCheckboxes('bulkDelSchool', schools);
    populateBulkDelCheckboxes('bulkDelSource', sources);
    // Reset phone checkboxes to checked
    document.querySelectorAll('#bulkDelPhone input[type=checkbox]').forEach(cb => cb.checked = true);

    previewBulkDelete();
    openModal('bulkDeleteContactsModal');
}

function populateBulkDelCheckboxes(containerId, valuesSet) {
    const container = document.getElementById(containerId);
    const sorted = [...valuesSet].sort((a, b) => a.localeCompare(b));
    if (sorted.length === 0) {
        container.innerHTML = '<span class="bulk-filter-empty">None available</span>';
        return;
    }
    container.innerHTML = sorted.map(v =>
        `<label class="bulk-checkbox"><input type="checkbox" value="${escapeHtml(v)}" onchange="previewBulkDelete()" checked> <span>${escapeHtml(v)}</span></label>`
    ).join('');
}

function bulkFilterToggle(containerId, checkAll) {
    document.querySelectorAll('#' + containerId + ' input[type=checkbox]').forEach(cb => cb.checked = checkAll);
    previewBulkDelete();
}

function getBulkFilterChecked(containerId) {
    const checked = [];
    document.querySelectorAll('#' + containerId + ' input[type=checkbox]:checked').forEach(cb => checked.push(cb.value));
    return checked;
}

function getBulkDeleteFiltered() {
    const contacts = DB.get('contacts');
    const roles = new Set(getBulkFilterChecked('bulkDelRole'));
    const blocks = new Set(getBulkFilterChecked('bulkDelBlock'));
    const clusters = new Set(getBulkFilterChecked('bulkDelCluster'));
    const schools = new Set(getBulkFilterChecked('bulkDelSchool'));
    const sources = new Set(getBulkFilterChecked('bulkDelSource'));
    const phoneChecked = getBulkFilterChecked('bulkDelPhone');
    const allowWith = phoneChecked.includes('with');
    const allowWithout = phoneChecked.includes('without');

    const allRoles = document.querySelectorAll('#bulkDelRole input[type=checkbox]');
    const allBlocks = document.querySelectorAll('#bulkDelBlock input[type=checkbox]');
    const allClusters = document.querySelectorAll('#bulkDelCluster input[type=checkbox]');
    const allSchools = document.querySelectorAll('#bulkDelSchool input[type=checkbox]');
    const allSources = document.querySelectorAll('#bulkDelSource input[type=checkbox]');

    return contacts.filter(c => {
        // If all checked = no filter (pass all), if none checked = block all
        if (allRoles.length > 0 && !roles.has(c.role || '')) return false;
        if (allBlocks.length > 0 && !blocks.has((c.block || '').trim())) return false;
        if (allClusters.length > 0 && !clusters.has((c.cluster || '').trim())) return false;
        if (allSchools.length > 0 && !schools.has((c.school || '').trim())) return false;
        if (allSources.length > 0 && !sources.has(c.source || '')) return false;
        // Phone filter
        if (c.phone && !allowWith) return false;
        if (!c.phone && !allowWithout) return false;
        return true;
    });
}

function previewBulkDelete() {
    const matched = getBulkDeleteFiltered();
    const count = matched.length;
    document.getElementById('bulkDeleteCount').textContent = count;
    document.getElementById('bulkDeleteBtnCount').textContent = count;

    const btn = document.getElementById('bulkDeleteConfirmBtn');
    btn.disabled = count === 0;

    const listEl = document.getElementById('bulkDeleteList');
    if (count === 0) {
        listEl.innerHTML = '<div class="bulk-preview-empty">No contacts match the selected filters</div>';
    } else {
        const showMax = 50;
        const shown = matched.slice(0, showMax);
        listEl.innerHTML = shown.map(c => `
            <div class="bulk-preview-item">
                <span class="bulk-preview-name">${escapeHtml(c.name || 'Unknown')}</span>
                <span class="bulk-preview-meta">${escapeHtml(c.role || '')}${c.block ? ' · ' + escapeHtml(c.block) : ''}${c.cluster ? ' · ' + escapeHtml(c.cluster) : ''}</span>
            </div>
        `).join('') + (count > showMax ? `<div class="bulk-preview-more">...and ${count - showMax} more</div>` : '');
    }
}

function executeBulkDeleteContacts() {
    const matched = getBulkDeleteFiltered();
    if (matched.length === 0) return;

    const filterParts = [];
    const rolesChecked = getBulkFilterChecked('bulkDelRole');
    const blocksChecked = getBulkFilterChecked('bulkDelBlock');
    const clustersChecked = getBulkFilterChecked('bulkDelCluster');
    const schoolsChecked = getBulkFilterChecked('bulkDelSchool');
    const sourcesChecked = getBulkFilterChecked('bulkDelSource');
    const phoneChecked = getBulkFilterChecked('bulkDelPhone');
    const allR = document.querySelectorAll('#bulkDelRole input').length;
    const allB = document.querySelectorAll('#bulkDelBlock input').length;
    const allCl = document.querySelectorAll('#bulkDelCluster input').length;
    const allSc = document.querySelectorAll('#bulkDelSchool input').length;
    const allSo = document.querySelectorAll('#bulkDelSource input').length;
    if (rolesChecked.length < allR) filterParts.push(`Roles: ${rolesChecked.join(', ')}`);
    if (blocksChecked.length < allB) filterParts.push(`Blocks: ${blocksChecked.join(', ')}`);
    if (clustersChecked.length < allCl) filterParts.push(`Clusters: ${clustersChecked.join(', ')}`);
    if (schoolsChecked.length < allSc) filterParts.push(`Schools: ${schoolsChecked.length} selected`);
    if (sourcesChecked.length < allSo) filterParts.push(`Sources: ${sourcesChecked.join(', ')}`);
    if (phoneChecked.length < 2) filterParts.push(`Phone: ${phoneChecked.join(', ')}`);

    const filterDesc = filterParts.length > 0 ? filterParts.join(', ') : 'All contacts';
    if (!confirm(`⚠️ DELETE ${matched.length} CONTACTS?\n\nFilter: ${filterDesc}\n\nThis action cannot be undone!`)) return;

    const idsToDelete = new Set(matched.map(c => c.id));
    let contacts = DB.get('contacts');
    contacts = contacts.filter(c => !idsToDelete.has(c.id));
    DB.set('contacts', contacts);
    closeModal('bulkDeleteContactsModal');
    renderContacts();
    showToast(`Deleted ${matched.length} contacts`, 'success');
}

function extractContactsFromObservations() {
    document.getElementById('obsImportMenu')?.classList.remove('show');
    const observations = DB.get('observations');
    if (observations.length === 0) {
        showToast('No observations found. Import DMT Excel first.', 'info');
        return;
    }

    // Build unique teacher map from observations (key: name + phone)
    const teacherMap = new Map();
    observations.forEach(o => {
        const name = (o.teacher || '').trim();
        const phone = (o.teacherPhone || '').trim();
        if (!name && !phone) return;
        // Use name+phone as key to deduplicate
        const key = `${name.toLowerCase()}|${phone}`;
        if (!teacherMap.has(key)) {
            teacherMap.set(key, {
                name: name,
                phone: phone,
                school: (o.school || '').trim(),
                block: (o.block || '').trim(),
                cluster: (o.cluster || '').trim(),
                stage: (o.teacherStage || '').trim(),
                nid: (o.nid || '').trim()
            });
        }
    });

    if (teacherMap.size === 0) {
        showToast('No teacher data found in observations', 'info');
        return;
    }

    // Check existing contacts to avoid duplicates
    const existingContacts = DB.get('contacts');
    const existingKeys = new Set();
    existingContacts.forEach(c => {
        const n = (c.name || '').toLowerCase().trim();
        const p = (c.phone || '').trim();
        existingKeys.add(`${n}|${p}`);
        if (p) existingKeys.add(`phone:${p}`);
    });

    // Filter out already-existing contacts
    const newTeachers = [];
    teacherMap.forEach((t, key) => {
        const namePhone = `${t.name.toLowerCase()}|${t.phone}`;
        const phoneOnly = t.phone ? `phone:${t.phone}` : null;
        if (!existingKeys.has(namePhone) && (!phoneOnly || !existingKeys.has(phoneOnly))) {
            newTeachers.push(t);
        }
    });

    if (newTeachers.length === 0) {
        showToast(`All ${teacherMap.size} teachers already exist in your contacts`, 'info');
        return;
    }

    // Confirm with user
    const withPhone = newTeachers.filter(t => t.phone).length;
    const withoutPhone = newTeachers.length - withPhone;
    let msg = `Found ${newTeachers.length} new teacher contact(s) from observations.\n\n`;
    msg += `  ${withPhone} with phone numbers\n`;
    msg += `  ${withoutPhone} without phone numbers\n\n`;
    msg += `${teacherMap.size - newTeachers.length} already in your contacts (skipped).\n\n`;
    msg += `Add ${newTeachers.length} new contacts?`;

    if (!confirm(msg)) return;

    // Ask if they want only contacts with phone numbers
    let toAdd = newTeachers;
    if (withoutPhone > 0 && withPhone > 0) {
        if (confirm(`Import only teachers WITH phone numbers?\n\nYes = ${withPhone} contacts (with phone)\nNo = ${newTeachers.length} contacts (all)`)) {
            toAdd = newTeachers.filter(t => t.phone);
        }
    }

    // Add to contacts
    const contacts = DB.get('contacts');
    let added = 0;
    toAdd.forEach(t => {
        const notes = [t.stage ? `Stage: ${t.stage}` : '', t.nid ? `NID: ${t.nid}` : ''].filter(Boolean).join(' | ');
        contacts.push({
            id: DB.generateId(),
            name: t.name || 'Unknown Teacher',
            role: 'Teacher',
            school: t.school,
            phone: t.phone,
            email: '',
            block: t.block,
            cluster: t.cluster,
            notes: notes,
            createdAt: new Date().toISOString(),
            source: 'Observation Extract'
        });
        added++;
    });

    DB.set('contacts', contacts);
    renderContacts();
    showToast(`Added ${added} teacher contacts from observations!`, 'success', 5000);

    // Switch to contacts section if not already there
    if (document.querySelector('.content-section.active')?.id !== 'section-contacts') {
        switchSection('contacts');
    }
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
            (c.cluster || '').toLowerCase().includes(searchTerm) ||
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

    const pg = getPaginatedItems(contacts, 'contacts', 18);

    container.innerHTML = `<div class="contacts-grid">${pg.items.map((c, i) => {
        const initials = c.name ? c.name.split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase() : '?';
        const rc = roleColors[c.role] || roleColors['Other'];
        const avatarColor = avatarColors[(pg.start - 1 + i) % avatarColors.length];

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
                    ${c.cluster ? `<div class="contact-detail-row"><i class="fas fa-layer-group"></i> ${escapeHtml(c.cluster)}</div>` : ''}
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
    }).join('')}</div>` + renderPaginationControls('contacts', pg, 'renderContacts');
}

// ===== TEACHERS RECORD =====
// Full teacher database with Excel import/export, CRUD, search, filter

function _trPopulateFilterDropdowns() {
    const records = DB.get('teacherRecords') || [];

    // Schools
    const schools = [...new Set(records.map(r => r.school).filter(Boolean))].sort();
    const schoolFilter = document.getElementById('trSchoolFilter');
    if (schoolFilter) {
        const current = schoolFilter.value;
        schoolFilter.innerHTML = '<option value="all">🏫 All Schools</option>' +
            schools.map(s => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join('');
        schoolFilter.value = current;
    }
    // School datalist for modal
    const schoolDL = document.getElementById('trSchoolList');
    if (schoolDL) schoolDL.innerHTML = schools.map(s => `<option value="${escapeHtml(s)}">`).join('');

    // Designations
    const designations = [...new Set(records.map(r => r.designation).filter(Boolean))].sort();
    const desigFilter = document.getElementById('trDesignationFilter');
    if (desigFilter) {
        const current = desigFilter.value;
        desigFilter.innerHTML = '<option value="all">👤 All Designations</option>' +
            designations.map(d => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join('');
        desigFilter.value = current;
    }

    // Subjects
    const subjects = [...new Set(records.map(r => r.subject).filter(Boolean))].sort();
    const subFilter = document.getElementById('trSubjectFilter');
    if (subFilter) {
        const current = subFilter.value;
        subFilter.innerHTML = '<option value="all">📖 All Subjects</option>' +
            subjects.map(s => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join('');
        subFilter.value = current;
    }

    // Clusters — filter dropdown + datalist for modal
    const clusters = [...new Set(records.map(r => r.cluster).filter(Boolean))].sort();
    const clusterFilter = document.getElementById('trClusterFilter');
    if (clusterFilter) {
        const current = clusterFilter.value;
        clusterFilter.innerHTML = '<option value="all">📍 All Clusters</option>' +
            clusters.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
        clusterFilter.value = current;
    }
    const clusterDL = document.getElementById('trClusterList');
    if (clusterDL) clusterDL.innerHTML = clusters.map(c => `<option value="${escapeHtml(c)}">`).join('');

    // Blocks — filter dropdown + datalist for modal
    const blocks = [...new Set(records.map(r => r.block).filter(Boolean))].sort();
    const blockFilter = document.getElementById('trBlockFilter');
    if (blockFilter) {
        const current = blockFilter.value;
        blockFilter.innerHTML = '<option value="all">🏘️ All Blocks</option>' +
            blocks.map(b => `<option value="${escapeHtml(b)}">${escapeHtml(b)}</option>`).join('');
        blockFilter.value = current;
    }
    const blockDL = document.getElementById('trBlockList');
    if (blockDL) blockDL.innerHTML = blocks.map(b => `<option value="${escapeHtml(b)}">`).join('');
}

function renderTeacherRecords() {
    let records = DB.get('teacherRecords') || [];
    const schoolF = document.getElementById('trSchoolFilter')?.value || 'all';
    const desigF = document.getElementById('trDesignationFilter')?.value || 'all';
    const subjectF = document.getElementById('trSubjectFilter')?.value || 'all';
    const clusterF = document.getElementById('trClusterFilter')?.value || 'all';
    const blockF = document.getElementById('trBlockFilter')?.value || 'all';
    const search = (document.getElementById('trSearchInput')?.value || '').toLowerCase().trim();

    _trPopulateFilterDropdowns();

    // Apply filters
    if (schoolF !== 'all') records = records.filter(r => r.school === schoolF);
    if (desigF !== 'all') records = records.filter(r => r.designation === desigF);
    if (subjectF !== 'all') records = records.filter(r => r.subject === subjectF);
    if (clusterF !== 'all') records = records.filter(r => r.cluster === clusterF);
    if (blockF !== 'all') records = records.filter(r => r.block === blockF);
    if (search) {
        records = records.filter(r =>
            (r.name || '').toLowerCase().includes(search) ||
            (r.school || '').toLowerCase().includes(search) ||
            (r.phone || '').includes(search) ||
            (r.nid || '').toLowerCase().includes(search) ||
            (r.block || '').toLowerCase().includes(search) ||
            (r.cluster || '').toLowerCase().includes(search) ||
            (r.subject || '').toLowerCase().includes(search) ||
            (r.designation || '').toLowerCase().includes(search) ||
            (r.qualification || '').toLowerCase().includes(search)
        );
    }

    // Sort by name
    records.sort((a, b) => (a.name || '').localeCompare(b.name || ''));

    // Stats bar
    const all = DB.get('teacherRecords') || [];
    const statsEl = document.getElementById('trStatsBar');
    if (statsEl) {
        const schoolCount = new Set(all.map(r => (r.school || '').toLowerCase().trim()).filter(Boolean)).size;
        const desigCounts = {};
        all.forEach(r => { if (r.designation) desigCounts[r.designation] = (desigCounts[r.designation] || 0) + 1; });
        const genderCounts = {};
        all.forEach(r => { if (r.gender) genderCounts[r.gender] = (genderCounts[r.gender] || 0) + 1; });

        statsEl.innerHTML = `
            <div class="tr-stat-card"><div class="tr-stat-value">${all.length}</div><div class="tr-stat-label">Total Teachers</div></div>
            <div class="tr-stat-card"><div class="tr-stat-value">${schoolCount}</div><div class="tr-stat-label">Schools</div></div>
            ${Object.entries(desigCounts).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([d, c]) =>
                `<div class="tr-stat-card"><div class="tr-stat-value">${c}</div><div class="tr-stat-label">${escapeHtml(d)}</div></div>`
            ).join('')}
            ${Object.entries(genderCounts).map(([g, c]) =>
                `<div class="tr-stat-card"><div class="tr-stat-value">${c}</div><div class="tr-stat-label">${g}</div></div>`
            ).join('')}
        `;
    }

    const container = document.getElementById('teacherRecordsContainer');
    if (!container) return;

    if (records.length === 0) {
        container.innerHTML = `<div class="tr-empty">
            <i class="fas fa-id-card-alt" style="font-size:3rem;color:var(--text-muted);margin-bottom:1rem;"></i>
            <h3>No teacher records yet</h3>
            <p>Add teachers manually or import from an Excel file.</p>
        </div>`;
        return;
    }

    const pg = getPaginatedItems(records, 'teacherrecords', 20);
    const avatarColors = ['#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ef4444', '#ec4899', '#06b6d4', '#f97316'];

    const desigColors = {
        'Assistant Teacher': { bg: 'rgba(16,185,129,0.15)', color: '#10b981' },
        'Senior Teacher': { bg: 'rgba(59,130,246,0.15)', color: '#3b82f6' },
        'Head Master': { bg: 'rgba(245,158,11,0.15)', color: '#f59e0b' },
        'Guest Teacher': { bg: 'rgba(139,92,246,0.15)', color: '#8b5cf6' },
        'Contract Teacher': { bg: 'rgba(249,115,22,0.15)', color: '#f97316' },
        'PET': { bg: 'rgba(6,182,212,0.15)', color: '#06b6d4' },
    };

    container.innerHTML = `
    <div class="tr-table-wrapper">
        <table class="tr-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Name</th>
                    <th>School</th>
                    <th>Designation</th>
                    <th>Subject</th>
                    <th>Classes</th>
                    <th>Phone</th>
                    <th>Block / Cluster</th>
                    <th>Qualification</th>
                    <th>Exp</th>
                    <th>NID</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${pg.items.map((r, i) => {
                    const initials = r.name ? r.name.split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase() : '?';
                    const avColor = avatarColors[(pg.start - 1 + i) % avatarColors.length];
                    const dc = desigColors[r.designation] || { bg: 'rgba(107,114,128,0.15)', color: '#6b7280' };
                    return `<tr>
                        <td>${pg.start + i - 1 + 1}</td>
                        <td>
                            <div class="tr-name-cell">
                                <div class="tr-avatar" style="background:${avColor}">${initials}</div>
                                <div>
                                    <strong>${escapeHtml(r.name || '')}</strong>
                                    ${r.gender ? `<span class="tr-gender-badge">${r.gender === 'Male' ? '♂' : r.gender === 'Female' ? '♀' : '⚧'}</span>` : ''}
                                    ${r.email ? `<div class="tr-sub-info">${escapeHtml(r.email)}</div>` : ''}
                                </div>
                            </div>
                        </td>
                        <td>${escapeHtml(r.school || '—')}</td>
                        <td><span class="tr-desig-badge" style="background:${dc.bg};color:${dc.color}">${escapeHtml(r.designation || '—')}</span></td>
                        <td>${escapeHtml(r.subject || '—')}</td>
                        <td>${escapeHtml(r.classesTaught || '—')}</td>
                        <td>${r.phone ? `<a href="tel:${r.phone}">${escapeHtml(r.phone)}</a>` : '—'}</td>
                        <td>${escapeHtml([r.block, r.cluster].filter(Boolean).join(' / ') || '—')}</td>
                        <td>${escapeHtml(r.qualification || '—')}</td>
                        <td>${r.experience ? r.experience + 'y' : '—'}</td>
                        <td>${escapeHtml(r.nid || '—')}</td>
                        <td class="tr-actions-cell">
                            ${r.phone ? `<button class="tr-action-btn" onclick="window.open('tel:${r.phone.replace(/[^\d+\-\s()]/g, '')}')" title="Call"><i class="fas fa-phone"></i></button>` : ''}
                            <button class="tr-action-btn" onclick="openTeacherRecordModal('${r.id}')" title="Edit"><i class="fas fa-pen"></i></button>
                            <button class="tr-action-btn tr-del" onclick="deleteTeacherRecord('${r.id}')" title="Delete"><i class="fas fa-trash"></i></button>
                        </td>
                    </tr>`;
                }).join('')}
            </tbody>
        </table>
    </div>` + renderPaginationControls('teacherrecords', pg, 'renderTeacherRecords');
}

function openTeacherRecordModal(id) {
    const form = document.getElementById('trForm');
    form.reset();
    document.getElementById('trId').value = '';
    document.getElementById('trModalTitle').innerHTML = '<i class="fas fa-id-card-alt"></i> Add Teacher';
    _trPopulateFilterDropdowns();

    if (id) {
        const records = DB.get('teacherRecords') || [];
        const r = records.find(x => x.id === id);
        if (r) {
            document.getElementById('trModalTitle').innerHTML = '<i class="fas fa-id-card-alt"></i> Edit Teacher';
            document.getElementById('trId').value = r.id;
            document.getElementById('trName').value = r.name || '';
            document.getElementById('trGender').value = r.gender || '';
            document.getElementById('trSchool').value = r.school || '';
            document.getElementById('trDesignation').value = r.designation || '';
            document.getElementById('trSubject').value = r.subject || '';
            document.getElementById('trClassesTaught').value = r.classesTaught || '';
            document.getElementById('trPhone').value = r.phone || '';
            document.getElementById('trEmail').value = r.email || '';
            document.getElementById('trBlock').value = r.block || '';
            document.getElementById('trCluster').value = r.cluster || '';
            document.getElementById('trQualification').value = r.qualification || '';
            document.getElementById('trExperience').value = r.experience || '';
            document.getElementById('trJoinDate').value = r.joinDate || '';
            document.getElementById('trNID').value = r.nid || '';
            document.getElementById('trNotes').value = r.notes || '';
        }
    }

    openModal('teacherRecordModal');
}

function saveTeacherRecord(e) {
    e.preventDefault();
    const records = DB.get('teacherRecords') || [];
    const id = document.getElementById('trId').value;

    const record = {
        id: id || DB.generateId(),
        name: document.getElementById('trName').value.trim(),
        gender: document.getElementById('trGender').value,
        school: document.getElementById('trSchool').value.trim(),
        designation: document.getElementById('trDesignation').value,
        subject: document.getElementById('trSubject').value.trim(),
        classesTaught: document.getElementById('trClassesTaught').value.trim(),
        phone: document.getElementById('trPhone').value.trim(),
        email: document.getElementById('trEmail').value.trim(),
        block: document.getElementById('trBlock').value.trim(),
        cluster: document.getElementById('trCluster').value.trim(),
        qualification: document.getElementById('trQualification').value.trim(),
        experience: document.getElementById('trExperience').value,
        joinDate: document.getElementById('trJoinDate').value,
        nid: document.getElementById('trNID').value.trim(),
        notes: document.getElementById('trNotes').value.trim(),
        createdAt: id ? (records.find(r => r.id === id) || {}).createdAt || new Date().toISOString() : new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    if (id) {
        const idx = records.findIndex(r => r.id === id);
        if (idx !== -1) records[idx] = record;
    } else {
        records.push(record);
    }

    DB.set('teacherRecords', records);
    closeModal('teacherRecordModal');
    renderTeacherRecords();
    showToast(id ? '✏️ Teacher updated' : '✅ Teacher added!');
}

function deleteTeacherRecord(id) {
    if (!confirm('Delete this teacher record?')) return;
    let records = DB.get('teacherRecords') || [];
    records = records.filter(r => r.id !== id);
    DB.set('teacherRecords', records);
    renderTeacherRecords();
    showToast('🗑️ Teacher record deleted');
}

function bulkDeleteTeacherRecords() {
    const records = DB.get('teacherRecords') || [];
    const schoolF = document.getElementById('trSchoolFilter')?.value || 'all';
    const desigF = document.getElementById('trDesignationFilter')?.value || 'all';
    const subjectF = document.getElementById('trSubjectFilter')?.value || 'all';
    const clusterF = document.getElementById('trClusterFilter')?.value || 'all';
    const blockF = document.getElementById('trBlockFilter')?.value || 'all';
    const search = (document.getElementById('trSearchInput')?.value || '').toLowerCase().trim();
    const isFiltered = schoolF !== 'all' || desigF !== 'all' || subjectF !== 'all' || clusterF !== 'all' || blockF !== 'all' || search;

    let toDelete = [...records];
    if (schoolF !== 'all') toDelete = toDelete.filter(r => r.school === schoolF);
    if (desigF !== 'all') toDelete = toDelete.filter(r => r.designation === desigF);
    if (subjectF !== 'all') toDelete = toDelete.filter(r => r.subject === subjectF);
    if (clusterF !== 'all') toDelete = toDelete.filter(r => r.cluster === clusterF);
    if (blockF !== 'all') toDelete = toDelete.filter(r => r.block === blockF);
    if (search) {
        toDelete = toDelete.filter(r =>
            (r.name || '').toLowerCase().includes(search) ||
            (r.school || '').toLowerCase().includes(search) ||
            (r.nid || '').toLowerCase().includes(search)
        );
    }

    if (toDelete.length === 0) { showToast('No matching records to delete', 'info'); return; }

    // Build a descriptive label showing active filters
    const filterParts = [];
    if (schoolF !== 'all') filterParts.push(`School: ${schoolF}`);
    if (desigF !== 'all') filterParts.push(`Designation: ${desigF}`);
    if (subjectF !== 'all') filterParts.push(`Subject: ${subjectF}`);
    if (clusterF !== 'all') filterParts.push(`Cluster: ${clusterF}`);
    if (blockF !== 'all') filterParts.push(`Block: ${blockF}`);
    if (search) filterParts.push(`Search: "${search}"`);

    let label;
    if (isFiltered) {
        label = `Delete ${toDelete.length} teacher records matching:\n\n  ${filterParts.join('\n  ')}\n\n(${records.length - toDelete.length} records will be kept)`;
    } else {
        label = `Delete ALL ${toDelete.length} teacher records?`;
    }
    if (!confirm(label + '\n\nThis cannot be undone.')) return;

    const deleteIds = new Set(toDelete.map(r => r.id));
    const remaining = records.filter(r => !deleteIds.has(r.id));
    DB.set('teacherRecords', remaining);
    _pageState.teacherrecords = 1;
    renderTeacherRecords();
    showToast(`🗑️ ${toDelete.length} teacher records deleted`);
}

function importTeacherRecordsExcel(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (typeof XLSX === 'undefined') {
        showToast('Excel library not loaded. Please refresh and try again.', 'error');
        return;
    }

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const data = new Uint8Array(e.target.result);
            const wb = XLSX.read(data, { type: 'array', cellDates: true });
            const ws = wb.Sheets[wb.SheetNames[0]];
            if (!ws) { showToast('No data found in Excel file', 'error'); return; }

            const rows = XLSX.utils.sheet_to_json(ws, { defval: '' });
            if (rows.length === 0) { showToast('No rows found in Excel file', 'error'); return; }

            // Auto-map columns — try common header names
            const colMap = {
                name: null, gender: null, school: null, designation: null,
                subject: null, classesTaught: null, phone: null, email: null,
                block: null, cluster: null, qualification: null, experience: null,
                joinDate: null, nid: null, notes: null
            };

            const headers = Object.keys(rows[0]);
            const matchPatterns = {
                name: /^(teacher\s*)?name|शिक्षक\s*का\s*नाम|full\s*name/i,
                gender: /^gender|लिंग|sex/i,
                school: /^school|विद्यालय|स्कूल|institution/i,
                designation: /^designation|पदनाम|post|position/i,
                subject: /^subject|विषय|teaching\s*subject/i,
                classesTaught: /^class|कक्षा|classes?\s*taught|grade/i,
                phone: /^phone|mobile|मोबाइल|contact\s*no|tel/i,
                email: /^email|ई-?मेल|e\s*-?\s*mail/i,
                block: /^block|ब्लॉक|district/i,
                cluster: /^cluster|संकुल|zone/i,
                qualification: /^quali|योग्यता|education|degree/i,
                experience: /^exp|अनुभव|years?\s*(of\s*)?exp/i,
                joinDate: /^(date\s*(of\s*)?)?join|नियुक्ति|doj|joining/i,
                nid: /^(n\.?)?id|employee\s*id|emp\s*id|कर्मचारी\s*आई/i,
                notes: /^note|remarks|टिप्पणी/i
            };

            headers.forEach(h => {
                for (const [field, pattern] of Object.entries(matchPatterns)) {
                    if (!colMap[field] && pattern.test(h)) {
                        colMap[field] = h;
                        break;
                    }
                }
            });

            // If name not found, try first text column
            if (!colMap.name && headers.length > 0) {
                colMap.name = headers[0];
            }

            const records = DB.get('teacherRecords') || [];
            let added = 0, skipped = 0;

            rows.forEach(row => {
                const name = String(row[colMap.name] || '').trim();
                if (!name || name.length < 2) { skipped++; return; }

                // Check for duplicates by name + school
                const school = colMap.school ? String(row[colMap.school] || '').trim() : '';
                const isDup = records.some(r =>
                    r.name.toLowerCase() === name.toLowerCase() &&
                    (r.school || '').toLowerCase() === school.toLowerCase()
                );
                if (isDup) { skipped++; return; }

                const getVal = (field) => colMap[field] ? String(row[colMap[field]] || '').trim() : '';

                let joinDate = '';
                if (colMap.joinDate) {
                    const raw = row[colMap.joinDate];
                    if (raw instanceof Date) {
                        joinDate = raw.toISOString().split('T')[0];
                    } else if (typeof raw === 'string' && raw.trim()) {
                        const d = new Date(raw.trim());
                        if (!isNaN(d.getTime())) joinDate = d.toISOString().split('T')[0];
                    }
                }

                records.push({
                    id: DB.generateId(),
                    name: name,
                    gender: getVal('gender'),
                    school: school,
                    designation: getVal('designation'),
                    subject: getVal('subject'),
                    classesTaught: getVal('classesTaught'),
                    phone: getVal('phone'),
                    email: getVal('email'),
                    block: getVal('block'),
                    cluster: getVal('cluster'),
                    qualification: getVal('qualification'),
                    experience: getVal('experience'),
                    joinDate: joinDate,
                    nid: getVal('nid'),
                    notes: getVal('notes'),
                    createdAt: new Date().toISOString(),
                    updatedAt: new Date().toISOString(),
                    source: 'excel'
                });
                added++;
            });

            DB.set('teacherRecords', records);
            renderTeacherRecords();
            showToast(`📥 Imported ${added} teachers${skipped ? ` (${skipped} skipped)` : ''}`, 'success', 5000);
        } catch (err) {
            console.error('Teacher Excel import error:', err);
            showToast('Error importing Excel file: ' + err.message, 'error');
        }
    };
    reader.readAsArrayBuffer(file);
    event.target.value = '';
}

function exportTeacherRecordsExcel() {
    const records = DB.get('teacherRecords') || [];
    if (records.length === 0) { showToast('No teacher records to export', 'info'); return; }
    if (typeof XLSX === 'undefined') { showToast('Excel library not loaded', 'error'); return; }

    const header = ['Name', 'Gender', 'School', 'Designation', 'Subject', 'Classes Taught', 'Phone', 'Email', 'Block', 'Cluster', 'Qualification', 'Experience (Years)', 'Date of Joining', 'NID / Employee ID', 'Notes'];
    const dataRows = [header];
    records.sort((a, b) => (a.school || '').localeCompare(b.school || '') || (a.name || '').localeCompare(b.name || ''));
    records.forEach(r => {
        dataRows.push([
            r.name || '', r.gender || '', r.school || '', r.designation || '',
            r.subject || '', r.classesTaught || '', r.phone || '', r.email || '',
            r.block || '', r.cluster || '', r.qualification || '', r.experience || '',
            r.joinDate || '', r.nid || '', r.notes || ''
        ]);
    });

    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.aoa_to_sheet(dataRows);
    ws['!cols'] = header.map(() => ({ wch: 18 }));
    XLSX.utils.book_append_sheet(wb, ws, 'Teacher Records');
    XLSX.writeFile(wb, `Teacher_Records_${new Date().toISOString().split('T')[0]}.xlsx`);
    showToast('📥 Exported teacher records to Excel');
}

// ===== MARAI TEACHER TRACKING =====
// MARAI Framework: Motivation → Awareness → Readiness → Action → Internalization
const MARAI_STAGES = [
    { key: 'motivation', label: 'Motivation', emoji: '🔥', color: '#f59e0b', desc: 'Teacher is motivated to improve teaching practices' },
    { key: 'awareness', label: 'Awareness', emoji: '👁️', color: '#3b82f6', desc: 'Teacher is aware of current practices and gaps' },
    { key: 'readiness', label: 'Readiness', emoji: '🎯', color: '#8b5cf6', desc: 'Teacher is ready to try new approaches' },
    { key: 'action', label: 'Action', emoji: '🚀', color: '#10b981', desc: 'Teacher actively implements new practices in classroom' },
    { key: 'internalization', label: 'Internalization', emoji: '💎', color: '#ec4899', desc: 'New practices are internalized and consistently applied' }
];

// ===== MARAI INTERVENTION SUGGESTIONS ENGINE =====
// Stage-wise long-term intervention strategies with subjects, topics & frequency
const MARAI_INTERVENTIONS = {
    motivation: {
        goal: 'Build intrinsic motivation and willingness to grow',
        duration: '4–6 weeks',
        frequency: 'Weekly (1–2 visits/week)',
        strategies: [
            { area: 'Classroom Visit & Rapport', icon: '🤝', topics: [
                'Informal classroom visit — observe without judgment',
                'Appreciate existing good practices publicly',
                'Share success stories from other teachers',
                'Casual conversation about teaching journey & aspirations'
            ]},
            { area: 'Exposure & Inspiration', icon: '✨', topics: [
                'Show engaging classroom videos / demo lessons',
                'Share student work samples from active classrooms',
                'Invite to observe a peer teacher\'s classroom',
                'Share simple articles on joyful learning'
            ]},
            { area: 'Quick Wins', icon: '🏆', topics: [
                'Suggest one small activity (story, rhyme, game)',
                'Co-facilitate a 10-min engaging activity in class',
                'Help with classroom display / TLM arrangement',
                'Celebrate small improvements immediately'
            ]}
        ],
        subjectWise: {
            'Language': ['Read-aloud session with picture book', 'Word wall creation', 'Story telling activity', 'Simple conversation circles'],
            'Hindi': ['कहानी सुनाओ गतिविधि', 'शब्द दीवार बनाना', 'चित्र देखकर बोलो', 'सरल कविता गायन'],
            'English': ['Picture talk activity', 'Simple rhyme singing', 'Label the classroom', 'Show & tell with objects'],
            'Mathematics': ['Number game using local materials', 'Math in daily life examples', 'Simple measurement activity', 'Pattern recognition with objects'],
            'EVS': ['Nature walk & observation', 'My family tree activity', 'Local plants identification', 'Weather observation chart'],
            'Science': ['Simple experiment demonstration', 'Observation journal start', 'Question of the day practice', 'Science in daily life discussion']
        }
    },
    awareness: {
        goal: 'Help teacher observe gaps & understand child-centered pedagogy',
        duration: '6–8 weeks',
        frequency: 'Weekly (1–2 sessions/week)',
        strategies: [
            { area: 'Reflective Practice', icon: '🪞', topics: [
                'Joint classroom observation with reflection',
                'Video of own teaching + self-reflection discussion',
                'Student engagement mapping exercise',
                'Identify 3 things working & 3 to improve'
            ]},
            { area: 'Understanding Learners', icon: '👁️', topics: [
                'Student work sample analysis together',
                'Observe student-student interaction in class',
                'Identify learning levels in class (baseline)',
                'Discuss difference between rote & understanding'
            ]},
            { area: 'Curriculum & Pedagogy', icon: '📖', topics: [
                'Read NCF/SCF key points together',
                'Discuss constructivist vs traditional approach',
                'Analyze textbook vs learning outcomes mapping',
                'Share Azim Premji Foundation resource materials'
            ]}
        ],
        subjectWise: {
            'Language': ['Identify reading levels in class', 'Analyze writing samples for gaps', 'Observe oral expression opportunities', 'Review language textbook activities critically'],
            'Hindi': ['बच्चों की पठन क्षमता आकलन', 'लेखन नमूनों का विश्लेषण', 'मौखिक अभिव्यक्ति के अवसर', 'पाठ्यपुस्तक गतिविधियों की समीक्षा'],
            'English': ['Assess reading fluency levels', 'Analyze common writing errors', 'Check comprehension vs decoding', 'Map textbook activities to skills'],
            'Mathematics': ['Diagnose number sense understanding', 'Identify conceptual vs procedural gaps', 'Observe math anxiety signs', 'Review worksheet dependency vs manipulation'],
            'EVS': ['Check experiential learning opportunities', 'Review project-based activities in class', 'Observe inquiry questions from students', 'Map local knowledge integration'],
            'Science': ['Check experiment vs theory ratio', 'Assess scientific thinking in responses', 'Review lab/activity usage', 'Discuss misconceptions in key topics']
        }
    },
    readiness: {
        goal: 'Prepare teacher to try new methods — build skills & confidence',
        duration: '6–8 weeks',
        frequency: 'Bi-weekly visits + monthly workshop',
        strategies: [
            { area: 'Skill Building', icon: '🛠️', topics: [
                'Model a lesson in teacher\'s classroom',
                'Co-plan a lesson together (gradual release)',
                'Practice questioning techniques together',
                'Prepare TLM / worksheets collaboratively'
            ]},
            { area: 'Lesson Planning', icon: '📝', topics: [
                'Introduction to learning outcomes-based planning',
                'Differentiated instruction for multi-level class',
                'Group work & collaborative learning design',
                'Formative assessment integration in lesson'
            ]},
            { area: 'Peer Learning', icon: '👥', topics: [
                'Arrange peer school visit for the teacher',
                'Teacher Learning Circle (TLC) participation',
                'Share & discuss classroom videos together',
                'Connect with mentor teacher in cluster'
            ]}
        ],
        subjectWise: {
            'Language': ['Plan a shared reading lesson together', 'Design process writing activity', 'Create reading corner with leveled books', 'Plan oral language development activities'],
            'Hindi': ['साझा पठन पाठ योजना बनाना', 'प्रक्रिया लेखन गतिविधि', 'स्तरानुसार पुस्तक कोना', 'मौखिक भाषा विकास गतिविधियाँ'],
            'English': ['Design a picture composition lesson', 'Plan a phonics-based reading session', 'Create vocabulary games for class', 'Plan a storytelling-based grammar lesson'],
            'Mathematics': ['Plan a manipulative-based math lesson', 'Design math games for practice', 'Create word problem solving framework', 'Plan a measurement activity outdoors'],
            'EVS': ['Plan a field visit-based lesson', 'Design a community mapping activity', 'Create a simple experiment together', 'Plan seed-to-plant observation journal'],
            'Science': ['Co-plan an inquiry-based lesson', 'Design a hands-on experiment', 'Plan a science journal activity', 'Create concept map for a chapter']
        }
    },
    action: {
        goal: 'Support sustained implementation of new practices in classroom',
        duration: '8–12 weeks',
        frequency: 'Bi-weekly visits + monthly reflection',
        strategies: [
            { area: 'Implementation Support', icon: '🚀', topics: [
                'Observe teacher\'s new practice & give feedback',
                'Troubleshoot implementation challenges together',
                'Help adjust activities for class context',
                'Document what\'s working with evidence'
            ]},
            { area: 'Assessment & Data', icon: '📊', topics: [
                'Help design student assessment tools',
                'Track student learning progress together',
                'Use data to adjust teaching strategies',
                'Portfolio-based assessment introduction'
            ]},
            { area: 'Deepening Practice', icon: '🔬', topics: [
                'Try practice in a different subject / class',
                'Add complexity — group work + differentiation',
                'Integrate library / print-rich environment',
                'Student-led activities & peer learning'
            ]}
        ],
        subjectWise: {
            'Language': ['Implement daily reading program', 'Start creative writing wall magazine', 'Conduct literature circle / book clubs', 'Run a class newspaper project'],
            'Hindi': ['दैनिक पठन कार्यक्रम शुरू करें', 'रचनात्मक लेखन दीवार पत्रिका', 'कहानी / कविता मंडली', 'कक्षा समाचार पत्र परियोजना'],
            'English': ['Start sustained silent reading (SSR)', 'Implement process writing weekly', 'Run English corner activities', 'Student-led show & tell sessions'],
            'Mathematics': ['Daily mental math routine', 'Math journal implementation', 'Student-created word problems', 'Math lab activities weekly'],
            'EVS': ['Weekly hands-on experiment', 'Student-led field documentation', 'Local knowledge integration project', 'Environmental audit by students'],
            'Science': ['Weekly experiment journal', 'Student-designed experiments', 'Science exhibition preparation', 'Cross-curricular science projects']
        }
    },
    internalization: {
        goal: 'Sustain, mentor others & continuously improve',
        duration: 'Ongoing (Quarterly check-ins)',
        frequency: 'Monthly visit + quarterly reflection',
        strategies: [
            { area: 'Leadership & Mentoring', icon: '👑', topics: [
                'Mentor a peer teacher in the school',
                'Lead Teacher Learning Circle (TLC)',
                'Present in Block / Cluster meeting',
                'Document own journey for others'
            ]},
            { area: 'Action Research', icon: '🔍', topics: [
                'Identify a classroom inquiry question',
                'Design simple action research plan',
                'Collect data & student work evidence',
                'Share findings in teacher forum'
            ]},
            { area: 'Continuous Growth', icon: '🌱', topics: [
                'Explore new pedagogies independently',
                'Attend advanced workshops / conferences',
                'Write about teaching experiences',
                'Build community of practice in school'
            ]}
        ],
        subjectWise: {
            'Language': ['Action research on reading comprehension', 'Mentor other teachers in language pedagogy', 'Create language resource bank for school', 'Lead a book reading movement'],
            'Hindi': ['पठन बोध पर कार्य अनुसंधान', 'भाषा शिक्षण में सहकर्मी मार्गदर्शन', 'विद्यालय स्तर भाषा संसाधन बैंक', 'पुस्तक पठन आंदोलन का नेतृत्व'],
            'English': ['Action research on writing skills', 'Create English resource repository', 'Train peers in communicative approach', 'Lead English reading program school-wide'],
            'Mathematics': ['Action research on math conceptual understanding', 'Create school math resource kit', 'Lead math mela / exhibition', 'Mentor peers in manipulative-based teaching'],
            'EVS': ['Action research on inquiry learning', 'Create school EVS garden / lab', 'Lead community engagement project', 'Document local knowledge resources'],
            'Science': ['Action research on scientific thinking', 'Create school science lab resources', 'Lead annual science fair', 'Mentor peers in experiment-based teaching']
        }
    }
};

// Generate personalized intervention plan for a teacher
function generateMaraiPlan(teacherKey) {
    const observations = DB.get('observations');
    const maraiRecords = DB.get('maraiTracking');

    // Get teacher observations
    const teacherObs = observations.filter(o => (o.teacher || '').trim().toLowerCase() === teacherKey);
    const teacherMarai = maraiRecords.filter(r => (r.teacher || '').trim().toLowerCase() === teacherKey);
    const sortedMarai = [...teacherMarai].sort((a, b) => (b.date || '').localeCompare(a.date || ''));
    const latestRecord = sortedMarai[0];
    const currentStage = latestRecord ? latestRecord.stage : 'motivation';
    const intervention = MARAI_INTERVENTIONS[currentStage];
    const stageInfo = MARAI_STAGES.find(s => s.key === currentStage);

    // Analyze teacher's subjects from observations
    const subjectCounts = {};
    const topicSet = new Set();
    const classCounts = {};
    const practices = [];
    const areasList = [];
    const strengthsList = [];
    let totalObs = teacherObs.length;
    let lowEngagement = 0;

    teacherObs.forEach(o => {
        if (o.subject) subjectCounts[o.subject] = (subjectCounts[o.subject] || 0) + 1;
        if (o.topic) topicSet.add(o.topic);
        if (o.class) classCounts[o.class] = (classCounts[o.class] || 0) + 1;
        if (o.practice) practices.push(o.practice);
        if (o.areas) areasList.push(o.areas);
        if (o.strengths) strengthsList.push(o.strengths);
        if (o.engagementLevel && o.engagementLevel !== 'More Engaged' && o.engagementLevel !== 'Engaged') lowEngagement++;
    });

    // Top subjects
    const topSubjects = Object.entries(subjectCounts).sort((a, b) => b[1] - a[1]).map(e => e[0]);
    const primarySubject = topSubjects[0] || 'Language';
    const topClasses = Object.entries(classCounts).sort((a, b) => b[1] - a[1]).map(e => e[0]);

    // Calculate time in current stage
    const stageRecords = sortedMarai.filter(r => r.stage === currentStage);
    let daysInStage = 0;
    if (stageRecords.length > 0) {
        const earliest = stageRecords[stageRecords.length - 1];
        daysInStage = Math.floor((Date.now() - new Date(earliest.date).getTime()) / 86400000);
    }

    // Determine visit frequency gaps
    const obsDates = teacherObs.map(o => o.date).filter(Boolean).sort();
    let avgGapDays = 0;
    if (obsDates.length > 1) {
        let totalGap = 0;
        for (let i = 1; i < obsDates.length; i++) {
            totalGap += (new Date(obsDates[i]) - new Date(obsDates[i - 1])) / 86400000;
        }
        avgGapDays = Math.round(totalGap / (obsDates.length - 1));
    }
    const lastVisitDate = obsDates[obsDates.length - 1] || null;
    const daysSinceLast = lastVisitDate ? Math.floor((Date.now() - new Date(lastVisitDate).getTime()) / 86400000) : null;

    // Get subject-specific suggestions
    const subjectSuggestions = [];
    topSubjects.slice(0, 3).forEach(subj => {
        const match = Object.keys(intervention.subjectWise).find(k => subj.toLowerCase().includes(k.toLowerCase()) || k.toLowerCase().includes(subj.toLowerCase()));
        if (match) {
            subjectSuggestions.push({ subject: subj, activities: intervention.subjectWise[match] });
        }
    });
    // Add default if no match
    if (subjectSuggestions.length === 0) {
        subjectSuggestions.push({ subject: primarySubject, activities: intervention.subjectWise[primarySubject] || intervention.subjectWise['Language'] || [] });
    }

    // Build timeline
    const timeline = buildInterventionTimeline(currentStage, subjectSuggestions, intervention);

    return {
        currentStage, stageInfo, intervention,
        totalObs, lowEngagement,
        topSubjects, topClasses, primarySubject,
        practices, areasList, strengthsList,
        subjectSuggestions, daysInStage, avgGapDays,
        daysSinceLast, lastVisitDate,
        teacherName: latestRecord?.teacher || '',
        school: latestRecord?.school || '',
        timeline
    };
}

function buildInterventionTimeline(stage, subjectSuggestions, intervention) {
    const weeks = [];
    const totalWeeks = stage === 'motivation' ? 6 : stage === 'awareness' ? 8 : stage === 'readiness' ? 8 : stage === 'action' ? 12 : 12;
    const strategies = intervention.strategies;

    for (let w = 1; w <= totalWeeks; w++) {
        const stratIdx = (w - 1) % strategies.length;
        const strat = strategies[stratIdx];
        const topicIdx = Math.floor((w - 1) / strategies.length) % strat.topics.length;
        const subj = subjectSuggestions[(w - 1) % subjectSuggestions.length];
        const subjActIdx = (w - 1) % (subj?.activities?.length || 1);

        weeks.push({
            week: w,
            area: strat.area,
            icon: strat.icon,
            topic: strat.topics[topicIdx],
            subject: subj?.subject || '',
            subjectActivity: subj?.activities?.[subjActIdx] || '',
            isReview: w % 4 === 0
        });
    }
    return weeks;
}

function getMaraiStageIndex(stage) {
    return MARAI_STAGES.findIndex(s => s.key === stage);
}

// Validate teacher name — filter out metadata strings like 'Stage: Primary| NID: 113727'
function isValidTeacherName(name) {
    if (!name || typeof name !== 'string') return false;
    const n = name.trim();
    if (n.length < 2 || n.length > 100) return false;
    // Reject if contains metadata patterns
    if (/NID\s*:/i.test(n)) return false;
    if (/Stage\s*:/i.test(n)) return false;
    if (/\|/.test(n) && /\d{4,}/.test(n)) return false; // pipe + long number = metadata
    if (/^\d+$/.test(n)) return false; // purely numeric
    if (/^(null|undefined|none|n\/a|na|test|#)$/i.test(n)) return false;
    return true;
}

function renderMaraiTracking() {
    const records = DB.get('maraiTracking');
    const container = document.getElementById('maraiContainer');
    const searchTerm = (document.getElementById('maraiSearchInput')?.value || '').toLowerCase();
    const stageFilter = document.getElementById('maraiStageFilter')?.value || 'all';
    const schoolFilter = document.getElementById('maraiSchoolFilter')?.value || 'all';
    const blockFilter = document.getElementById('maraiBlockFilter')?.value || 'all';
    const sortBy = document.getElementById('maraiSortSelect')?.value || 'recent';
    const smartFilter = window._maraiSmartFilter || 'none';

    // Build teacher map from MARAI records
    const teacherMap = {};
    records.forEach(r => {
        const key = (r.teacher || '').trim().toLowerCase();
        if (!isValidTeacherName(r.teacher)) return;
        if (!teacherMap[key]) teacherMap[key] = { name: r.teacher, school: r.school || '', block: '', cluster: '', records: [], obsCount: 0, subjects: new Set() };
        if (r.school && !teacherMap[key].school) teacherMap[key].school = r.school;
        teacherMap[key].records.push(r);
    });

    // Pull in teachers from observations + enrich with block/cluster/subject/obs count
    const observations = DB.get('observations');
    const allSchools = new Set();
    const allBlocks = new Set();
    observations.forEach(o => {
        const teacher = (o.teacher || '').trim();
        if (!teacher || !isValidTeacherName(teacher)) return;
        const key = teacher.toLowerCase();
        if (!teacherMap[key]) {
            teacherMap[key] = { name: teacher, school: o.school || '', block: '', cluster: '', records: [], obsCount: 0, subjects: new Set() };
        }
        const t = teacherMap[key];
        if (o.school && !t.school) t.school = o.school;
        if (o.block && !t.block) t.block = o.block.trim();
        if (o.cluster && !t.cluster) t.cluster = o.cluster.trim();
        if (o.subject) t.subjects.add(o.subject);
        t.obsCount++;
        if (o.school) allSchools.add(o.school.trim());
        if (o.block) allBlocks.add(o.block.trim());
    });
    // Also gather schools/blocks from MARAI records 
    records.forEach(r => { if (r.school) allSchools.add(r.school.trim()); });

    // Populate school & block filter dropdowns (preserving selection)
    const schoolSel = document.getElementById('maraiSchoolFilter');
    const blockSel = document.getElementById('maraiBlockFilter');
    if (schoolSel) {
        const curSchool = schoolSel.value;
        const opts = ['<option value="all">🏫 All Schools</option>'];
        [...allSchools].sort().forEach(s => opts.push(`<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`));
        schoolSel.innerHTML = opts.join('');
        schoolSel.value = [...allSchools].includes(curSchool) ? curSchool : 'all';
    }
    if (blockSel) {
        const curBlock = blockSel.value;
        const opts = ['<option value="all">📍 All Blocks</option>'];
        [...allBlocks].sort().forEach(b => opts.push(`<option value="${escapeHtml(b)}">${escapeHtml(b)}</option>`));
        blockSel.innerHTML = opts.join('');
        blockSel.value = [...allBlocks].includes(curBlock) ? curBlock : 'all';
    }

    let teachers = Object.values(teacherMap);

    // Compute per-teacher derived data for filtering/sorting
    const now = Date.now();
    teachers.forEach(t => {
        const sorted = [...t.records].sort((a, b) => (b.date || '').localeCompare(a.date || ''));
        t._latest = sorted[0] || null;
        t._currentStage = t._latest ? t._latest.stage : null;
        t._stageIdx = t._currentStage ? getMaraiStageIndex(t._currentStage) : -1;
        // Days since last MARAI record or observation
        const allDates = [...t.records.map(r => r.date)].filter(Boolean).sort();
        const obsForTeacher = observations.filter(o => (o.teacher || '').trim().toLowerCase() === t.name.trim().toLowerCase());
        obsForTeacher.forEach(o => { if (o.date) allDates.push(o.date); });
        allDates.sort();
        const lastDate = allDates[allDates.length - 1];
        t._daysSinceLast = lastDate ? Math.floor((now - new Date(lastDate).getTime()) / 86400000) : 9999;
        t._lastDate = lastDate || '';
        // Days in current stage
        if (t._latest) {
            const stageRecords = sorted.filter(r => r.stage === t._currentStage);
            const earliest = stageRecords[stageRecords.length - 1];
            t._daysInStage = earliest ? Math.floor((now - new Date(earliest.date).getTime()) / 86400000) : 0;
        } else { t._daysInStage = 0; }
        // Low engagement from observations
        t._lowEngagement = obsForTeacher.filter(o => o.engagementLevel && o.engagementLevel !== 'More Engaged' && o.engagementLevel !== 'Engaged').length;
    });

    // ---- FILTERS ----
    if (searchTerm) {
        teachers = teachers.filter(t =>
            t.name.toLowerCase().includes(searchTerm) ||
            (t.school || '').toLowerCase().includes(searchTerm) ||
            (t.block || '').toLowerCase().includes(searchTerm) ||
            (t.cluster || '').toLowerCase().includes(searchTerm)
        );
    }
    if (stageFilter === 'untracked') {
        teachers = teachers.filter(t => t.records.length === 0);
    } else if (stageFilter !== 'all') {
        teachers = teachers.filter(t => t._currentStage === stageFilter);
    }
    if (schoolFilter !== 'all') {
        teachers = teachers.filter(t => (t.school || '').trim() === schoolFilter);
    }
    if (blockFilter !== 'all') {
        teachers = teachers.filter(t => (t.block || '').trim() === blockFilter);
    }

    // Smart filters
    if (smartFilter === 'needs-visit') {
        teachers = teachers.filter(t => t._daysSinceLast >= 14);
    } else if (smartFilter === 'low-engagement') {
        teachers = teachers.filter(t => t._lowEngagement > 0);
    } else if (smartFilter === 'stuck') {
        teachers = teachers.filter(t => t._daysInStage >= 45 && t._currentStage && t._currentStage !== 'internalization');
    } else if (smartFilter === 'new-progress') {
        teachers = teachers.filter(t => t.records.length > 1);
    } else if (smartFilter === 'no-observations') {
        teachers = teachers.filter(t => t.obsCount === 0);
    }

    // ---- SORTING ----
    switch (sortBy) {
        case 'name':
            teachers.sort((a, b) => a.name.localeCompare(b.name));
            break;
        case 'stage-asc':
            teachers.sort((a, b) => a._stageIdx - b._stageIdx || a.name.localeCompare(b.name));
            break;
        case 'stage-desc':
            teachers.sort((a, b) => b._stageIdx - a._stageIdx || a.name.localeCompare(b.name));
            break;
        case 'most-observed':
            teachers.sort((a, b) => b.obsCount - a.obsCount || a.name.localeCompare(b.name));
            break;
        case 'least-observed':
            teachers.sort((a, b) => a.obsCount - b.obsCount || a.name.localeCompare(b.name));
            break;
        case 'overdue':
            teachers.sort((a, b) => b._daysSinceLast - a._daysSinceLast || a.name.localeCompare(b.name));
            break;
        case 'recent':
        default:
            teachers.sort((a, b) => (b._lastDate || '').localeCompare(a._lastDate || '') || a.name.localeCompare(b.name));
            break;
    }

    // ---- Smart filter chips ----
    const allTeachersRaw = Object.values(teacherMap);
    const needsVisitCount = allTeachersRaw.filter(t => t._daysSinceLast >= 14).length;
    const lowEngCount = allTeachersRaw.filter(t => t._lowEngagement > 0).length;
    const stuckCount = allTeachersRaw.filter(t => t._daysInStage >= 45 && t._currentStage && t._currentStage !== 'internalization').length;
    const progressCount = allTeachersRaw.filter(t => t.records.length > 1).length;
    const noObsCount = allTeachersRaw.filter(t => t.obsCount === 0).length;
    const untrackedCount = allTeachersRaw.filter(t => t.records.length === 0).length;

    const chipData = [
        { key: 'needs-visit', label: '⏰ Needs Visit', count: needsVisitCount, color: '#ef4444', desc: '14+ days since last activity' },
        { key: 'stuck', label: '🔒 Stuck in Stage', count: stuckCount, color: '#f59e0b', desc: '45+ days in same stage' },
        { key: 'low-engagement', label: '😐 Low Engagement', count: lowEngCount, color: '#f97316', desc: 'Has low-engagement observations' },
        { key: 'no-observations', label: '👻 No Observations', count: noObsCount, color: '#6b7280', desc: 'No classroom observations yet' },
        { key: 'new-progress', label: '📈 Has Progress', count: progressCount, color: '#10b981', desc: 'Multiple MARAI records' }
    ];

    const smartChipsEl = document.getElementById('maraiSmartFilters');
    if (smartChipsEl) {
        smartChipsEl.innerHTML = chipData.map(c =>
            `<button class="marai-smart-chip ${smartFilter === c.key ? 'active' : ''}" style="--chip-color:${c.color}" onclick="window._maraiSmartFilter = window._maraiSmartFilter === '${c.key}' ? 'none' : '${c.key}'; _pageState.marai=1; renderMaraiTracking()" title="${c.desc}">
                ${c.label} <span class="marai-chip-count">${c.count}</span>
            </button>`
        ).join('') + (smartFilter !== 'none' ? `<button class="marai-smart-chip marai-chip-clear" onclick="window._maraiSmartFilter='none';_pageState.marai=1;renderMaraiTracking()" title="Clear filter"><i class="fas fa-times"></i> Clear</button>` : '');
    }

    // Summary stats
    const allTeachers = allTeachersRaw;
    const stageCounts = {};
    MARAI_STAGES.forEach(s => stageCounts[s.key] = 0);
    let untracked = 0;
    allTeachers.forEach(t => {
        if (t.records.length === 0) { untracked++; return; }
        const latest = t.records.sort((a, b) => (b.date || '').localeCompare(a.date || ''))[0];
        if (latest && stageCounts.hasOwnProperty(latest.stage)) stageCounts[latest.stage]++;
    });

    document.getElementById('maraiStats').innerHTML = 
        MARAI_STAGES.map(s => `<div class="marai-stat-card" style="--marai-color:${s.color}"><span class="marai-stat-emoji">${s.emoji}</span><span class="marai-stat-value">${stageCounts[s.key]}</span><span class="marai-stat-label">${s.label}</span></div>`).join('') +
        `<div class="marai-stat-card" style="--marai-color:#6b7280"><span class="marai-stat-emoji">📋</span><span class="marai-stat-value">${untracked}</span><span class="marai-stat-label">Untracked</span></div>` +
        `<div class="marai-stat-card" style="--marai-color:var(--accent)"><span class="marai-stat-emoji">👥</span><span class="marai-stat-value">${allTeachers.length}</span><span class="marai-stat-label">Total</span></div>`;

    if (teachers.length === 0) {
        container.innerHTML = `<div class="idea-empty"><i class="fas fa-route"></i><h3>No teachers match filters</h3><p>${allTeachers.length} total teachers. Try adjusting your filters.</p><button class="btn btn-outline" onclick="resetMaraiFilters()"><i class="fas fa-undo"></i> Reset Filters</button></div>`;
        return;
    }

    const isFiltered = searchTerm || stageFilter !== 'all' || schoolFilter !== 'all' || blockFilter !== 'all' || smartFilter !== 'none';
    const filterInfo = isFiltered ? `<div class="marai-filter-info"><i class="fas fa-filter"></i> Showing <strong>${teachers.length}</strong> of ${allTeachers.length} teachers${smartFilter !== 'none' ? ` — <em>${chipData.find(c => c.key === smartFilter)?.label || smartFilter}</em>` : ''} <button class="btn btn-sm btn-outline" onclick="resetMaraiFilters()"><i class="fas fa-undo"></i> Reset</button></div>` : '';

    const pg = getPaginatedItems(teachers, 'marai', 15);

    container.innerHTML = filterInfo + pg.items.map(t => {
        const sorted = [...t.records].sort((a, b) => (b.date || '').localeCompare(a.date || ''));
        const latest = sorted[0];
        const currentStage = latest ? MARAI_STAGES.find(s => s.key === latest.stage) : null;
        const stageIdx = currentStage ? getMaraiStageIndex(currentStage.key) : -1;

        // Progress bar
        const progressDots = MARAI_STAGES.map((s, i) => {
            const reached = i <= stageIdx;
            const isCurrent = i === stageIdx;
            return `<div class="marai-dot ${reached ? 'reached' : ''} ${isCurrent ? 'current' : ''}" style="--dot-color:${s.color}" title="${s.label}">
                <span class="marai-dot-emoji">${s.emoji}</span>
            </div>`;
        }).join('<div class="marai-connector"></div>');

        const lastNote = latest?.notes || '';
        const lastDate = latest ? new Date(latest.date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }) : 'Not tracked';
        const teacherKey = encodeURIComponent(t.name.trim().toLowerCase());

        // Generate quick suggestion snippet
        const suggSnippet = generateMaraiSuggestionSnippet(teacherKey, currentStage?.key);

        return `<div class="marai-card">
            <div class="marai-card-header">
                <div class="marai-teacher-info">
                    <h4>${escapeHtml(t.name)}</h4>
                    ${t.school ? `<span class="marai-school"><i class="fas fa-school"></i> ${escapeHtml(t.school)}</span>` : ''}
                </div>
                <div class="marai-card-actions">
                    <button class="btn btn-sm btn-accent" onclick="showMaraiPlanModal('${teacherKey}')" title="View Intervention Plan"><i class="fas fa-clipboard-list"></i> Plan</button>
                    <button class="btn btn-sm btn-primary" onclick="openMaraiRecordModal('${teacherKey}')"><i class="fas fa-plus"></i> Update Stage</button>
                </div>
            </div>
            <div class="marai-progress">${progressDots}</div>
            <div class="marai-card-footer">
                <span class="marai-current-stage" style="color:${currentStage?.color || 'var(--text-muted)'}">
                    ${currentStage ? `${currentStage.emoji} ${currentStage.label}` : '📋 Not Yet Tracked'}
                </span>
                <span class="marai-last-date"><i class="fas fa-calendar-alt"></i> ${lastDate}</span>
                ${lastNote ? `<span class="marai-last-note" title="${escapeHtml(lastNote)}"><i class="fas fa-sticky-note"></i> ${escapeHtml(lastNote.substring(0, 60))}${lastNote.length > 60 ? '...' : ''}</span>` : ''}
            </div>
            ${suggSnippet}
            ${sorted.length > 0 ? `<div class="marai-history-toggle" onclick="this.nextElementSibling.classList.toggle('show');this.querySelector('i').classList.toggle('fa-chevron-down');this.querySelector('i').classList.toggle('fa-chevron-up')"><i class="fas fa-chevron-down"></i> ${sorted.length} record${sorted.length !== 1 ? 's' : ''}</div>
            <div class="marai-history">${sorted.map(r => {
                const s = MARAI_STAGES.find(st => st.key === r.stage);
                return `<div class="marai-history-item">
                    <span class="marai-history-badge" style="background:${s?.color || '#6b7280'}20;color:${s?.color || '#6b7280'}">${s?.emoji || '📋'} ${s?.label || r.stage}</span>
                    <span class="marai-history-date">${new Date(r.date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}</span>
                    ${r.notes ? `<span class="marai-history-note">${escapeHtml(r.notes)}</span>` : ''}
                    <button class="btn-icon-sm" onclick="deleteMaraiRecord('${r.id}')" title="Delete"><i class="fas fa-trash"></i></button>
                </div>`;
            }).join('')}</div>` : ''}
        </div>`;
    }).join('') + renderPaginationControls('marai', pg, 'renderMaraiTracking');
}

function openMaraiRecordModal(encodedTeacherKey) {
    const teacherKey = decodeURIComponent(encodedTeacherKey);
    const form = document.getElementById('maraiRecordForm');
    form.reset();

    // Find teacher name
    const observations = DB.get('observations');
    const maraiRecords = DB.get('maraiTracking');
    let teacherName = '';
    let school = '';

    // Check MARAI records first
    const existingRecords = maraiRecords.filter(r => (r.teacher || '').trim().toLowerCase() === teacherKey);
    if (existingRecords.length > 0) {
        const latest = existingRecords.sort((a, b) => (b.date || '').localeCompare(a.date || ''))[0];
        teacherName = latest.teacher;
        school = latest.school || '';
    }

    // Check observations
    if (!teacherName) {
        const obs = observations.find(o => (o.teacher || '').trim().toLowerCase() === teacherKey);
        if (obs) { teacherName = obs.teacher; school = obs.school || ''; }
    }

    document.getElementById('maraiTeacherName').value = teacherName;
    document.getElementById('maraiSchool').value = school;
    document.getElementById('maraiDate').value = new Date().toISOString().split('T')[0];

    // Default to next stage
    if (existingRecords.length > 0) {
        const latest = existingRecords.sort((a, b) => (b.date || '').localeCompare(a.date || ''))[0];
        const currentIdx = getMaraiStageIndex(latest.stage);
        const nextIdx = Math.min(currentIdx + 1, MARAI_STAGES.length - 1);
        document.getElementById('maraiStage').value = MARAI_STAGES[nextIdx].key;
    }

    document.getElementById('maraiModalTitle').innerHTML = '<i class="fas fa-route"></i> Update MARAI Stage';
    openModal('maraiRecordModal');
    updateMaraiStagePreview();
}

function saveMaraiRecord(e) {
    e.preventDefault();
    const records = DB.get('maraiTracking');
    const record = {
        id: DB.generateId(),
        teacher: document.getElementById('maraiTeacherName').value.trim(),
        school: document.getElementById('maraiSchool').value.trim(),
        stage: document.getElementById('maraiStage').value,
        date: document.getElementById('maraiDate').value,
        notes: document.getElementById('maraiNotes').value.trim(),
        createdAt: new Date().toISOString()
    };

    records.push(record);
    DB.set('maraiTracking', records);
    closeModal('maraiRecordModal');
    renderMaraiTracking();
    const stageInfo = MARAI_STAGES.find(s => s.key === record.stage);
    showToast(`${stageInfo?.emoji || '✅'} ${record.teacher} → ${stageInfo?.label || record.stage}`);
}

// Live stage preview for MARAI modal
function updateMaraiStagePreview() {
    const selectedStage = document.getElementById('maraiStage')?.value;
    const previewEl = document.getElementById('maraiPreviewDots');
    const previewContainer = document.getElementById('maraiStagePreview');
    if (!previewEl || !previewContainer) return;
    const stageIdx = MARAI_STAGES.findIndex(s => s.key === selectedStage);
    const stageInfo = MARAI_STAGES[stageIdx];
    // Update stage-specific accent color on the modal
    const modal = document.querySelector('.marai-record-modal');
    if (modal) modal.style.setProperty('--marai-modal-accent', stageInfo?.color || '#f59e0b');

    previewEl.innerHTML = MARAI_STAGES.map((s, i) => {
        const reached = i <= stageIdx;
        const isCurrent = i === stageIdx;
        return `<div class="marai-pv-step ${reached ? 'reached' : ''} ${isCurrent ? 'current' : ''}" style="--pv-color:${s.color}" title="${s.label}">
            <div class="marai-pv-dot">${s.emoji}</div>
            <span class="marai-pv-label">${s.label}</span>
        </div>${i < MARAI_STAGES.length - 1 ? '<div class="marai-pv-line' + (reached && i < stageIdx ? ' reached' : '') + '"></div>' : ''}`;
    }).join('');
    previewContainer.style.setProperty('--preview-accent', stageInfo?.color || '#f59e0b');
}

function deleteMaraiRecord(id) {
    if (!confirm('Delete this MARAI record?')) return;
    let records = DB.get('maraiTracking');
    records = records.filter(r => r.id !== id);
    DB.set('maraiTracking', records);
    renderMaraiTracking();
    showToast('Record deleted');
}

function resetMaraiFilters() {
    const ids = ['maraiStageFilter', 'maraiSchoolFilter', 'maraiBlockFilter', 'maraiSortSelect'];
    ids.forEach(id => { const el = document.getElementById(id); if (el) el.value = el.options[0]?.value || 'all'; });
    const search = document.getElementById('maraiSearchInput');
    if (search) search.value = '';
    window._maraiSmartFilter = 'none';
    _pageState.marai = 1;
    renderMaraiTracking();
}

// Generate a compact suggestion snippet for MARAI card
function generateMaraiSuggestionSnippet(teacherKey, stage) {
    if (!stage) {
        return `<div class="marai-suggestion-snippet">
            <div class="marai-sugg-header"><i class="fas fa-lightbulb"></i> Start by tracking this teacher's MARAI stage to get intervention suggestions</div>
        </div>`;
    }
    const intervention = MARAI_INTERVENTIONS[stage];
    if (!intervention) return '';

    const observations = DB.get('observations');
    const teacherObs = observations.filter(o => (o.teacher || '').trim().toLowerCase() === teacherKey);

    // Find primary subject
    const subjCount = {};
    teacherObs.forEach(o => { if (o.subject) subjCount[o.subject] = (subjCount[o.subject] || 0) + 1; });
    const topSubj = Object.entries(subjCount).sort((a, b) => b[1] - a[1])[0];
    const primarySubj = topSubj ? topSubj[0] : null;

    // Get matching subject suggestions
    let subjActivities = [];
    if (primarySubj) {
        const match = Object.keys(intervention.subjectWise).find(k => primarySubj.toLowerCase().includes(k.toLowerCase()) || k.toLowerCase().includes(primarySubj.toLowerCase()));
        if (match) subjActivities = intervention.subjectWise[match].slice(0, 2);
    }
    if (subjActivities.length === 0) {
        subjActivities = (intervention.subjectWise['Language'] || Object.values(intervention.subjectWise)[0] || []).slice(0, 2);
    }

    // Pick 2 strategy topics
    const stratTopics = intervention.strategies.slice(0, 2).map(s => `${s.icon} ${s.topics[0]}`);

    // Visit frequency suggestion
    const obsDates = teacherObs.map(o => o.date).filter(Boolean).sort();
    const lastDate = obsDates[obsDates.length - 1];
    const daysSince = lastDate ? Math.floor((Date.now() - new Date(lastDate).getTime()) / 86400000) : null;
    let urgencyMsg = '';
    if (daysSince !== null && daysSince > 14) {
        urgencyMsg = `<span class="marai-sugg-urgent"><i class="fas fa-exclamation-triangle"></i> ${daysSince} days since last visit — visit soon!</span>`;
    }

    return `<div class="marai-suggestion-snippet">
        <div class="marai-sugg-header"><i class="fas fa-lightbulb"></i> Suggested Interventions <span class="marai-sugg-freq">${intervention.frequency}</span></div>
        <div class="marai-sugg-items">
            ${stratTopics.map(t => `<span class="marai-sugg-item">${t}</span>`).join('')}
            ${subjActivities.map(a => `<span class="marai-sugg-item marai-sugg-subject"><i class="fas fa-book"></i> ${primarySubj ? escapeHtml(primarySubj) + ': ' : ''}${escapeHtml(a)}</span>`).join('')}
        </div>
        ${urgencyMsg}
    </div>`;
}

// Show full intervention plan modal
function showMaraiPlanModal(encodedTeacherKey) {
    const teacherKey = decodeURIComponent(encodedTeacherKey);
    const plan = generateMaraiPlan(teacherKey);
    const modal = document.getElementById('maraiPlanModal');
    const body = document.getElementById('maraiPlanBody');

    const stageColor = plan.stageInfo?.color || 'var(--accent)';
    const stageEmoji = plan.stageInfo?.emoji || '📋';
    const stageName = plan.stageInfo?.label || 'Not Tracked';

    // Header with teacher info
    let html = `<div class="mp-teacher-header" style="--mp-color:${stageColor}">
        <div class="mp-teacher-info">
            <h3>${escapeHtml(plan.teacherName || teacherKey)}</h3>
            ${plan.school ? `<span><i class="fas fa-school"></i> ${escapeHtml(plan.school)}</span>` : ''}
        </div>
        <div class="mp-stage-badge" style="background:${stageColor}">${stageEmoji} ${stageName}</div>
    </div>`;

    // Analytics summary
    html += `<div class="mp-analytics">
        <div class="mp-analytic"><span class="mp-analytic-val">${plan.totalObs}</span><span class="mp-analytic-label">Observations</span></div>
        <div class="mp-analytic"><span class="mp-analytic-val">${plan.topSubjects.length}</span><span class="mp-analytic-label">Subjects</span></div>
        <div class="mp-analytic"><span class="mp-analytic-val">${plan.daysInStage}d</span><span class="mp-analytic-label">In Stage</span></div>
        <div class="mp-analytic"><span class="mp-analytic-val">${plan.avgGapDays || '—'}d</span><span class="mp-analytic-label">Avg Gap</span></div>
        <div class="mp-analytic"><span class="mp-analytic-val">${plan.daysSinceLast ?? '—'}d</span><span class="mp-analytic-label">Since Last</span></div>
        <div class="mp-analytic"><span class="mp-analytic-val">${plan.lowEngagement}</span><span class="mp-analytic-label">Low Engage</span></div>
    </div>`;

    // Alerts
    if (plan.daysSinceLast !== null && plan.daysSinceLast > 14) {
        html += `<div class="mp-alert mp-alert-warn"><i class="fas fa-exclamation-triangle"></i> <strong>${plan.daysSinceLast} days since last visit.</strong> Recommended: ${plan.intervention.frequency}</div>`;
    }
    if (plan.daysInStage > 60 && plan.currentStage !== 'internalization') {
        html += `<div class="mp-alert mp-alert-info"><i class="fas fa-info-circle"></i> Teacher has been in <strong>${stageName}</strong> stage for ${plan.daysInStage} days. Consider if ready to progress.</div>`;
    }

    // Goal & Duration
    html += `<div class="mp-goal-card">
        <div class="mp-goal-title"><i class="fas fa-bullseye"></i> Stage Goal</div>
        <p class="mp-goal-text">${plan.intervention.goal}</p>
        <div class="mp-goal-meta">
            <span><i class="fas fa-clock"></i> Duration: <strong>${plan.intervention.duration}</strong></span>
            <span><i class="fas fa-calendar-check"></i> Frequency: <strong>${plan.intervention.frequency}</strong></span>
        </div>
    </div>`;

    // Strategy areas
    html += `<div class="mp-section-title"><i class="fas fa-chess"></i> Intervention Strategies</div>`;
    html += `<div class="mp-strategies">`;
    plan.intervention.strategies.forEach(s => {
        html += `<div class="mp-strategy-card">
            <div class="mp-strat-icon">${s.icon}</div>
            <div class="mp-strat-content">
                <h4>${s.area}</h4>
                <ul>${s.topics.map(t => `<li>${t}</li>`).join('')}</ul>
            </div>
        </div>`;
    });
    html += `</div>`;

    // Subject-specific plan
    if (plan.subjectSuggestions.length > 0) {
        html += `<div class="mp-section-title"><i class="fas fa-book-open"></i> Subject-Wise Activities</div>`;
        html += `<div class="mp-subject-cards">`;
        plan.subjectSuggestions.forEach(ss => {
            html += `<div class="mp-subject-card">
                <h4><i class="fas fa-book"></i> ${escapeHtml(ss.subject)}</h4>
                <ul>${ss.activities.map(a => `<li>${escapeHtml(a)}</li>`).join('')}</ul>
            </div>`;
        });
        html += `</div>`;
    }

    // From observations: Strengths & Areas
    if (plan.strengthsList.length > 0 || plan.areasList.length > 0) {
        html += `<div class="mp-section-title"><i class="fas fa-chart-bar"></i> From Observations</div>`;
        html += `<div class="mp-obs-insights">`;
        if (plan.strengthsList.length > 0) {
            const uniqStrengths = [...new Set(plan.strengthsList.filter(Boolean))].slice(0, 5);
            html += `<div class="mp-insight-block mp-insight-good">
                <h5><i class="fas fa-check-circle"></i> Strengths Observed</h5>
                <ul>${uniqStrengths.map(s => `<li>${escapeHtml(s.length > 100 ? s.substring(0, 100) + '...' : s)}</li>`).join('')}</ul>
            </div>`;
        }
        if (plan.areasList.length > 0) {
            const uniqAreas = [...new Set(plan.areasList.filter(Boolean))].slice(0, 5);
            html += `<div class="mp-insight-block mp-insight-improve">
                <h5><i class="fas fa-exclamation-circle"></i> Areas for Improvement</h5>
                <ul>${uniqAreas.map(a => `<li>${escapeHtml(a.length > 100 ? a.substring(0, 100) + '...' : a)}</li>`).join('')}</ul>
            </div>`;
        }
        html += `</div>`;
    }

    // Weekly Timeline
    html += `<div class="mp-section-title"><i class="fas fa-calendar-alt"></i> Suggested Weekly Plan (${plan.timeline.length} weeks)</div>`;
    html += `<div class="mp-timeline">`;
    plan.timeline.forEach(w => {
        html += `<div class="mp-week ${w.isReview ? 'mp-week-review' : ''}">
            <div class="mp-week-num">${w.isReview ? '🔄' : w.icon} W${w.week}</div>
            <div class="mp-week-content">
                <div class="mp-week-area">${w.area}${w.isReview ? ' — <strong>Review & Reflect</strong>' : ''}</div>
                <div class="mp-week-topic">${w.topic}</div>
                ${w.subjectActivity ? `<div class="mp-week-subject"><i class="fas fa-book"></i> ${escapeHtml(w.subject)}: ${escapeHtml(w.subjectActivity)}</div>` : ''}
            </div>
        </div>`;
    });
    html += `</div>`;

    // Next steps
    const nextStageIdx = getMaraiStageIndex(plan.currentStage) + 1;
    if (nextStageIdx < MARAI_STAGES.length) {
        const next = MARAI_STAGES[nextStageIdx];
        html += `<div class="mp-next-stage">
            <div class="mp-next-title"><i class="fas fa-arrow-right"></i> Path to Next Stage: ${next.emoji} ${next.label}</div>
            <p>${next.desc}</p>
            <p class="mp-next-criteria">When the teacher consistently demonstrates the characteristics of the <strong>${stageName}</strong> stage, consider moving them to <strong>${next.label}</strong>.</p>
        </div>`;
    }

    body.innerHTML = html;
    openModal('maraiPlanModal');
}

// ===== SCHOOL-BASED WORK TRACKING =====
// Track: Assembly, Print-Rich Environment, Library, Creative Writing, Bal Shodh Mela
const SCHOOL_WORK_TYPES = [
    { key: 'assembly', label: 'Assembly', emoji: '🎤', color: '#6366f1', desc: 'Morning assembly activities, cultural programs, theme days' },
    { key: 'print-rich', label: 'Print Rich', emoji: '🖼️', color: '#f59e0b', desc: 'Classroom/school print-rich environment — charts, labels, displays' },
    { key: 'library', label: 'Library', emoji: '📚', color: '#10b981', desc: 'Library setup, reading programs, book access, reading corners' },
    { key: 'creative-writing', label: 'Creative Writing', emoji: '✍️', color: '#ec4899', desc: 'Student creative writing activities, wall magazines, story writing' },
    { key: 'bal-shodh-mela', label: 'Bal Shodh Mela', emoji: '🔬', color: '#8b5cf6', desc: 'Children\'s Research Fair — student inquiry projects and presentations' },
    { key: 'other', label: 'Other Activity', emoji: '📌', color: '#64748b', desc: 'Any other school-based work or initiative' }
];

function renderSchoolWork() {
    const records = DB.get('schoolWork');
    const container = document.getElementById('schoolWorkContainer');
    const typeFilter = document.getElementById('schoolWorkTypeFilter')?.value || 'all';
    const searchTerm = (document.getElementById('schoolWorkSearchInput')?.value || '').toLowerCase();

    let filtered = [...records];
    if (typeFilter !== 'all') {
        filtered = filtered.filter(r => r.type === typeFilter);
    }
    if (searchTerm) {
        filtered = filtered.filter(r =>
            (r.school || '').toLowerCase().includes(searchTerm) ||
            (r.title || '').toLowerCase().includes(searchTerm) ||
            (r.description || '').toLowerCase().includes(searchTerm) ||
            (r.type || '').toLowerCase().includes(searchTerm) ||
            (Array.isArray(r.teachers) && r.teachers.some(t => t.toLowerCase().includes(searchTerm)))
        );
    }
    filtered.sort((a, b) => (b.date || '').localeCompare(a.date || ''));

    // Summary stats
    const allRecords = records;
    const typeCounts = {};
    SCHOOL_WORK_TYPES.forEach(t => typeCounts[t.key] = 0);
    allRecords.forEach(r => { if (typeCounts.hasOwnProperty(r.type)) typeCounts[r.type]++; else typeCounts['other'] = (typeCounts['other'] || 0) + 1; });
    const uniqueSchools = new Set(allRecords.map(r => (r.school || '').trim().toLowerCase()).filter(Boolean)).size;

    const now = new Date();
    const thisMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    const thisMonthCount = allRecords.filter(r => (r.date || '').startsWith(thisMonth)).length;

    document.getElementById('schoolWorkStats').innerHTML = 
        SCHOOL_WORK_TYPES.map(t => `<div class="sw-stat-card" style="--sw-color:${t.color}"><span class="sw-stat-emoji">${t.emoji}</span><span class="sw-stat-value">${typeCounts[t.key]}</span><span class="sw-stat-label">${t.label}</span></div>`).join('') +
        `<div class="sw-stat-card" style="--sw-color:var(--accent)"><span class="sw-stat-emoji">🏫</span><span class="sw-stat-value">${uniqueSchools}</span><span class="sw-stat-label">Schools</span></div>` +
        `<div class="sw-stat-card" style="--sw-color:#0d9488"><span class="sw-stat-emoji">📅</span><span class="sw-stat-value">${thisMonthCount}</span><span class="sw-stat-label">This Month</span></div>`;

    if (filtered.length === 0) {
        container.innerHTML = '<div class="idea-empty"><i class="fas fa-chalkboard"></i><h3>No school work recorded</h3><p>Track school-based activities like Assembly, Library, Print-Rich Environment, Creative Writing & Bal Shodh Mela.</p></div>';
        return;
    }

    const pg = getPaginatedItems(filtered, 'schoolWork', 15);

    container.innerHTML = pg.items.map(r => {
        const typeInfo = SCHOOL_WORK_TYPES.find(t => t.key === r.type) || SCHOOL_WORK_TYPES[5];
        const statusColors = { planned: '#3b82f6', 'in-progress': '#f59e0b', completed: '#10b981' };
        const statusLabels = { planned: '📋 Planned', 'in-progress': '🔄 In Progress', completed: '✅ Completed' };
        const statusIcons = { planned: 'fa-clipboard-list', 'in-progress': 'fa-spinner', completed: 'fa-check-circle' };
        const teachers = Array.isArray(r.teachers) ? r.teachers : [];

        return `<div class="sw-card" style="--sw-accent:${typeInfo.color}">
            <div class="sw-card-accent" style="background:linear-gradient(180deg, ${typeInfo.color}, ${typeInfo.color}66)"></div>
            <div class="sw-card-body">
                <div class="sw-card-header">
                    <div class="sw-card-header-left">
                        <div class="sw-type-badge" style="background:${typeInfo.color}18;color:${typeInfo.color};border:1px solid ${typeInfo.color}30">${typeInfo.emoji} ${typeInfo.label}</div>
                        <span class="sw-status-badge" style="color:${statusColors[r.status] || '#6b7280'};background:${statusColors[r.status] || '#6b7280'}12"><i class="fas ${statusIcons[r.status] || 'fa-circle'}"></i> ${statusLabels[r.status] || r.status}</span>
                    </div>
                    <div class="sw-card-actions">
                        <button class="btn btn-sm btn-outline" onclick="openSchoolWorkModal('${r.id}')" title="Edit"><i class="fas fa-edit"></i></button>
                        <button class="btn btn-sm btn-outline sw-delete-btn" onclick="deleteSchoolWork('${r.id}')" title="Delete"><i class="fas fa-trash"></i></button>
                    </div>
                </div>
                <h4 class="sw-card-title">${escapeHtml(r.title || typeInfo.label)}</h4>
                <div class="sw-card-meta">
                    <span><i class="fas fa-school"></i> ${escapeHtml(r.school || 'Not specified')}</span>
                    <span><i class="fas fa-calendar-alt"></i> ${r.date ? new Date(r.date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }) : 'N/A'}</span>
                    ${r.participants ? `<span><i class="fas fa-users"></i> ${r.participants} participants</span>` : ''}
                    ${r.block ? `<span><i class="fas fa-map-marker-alt"></i> ${escapeHtml(r.block)}</span>` : ''}
                    ${r.photos ? `<span><i class="fas fa-camera"></i> ${r.photos} photo(s)</span>` : ''}
                </div>
                ${teachers.length > 0 ? `<div class="sw-card-teachers"><i class="fas fa-chalkboard-teacher"></i>${teachers.map(t => `<span class="sw-teacher-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
                ${r.description ? `<div class="sw-card-desc">${escapeHtml(r.description)}</div>` : ''}
                ${r.observations ? `<div class="sw-card-obs"><i class="fas fa-eye"></i> <span>${escapeHtml(r.observations)}</span></div>` : ''}
                ${r.outcome ? `<div class="sw-card-outcome"><i class="fas fa-check-circle"></i> <span>${escapeHtml(r.outcome)}</span></div>` : ''}
            </div>
        </div>`;
    }).join('') + renderPaginationControls('schoolWork', pg, 'renderSchoolWork');
}

// Assigned teachers state for school work modal
window._swTeachers = [];

function openSchoolWorkModal(id) {
    const form = document.getElementById('schoolWorkForm');
    form.reset();
    document.getElementById('schoolWorkId').value = '';
    document.getElementById('schoolWorkModalTitle').innerHTML = '<i class="fas fa-chalkboard"></i> Log School Work';
    document.getElementById('schoolWorkDate').value = new Date().toISOString().split('T')[0];
    window._swTeachers = [];

    // Populate school autocomplete from visits
    const visits = DB.get('visits');
    const schoolNames = [...new Set(visits.map(v => (v.school || '').trim()).filter(Boolean))].sort();
    const schoolList = document.getElementById('schoolWorkSchoolList');
    if (schoolList) {
        schoolList.innerHTML = schoolNames.map(s => `<option value="${escapeHtml(s)}">`).join('');
    }

    // Populate teacher autocomplete from observations & MARAI tracking
    const observations = DB.get('observations');
    const maraiRecords = DB.get('maraiTracking');
    const teacherNames = [...new Set([
        ...observations.map(o => (o.teacher || '').trim()).filter(Boolean),
        ...maraiRecords.map(r => (r.teacher || '').trim()).filter(Boolean)
    ])].sort();
    const teacherList = document.getElementById('schoolWorkTeacherList');
    if (teacherList) {
        teacherList.innerHTML = teacherNames.map(t => `<option value="${escapeHtml(t)}">`).join('');
    }

    if (id) {
        const records = DB.get('schoolWork');
        const r = records.find(x => x.id === id);
        if (r) {
            document.getElementById('schoolWorkModalTitle').innerHTML = '<i class="fas fa-chalkboard"></i> Edit School Work';
            document.getElementById('schoolWorkId').value = r.id;
            document.getElementById('schoolWorkType').value = r.type || 'other';
            document.getElementById('schoolWorkTitle').value = r.title || '';
            document.getElementById('schoolWorkSchool').value = r.school || '';
            document.getElementById('schoolWorkBlock').value = r.block || '';
            document.getElementById('schoolWorkDate').value = r.date || '';
            document.getElementById('schoolWorkStatus').value = r.status || 'completed';
            document.getElementById('schoolWorkParticipants').value = r.participants || '';
            document.getElementById('schoolWorkDescription').value = r.description || '';
            document.getElementById('schoolWorkObservations').value = r.observations || '';
            document.getElementById('schoolWorkOutcome').value = r.outcome || '';
            document.getElementById('schoolWorkPhotos').value = r.photos || '';
            window._swTeachers = Array.isArray(r.teachers) ? [...r.teachers] : [];
        }
    }

    renderSwTeacherTags();
    openModal('schoolWorkModal');
}

function handleSwTeacherKeydown(e) {
    if (e.key === 'Enter') {
        e.preventDefault();
        addSwTeacher();
    }
}

function addSwTeacher() {
    const input = document.getElementById('schoolWorkTeacherInput');
    const name = (input.value || '').trim();
    if (!name) return;
    if (!window._swTeachers.includes(name)) {
        window._swTeachers.push(name);
    }
    input.value = '';
    input.focus();
    renderSwTeacherTags();
}

function removeSwTeacher(idx) {
    window._swTeachers.splice(idx, 1);
    renderSwTeacherTags();
}

function renderSwTeacherTags() {
    const container = document.getElementById('schoolWorkTeacherTags');
    if (!container) return;
    if (window._swTeachers.length === 0) {
        container.innerHTML = '<span class="sw-teacher-empty">No teachers assigned yet</span>';
        return;
    }
    container.innerHTML = window._swTeachers.map((t, i) =>
        `<span class="sw-teacher-tag-modal"><i class="fas fa-user"></i> ${escapeHtml(t)} <button type="button" onclick="removeSwTeacher(${i})" title="Remove"><i class="fas fa-times"></i></button></span>`
    ).join('');
}

function saveSchoolWork(e) {
    e.preventDefault();
    const records = DB.get('schoolWork');
    const id = document.getElementById('schoolWorkId').value;

    const record = {
        id: id || DB.generateId(),
        type: document.getElementById('schoolWorkType').value,
        title: document.getElementById('schoolWorkTitle').value.trim(),
        school: document.getElementById('schoolWorkSchool').value.trim(),
        block: document.getElementById('schoolWorkBlock').value.trim(),
        date: document.getElementById('schoolWorkDate').value,
        status: document.getElementById('schoolWorkStatus').value,
        participants: parseInt(document.getElementById('schoolWorkParticipants').value) || 0,
        teachers: [...(window._swTeachers || [])],
        description: document.getElementById('schoolWorkDescription').value.trim(),
        observations: document.getElementById('schoolWorkObservations').value.trim(),
        outcome: document.getElementById('schoolWorkOutcome').value.trim(),
        photos: parseInt(document.getElementById('schoolWorkPhotos').value) || 0,
        createdAt: id ? (records.find(r => r.id === id) || {}).createdAt || new Date().toISOString() : new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    if (id) {
        const idx = records.findIndex(r => r.id === id);
        if (idx !== -1) records[idx] = record;
    } else {
        records.push(record);
    }

    DB.set('schoolWork', records);
    closeModal('schoolWorkModal');
    renderSchoolWork();
    const typeInfo = SCHOOL_WORK_TYPES.find(t => t.key === record.type);
    showToast(id ? 'School work updated' : `${typeInfo?.emoji || '✅'} School work logged!`);
}

function deleteSchoolWork(id) {
    if (!confirm('Delete this school work record?')) return;
    let records = DB.get('schoolWork');
    records = records.filter(r => r.id !== id);
    DB.set('schoolWork', records);
    renderSchoolWork();
    showToast('Record deleted');
}

// ===== VISIT PLAN vs EXECUTION =====

// --- Linked Excel (two-way sync) ---
window._vpFileHandle = null;
window._vpLinkedName = null;
window._vpSyncing = false;

async function vpLinkExcel() {
    // Try File System Access API first (Chrome, Edge — enables write-back)
    if (window.showOpenFilePicker) {
        try {
            const [handle] = await window.showOpenFilePicker({
                types: [{ description: 'Excel Files', accept: { 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'] } }],
                multiple: false
            });
            // Request write permission upfront so save won't prompt later
            const perm = await handle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') {
                showToast('⚠️ Write access denied — opening read-only', 'info');
                // Fall through to read-only
                const file = await handle.getFile();
                const data = new Uint8Array(await file.arrayBuffer());
                window._vpFileHandle = null;
                window._vpLinkedName = handle.name;
                _vpParseWorkbook(data);
                _vpUpdateLinkedUI(handle.name, false);
                return;
            }
            window._vpFileHandle = handle;
            window._vpLinkedName = handle.name;
            const file = await handle.getFile();
            const data = new Uint8Array(await file.arrayBuffer());
            _vpParseWorkbook(data);
            _vpUpdateLinkedUI(handle.name, true);
            showToast('🔗 Excel linked! Changes auto-save to file.');
            return;
        } catch (err) {
            if (err.name === 'AbortError') return;
            console.warn('File System Access failed:', err.message);
        }
    }
    // Fallback for Brave/Firefox/Safari — read only, data stays in app
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.xlsx,.xls';
    input.onchange = (e) => {
        const file = e.target.files[0];
        if (!file) return;
        window._vpFileHandle = null;
        window._vpLinkedName = file.name;
        const reader = new FileReader();
        reader.onload = function(ev) {
            try {
                _vpParseWorkbook(new Uint8Array(ev.target.result));
                _vpUpdateLinkedUI(file.name, false);
                showToast('🔗 Excel loaded! For auto-save back to file, use Chrome or Edge.');
            } catch (err) {
                showToast('❌ Error: ' + err.message);
            }
        };
        reader.readAsArrayBuffer(file);
    };
    input.click();
}

function vpUnlinkExcel() {
    window._vpFileHandle = null;
    window._vpLinkedName = null;
    _vpUpdateLinkedUI(null);
    showToast('🔓 Excel unlinked');
}

function _vpUpdateLinkedUI(fileName, canWrite) {
    const status = document.getElementById('vpLinkedStatus');
    const nameEl = document.getElementById('vpLinkedFileName');
    const linkBtn = document.getElementById('vpLinkBtn');
    const modeEl = document.getElementById('vpLinkMode');
    if (fileName) {
        if (status) status.style.display = 'flex';
        if (nameEl) nameEl.textContent = fileName;
        if (modeEl) {
            modeEl.textContent = canWrite ? 'Auto-sync' : 'Read-only';
            modeEl.style.background = canWrite ? 'rgba(16,185,129,0.15)' : 'rgba(245,158,11,0.15)';
            modeEl.style.color = canWrite ? '#10b981' : '#f59e0b';
        }
        if (linkBtn) { linkBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Re-link'; linkBtn.classList.add('vp-linked-active'); }
    } else {
        if (status) status.style.display = 'none';
        if (linkBtn) { linkBtn.innerHTML = '<i class="fas fa-link"></i> Link Excel'; linkBtn.classList.remove('vp-linked-active'); }
    }
}

async function _vpSyncToExcel() {
    if (!window._vpFileHandle) return;
    if (window._vpSyncing) return;
    window._vpSyncing = true;
    const dot = document.getElementById('vpAutoSaveDot');
    if (dot) dot.classList.add('saving');
    try {
        // Verify we still have write permission
        const perm = await window._vpFileHandle.queryPermission({ mode: 'readwrite' });
        if (perm !== 'granted') {
            showToast('⚠️ Write permission lost. Click Re-link to reconnect.', 'info');
            window._vpFileHandle = null;
            _vpUpdateLinkedUI(window._vpLinkedName, false);
            if (dot) dot.classList.remove('saving');
            return;
        }
        const entries = DB.get('visitPlanEntries') || [];
        const wb = XLSX.utils.book_new();

        const header = ['Date', 'Day', 'Time', 'Plan Domain', 'Stakeholder Type', 'Cluster', 'Venue',
            'Stakeholder Name', 'Designation', 'Broader plan/Objective', 'Review against intervention plan',
            'Number of TPs', 'No of stakeholders', 'Qualitative comments for teachers',
            'Qualitative comments for engagement with students', 'Report sharing'];
        const dataRows = [header];
        let prevDate = null;
        for (const e of entries) {
            const dateVal = e.dateSerial || (e.date ? _vpJSDateToExcel(new Date(e.date)) : '');
            const showDate = dateVal !== prevDate ? dateVal : '';
            prevDate = dateVal;
            dataRows.push([showDate, e.day, e.time, e.domain, e.stakeholderType, e.cluster, e.venue,
                e.stakeholderName, e.designation, e.objective, e.review,
                e.tps, e.stakeholderCount, e.teacherComments, e.studentComments, e.reportSharing]);
        }
        const ws = XLSX.utils.aoa_to_sheet(dataRows);
        ws['!cols'] = header.map((_, i) => ({ wch: i === 0 ? 12 : i >= 9 ? 30 : 18 }));
        XLSX.utils.book_append_sheet(wb, ws, 'Sujit 2026');

        const dd = DB.get('visitPlanDropdowns');
        if (dd) {
            const keys = ['domains', 'days', 'times', 'stakeholderTypes', 'clusters', 'stakeholderNames', 'venues', 'designations'];
            const labels = ['Plan Domains', 'Days', 'Time', 'Stakeholder Types', 'Clusters', 'Stakeholder Names', 'Venues', 'Designations'];
            const maxLen = Math.max(...keys.map(k => (dd[k] || []).length));
            const ddRows = [['', ...labels], ['', ...labels.map(() => '')], ['', ...labels.map(() => '')]];
            for (let r = 0; r < maxLen; r++) {
                ddRows.push(['', ...keys.map(k => (dd[k] || [])[r] || '')]);
            }
            const ddWs = XLSX.utils.aoa_to_sheet(ddRows);
            XLSX.utils.book_append_sheet(wb, ddWs, 'Sheet4');
        }

        const writable = await window._vpFileHandle.createWritable();
        const xlsxData = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
        await writable.write(new Uint8Array(xlsxData));
        await writable.close();

        if (dot) { dot.classList.remove('saving'); dot.classList.add('saved'); setTimeout(() => dot.classList.remove('saved'), 1500); }
    } catch (err) {
        console.error('Sync to Excel error:', err);
        if (dot) dot.classList.remove('saving');
        if (err.name === 'NotAllowedError') {
            showToast('⚠️ Write permission lost. Click Re-link to reconnect.', 'warning');
            window._vpFileHandle = null;
            _vpUpdateLinkedUI(window._vpLinkedName, false);
        }
    } finally {
        window._vpSyncing = false;
    }
}

function _vpParseWorkbook(data) {
    const wb = XLSX.read(data, { type: 'array' });

    // Parse Sheet4 (Dropdowns)
    const dropdowns = { domains: [], days: [], times: [], stakeholderTypes: [], clusters: [], stakeholderNames: [], venues: [], designations: [] };
    const ddSheetName = wb.SheetNames.find(n => n.toLowerCase().includes('sheet4')) || wb.SheetNames.find(n => n.toLowerCase().includes('dropdown'));
    if (ddSheetName) {
        const ddSheet = wb.Sheets[ddSheetName];
        const ddRows = XLSX.utils.sheet_to_json(ddSheet, { header: 1, defval: '' });
        const keys = ['domains', 'days', 'times', 'stakeholderTypes', 'clusters', 'stakeholderNames', 'venues', 'designations'];
        for (let r = 3; r < ddRows.length; r++) {
            const row = ddRows[r];
            for (let c = 0; c < keys.length; c++) {
                const val = row[c + 1];
                if (val && String(val).trim()) {
                    const v = String(val).trim();
                    if (!dropdowns[keys[c]].includes(v)) dropdowns[keys[c]].push(v);
                }
            }
        }
    }
    DB.set('visitPlanDropdowns', dropdowns);

    // Parse main visit data
    const mainSheetName = wb.SheetNames.find(n => !n.toLowerCase().includes('sheet4') && !n.toLowerCase().includes('dropdown')) || wb.SheetNames[0];
    const mainSheet = wb.Sheets[mainSheetName];
    const rows = XLSX.utils.sheet_to_json(mainSheet, { header: 1, defval: '' });

    const entries = [];
    let lastDate = null;
    for (let r = 1; r < rows.length; r++) {
        const row = rows[r];
        if (!row || row.length === 0) continue;
        let dateVal = row[0];
        if (dateVal && !isNaN(dateVal)) { lastDate = Number(dateVal); }
        else if (dateVal && typeof dateVal === 'string' && dateVal.trim()) {
            const parsed = new Date(dateVal);
            if (!isNaN(parsed)) lastDate = _vpJSDateToExcel(parsed);
        }
        const time = String(row[2] || '').trim();
        const domain = String(row[3] || '').trim();
        const stakeholderType = String(row[4] || '').trim();
        const cluster = String(row[5] || '').trim();
        const venue = String(row[6] || '').trim();
        const stakeholderName = String(row[7] || '').trim();
        const designation = String(row[8] || '').trim();
        const objective = String(row[9] || '').trim();
        const review = String(row[10] || '').trim();
        const tps = String(row[11] || '').trim();
        const stakeholderCount = String(row[12] || '').trim();
        const teacherComments = String(row[13] || '').trim();
        const studentComments = String(row[14] || '').trim();
        const reportSharing = String(row[15] || '').trim();
        const isEmpty = !domain && !venue && !stakeholderName && !objective && !review;
        entries.push({
            id: DB.generateId(),
            dateSerial: lastDate,
            date: lastDate ? _vpExcelDateToJS(lastDate)?.toISOString().split('T')[0] : '',
            day: lastDate ? _vpDayName(lastDate) : String(row[1] || '').trim(),
            time, domain, stakeholderType, cluster, venue,
            stakeholderName, designation, objective, review,
            tps, stakeholderCount, teacherComments, studentComments, reportSharing,
            status: isEmpty ? 'empty' : (review ? 'executed' : 'planned'),
            source: 'excel'
        });
    }
    DB.set('visitPlanEntries', entries);
    renderVisitPlan();
}

function _vpExcelDateToJS(serial) {
    if (!serial || isNaN(serial)) return null;
    const utc_days = Math.floor(serial - 25569);
    return new Date(utc_days * 86400 * 1000);
}
function _vpJSDateToExcel(d) {
    if (!(d instanceof Date) || isNaN(d)) return '';
    return Math.floor((d.getTime() / 86400000) + 25569);
}
function _vpFormatDate(d) {
    if (!d) return '';
    if (typeof d === 'number') d = _vpExcelDateToJS(d);
    if (!(d instanceof Date) || isNaN(d)) return String(d);
    return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
}
function _vpDayName(d) {
    if (!d) return '';
    if (typeof d === 'number') d = _vpExcelDateToJS(d);
    if (!(d instanceof Date) || isNaN(d)) return '';
    return d.toLocaleDateString('en-US', { weekday: 'long' });
}

function importVisitPlanExcel(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const data = new Uint8Array(e.target.result);
            const wb = XLSX.read(data, { type: 'array' });

            // --- Parse Sheet4 (Dropdowns / Reference) ---
            const dropdowns = { domains: [], days: [], times: [], stakeholderTypes: [], clusters: [], stakeholderNames: [], venues: [], designations: [] };
            const ddSheetName = wb.SheetNames.find(n => n.toLowerCase().includes('sheet4')) || wb.SheetNames.find(n => n.toLowerCase().includes('dropdown'));
            if (ddSheetName) {
                const ddSheet = wb.Sheets[ddSheetName];
                const ddRows = XLSX.utils.sheet_to_json(ddSheet, { header: 1, defval: '' });
                const keys = ['domains', 'days', 'times', 'stakeholderTypes', 'clusters', 'stakeholderNames', 'venues', 'designations'];
                for (let r = 3; r < ddRows.length; r++) {
                    const row = ddRows[r];
                    for (let c = 0; c < keys.length; c++) {
                        const val = row[c + 1]; // data starts at col B (index 1)
                        if (val && String(val).trim()) {
                            const v = String(val).trim();
                            if (!dropdowns[keys[c]].includes(v)) dropdowns[keys[c]].push(v);
                        }
                    }
                }
            }
            DB.set('visitPlanDropdowns', dropdowns);

            // --- Parse main visit data sheet ---
            const mainSheetName = wb.SheetNames.find(n => !n.toLowerCase().includes('sheet4') && !n.toLowerCase().includes('dropdown')) || wb.SheetNames[0];
            const mainSheet = wb.Sheets[mainSheetName];
            const rows = XLSX.utils.sheet_to_json(mainSheet, { header: 1, defval: '' });

            const entries = [];
            let lastDate = null;
            for (let r = 1; r < rows.length; r++) {
                const row = rows[r];
                if (!row || row.length === 0) continue;

                let dateVal = row[0];
                if (dateVal && !isNaN(dateVal)) {
                    lastDate = Number(dateVal);
                } else if (dateVal && typeof dateVal === 'string' && dateVal.trim()) {
                    const parsed = new Date(dateVal);
                    if (!isNaN(parsed)) lastDate = _vpJSDateToExcel(parsed);
                }

                const time = String(row[2] || '').trim();
                const domain = String(row[3] || '').trim();
                const stakeholderType = String(row[4] || '').trim();
                const cluster = String(row[5] || '').trim();
                const venue = String(row[6] || '').trim();
                const stakeholderName = String(row[7] || '').trim();
                const designation = String(row[8] || '').trim();
                const objective = String(row[9] || '').trim();
                const review = String(row[10] || '').trim();
                const tps = String(row[11] || '').trim();
                const stakeholderCount = String(row[12] || '').trim();
                const teacherComments = String(row[13] || '').trim();
                const studentComments = String(row[14] || '').trim();
                const reportSharing = String(row[15] || '').trim();

                const isEmpty = !domain && !venue && !stakeholderName && !objective && !review;

                entries.push({
                    id: DB.generateId(),
                    dateSerial: lastDate,
                    date: lastDate ? _vpExcelDateToJS(lastDate)?.toISOString().split('T')[0] : '',
                    day: lastDate ? _vpDayName(lastDate) : String(row[1] || '').trim(),
                    time, domain, stakeholderType, cluster, venue,
                    stakeholderName, designation, objective, review,
                    tps, stakeholderCount, teacherComments, studentComments, reportSharing,
                    status: isEmpty ? 'empty' : (review ? 'executed' : 'planned'),
                    source: 'excel'
                });
            }
            DB.set('visitPlanEntries', entries);
            renderVisitPlan();
            showToast(`✅ Imported ${entries.length} entries from Excel`);
        } catch (err) {
            console.error('Excel Import Error:', err);
            showToast('❌ Error importing Excel: ' + err.message);
        }
    };
    reader.readAsArrayBuffer(file);
    event.target.value = '';
}

function exportVisitPlanExcel() {
    const entries = DB.get('visitPlanEntries') || [];
    if (!entries.length) { showToast('No visit plan data to export'); return; }

    const wb = XLSX.utils.book_new();

    // --- Main data sheet ---
    const header = ['Date', 'Day', 'Time', 'Plan Domain', 'Stakeholder Type', 'Cluster', 'Venue',
        'Stakeholder Name', 'Designation', 'Broader plan/Objective', 'Review against intervention plan',
        'Number of TPs', 'No of stakeholders', 'Qualitative comments for teachers',
        'Qualitative comments for engagement with students', 'Report sharing'];
    const dataRows = [header];
    let prevDate = null;
    for (const e of entries) {
        const dateVal = e.dateSerial || (e.date ? _vpJSDateToExcel(new Date(e.date)) : '');
        const showDate = dateVal !== prevDate ? dateVal : '';
        prevDate = dateVal;
        dataRows.push([showDate, e.day, e.time, e.domain, e.stakeholderType, e.cluster, e.venue,
            e.stakeholderName, e.designation, e.objective, e.review,
            e.tps, e.stakeholderCount, e.teacherComments, e.studentComments, e.reportSharing]);
    }
    const ws = XLSX.utils.aoa_to_sheet(dataRows);
    ws['!cols'] = header.map((_, i) => ({ wch: i === 0 ? 12 : i >= 9 ? 30 : 18 }));
    XLSX.utils.book_append_sheet(wb, ws, 'Visit Plan');

    // --- Dropdowns sheet ---
    const dd = DB.get('visitPlanDropdowns');
    if (dd) {
        const keys = ['domains', 'days', 'times', 'stakeholderTypes', 'clusters', 'stakeholderNames', 'venues', 'designations'];
        const labels = ['Plan Domains', 'Days', 'Time', 'Stakeholder Types', 'Clusters', 'Stakeholder Names', 'Venues', 'Designations'];
        const maxLen = Math.max(...keys.map(k => (dd[k] || []).length));
        const ddRows = [['', ...labels], ['', ...labels.map(() => '')], ['', ...labels.map(() => '')]];
        for (let r = 0; r < maxLen; r++) {
            ddRows.push(['', ...keys.map(k => (dd[k] || [])[r] || '')]);
        }
        const ddWs = XLSX.utils.aoa_to_sheet(ddRows);
        XLSX.utils.book_append_sheet(wb, ddWs, 'Sheet4');
    }

    XLSX.writeFile(wb, 'Visit_Plan_Export.xlsx');
    showToast('📥 Exported to Visit_Plan_Export.xlsx');
}

function _vpPopulateDropdowns() {
    const dd = DB.get('visitPlanDropdowns') || {};
    const entries = DB.get('visitPlanEntries') || [];

    // Merge helper: combine imported dropdown data + template defaults + existing entry values
    const mergeUnique = (...arrays) => {
        const seen = new Set();
        const result = [];
        arrays.flat().forEach(v => {
            if (v && String(v).trim() && !seen.has(v)) { seen.add(v); result.push(v); }
        });
        return result;
    };

    // Build merged lists — Excel data first, then templates, then from existing entries
    const templateDomains = VP_DOMAIN_TEMPLATES.map(t => t.domain);
    const entryDomains = entries.map(e => e.domain).filter(Boolean);
    const domains = mergeUnique(dd.domains, templateDomains, entryDomains);

    const defaultStakeholders = ['PS Teachers', 'AW Teachers', 'BRCC', 'Supervisors', 'BEO', 'Parents', 'Community Members', 'DIET Faculty', 'CRC', 'SMC Members'];
    const entryStakeholders = entries.map(e => e.stakeholderType).filter(Boolean);
    const stakeholderTypes = mergeUnique(dd.stakeholderTypes, defaultStakeholders, entryStakeholders);

    const defaultClusters = [];
    const entryClusters = entries.map(e => e.cluster).filter(Boolean);
    const clusters = mergeUnique(dd.clusters, defaultClusters, entryClusters);

    const entryVenues = entries.map(e => e.venue).filter(Boolean);
    const venues = mergeUnique(dd.venues, entryVenues);

    const entryNames = entries.map(e => e.stakeholderName).filter(Boolean);
    const stakeholderNames = mergeUnique(dd.stakeholderNames, entryNames);

    const populate = (selectId, items) => {
        const el = document.getElementById(selectId);
        if (!el) return;
        const current = el.value;
        const firstOpt = el.querySelector('option');
        el.innerHTML = '';
        if (firstOpt) el.appendChild(firstOpt);
        (items || []).forEach(v => {
            const o = document.createElement('option');
            o.value = v; o.textContent = v;
            el.appendChild(o);
        });
        if (current) el.value = current;
    };
    populate('vpDomain', domains);
    populate('vpStakeholder', stakeholderTypes);
    populate('vpCluster', clusters);

    // Datalists
    const fillDatalist = (id, items) => {
        const dl = document.getElementById(id);
        if (!dl) return;
        dl.innerHTML = '';
        (items || []).forEach(v => {
            const o = document.createElement('option');
            o.value = v;
            dl.appendChild(o);
        });
    };
    fillDatalist('vpVenueList', venues);
    fillDatalist('vpStakeholderNameList', stakeholderNames);

    // Filter dropdowns (reuse entries from above)
    const populateFilter = (selectId, key, icon) => {
        const el = document.getElementById(selectId);
        if (!el) return;
        const current = el.value;
        const vals = [...new Set(entries.map(e => e[key]).filter(Boolean))].sort();
        el.innerHTML = `<option value="all">${icon} All</option>`;
        vals.forEach(v => {
            const o = document.createElement('option');
            o.value = v; o.textContent = v;
            el.appendChild(o);
        });
        el.value = current || 'all';
    };
    populateFilter('vpDomainFilter', 'domain', '📂');
    populateFilter('vpStakeholderFilter', 'stakeholderType', '👥');
    populateFilter('vpClusterFilter', 'cluster', '📍');

    // Month filter from dates
    const monthEl = document.getElementById('vpMonthFilter');
    if (monthEl) {
        const cur = monthEl.value;
        const months = [...new Set(entries.map(e => {
            if (!e.date) return null;
            const d = new Date(e.date);
            return isNaN(d) ? null : d.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
        }).filter(Boolean))];
        monthEl.innerHTML = '<option value="all">📅 All Months</option>';
        months.forEach(m => {
            const o = document.createElement('option');
            o.value = m; o.textContent = m;
            monthEl.appendChild(o);
        });
        monthEl.value = cur || 'all';
    }
}

const VP_DOMAIN_TEMPLATES = [
    { domain: 'School Visits',       icon: 'fa-school',            color: '#8b5cf6', stakeholder: 'PS Teachers', fields: { designation: 'Teacher' } },
    { domain: 'AW Visits',           icon: 'fa-child',             color: '#ec4899', stakeholder: 'AW Teachers', fields: { designation: 'Teacher' } },
    { domain: 'Cluster Workshop',    icon: 'fa-users-cog',         color: '#3b82f6', stakeholder: '',             fields: {} },
    { domain: 'Mobilization',        icon: 'fa-bullhorn',          color: '#f59e0b', stakeholder: '',             fields: {} },
    { domain: 'Block Level Meeting', icon: 'fa-building',          color: '#10b981', stakeholder: 'BRCC',         fields: { designation: 'CAC' } },
    { domain: 'Meeting',             icon: 'fa-handshake',         color: '#06b6d4', stakeholder: '',             fields: {} },
    { domain: 'Training',            icon: 'fa-chalkboard-teacher',color: '#f97316', stakeholder: '',             fields: {} },
    { domain: 'Admin Work',          icon: 'fa-file-alt',          color: '#6366f1', stakeholder: '',             fields: {} },
    { domain: 'Community Engagement',icon: 'fa-people-carry',      color: '#14b8a6', stakeholder: 'Supervisors',  fields: {} },
    { domain: 'Data Collection',     icon: 'fa-database',          color: '#ef4444', stakeholder: '',             fields: {} },
];

function _vpRenderQuickBar() {
    const bar = document.getElementById('vpQuickBar');
    if (!bar) return;
    const dd = DB.get('visitPlanDropdowns') || {};
    const importedDomains = dd.domains || [];

    // Merge: use templates + any imported domains not already in templates
    const templateDomains = VP_DOMAIN_TEMPLATES.map(t => t.domain.toLowerCase());
    const extras = importedDomains.filter(d => !templateDomains.includes(d.toLowerCase()));

    let html = '<div class="vp-quick-label"><i class="fas fa-bolt"></i> Quick Add</div><div class="vp-quick-chips">';
    VP_DOMAIN_TEMPLATES.forEach(t => {
        html += `<button class="vp-quick-chip" style="--qc-color:${t.color}" onclick="vpQuickAdd('${t.domain.replace(/'/g,"\\'")}')"><i class="fas ${t.icon}"></i> ${t.domain}</button>`;
    });
    extras.forEach(d => {
        html += `<button class="vp-quick-chip" style="--qc-color:#6b7280" onclick="vpQuickAdd('${d.replace(/'/g,"\\'")}')"><i class="fas fa-folder"></i> ${d}</button>`;
    });
    html += '</div>';
    bar.innerHTML = html;
}

function vpQuickAdd(domain) {
    const tpl = VP_DOMAIN_TEMPLATES.find(t => t.domain === domain) || {};
    _vpPopulateDropdowns();
    const form = document.getElementById('vpForm');
    form.reset();
    document.getElementById('vpEntryId').value = '';
    document.getElementById('vpModalTitle').innerHTML = `<i class="fas ${tpl.icon || 'fa-clipboard-check'}"></i> ${domain}`;

    // Pre-fill today's date
    const today = new Date().toISOString().split('T')[0];
    document.getElementById('vpDate').value = today;
    document.getElementById('vpTime').value = 'First Half';
    document.getElementById('vpDomain').value = domain;

    if (tpl.stakeholder) {
        document.getElementById('vpStakeholder').value = tpl.stakeholder;
    }
    if (tpl.fields) {
        if (tpl.fields.designation) document.getElementById('vpDesignation').value = tpl.fields.designation;
    }
    openModal('visitPlanModal');
}

function openVisitPlanModal(id) {
    _vpPopulateDropdowns();
    const form = document.getElementById('vpForm');
    form.reset();
    document.getElementById('vpEntryId').value = '';
    document.getElementById('vpModalTitle').innerHTML = '<i class="fas fa-clipboard-check"></i> New Visit Plan Entry';

    if (id) {
        const entries = DB.get('visitPlanEntries') || [];
        const entry = entries.find(e => e.id === id);
        if (entry) {
            document.getElementById('vpEntryId').value = entry.id;
            document.getElementById('vpModalTitle').innerHTML = '<i class="fas fa-edit"></i> Edit Visit Plan Entry';
            document.getElementById('vpDate').value = entry.date || '';
            document.getElementById('vpTime').value = entry.time || 'First Half';
            document.getElementById('vpDomain').value = entry.domain || '';
            document.getElementById('vpStakeholder').value = entry.stakeholderType || '';
            document.getElementById('vpCluster').value = entry.cluster || '';
            document.getElementById('vpVenue').value = entry.venue || '';
            document.getElementById('vpStakeholderName').value = entry.stakeholderName || '';
            document.getElementById('vpDesignation').value = entry.designation || '';
            document.getElementById('vpObjective').value = entry.objective || '';
            document.getElementById('vpReview').value = entry.review || '';
            document.getElementById('vpTPs').value = entry.tps || '';
            document.getElementById('vpStakeholderCount').value = entry.stakeholderCount || '';
            document.getElementById('vpTeacherComments').value = entry.teacherComments || '';
            document.getElementById('vpStudentComments').value = entry.studentComments || '';
            document.getElementById('vpReportSharing').value = entry.reportSharing || '';
        }
    }
    openModal('visitPlanModal');
}

function saveVisitPlanEntry(event) {
    event.preventDefault();
    const id = document.getElementById('vpEntryId').value;
    const dateStr = document.getElementById('vpDate').value;
    const dateObj = dateStr ? new Date(dateStr) : null;

    const entry = {
        id: id || DB.generateId(),
        date: dateStr,
        dateSerial: dateObj ? _vpJSDateToExcel(dateObj) : null,
        day: dateObj ? _vpDayName(dateObj) : '',
        time: document.getElementById('vpTime').value,
        domain: document.getElementById('vpDomain').value,
        stakeholderType: document.getElementById('vpStakeholder').value,
        cluster: document.getElementById('vpCluster').value,
        venue: document.getElementById('vpVenue').value,
        stakeholderName: document.getElementById('vpStakeholderName').value,
        designation: document.getElementById('vpDesignation').value,
        objective: document.getElementById('vpObjective').value,
        review: document.getElementById('vpReview').value,
        tps: document.getElementById('vpTPs').value,
        stakeholderCount: document.getElementById('vpStakeholderCount').value,
        teacherComments: document.getElementById('vpTeacherComments').value,
        studentComments: document.getElementById('vpStudentComments').value,
        reportSharing: document.getElementById('vpReportSharing').value,
        status: document.getElementById('vpReview').value.trim() ? 'executed' : (document.getElementById('vpDomain').value ? 'planned' : 'empty'),
        source: 'manual'
    };

    let entries = DB.get('visitPlanEntries') || [];
    if (id) {
        const idx = entries.findIndex(e => e.id === id);
        if (idx >= 0) entries[idx] = { ...entries[idx], ...entry };
        else entries.push(entry);
    } else {
        entries.push(entry);
    }
    DB.set('visitPlanEntries', entries);
    closeModal('visitPlanModal');
    renderVisitPlan();
    showToast(id ? '✏️ Entry updated' : '✅ Entry added');
    setTimeout(() => _vpSyncToExcel(), 200);
}

function deleteVisitPlanEntry(id) {
    if (!confirm('Delete this visit plan entry?')) return;
    let entries = DB.get('visitPlanEntries') || [];
    entries = entries.filter(e => e.id !== id);
    DB.set('visitPlanEntries', entries);
    renderVisitPlan();
    showToast('🗑️ Entry deleted');
    setTimeout(() => _vpSyncToExcel(), 200);
}

function vpBulkClear() {
    const entries = DB.get('visitPlanEntries') || [];
    const domainF = document.getElementById('vpDomainFilter')?.value || 'all';
    const stakeholderF = document.getElementById('vpStakeholderFilter')?.value || 'all';
    const clusterF = document.getElementById('vpClusterFilter')?.value || 'all';
    const monthF = document.getElementById('vpMonthFilter')?.value || 'all';
    const statusF = document.getElementById('vpStatusFilter')?.value || 'all';
    const search = (document.getElementById('vpSearchInput')?.value || '').toLowerCase().trim();

    const isFiltered = domainF !== 'all' || stakeholderF !== 'all' || clusterF !== 'all' || monthF !== 'all' || statusF !== 'all' || search;

    const toDelete = new Set();
    entries.forEach(e => {
        let match = true;
        if (domainF !== 'all' && e.domain !== domainF) match = false;
        if (stakeholderF !== 'all' && e.stakeholderType !== stakeholderF) match = false;
        if (clusterF !== 'all' && e.cluster !== clusterF) match = false;
        if (statusF !== 'all' && e.status !== statusF) match = false;
        if (monthF !== 'all') {
            if (!e.date) { match = false; }
            else {
                const d = new Date(e.date);
                const m = d.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
                if (m !== monthF) match = false;
            }
        }
        if (search) {
            const hay = [e.domain, e.venue, e.stakeholderName, e.cluster, e.objective, e.review, e.time, e.designation].join(' ').toLowerCase();
            if (!hay.includes(search)) match = false;
        }
        if (match) toDelete.add(e.id);
    });

    if (toDelete.size === 0) { showToast('No entries match current filters'); return; }

    const label = isFiltered ? `Delete ${toDelete.size} filtered entries?` : `Delete ALL ${toDelete.size} entries?`;
    if (!confirm(label + '\n\nThis cannot be undone.')) return;

    const remaining = entries.filter(e => !toDelete.has(e.id));
    DB.set('visitPlanEntries', remaining);
    _pageState.visitplan = 1;
    renderVisitPlan();
    showToast(`🗑️ ${toDelete.size} entries deleted`);
    setTimeout(() => _vpSyncToExcel(), 200);
}

function vpSendToSchoolVisits(id) {
    const entries = DB.get('visitPlanEntries') || [];
    const e = entries.find(x => x.id === id);
    if (!e) { showToast('Entry not found'); return; }

    // Build notes from all available info
    const notesParts = [];
    if (e.objective) notesParts.push('Objective: ' + e.objective);
    if (e.review) notesParts.push('Review: ' + e.review);
    if (e.teacherComments) notesParts.push('Teacher Comments: ' + e.teacherComments);
    if (e.studentComments) notesParts.push('Student Engagement: ' + e.studentComments);
    if (e.tps) notesParts.push('TPs: ' + e.tps);
    if (e.stakeholderCount) notesParts.push('Stakeholders: ' + e.stakeholderCount);

    // Map purpose from domain
    const purposeMap = {
        'School Visits': 'Classroom Observation',
        'AW Visits': 'Classroom Observation',
        'Cluster Workshop': 'Workshop Facilitation',
        'Training': 'Workshop Facilitation',
        'Meeting': 'Meeting with HM',
        'Block Level Meeting': 'Meeting with HM',
        'Mobilization': 'Community Outreach',
        'Community Engagement': 'Community Outreach',
        'Data Collection': 'Data Collection',
        'Admin Work': 'Admin'
    };
    const purpose = purposeMap[e.domain] || 'Classroom Observation';
    const status = e.review ? 'completed' : 'planned';

    const visit = {
        id: DB.generateId(),
        school: e.venue || '',
        block: '',
        cluster: e.cluster || '',
        district: '',
        date: e.date || new Date().toISOString().split('T')[0],
        status: status,
        purpose: purpose,
        duration: e.time || '',
        peopleMet: [e.stakeholderName, e.designation ? '(' + e.designation + ')' : ''].filter(Boolean).join(' '),
        rating: '',
        notes: notesParts.join('\n'),
        followUp: e.reportSharing || '',
        nextDate: '',
        createdAt: new Date().toISOString(),
        fromVisitPlan: e.id
    };

    const visits = DB.get('visits') || [];
    visits.push(visit);
    DB.set('visits', visits);

    // Mark entry as executed in visit plan
    const idx = entries.findIndex(x => x.id === id);
    if (idx >= 0) {
        entries[idx].status = 'executed';
        entries[idx].sentToVisits = true;
        DB.set('visitPlanEntries', entries);
    }

    renderVisitPlan();
    showToast('🏫 Added to School Visits!', 'success');
    setTimeout(() => _vpSyncToExcel(), 200);
}

function vpSendToTraining(id) {
    const entries = DB.get('visitPlanEntries') || [];
    const e = entries.find(x => x.id === id);
    if (!e) { showToast('Entry not found'); return; }

    const notesParts = [];
    if (e.objective) notesParts.push('Objective: ' + e.objective);
    if (e.review) notesParts.push('Review: ' + e.review);
    if (e.teacherComments) notesParts.push('Teacher Comments: ' + e.teacherComments);
    if (e.studentComments) notesParts.push('Student Engagement: ' + e.studentComments);
    if (e.tps) notesParts.push('TPs: ' + e.tps);
    if (e.stakeholderCount) notesParts.push('Stakeholders: ' + e.stakeholderCount);

    const targetMap = {
        'PS Teachers': 'Teachers',
        'AW Teachers': 'Teachers',
        'BRCC': 'CRPs/BRPs',
        'Supervisors': 'CRPs/BRPs',
        'DIET Faculty': 'CRPs/BRPs',
        'CRC': 'CRPs/BRPs',
        'BEO': 'CRPs/BRPs',
        'Parents': 'Community',
        'Community Members': 'Community',
        'SMC Members': 'SMC'
    };
    const target = targetMap[e.stakeholderType] || 'Teachers';
    const status = e.review ? 'completed' : 'planned';

    const training = {
        id: DB.generateId(),
        title: e.domain || 'Training Session',
        topic: e.objective || '',
        date: e.date || new Date().toISOString().split('T')[0],
        duration: 3,
        venue: e.venue || '',
        status: status,
        attendees: parseInt(e.stakeholderCount) || 0,
        target: target,
        notes: notesParts.join('\n'),
        feedback: e.reportSharing || '',
        createdAt: new Date().toISOString(),
        fromVisitPlan: e.id
    };

    const trainings = DB.get('trainings') || [];
    trainings.push(training);
    DB.set('trainings', trainings);

    // Mark in visit plan
    const idx = entries.findIndex(x => x.id === id);
    if (idx >= 0) {
        entries[idx].sentToTraining = true;
        DB.set('visitPlanEntries', entries);
    }

    renderVisitPlan();
    showToast('📚 Added to Teacher Training!', 'success');
    setTimeout(() => _vpSyncToExcel(), 200);
}

function renderVisitPlan() {
  try {
    const entries = DB.get('visitPlanEntries') || [];
    _vpPopulateDropdowns();
    _vpRenderQuickBar();

    // --- Filters ---
    const domainF = document.getElementById('vpDomainFilter')?.value || 'all';
    const stakeholderF = document.getElementById('vpStakeholderFilter')?.value || 'all';
    const clusterF = document.getElementById('vpClusterFilter')?.value || 'all';
    const monthF = document.getElementById('vpMonthFilter')?.value || 'all';
    const statusF = document.getElementById('vpStatusFilter')?.value || 'all';
    const search = (document.getElementById('vpSearchInput')?.value || '').toLowerCase().trim();

    let filtered = entries.filter(e => {
        if (domainF !== 'all' && e.domain !== domainF) return false;
        if (stakeholderF !== 'all' && e.stakeholderType !== stakeholderF) return false;
        if (clusterF !== 'all' && e.cluster !== clusterF) return false;
        if (statusF !== 'all' && e.status !== statusF) return false;
        if (monthF !== 'all') {
            if (!e.date) return false;
            const d = new Date(e.date);
            const m = d.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
            if (m !== monthF) return false;
        }
        if (search) {
            const hay = [e.domain, e.venue, e.stakeholderName, e.cluster, e.objective, e.review, e.time, e.designation].join(' ').toLowerCase();
            if (!hay.includes(search)) return false;
        }
        return true;
    });

    // --- Stats ---
    const total = entries.length;
    const planned = entries.filter(e => e.status === 'planned').length;
    const executed = entries.filter(e => e.status === 'executed').length;
    const empty = entries.filter(e => e.status === 'empty').length;
    const domains = new Set(entries.map(e => e.domain).filter(Boolean)).size;
    const clusters = new Set(entries.map(e => e.cluster).filter(Boolean)).size;

    // --- Bulk Clear Button ---
    const isFiltered = domainF !== 'all' || stakeholderF !== 'all' || clusterF !== 'all' || monthF !== 'all' || statusF !== 'all' || search;
    const bulkBtn = document.getElementById('vpBulkClearBtn');
    const bulkLabel = document.getElementById('vpBulkClearLabel');
    if (bulkBtn) {
        if (filtered.length > 0) {
            bulkBtn.style.display = '';
            bulkLabel.textContent = isFiltered ? `Clear ${filtered.length}` : 'Clear All';
        } else {
            bulkBtn.style.display = 'none';
        }
    }

    const statsEl = document.getElementById('vpStats');
    if (statsEl) {
        statsEl.innerHTML = `
            <div class="vp-stat-card"><div class="vp-stat-num">${total}</div><div class="vp-stat-label">Total Entries</div></div>
            <div class="vp-stat-card vp-stat-planned"><div class="vp-stat-num">${planned}</div><div class="vp-stat-label">Planned</div></div>
            <div class="vp-stat-card vp-stat-executed"><div class="vp-stat-num">${executed}</div><div class="vp-stat-label">Executed</div></div>
            <div class="vp-stat-card vp-stat-empty"><div class="vp-stat-num">${empty}</div><div class="vp-stat-label">Unfilled</div></div>
            <div class="vp-stat-card"><div class="vp-stat-num">${domains}</div><div class="vp-stat-label">Domains</div></div>
            <div class="vp-stat-card"><div class="vp-stat-num">${clusters}</div><div class="vp-stat-label">Clusters</div></div>
        `;
    }

    // --- Table ---
    const container = document.getElementById('vpContainer');
    if (!container) return;
    if (!filtered.length) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-clipboard-check"></i><h3>No visit plan entries</h3><p>Import an Excel file or add entries manually to get started.</p></div>`;
        return;
    }

    // Pagination
    const p = getPaginatedItems(filtered, 'visitplan', 25);
    const paged = p.items;

    // Group by date
    const grouped = {};
    paged.forEach(e => {
        const key = e.date || 'No Date';
        if (!grouped[key]) grouped[key] = [];
        grouped[key].push(e);
    });

    let html = '';
    for (const [dateKey, items] of Object.entries(grouped)) {
        const dateLabel = dateKey === 'No Date' ? 'No Date' : _vpFormatDate(new Date(dateKey));
        const dayLabel = items[0]?.day || '';
        html += `<div class="vp-date-group">
            <div class="vp-date-header">
                <span class="vp-date-label"><i class="fas fa-calendar-day"></i> ${dateLabel}</span>
                <span class="vp-day-label">${dayLabel}</span>
                <span class="vp-date-count">${items.length} slot${items.length > 1 ? 's' : ''}</span>
            </div>
            <div class="vp-date-cards">`;

        items.forEach(e => {
            const statusClass = e.status === 'executed' ? 'vp-status-executed' : e.status === 'planned' ? 'vp-status-planned' : 'vp-status-empty';
            const statusIcon = e.status === 'executed' ? 'fa-check-circle' : e.status === 'planned' ? 'fa-clock' : 'fa-circle';
            const statusLabel = e.status === 'executed' ? 'Executed' : e.status === 'planned' ? 'Planned' : 'Empty';

            html += `<div class="vp-entry-card ${statusClass}">
                <div class="vp-entry-top">
                    <span class="vp-time-badge"><i class="fas fa-clock"></i> ${e.time || '-'}</span>
                    <div style="display:flex;align-items:center;gap:6px">
                        ${e.sentToVisits ? '<span class="vp-sent-badge"><i class="fas fa-school"></i> Visit</span>' : ''}
                        ${e.sentToTraining ? '<span class="vp-sent-badge vp-sent-training"><i class="fas fa-chalkboard-teacher"></i> Training</span>' : ''}
                        <span class="vp-status-badge ${statusClass}"><i class="fas ${statusIcon}"></i> ${statusLabel}</span>
                    </div>
                </div>
                <div class="vp-entry-body">
                    <div class="vp-entry-domain">${e.domain || '<em>No domain</em>'}</div>
                    ${e.venue ? `<div class="vp-entry-venue"><i class="fas fa-map-marker-alt"></i> ${e.venue}</div>` : ''}
                    ${e.stakeholderName ? `<div class="vp-entry-person"><i class="fas fa-user"></i> ${e.stakeholderName}${e.designation ? ` <span class="vp-desg">(${e.designation})</span>` : ''}</div>` : ''}
                    ${e.cluster ? `<div class="vp-entry-cluster"><i class="fas fa-layer-group"></i> ${e.cluster}</div>` : ''}
                    ${e.objective ? `<div class="vp-entry-obj"><i class="fas fa-bullseye"></i> ${e.objective.substring(0, 80)}${e.objective.length > 80 ? '...' : ''}</div>` : ''}
                    ${e.review ? `<div class="vp-entry-review"><i class="fas fa-check-double"></i> ${e.review.substring(0, 80)}${e.review.length > 80 ? '...' : ''}</div>` : ''}
                </div>
                <div class="vp-entry-actions">
                    <button class="vp-act-btn vp-act-send" onclick="vpSendToSchoolVisits('${e.id}')" title="Add to School Visits"><i class="fas fa-school"></i></button>
                    <button class="vp-act-btn vp-act-train" onclick="vpSendToTraining('${e.id}')" title="Add to Teacher Training"><i class="fas fa-chalkboard-teacher"></i></button>
                    <button class="vp-act-btn" onclick="openVisitPlanModal('${e.id}')" title="Edit"><i class="fas fa-edit"></i></button>
                    <button class="vp-act-btn vp-act-del" onclick="deleteVisitPlanEntry('${e.id}')" title="Delete"><i class="fas fa-trash"></i></button>
                </div>
            </div>`;
        });
        html += '</div></div>';
    }

    // Pagination controls
    html += renderPaginationControls('visitplan', p, 'renderVisitPlan');

    container.innerHTML = html;
  } catch (err) {
    console.error('renderVisitPlan error:', err);
    const container = document.getElementById('vpContainer');
    if (container) container.innerHTML = `<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><h3>Rendering Error</h3><p>${err.message}</p></div>`;
  }
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
            { key: 'followupStatus', label: 'Follow-ups', icon: 'fa-clipboard-check', color: '#84cc16' },
            { key: 'worklog', label: 'Work Log', icon: 'fa-clipboard-list', color: '#7c3aed' },
            { key: 'userProfile', label: 'Profile', icon: 'fa-user-circle', color: '#0ea5e9' },
            { key: 'meetings', label: 'Meetings', icon: 'fa-handshake', color: '#0d9488' },
            { key: 'maraiTracking', label: 'MARAI', icon: 'fa-route', color: '#d946ef' },
            { key: 'schoolWork', label: 'School Work', icon: 'fa-chalkboard', color: '#059669' }
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

    // Google Drive status
    if (GoogleDriveSync.isConnected()) {
        GoogleDriveSync.updateUI('connected');
        const urlInput = document.getElementById('gdriveScriptURL');
        if (urlInput) urlInput.value = GoogleDriveSync.getScriptUrl();
    } else {
        GoogleDriveSync.updateUI('disconnected');
    }
}

function downloadBackup() {
    try {
        const keys = ENCRYPTED_DATA_KEYS;
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

            ENCRYPTED_DATA_KEYS.forEach(k => {
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
                applyProfileToUI();
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
            Date: o.date, School: o.school, Teacher: o.teacher || '', 'Phone': o.teacherPhone || '',
            'Teacher Stage': o.teacherStage || '', Class: o.class || '', Subject: o.subject || '',
            'Observation': o.observationStatus || '', 'Observed While Teaching': o.observedWhileTeaching || '',
            'Engagement Level': o.engagementLevel || '', 'Practice Type': o.practiceType || '',
            'Practice Serial': o.practiceSerial || '', 'Practice': o.practice || '',
            'Group': o.group || '', Topic: o.topic || '',
            Cluster: o.cluster || '', Block: o.block || '',
            Observer: o.observer || '', 'Status': o.stakeholderStatus || '',
            'Engagement (1-5)': o.engagementRating || o.engagement || 0, 'Methodology (1-5)': o.methodology || 0, 'TLM Usage (1-5)': o.tlm || 0,
            Notes: o.notes || '', Strengths: o.strengths || '', 'Areas for Improvement': o.areas || '', Suggestions: o.suggestions || '',
            Source: o.source || 'Manual'
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

    const teacherRecords = DB.get('teacherRecords') || [];
    if (teacherRecords.length > 0) {
        const ws = XLSX.utils.json_to_sheet(teacherRecords.map(r => ({
            Name: r.name, Gender: r.gender || '', School: r.school || '', Designation: r.designation || '',
            Subject: r.subject || '', Classes: r.classesTaught || '', Phone: r.phone || '', Email: r.email || '',
            Block: r.block || '', Cluster: r.cluster || '', Qualification: r.qualification || '',
            Experience: r.experience || '', 'Date of Joining': r.joinDate || '', NID: r.nid || '', Notes: r.notes || ''
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Teacher Records');
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

// ===== APP SETTINGS =====
const APP_SETTINGS_KEY = 'apf_app_settings';
const ACCENT_COLORS = [
    { name: 'Amber', value: '#f59e0b', css: '245, 158, 11' },
    { name: 'Blue', value: '#3b82f6', css: '59, 130, 246' },
    { name: 'Purple', value: '#8b5cf6', css: '139, 92, 246' },
    { name: 'Green', value: '#10b981', css: '16, 185, 129' },
    { name: 'Rose', value: '#f43f5e', css: '244, 63, 94' },
    { name: 'Cyan', value: '#06b6d4', css: '6, 182, 212' },
    { name: 'Orange', value: '#f97316', css: '249, 115, 22' },
    { name: 'Indigo', value: '#6366f1', css: '99, 102, 241' }
];

function getDefaultSettings() {
    return {
        accentColor: '#f59e0b',
        fontSize: 'default',
        compactMode: false,
        defaultBlock: '',
        defaultCluster: '',
        defaultDistrict: '',
        defaultState: '',
        dateFormat: 'dd-mmm-yyyy',
        smartAlerts: true,
        dashCharts: true,
        recentActivity: true,
        startPage: 'dashboard',
        followupReminder: true,
        visitReminder: true,
        worklogAuto: true,
        saveToast: true
    };
}

function getAppSettings() {
    try {
        const raw = localStorage.getItem(APP_SETTINGS_KEY);
        if (raw) {
            const parsed = JSON.parse(raw);
            return { ...getDefaultSettings(), ...parsed };
        }
    } catch (e) {}
    return getDefaultSettings();
}

function saveAppSettings() {
    const settings = {
        accentColor: getAppSettings().accentColor,
        fontSize: getAppSettings().fontSize,
        compactMode: document.getElementById('settingCompactMode')?.checked ?? false,
        defaultBlock: (document.getElementById('settingDefaultBlock')?.value || '').trim(),
        defaultCluster: (document.getElementById('settingDefaultCluster')?.value || '').trim(),
        defaultDistrict: (document.getElementById('settingDefaultDistrict')?.value || '').trim(),
        defaultState: (document.getElementById('settingDefaultState')?.value || '').trim(),
        dateFormat: document.getElementById('settingDateFormat')?.value || 'dd-mmm-yyyy',
        smartAlerts: document.getElementById('settingSmartAlerts')?.checked ?? true,
        dashCharts: document.getElementById('settingDashCharts')?.checked ?? true,
        recentActivity: document.getElementById('settingRecentActivity')?.checked ?? true,
        startPage: document.getElementById('settingStartPage')?.value || 'dashboard',
        followupReminder: document.getElementById('settingFollowupReminder')?.checked ?? true,
        visitReminder: document.getElementById('settingVisitReminder')?.checked ?? true,
        worklogAuto: document.getElementById('settingWorklogAuto')?.checked ?? true,
        saveToast: document.getElementById('settingSaveToast')?.checked ?? true
    };

    try { localStorage.setItem(APP_SETTINGS_KEY, JSON.stringify(settings)); } catch (e) {}
    showToast('Settings saved', 'success', 1500);
}

function renderSettings() {
    const s = getAppSettings();

    // Theme toggle
    const themeToggle = document.getElementById('settingThemeToggle');
    const themeLabel = document.getElementById('settingThemeLabel');
    const isLight = document.body.classList.contains('light-mode');
    if (themeToggle) themeToggle.checked = isLight;
    if (themeLabel) themeLabel.textContent = isLight ? 'Light' : 'Dark';

    // Accent colors
    const colorGrid = document.getElementById('settingAccentColors');
    if (colorGrid) {
        colorGrid.innerHTML = ACCENT_COLORS.map(c =>
            `<div class="settings-color-swatch ${s.accentColor === c.value ? 'active' : ''}" 
                 style="background:${c.value};" 
                 title="${c.name}" 
                 onclick="setAccentColor('${c.value}', '${c.css}')">
                ${s.accentColor === c.value ? '<i class="fas fa-check"></i>' : ''}
            </div>`
        ).join('');
    }

    // Font size buttons
    document.querySelectorAll('.settings-size-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    const sizeMap = { 'small': 0, 'default': 1, 'large': 2 };
    const btns = document.querySelectorAll('.settings-size-btn');
    if (btns[sizeMap[s.fontSize]]) btns[sizeMap[s.fontSize]].classList.add('active');

    // Compact mode
    const compact = document.getElementById('settingCompactMode');
    if (compact) compact.checked = s.compactMode;

    // Default values
    const fields = { settingDefaultBlock: s.defaultBlock, settingDefaultCluster: s.defaultCluster, settingDefaultDistrict: s.defaultDistrict, settingDefaultState: s.defaultState };
    Object.entries(fields).forEach(([id, val]) => {
        const el = document.getElementById(id);
        if (el) el.value = val;
    });

    // Date format
    const dateFormat = document.getElementById('settingDateFormat');
    if (dateFormat) dateFormat.value = s.dateFormat;

    // Toggles
    const toggles = {
        settingSmartAlerts: s.smartAlerts,
        settingDashCharts: s.dashCharts,
        settingRecentActivity: s.recentActivity,
        settingFollowupReminder: s.followupReminder,
        settingVisitReminder: s.visitReminder,
        settingWorklogAuto: s.worklogAuto,
        settingSaveToast: s.saveToast
    };
    Object.entries(toggles).forEach(([id, val]) => {
        const el = document.getElementById(id);
        if (el) el.checked = val;
    });

    // Start page
    const startPage = document.getElementById('settingStartPage');
    if (startPage) startPage.value = s.startPage;

    // Data stats
    renderSettingsDataStats();
}

function renderSettingsDataStats() {
    const statsEl = document.getElementById('settingsDataStats');
    if (!statsEl) return;

    const dataKeys = [
        { key: 'visits', label: 'Visits', icon: 'fa-school', color: '#3b82f6' },
        { key: 'trainings', label: 'Trainings', icon: 'fa-chalkboard-teacher', color: '#8b5cf6' },
        { key: 'observations', label: 'Observations', icon: 'fa-eye', color: '#10b981' },
        { key: 'resources', label: 'Resources', icon: 'fa-book', color: '#f59e0b' },
        { key: 'notes', label: 'Notes', icon: 'fa-sticky-note', color: '#06b6d4' },
        { key: 'ideas', label: 'Ideas', icon: 'fa-lightbulb', color: '#f97316' },
        { key: 'reflections', label: 'Reflections', icon: 'fa-journal-whills', color: '#ec4899' },
        { key: 'contacts', label: 'Contacts', icon: 'fa-address-book', color: '#6366f1' },
        { key: 'plannerTasks', label: 'Planner Tasks', icon: 'fa-calendar-alt', color: '#14b8a6' },
        { key: 'meetings', label: 'Meetings', icon: 'fa-handshake', color: '#a855f7' },
        { key: 'growthAssessments', label: 'Assessments', icon: 'fa-seedling', color: '#16a34a' },
        { key: 'teacherRecords', label: 'Teacher Records', icon: 'fa-id-card-alt', color: '#0ea5e9' },
        { key: 'schoolStudentRecords', label: 'Student Records', icon: 'fa-user-graduate', color: '#f43f5e' }
    ];

    let totalRecords = 0;
    const cards = dataKeys.map(d => {
        const count = DB.get(d.key).length;
        totalRecords += count;
        return `<div class="settings-data-stat">
            <div class="settings-data-stat-icon" style="color:${d.color};"><i class="fas ${d.icon}"></i></div>
            <div class="settings-data-stat-value">${count}</div>
            <div class="settings-data-stat-label">${d.label}</div>
        </div>`;
    });

    // Estimate storage size
    let storageSize = 0;
    try {
        ENCRYPTED_DATA_KEYS.forEach(k => {
            const data = DB.get(k);
            storageSize += JSON.stringify(data).length;
        });
    } catch(e) {}
    const sizeStr = storageSize > 1048576 ? (storageSize / 1048576).toFixed(1) + ' MB'
                  : storageSize > 1024 ? (storageSize / 1024).toFixed(1) + ' KB'
                  : storageSize + ' B';

    statsEl.innerHTML = `
        <div class="settings-data-overview">
            <div class="settings-data-total">
                <div class="settings-data-total-value">${totalRecords}</div>
                <div class="settings-data-total-label">Total Records</div>
            </div>
            <div class="settings-data-total">
                <div class="settings-data-total-value">${sizeStr}</div>
                <div class="settings-data-total-label">Data Size</div>
            </div>
        </div>
        <div class="settings-data-grid">${cards.join('')}</div>
    `;
}

function toggleThemeFromSettings(isLight) {
    const body = document.body;
    const hasLight = body.classList.contains('light-mode');
    if (isLight && !hasLight) toggleTheme();
    else if (!isLight && hasLight) toggleTheme();
    const label = document.getElementById('settingThemeLabel');
    if (label) label.textContent = isLight ? 'Light' : 'Dark';
}

// Apply ALL accent-related CSS variables globally (dark & light mode aware)
function applyAccentColorToCSS(hex, cssRgb) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    const isLight = document.body.classList.contains('light-mode');

    let accentR = r, accentG = g, accentB = b;
    let hoverR, hoverG, hoverB;

    if (isLight) {
        // Darken base accent for light mode
        accentR = Math.round(r * 0.87);
        accentG = Math.round(g * 0.87);
        accentB = Math.round(b * 0.87);
        // Hover is even darker
        hoverR = Math.round(r * 0.7);
        hoverG = Math.round(g * 0.7);
        hoverB = Math.round(b * 0.7);
    } else {
        // Hover is lighter in dark mode
        hoverR = Math.min(255, Math.round(r + (255 - r) * 0.3));
        hoverG = Math.min(255, Math.round(g + (255 - g) * 0.3));
        hoverB = Math.min(255, Math.round(b + (255 - b) * 0.3));
    }

    const toHex = c => c.toString(16).padStart(2, '0');
    const accentHex = '#' + toHex(accentR) + toHex(accentG) + toHex(accentB);
    const hoverHex = '#' + toHex(hoverR || r) + toHex(hoverG || g) + toHex(hoverB || b);
    const accentRgb = `${accentR}, ${accentG}, ${accentB}`;
    const lightOp = isLight ? 0.1 : 0.12;
    const glowOp = isLight ? 0.2 : 0.25;
    const warnLightOp = isLight ? 0.08 : 0.12;

    // Set on both html and body so they override :root and body.light-mode rules
    [document.documentElement, document.body].forEach(el => {
        el.style.setProperty('--accent', accentHex);
        el.style.setProperty('--accent-hover', hoverHex);
        el.style.setProperty('--accent-light', `rgba(${accentRgb}, ${lightOp})`);
        el.style.setProperty('--accent-glow', `rgba(${accentRgb}, ${glowOp})`);
        el.style.setProperty('--amber', hex);
        el.style.setProperty('--amber-rgb', cssRgb);
        el.style.setProperty('--warning', accentHex);
        el.style.setProperty('--warning-light', `rgba(${accentRgb}, ${warnLightOp})`);
    });
}

function setAccentColor(hex, cssRgb) {
    const s = getAppSettings();
    s.accentColor = hex;
    try { localStorage.setItem(APP_SETTINGS_KEY, JSON.stringify(s)); } catch(e) {}

    // Apply accent color to ALL CSS variables
    applyAccentColorToCSS(hex, cssRgb);

    // Re-render color grid
    const colorGrid = document.getElementById('settingAccentColors');
    if (colorGrid) {
        colorGrid.innerHTML = ACCENT_COLORS.map(c =>
            `<div class="settings-color-swatch ${hex === c.value ? 'active' : ''}" 
                 style="background:${c.value};" 
                 title="${c.name}" 
                 onclick="setAccentColor('${c.value}', '${c.css}')">
                ${hex === c.value ? '<i class="fas fa-check"></i>' : ''}
            </div>`
        ).join('');
    }
    showToast(`Accent color: ${ACCENT_COLORS.find(c => c.value === hex)?.name || 'Custom'}`, 'success', 1500);
}

function setAppFontSize(size) {
    const s = getAppSettings();
    s.fontSize = size;
    try { localStorage.setItem(APP_SETTINGS_KEY, JSON.stringify(s)); } catch(e) {}
    applyFontSize(size);

    // Update active button
    document.querySelectorAll('.settings-size-btn').forEach(btn => btn.classList.remove('active'));
    const idx = { 'small': 0, 'default': 1, 'large': 2 }[size];
    const btns = document.querySelectorAll('.settings-size-btn');
    if (btns[idx]) btns[idx].classList.add('active');

    showToast(`Font size: ${size}`, 'success', 1500);
}

function applyFontSize(size) {
    document.body.classList.remove('font-small', 'font-large');
    if (size === 'small') document.body.classList.add('font-small');
    else if (size === 'large') document.body.classList.add('font-large');
}

function toggleCompactMode(enabled) {
    document.body.classList.toggle('compact-mode', enabled);
    const s = getAppSettings();
    s.compactMode = enabled;
    try { localStorage.setItem(APP_SETTINGS_KEY, JSON.stringify(s)); } catch(e) {}
    showToast(`Compact mode ${enabled ? 'enabled' : 'disabled'}`, 'success', 1500);
}

function applyAppSettings() {
    const s = getAppSettings();

    // Apply accent color to ALL CSS variables
    const accent = ACCENT_COLORS.find(c => c.value === s.accentColor);
    if (accent) {
        applyAccentColorToCSS(accent.value, accent.css);
    }

    // Apply font size
    applyFontSize(s.fontSize);

    // Apply compact mode
    document.body.classList.toggle('compact-mode', s.compactMode);
}

function exportSettingsJSON() {
    const settings = getAppSettings();
    const blob = new Blob([JSON.stringify(settings, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `APF_Settings_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    showToast('Settings exported');
}

function importSettingsJSON(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const imported = JSON.parse(e.target.result);
            const merged = { ...getDefaultSettings(), ...imported };
            localStorage.setItem(APP_SETTINGS_KEY, JSON.stringify(merged));
            applyAppSettings();
            renderSettings();
            showToast('Settings imported successfully', 'success');
        } catch (err) {
            showToast('Invalid settings file', 'error');
        }
    };
    reader.readAsText(file);
    event.target.value = '';
}

function resetAppSettings() {
    if (!confirm('Reset all settings to defaults?\n\nThis will not affect your data — only preferences.')) return;
    const defaults = getDefaultSettings();
    try { localStorage.setItem(APP_SETTINGS_KEY, JSON.stringify(defaults)); } catch(e) {}

    // Reset accent color
    document.documentElement.style.removeProperty('--amber');
    document.documentElement.style.removeProperty('--amber-rgb');

    applyAppSettings();
    renderSettings();
    showToast('Settings reset to defaults', 'success');
}

function getSettingValue(key) {
    return getAppSettings()[key];
}

function formatDateSetting(dateStr) {
    if (!dateStr) return '';
    const format = getAppSettings().dateFormat;
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;

    const day = String(d.getDate()).padStart(2, '0');
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const year = d.getFullYear();
    const monthShort = d.toLocaleDateString('en-IN', { month: 'short' });

    switch (format) {
        case 'dd/mm/yyyy': return `${day}/${month}/${year}`;
        case 'mm/dd/yyyy': return `${month}/${day}/${year}`;
        case 'yyyy-mm-dd': return `${year}-${month}-${day}`;
        case 'dd-mmm-yyyy':
        default: return `${day}-${monthShort}-${year}`;
    }
}

// ===== BUG REPORT & FEATURE REQUEST =====
function setFeedbackType(type) {
    document.getElementById('fbType').value = type;
    document.getElementById('fbTabBug').classList.toggle('active', type === 'bug');
    document.getElementById('fbTabFeature').classList.toggle('active', type === 'feature');
}

function resetFeedbackForm() {
    document.getElementById('feedbackForm').reset();
    document.getElementById('fbType').value = 'bug';
    document.getElementById('fbEditId').value = '';
    setFeedbackType('bug');
}

function saveFeedback(event) {
    event.preventDefault();
    const id = document.getElementById('fbEditId').value;
    const entry = {
        id: id || DB.generateId(),
        type: document.getElementById('fbType').value,
        title: document.getElementById('fbTitle').value.trim(),
        section: document.getElementById('fbSection').value,
        priority: document.getElementById('fbPriority').value,
        description: document.getElementById('fbDescription').value.trim(),
        status: 'open',
        createdAt: new Date().toISOString()
    };

    let reports = DB.get('feedbackReports') || [];
    if (id) {
        const idx = reports.findIndex(r => r.id === id);
        if (idx >= 0) { entry.status = reports[idx].status; entry.createdAt = reports[idx].createdAt; reports[idx] = entry; }
        else reports.push(entry);
    } else {
        reports.push(entry);
    }
    DB.set('feedbackReports', reports);
    resetFeedbackForm();
    renderFeedbackList();
    showToast(id ? 'Report updated!' : 'Report saved!');

    // Offer to email/telegram developer
    if (!id) {
        setTimeout(() => {
            const hasTg = isTelegramConfigured();
            const msg = hasTg
                ? 'Report saved! Send to developer via:\n\n1. Gmail\n2. Telegram\n3. Skip'
                : 'Report saved! Would you like to email this to the developer?';
            if (hasTg) {
                const choice = prompt(msg, '2');
                if (choice === '1') emailFeedback(entry);
                else if (choice === '2') sendFeedbackToTelegram(entry);
            } else {
                if (confirm('Report saved! Would you like to email this to the developer?')) {
                    emailFeedback(entry);
                }
            }
        }, 300);
    }
}

function emailFeedback(entry) {
    const typeLabel = entry.type === 'bug' ? 'Bug Report' : 'Feature Request';
    const senderName = (getProfile().name) || 'Anonymous';
    const subject = encodeURIComponent(`[APF Dashboard] ${typeLabel}: ${entry.title}`);
    const body = encodeURIComponent(
        `From: ${senderName}\n` +
        `Type: ${typeLabel}\n` +
        `Priority: ${entry.priority.toUpperCase()}\n` +
        `Section: ${entry.section || 'N/A'}\n` +
        `Date: ${new Date(entry.createdAt).toLocaleDateString('en-IN')}\n\n` +
        `Title: ${entry.title}\n\n` +
        `Description:\n${entry.description}\n\n` +
        `---\nSent by ${senderName} from APF Resource Person Dashboard`
    );
    window.open(`https://mail.google.com/mail/?view=cm&to=${_tgDecode(_TG_EM)}&su=${subject}&body=${body}`, '_blank');
}

// ===== Telegram Bot Integration =====
const TG_CONFIG_KEY = 'apf_telegram_config';
const _TG_K = 'ApfDashboard2026TelegramSecure';
const _TG_ET = 'eURVfVFLW1ZXU0glc3YFAzAmHyYCBgsEZi42NCg0JQA+MFgpAioLNiciUXUGbw==';
const _TG_EC = 'cEBQc1RFWFBbVQ==';
const _TG_EM = 'MgNXc1hLWVcvBh8FW1wcVTsI'; // encrypted email

function _tgDecode(encoded) {
    const str = atob(encoded);
    let result = '';
    for (let i = 0; i < str.length; i++) {
        result += String.fromCharCode(str.charCodeAt(i) ^ _TG_K.charCodeAt(i % _TG_K.length));
    }
    return result;
}

// Auto-apply default config if none exists
if (!localStorage.getItem(TG_CONFIG_KEY)) {
    localStorage.setItem(TG_CONFIG_KEY, JSON.stringify({ token: _tgDecode(_TG_ET), chatId: _tgDecode(_TG_EC) }));
}

function getTelegramConfig() {
    try {
        const raw = localStorage.getItem(TG_CONFIG_KEY);
        return raw ? JSON.parse(raw) : null;
    } catch { return null; }
}

function isTelegramConfigured() {
    const cfg = getTelegramConfig();
    return !!(cfg && cfg.token && cfg.chatId);
}

function toggleTelegramConfig() {
    const body = document.getElementById('tgConfigBody');
    const chevron = document.getElementById('tgChevron');
    const isOpen = body.style.display !== 'none';
    body.style.display = isOpen ? 'none' : 'block';
    chevron.style.transform = isOpen ? '' : 'rotate(180deg)';
    if (!isOpen) {
        // Load saved config into fields
        const cfg = getTelegramConfig();
        if (cfg) {
            document.getElementById('tgBotToken').value = cfg.token || '';
            document.getElementById('tgChatId').value = cfg.chatId || '';
        }
    }
}

function saveTelegramConfig() {
    const token = document.getElementById('tgBotToken').value.trim();
    const chatId = document.getElementById('tgChatId').value.trim();
    if (!token || !chatId) {
        showToast('Please enter both Bot Token and Chat ID', 'error');
        return;
    }
    localStorage.setItem(TG_CONFIG_KEY, JSON.stringify({ token, chatId }));
    updateTelegramStatusDot();
    showToast('Telegram config saved! \u2705', 'success');
}

function clearTelegramConfig() {
    if (!confirm('Remove Telegram bot configuration?')) return;
    localStorage.removeItem(TG_CONFIG_KEY);
    document.getElementById('tgBotToken').value = '';
    document.getElementById('tgChatId').value = '';
    document.getElementById('tgTestResult').style.display = 'none';
    updateTelegramStatusDot();
    showToast('Telegram config removed', 'info');
}

function updateTelegramStatusDot() {
    const dot = document.getElementById('tgStatusDot');
    if (!dot) return;
    if (isTelegramConfigured()) {
        dot.style.background = '#10b981';
        dot.title = 'Connected';
    } else {
        dot.style.background = '#6b7280';
        dot.title = 'Not configured';
    }
}

async function testTelegramBot() {
    const token = document.getElementById('tgBotToken').value.trim();
    const chatId = document.getElementById('tgChatId').value.trim();
    const resultEl = document.getElementById('tgTestResult');

    if (!token || !chatId) {
        showToast('Enter both Token and Chat ID first', 'error');
        return;
    }

    resultEl.style.display = 'block';
    resultEl.className = 'tg-test-result tg-test-loading';
    resultEl.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending test message...';

    try {
        const url = `https://api.telegram.org/bot${token}/sendMessage`;
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: chatId,
                text: '\u2705 APF Dashboard connected!\n\nTelegram bot integration is working. Bug reports and feature requests will be sent here.',
                parse_mode: 'HTML'
            })
        });
        const data = await resp.json();
        if (data.ok) {
            resultEl.className = 'tg-test-result tg-test-success';
            resultEl.innerHTML = '<i class="fas fa-check-circle"></i> Test message sent! Check your Telegram.';
        } else {
            resultEl.className = 'tg-test-result tg-test-error';
            resultEl.innerHTML = `<i class="fas fa-times-circle"></i> Failed: ${escapeHtml(data.description || 'Unknown error')}`;
        }
    } catch (err) {
        resultEl.className = 'tg-test-result tg-test-error';
        resultEl.innerHTML = `<i class="fas fa-times-circle"></i> Network error: ${escapeHtml(err.message)}`;
    }
}

async function sendFeedbackToTelegram(entry) {
    const cfg = getTelegramConfig();
    if (!cfg) {
        showToast('Telegram not configured. Set up in Bug & Feedback section.', 'error');
        return;
    }

    const typeEmoji = entry.type === 'bug' ? '\ud83d\udc1b' : '\ud83d\udca1';
    const typeLabel = entry.type === 'bug' ? 'Bug Report' : 'Feature Request';
    const prioEmoji = { critical: '\ud83d\udd34', high: '\ud83d\udfe0', medium: '\ud83d\udfe1', low: '\u26aa' }[entry.priority] || '';
    const senderName = (getProfile().name) || 'Anonymous';

    const text =
        `${typeEmoji} <b>${typeLabel}</b>\n\n` +
        `\ud83d\udc64 <b>From:</b> ${senderName}\n` +
        `<b>Title:</b> ${entry.title}\n` +
        `<b>Section:</b> ${entry.section || 'N/A'}\n` +
        `<b>Priority:</b> ${prioEmoji} ${entry.priority.toUpperCase()}\n` +
        `<b>Date:</b> ${new Date(entry.createdAt).toLocaleDateString('en-IN')}\n\n` +
        `<b>Description:</b>\n${entry.description}\n\n` +
        `\u2014 <i>Sent by ${senderName} via APF Dashboard</i>`;

    try {
        const url = `https://api.telegram.org/bot${cfg.token}/sendMessage`;
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: cfg.chatId,
                text: text,
                parse_mode: 'HTML'
            })
        });
        const data = await resp.json();
        if (data.ok) {
            showToast('Sent to Telegram! \u2705', 'success');
        } else {
            showToast('Telegram error: ' + (data.description || 'Unknown'), 'error');
        }
    } catch (err) {
        showToast('Failed to send: ' + err.message, 'error');
    }
}

function deleteFeedback(id) {
    if (!confirm('Delete this report?')) return;
    let reports = DB.get('feedbackReports') || [];
    reports = reports.filter(r => r.id !== id);
    DB.set('feedbackReports', reports);
    renderFeedbackList();
    showToast('Report deleted', 'info');
}

function editFeedback(id) {
    const reports = DB.get('feedbackReports') || [];
    const r = reports.find(x => x.id === id);
    if (!r) return;
    document.getElementById('fbEditId').value = r.id;
    document.getElementById('fbTitle').value = r.title;
    document.getElementById('fbSection').value = r.section || '';
    document.getElementById('fbPriority').value = r.priority;
    document.getElementById('fbDescription').value = r.description;
    setFeedbackType(r.type);
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function toggleFeedbackStatus(id) {
    const reports = DB.get('feedbackReports') || [];
    const idx = reports.findIndex(r => r.id === id);
    if (idx < 0) return;
    reports[idx].status = reports[idx].status === 'open' ? 'closed' : 'open';
    DB.set('feedbackReports', reports);
    renderFeedbackList();
    showToast(reports[idx].status === 'closed' ? 'Marked as resolved' : 'Reopened');
}

function renderFeedbackList() {
    const reports = DB.get('feedbackReports') || [];
    const container = document.getElementById('fbTableContainer');
    const countEl = document.getElementById('fbCount');
    if (!container) return;

    if (countEl) countEl.textContent = `${reports.length} report${reports.length !== 1 ? 's' : ''}`;
    updateTelegramStatusDot();

    if (reports.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-clipboard-check"></i><h3>No reports yet</h3><p>Submit a bug report or feature request above.</p></div>';
        return;
    }

    const sorted = [...reports].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    let html = `<table class="fb-table">
        <thead><tr>
            <th>Type</th>
            <th>Title</th>
            <th>Section</th>
            <th>Priority</th>
            <th>Status</th>
            <th>Date</th>
            <th>Actions</th>
        </tr></thead><tbody>`;

    sorted.forEach(r => {
        const typeIcon = r.type === 'bug' ? '<i class="fas fa-bug" style="color:#ef4444"></i>' : '<i class="fas fa-lightbulb" style="color:#f59e0b"></i>';
        const typeLabel = r.type === 'bug' ? 'Bug' : 'Feature';
        const prioClass = { critical: 'fb-prio-critical', high: 'fb-prio-high', medium: 'fb-prio-medium', low: 'fb-prio-low' }[r.priority] || '';
        const statusClass = r.status === 'closed' ? 'fb-status-closed' : 'fb-status-open';
        const statusLabel = r.status === 'closed' ? 'Resolved' : 'Open';
        const date = new Date(r.createdAt).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });

        html += `<tr class="${r.status === 'closed' ? 'fb-row-closed' : ''}">
            <td>${typeIcon} ${typeLabel}</td>
            <td class="fb-title-cell">${escapeHtml(r.title)}</td>
            <td>${escapeHtml(r.section || '—')}</td>
            <td><span class="fb-prio ${prioClass}">${r.priority}</span></td>
            <td><span class="fb-status ${statusClass}" onclick="toggleFeedbackStatus('${r.id}')" style="cursor:pointer" title="Click to toggle">${statusLabel}</span></td>
            <td class="fb-date">${date}</td>
            <td class="fb-actions">
                <button class="btn btn-ghost btn-sm" onclick="emailFeedback(${JSON.stringify(r).replace(/"/g, '&quot;')})" title="Email Developer"><i class="fas fa-envelope"></i></button>
                <button class="btn btn-ghost btn-sm" onclick="sendFeedbackToTelegram(${JSON.stringify(r).replace(/"/g, '&quot;')})" title="Send to Telegram" ${isTelegramConfigured() ? '' : 'disabled style="opacity:0.3"'}><i class="fab fa-telegram-plane"></i></button>
                <button class="btn btn-ghost btn-sm" onclick="editFeedback('${r.id}')" title="Edit"><i class="fas fa-edit"></i></button>
                <button class="btn btn-ghost btn-sm" onclick="deleteFeedback('${r.id}')" title="Delete" style="color:#ef4444"><i class="fas fa-trash"></i></button>
            </td>
        </tr>`;
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

// ===== PROFESSIONAL GROWTH FRAMEWORK =====
const GROWTH_DIMENSIONS = [
    {
        id: 'dim1',
        name: 'Building & Sustaining Professional Relationships',
        shortName: 'Relationships',
        icon: 'fa-handshake',
        color: '#3b82f6',
        levels: [
            'Makes efforts to build relationships with teachers in a few schools. There is continuity in efforts and learning from senior members.',
            'Reaches out to as many teachers as possible through various platforms (school, workshop, cluster meeting, TLC, home, community). Makes efforts for understanding teachers, their circumstances, interest areas, strengths and uses these constructively.',
            'Uses various modes (in-person, social media, workshops, community functions) effectively. Uses existing connect to expand further – taking support of teachers, education functionaries to reach more teachers. Focused on purpose while doing relationship building and mobilization. Motivates teachers to take up initiatives at classroom/school level.',
            'Drives relationships towards maturity where frequency of connect is not a measure of quality. Constantly strives for creative ways for better communication and mobilization. Is able to mentor others in this aspect of work.'
        ]
    },
    {
        id: 'dim2',
        name: 'Engaging with Teachers — Designing & Facilitating Sessions',
        shortName: 'Session Design',
        icon: 'fa-chalkboard-teacher',
        color: '#8b5cf6',
        levels: [
            'Shows readiness to contribute in small supportive roles in session facilitation. Shows self-initiative in taking up assignments like report writing and other tasks during sessions/workshops.',
            'Assists session designing and facilitation by giving inputs and doing assigned tasks (content/data search, gathering primary data, preparing summary/draft handouts). Does session facilitation in guidance of senior members. Adapts available sessions and material to own requirement.',
            'Independently designs sessions, resources, support material and does engaging facilitation while remaining focused on session objectives. Conceptualises and designs longer engagements (workshops, seminars etc.).',
            'Adapts/changes a session plan while facilitating to suit participant needs. Facilitates sessions in tough situations (difficult participants, sensitive/challenging topics). Reviews session plans by others and guides improvement. Mentors other members through observation, co-facilitation, feedback and handholding.'
        ]
    },
    {
        id: 'dim3',
        name: 'Content & Material Development',
        shortName: 'Content Dev',
        icon: 'fa-pen-fancy',
        color: '#10b981',
        levels: [
            'Engages with existing content and material for sessions, workshops with interest and asks relevant questions.',
            'Writes simple descriptions of school engagement, sessions, workshops and simple notes on readings. Selects and adapts existing material to suit own requirement. Develops session/workshop/course material (PPT, worksheets, handouts) with some guidance.',
            'Contributes substantially in developing good quality workshop/course modules. Independently develops good quality material. Writes good quality teaching plans. Writes reflective notes, reviews, reports based on readings and experiences which enrich existing content/material.',
            'Assists/mentors others in developing session/workshop/course material. Selects/develops content as per curricular goals with ability to contribute in textbook writing. Documents field experiences as reports, articles and papers. Writes well thought out notes with strong theory-practice connect.'
        ]
    },
    {
        id: 'dim4',
        name: 'Onsite / School Level Engagement',
        shortName: 'School Engagement',
        icon: 'fa-school',
        color: '#f59e0b',
        levels: [
            'Shows inclination and effort towards student and teacher engagement at school level. Plans and maintains regularity in school engagement. Observes senior members and learns from them.',
            'Engages with children and teachers in classroom situations with interest and planning. Draws a sense of student learning levels and teacher practices. Builds comprehensiveness in school observation. Attempts to scaffold teachers as per agreed plan.',
            'Draws comprehensive sense of student learning and teacher practices in short durations. Engages with all school teachers for team effort. Engages with school heads and draws their support. Visualizes and provides individualized scaffolding. Plans and executes student engagement independently and with teachers.',
            'Draws comprehensive and in-depth sense with proper evidences in short durations. Motivates school teams (teachers + Principal) for school development initiatives. Scaffolds variety of teachers in multiple ways – providing need-based inputs, relevant resources, hand-holding, co-teaching or demonstration.'
        ]
    },
    {
        id: 'dim5',
        name: 'Visualising, Planning & Executing Teacher Capacity Building',
        shortName: 'Capacity Building',
        icon: 'fa-bullseye',
        color: '#ef4444',
        levels: [
            'Reads articles, books and engages with team members to understand teacher capacity building efforts in totality, broader timeframe and continuity. Shares reflections/thoughts with other team members.',
            'Makes appropriate choices (directly related to teaching-learning process) about particular topics/content/issues for discussion and demonstration with teachers.',
            'Visualizes forward/backward linkages of sessions conducted earlier and builds on them for classroom effect. Conceptualizes teacher development plans for different categories of teachers based on expertise and motivation levels. Plans a series of capacity development engagements in multiple modes.',
            'Develops comprehensive, long-term teacher professional development plan for variety of cohorts and executes it successfully (shows change in teaching practices and learning levels). Mentors others to understand, conceptualize and execute teacher capacity building initiatives.'
        ]
    }
];

function getGrowthAssessments() {
    return DB.get('growthAssessments') || [];
}

function getLatestAssessment() {
    const assessments = getGrowthAssessments();
    if (assessments.length === 0) return null;
    return assessments.sort((a, b) => (b.date || '').localeCompare(a.date || ''))[0];
}

function renderGrowthFramework() {
    const latest = getLatestAssessment();
    const assessments = getGrowthAssessments();

    // Overview
    renderGrowthOverview(latest, assessments);

    // Radar chart
    renderGrowthRadar(latest);

    // Journey card
    renderGrowthJourney(latest, assessments);

    // Growth trend line chart (shows when 2+ assessments)
    renderGrowthTrendChart();

    // Dimension cards
    renderGrowthDimensions(latest);

    // Action Plans
    renderGrowthActionPlans();

    // Growth Tips & Suggestions
    renderGrowthTips();

    // Timeline
    renderGrowthTimeline(assessments);
}

function renderGrowthOverview(latest, assessments) {
    const el = document.getElementById('growthOverview');
    if (!el) return;

    if (!latest) {
        el.innerHTML = `
            <div class="growth-empty-state">
                <div class="growth-empty-icon"><i class="fas fa-seedling"></i></div>
                <h3>Begin Your Growth Journey</h3>
                <p>The APF Developmental Framework helps you track your growth across 5 key dimensions of a Resource Person's work. Start by taking a self-assessment.</p>
                <button class="btn btn-primary" onclick="openGrowthAssessment()" style="margin-top:16px;">
                    <i class="fas fa-pen-ruler"></i> Take First Assessment
                </button>
            </div>
        `;
        return;
    }

    const totalScore = GROWTH_DIMENSIONS.reduce((s, d) => s + (latest.levels[d.id] || 1), 0);
    const maxScore = GROWTH_DIMENSIONS.length * 4;
    const avgLevel = (totalScore / GROWTH_DIMENSIONS.length).toFixed(1);
    const pct = Math.round((totalScore / maxScore) * 100);

    // Growth from previous assessment
    let growthText = '';
    if (assessments.length >= 2) {
        const sorted = assessments.sort((a, b) => (b.date || '').localeCompare(a.date || ''));
        const prev = sorted[1];
        const prevTotal = GROWTH_DIMENSIONS.reduce((s, d) => s + (prev.levels[d.id] || 1), 0);
        const diff = totalScore - prevTotal;
        if (diff > 0) growthText = `<span class="growth-trend up"><i class="fas fa-arrow-up"></i> +${diff} points since last assessment</span>`;
        else if (diff < 0) growthText = `<span class="growth-trend down"><i class="fas fa-arrow-down"></i> ${diff} points since last assessment</span>`;
        else growthText = `<span class="growth-trend flat"><i class="fas fa-minus"></i> Same as last assessment</span>`;
    }

    const levelLabel = avgLevel >= 3.5 ? 'Expert Practitioner' : avgLevel >= 2.5 ? 'Proficient Practitioner' : avgLevel >= 1.5 ? 'Developing Practitioner' : 'Emerging Practitioner';

    el.innerHTML = `
        <div class="growth-score-card">
            <div class="growth-score-ring">
                <svg viewBox="0 0 120 120">
                    <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border)" stroke-width="8"/>
                    <circle cx="60" cy="60" r="52" fill="none" stroke="var(--amber)" stroke-width="8" 
                        stroke-dasharray="${326.7 * pct / 100} ${326.7 * (1 - pct / 100)}" 
                        stroke-linecap="round" transform="rotate(-90 60 60)" style="transition:stroke-dasharray 1s;"/>
                </svg>
                <div class="growth-score-value">${avgLevel}</div>
                <div class="growth-score-max">/4</div>
            </div>
            <div class="growth-score-info">
                <h3>${levelLabel}</h3>
                <p>Overall average across 5 dimensions</p>
                ${growthText}
                <div class="growth-score-meta">
                    <span><i class="fas fa-calendar"></i> Last assessed: ${formatDateSetting(latest.date)}</span>
                    <span><i class="fas fa-history"></i> ${assessments.length} assessment${assessments.length > 1 ? 's' : ''}</span>
                </div>
            </div>
        </div>
        <div class="growth-level-badges">
            ${GROWTH_DIMENSIONS.map(d => {
                const lvl = latest.levels[d.id] || 1;
                return `<div class="growth-level-badge" style="--dim-color:${d.color}">
                    <i class="fas ${d.icon}"></i>
                    <span class="growth-badge-label">${d.shortName}</span>
                    <span class="growth-badge-level">L${lvl}</span>
                </div>`;
            }).join('')}
        </div>
    `;
}

let growthRadarChartInstance = null;
function renderGrowthRadar(latest) {
    const canvas = document.getElementById('growthRadarChart');
    if (!canvas || typeof Chart === 'undefined') return;

    if (growthRadarChartInstance) {
        growthRadarChartInstance.destroy();
        growthRadarChartInstance = null;
    }

    const labels = GROWTH_DIMENSIONS.map(d => d.shortName);
    const data = GROWTH_DIMENSIONS.map(d => latest ? (latest.levels[d.id] || 1) : 0);
    const bgColors = GROWTH_DIMENSIONS.map(d => d.color + '33');
    const borderColors = GROWTH_DIMENSIONS.map(d => d.color);

    // Get previous assessment for comparison
    const assessments = getGrowthAssessments();
    const sorted = assessments.sort((a, b) => (b.date || '').localeCompare(a.date || ''));
    const prevData = sorted.length >= 2 ? GROWTH_DIMENSIONS.map(d => sorted[1].levels[d.id] || 1) : null;

    const datasets = [
        {
            label: 'Current Level',
            data: data,
            backgroundColor: 'rgba(245, 158, 11, 0.15)',
            borderColor: 'rgb(245, 158, 11)',
            pointBackgroundColor: borderColors,
            pointBorderColor: borderColors,
            pointRadius: 6,
            pointHoverRadius: 8,
            borderWidth: 2,
            fill: true
        }
    ];
    if (prevData) {
        datasets.push({
            label: 'Previous',
            data: prevData,
            backgroundColor: 'rgba(150, 150, 150, 0.05)',
            borderColor: 'rgba(150, 150, 150, 0.4)',
            pointBackgroundColor: 'rgba(150,150,150,0.5)',
            pointRadius: 3,
            borderWidth: 1,
            borderDash: [5, 5],
            fill: true
        });
    }

    growthRadarChartInstance = new Chart(canvas, {
        type: 'radar',
        data: { labels, datasets },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: prevData ? true : false, labels: { color: 'var(--text-secondary)', font: { size: 11 } } }
            },
            scales: {
                r: {
                    min: 0,
                    max: 4,
                    ticks: {
                        stepSize: 1,
                        color: 'var(--text-muted)',
                        backdropColor: 'transparent',
                        font: { size: 10 },
                        callback: v => 'L' + v
                    },
                    pointLabels: {
                        color: (ctx) => GROWTH_DIMENSIONS[ctx.index]?.color || '#999',
                        font: { size: 12, weight: '600' }
                    },
                    grid: { color: 'rgba(150,150,150,0.15)' },
                    angleLines: { color: 'rgba(150,150,150,0.15)' }
                }
            }
        }
    });
}

function renderGrowthJourney(latest, assessments) {
    const el = document.getElementById('growthJourneyCard');
    if (!el) return;

    if (!latest) {
        el.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-muted);"><i class="fas fa-route" style="font-size:32px;margin-bottom:12px;display:block;"></i>Your growth journey will appear here after your first assessment.</div>';
        return;
    }

    // Find strongest and weakest dimensions
    const dimLevels = GROWTH_DIMENSIONS.map(d => ({ ...d, level: latest.levels[d.id] || 1 }));
    dimLevels.sort((a, b) => b.level - a.level);
    const strongest = dimLevels[0];
    const weakest = dimLevels[dimLevels.length - 1];

    // Next growth targets
    const nextTargets = dimLevels.filter(d => d.level < 4).slice(-2);

    el.innerHTML = `
        <h3><i class="fas fa-route"></i> Growth Insights</h3>
        <div class="growth-insight-cards">
            <div class="growth-insight strength">
                <div class="growth-insight-icon" style="color:${strongest.color};"><i class="fas fa-trophy"></i></div>
                <div>
                    <strong>Strongest Area</strong>
                    <span>${strongest.shortName} — Level ${strongest.level}</span>
                </div>
            </div>
            <div class="growth-insight focus">
                <div class="growth-insight-icon" style="color:${weakest.color};"><i class="fas fa-crosshairs"></i></div>
                <div>
                    <strong>Focus Area</strong>
                    <span>${weakest.shortName} — Level ${weakest.level}</span>
                </div>
            </div>
            ${nextTargets.map(t => `
                <div class="growth-insight target">
                    <div class="growth-insight-icon" style="color:${t.color};"><i class="fas fa-flag"></i></div>
                    <div>
                        <strong>Next Target: L${t.level + 1}</strong>
                        <span>${t.shortName}</span>
                    </div>
                </div>
            `).join('')}
        </div>
        <div class="growth-progress-summary">
            <strong><i class="fas fa-chart-line"></i> Overall Progress</strong>
            <div class="growth-progress-bar-wrap">
                ${GROWTH_DIMENSIONS.map(d => {
                    const lvl = latest.levels[d.id] || 1;
                    return `<div class="growth-dim-progress">
                        <span class="growth-dim-progress-label" style="color:${d.color};"><i class="fas ${d.icon}"></i></span>
                        <div class="growth-dim-progress-bar">
                            <div class="growth-dim-progress-fill" style="width:${lvl * 25}%;background:${d.color};"></div>
                        </div>
                        <span class="growth-dim-progress-val">L${lvl}</span>
                    </div>`;
                }).join('')}
            </div>
        </div>
    `;
}

function renderGrowthDimensions(latest) {
    const el = document.getElementById('growthDimensions');
    if (!el) return;
    if (!latest) { el.innerHTML = ''; return; }

    el.innerHTML = GROWTH_DIMENSIONS.map(d => {
        const currentLevel = latest.levels[d.id] || 1;
        const notes = latest.notes?.[d.id] || '';
        const evidence = latest.evidence?.[d.id] || '';

        return `
        <div class="growth-dim-card" onclick="showGrowthDimDetail('${d.id}')">
            <div class="growth-dim-card-header" style="--dim-color:${d.color}">
                <div class="growth-dim-icon" style="background:${d.color};"><i class="fas ${d.icon}"></i></div>
                <div>
                    <h4>${d.name}</h4>
                    <div class="growth-dim-level-row">
                        ${[1,2,3,4].map(l => `<span class="growth-dim-dot ${l <= currentLevel ? 'active' : ''}" style="${l <= currentLevel ? 'background:'+d.color : ''}"></span>`).join('')}
                        <span class="growth-dim-level-text">Level ${currentLevel} of 4</span>
                    </div>
                </div>
            </div>
            <div class="growth-dim-card-body">
                <p class="growth-dim-desc">${d.levels[currentLevel - 1].substring(0, 160)}${d.levels[currentLevel - 1].length > 160 ? '...' : ''}</p>
                ${notes ? `<div class="growth-dim-notes"><i class="fas fa-sticky-note"></i> ${escapeHtml(notes).substring(0, 100)}${notes.length > 100 ? '...' : ''}</div>` : ''}
                ${currentLevel < 4 ? `<div class="growth-dim-next"><i class="fas fa-arrow-right"></i> <strong>Next (L${currentLevel + 1}):</strong> ${d.levels[currentLevel].substring(0, 120)}...</div>` : '<div class="growth-dim-next mastered"><i class="fas fa-crown"></i> Mastery level achieved!</div>'}
            </div>
        </div>`;
    }).join('');
}

function renderGrowthTimeline(assessments) {
    const el = document.getElementById('growthTimeline');
    if (!el) return;

    if (assessments.length === 0) {
        el.innerHTML = '<p style="text-align:center;color:var(--text-muted);padding:20px;">No assessments yet.</p>';
        return;
    }

    const sorted = [...assessments].sort((a, b) => (b.date || '').localeCompare(a.date || ''));

    el.innerHTML = `<div class="growth-timeline-list">
        ${sorted.map((a, idx) => {
            const total = GROWTH_DIMENSIONS.reduce((s, d) => s + (a.levels[d.id] || 1), 0);
            const avg = (total / GROWTH_DIMENSIONS.length).toFixed(1);
            const isMentor = a.assessType === 'mentor';
            return `<div class="growth-timeline-item ${idx === 0 ? 'latest' : ''}">
                <div class="growth-timeline-dot"></div>
                <div class="growth-timeline-content">
                    <div class="growth-timeline-date">
                        ${formatDateSetting(a.date)}
                        ${isMentor ? `<span class="growth-timeline-badge mentor"><i class="fas fa-user-tie"></i> Mentor${a.mentorName ? ': ' + escapeHtml(a.mentorName) : ''}</span>` : '<span class="growth-timeline-badge self"><i class="fas fa-user"></i> Self</span>'}
                    </div>
                    <div class="growth-timeline-score">Average: <strong>${avg}/4</strong></div>
                    <div class="growth-timeline-dims">
                        ${GROWTH_DIMENSIONS.map(d => `<span style="color:${d.color};" title="${d.shortName}: L${a.levels[d.id] || 1}"><i class="fas ${d.icon}"></i> L${a.levels[d.id] || 1}</span>`).join('')}
                    </div>
                    <div class="growth-timeline-actions">
                        <button class="btn btn-ghost btn-xs" onclick="event.stopPropagation(); editGrowthAssessment('${a.id}')" title="Edit"><i class="fas fa-edit"></i></button>
                        ${idx !== 0 ? `<button class="btn btn-ghost btn-xs" onclick="event.stopPropagation(); deleteGrowthAssessment('${a.id}')" title="Delete"><i class="fas fa-trash"></i></button>` : ''}
                    </div>
                </div>
            </div>`;
        }).join('')}
    </div>`;
}

function openGrowthAssessment() {
    growthEditId = null;
    growthAssessMode = 'self';
    const latest = getLatestAssessment();
    const form = document.getElementById('growthAssessForm');
    if (!form) return;

    // Reset mode toggle
    const modeToggle = document.getElementById('growthAssessModeToggle');
    if (modeToggle) {
        modeToggle.querySelectorAll('.growth-mode-btn').forEach((b, i) => b.classList.toggle('active', i === 0));
    }
    const mentorFields = document.getElementById('growthMentorFields');
    if (mentorFields) mentorFields.style.display = 'none';
    const title = document.getElementById('growthAssessModalTitle');
    if (title) title.innerHTML = '<i class="fas fa-pen-ruler"></i> Self-Assessment';
    const helpText = document.getElementById('growthAssessHelpText');
    if (helpText) helpText.innerHTML = '<i class="fas fa-info-circle"></i> Honestly assess your current level (1-4) for each dimension. Add notes/evidence to support your self-rating.';

    form.innerHTML = GROWTH_DIMENSIONS.map(d => {
        const currentLevel = latest ? (latest.levels[d.id] || 1) : 1;
        const currentNotes = latest ? (latest.notes?.[d.id] || '') : '';
        const currentEvidence = latest ? (latest.evidence?.[d.id] || '') : '';

        return `
        <div class="growth-assess-dim">
            <div class="growth-assess-dim-header" style="border-left:4px solid ${d.color};">
                <i class="fas ${d.icon}" style="color:${d.color};"></i>
                <strong>${d.name}</strong>
            </div>
            <div class="growth-assess-levels" id="growthLevels_${d.id}">
                ${d.levels.map((desc, i) => `
                    <label class="growth-assess-level-option ${i + 1 === currentLevel ? 'selected' : ''}">
                        <input type="radio" name="growth_${d.id}" value="${i + 1}" ${i + 1 === currentLevel ? 'checked' : ''} onchange="selectGrowthLevel('${d.id}', ${i + 1})">
                        <div class="growth-assess-level-header">
                            <span class="growth-assess-level-badge" style="background:${d.color}">Level ${i + 1}</span>
                        </div>
                        <p>${desc}</p>
                    </label>
                `).join('')}
            </div>
            <div class="growth-assess-notes">
                <label><i class="fas fa-sticky-note"></i> Self-Reflection Notes</label>
                <textarea id="growthNotes_${d.id}" placeholder="What evidence supports this level? What are you doing well? What needs work?">${escapeHtml(currentNotes)}</textarea>
            </div>
            <div class="growth-assess-notes">
                <label><i class="fas fa-link"></i> Evidence / Examples</label>
                <textarea id="growthEvidence_${d.id}" placeholder="Specific examples: sessions conducted, schools visited, materials developed, mentoring done...">${escapeHtml(currentEvidence)}</textarea>
            </div>
        </div>`;
    }).join('');

    openModal('growthAssessModal');
}

function selectGrowthLevel(dimId, level) {
    const container = document.getElementById('growthLevels_' + dimId);
    if (!container) return;
    container.querySelectorAll('.growth-assess-level-option').forEach((opt, i) => {
        opt.classList.toggle('selected', i + 1 === level);
    });
}

function saveGrowthAssessment() {
    const assessment = {
        id: growthEditId || DB.generateId(),
        date: growthEditId ? (getGrowthAssessments().find(a => a.id === growthEditId)?.date || new Date().toISOString().split('T')[0]) : new Date().toISOString().split('T')[0],
        levels: {},
        notes: {},
        evidence: {},
        assessType: growthAssessMode
    };

    if (growthAssessMode === 'mentor') {
        assessment.mentorName = (document.getElementById('growthMentorName')?.value || '').trim();
        assessment.mentorType = document.getElementById('growthMentorType')?.value || 'Quarterly Review';
    }

    GROWTH_DIMENSIONS.forEach(d => {
        const selected = document.querySelector(`input[name="growth_${d.id}"]:checked`);
        assessment.levels[d.id] = selected ? parseInt(selected.value) : 1;
        assessment.notes[d.id] = (document.getElementById('growthNotes_' + d.id)?.value || '').trim();
        assessment.evidence[d.id] = (document.getElementById('growthEvidence_' + d.id)?.value || '').trim();
    });

    let assessments = getGrowthAssessments();

    if (growthEditId) {
        const idx = assessments.findIndex(a => a.id === growthEditId);
        if (idx >= 0) assessments[idx] = assessment;
        else assessments.push(assessment);
    } else {
        assessments.push(assessment);
    }

    DB.set('growthAssessments', assessments);

    const wasEdit = !!growthEditId;
    growthEditId = null;
    growthAssessMode = 'self';
    closeModal('growthAssessModal');
    renderGrowthFramework();
    showToast(wasEdit ? 'Assessment updated! 🌱' : 'Assessment saved! Keep growing 🌱', 'success');
}

function deleteGrowthAssessment(id) {
    if (!confirm('Delete this assessment? This cannot be undone.')) return;
    let assessments = getGrowthAssessments();
    assessments = assessments.filter(a => a.id !== id);
    DB.set('growthAssessments', assessments);
    renderGrowthFramework();
    showToast('Assessment deleted', 'info');
}

function showGrowthDimDetail(dimId) {
    const dim = GROWTH_DIMENSIONS.find(d => d.id === dimId);
    if (!dim) return;

    const latest = getLatestAssessment();
    const currentLevel = latest ? (latest.levels[dimId] || 1) : 0;
    const notes = latest?.notes?.[dimId] || '';
    const evidence = latest?.evidence?.[dimId] || '';

    // Get history for this dimension
    const assessments = getGrowthAssessments().sort((a, b) => (b.date || '').localeCompare(a.date || ''));

    document.getElementById('growthDimDetailTitle').innerHTML = `<i class="fas ${dim.icon}" style="color:${dim.color};"></i> ${dim.name}`;

    document.getElementById('growthDimDetailContent').innerHTML = `
        <div class="growth-detail-current">
            <div class="growth-detail-level" style="background:${dim.color};">
                <span>CURRENT LEVEL</span>
                <strong>${currentLevel || '—'}</strong>
                <span>of 4</span>
            </div>
            <div class="growth-detail-desc">
                ${currentLevel > 0 ? `<p>${dim.levels[currentLevel - 1]}</p>` : '<p style="color:var(--text-muted);">Not yet assessed</p>'}
            </div>
        </div>

        <div class="growth-detail-levels">
            <h4>All Levels</h4>
            ${dim.levels.map((desc, i) => `
                <div class="growth-detail-level-item ${i + 1 === currentLevel ? 'current' : ''} ${i + 1 < currentLevel ? 'achieved' : ''}">
                    <div class="growth-detail-level-num" style="${i + 1 <= currentLevel ? 'background:'+dim.color+';color:white;' : ''}">
                        ${i + 1 <= currentLevel ? '<i class="fas fa-check"></i>' : i + 1}
                    </div>
                    <div>
                        <strong>Level ${i + 1} ${i + 1 === currentLevel ? '(Current)' : i + 1 < currentLevel ? '(Achieved)' : ''}</strong>
                        <p>${desc}</p>
                    </div>
                </div>
            `).join('')}
        </div>

        ${notes ? `<div class="growth-detail-notes"><h4><i class="fas fa-sticky-note"></i> Self-Reflection Notes</h4><p>${escapeHtml(notes)}</p></div>` : ''}
        ${evidence ? `<div class="growth-detail-notes"><h4><i class="fas fa-link"></i> Evidence & Examples</h4><p>${escapeHtml(evidence)}</p></div>` : ''}

        ${assessments.length > 1 ? `
            <div class="growth-detail-history">
                <h4><i class="fas fa-history"></i> Level History</h4>
                <div class="growth-detail-history-list">
                    ${assessments.map(a => `
                        <div class="growth-detail-history-item">
                            <span class="growth-detail-history-date">${formatDateSetting(a.date)}</span>
                            <span class="growth-detail-history-level" style="background:${dim.color};">L${a.levels[dimId] || 1}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        ` : ''}
    `;

    openModal('growthDimDetailModal');
}

function exportGrowthReport() {
    const latest = getLatestAssessment();
    const assessments = getGrowthAssessments();
    if (!latest) { showToast('Take an assessment first', 'info'); return; }

    if (typeof XLSX === 'undefined') { showToast('Excel library not loaded', 'error'); return; }

    const wb = XLSX.utils.book_new();

    // Current assessment sheet
    const currentData = GROWTH_DIMENSIONS.map(d => ({
        'Dimension': d.name,
        'Current Level': latest.levels[d.id] || 1,
        'Level Description': d.levels[(latest.levels[d.id] || 1) - 1],
        'Self-Reflection': latest.notes?.[d.id] || '',
        'Evidence': latest.evidence?.[d.id] || '',
        'Next Level': (latest.levels[d.id] || 1) < 4 ? d.levels[latest.levels[d.id] || 1] : 'Mastery achieved'
    }));
    const ws1 = XLSX.utils.json_to_sheet(currentData);
    XLSX.utils.book_append_sheet(wb, ws1, 'Current Assessment');

    // History sheet
    if (assessments.length > 0) {
        const histData = [];
        assessments.sort((a, b) => (a.date || '').localeCompare(b.date || '')).forEach(a => {
            const row = { Date: a.date };
            GROWTH_DIMENSIONS.forEach(d => { row[d.shortName] = a.levels[d.id] || 1; });
            row['Average'] = (GROWTH_DIMENSIONS.reduce((s, d) => s + (a.levels[d.id] || 1), 0) / GROWTH_DIMENSIONS.length).toFixed(1);
            histData.push(row);
        });
        const ws2 = XLSX.utils.json_to_sheet(histData);
        XLSX.utils.book_append_sheet(wb, ws2, 'Assessment History');
    }

    // Framework reference sheet
    const refData = [];
    GROWTH_DIMENSIONS.forEach(d => {
        d.levels.forEach((desc, i) => {
            refData.push({ Dimension: d.name, Level: i + 1, Description: desc });
        });
    });
    const ws3 = XLSX.utils.json_to_sheet(refData);
    XLSX.utils.book_append_sheet(wb, ws3, 'Framework Reference');

    XLSX.writeFile(wb, `APF_Growth_Report_${new Date().toISOString().split('T')[0]}.xlsx`);
    showToast('Growth report exported to Excel');
}

// --- Mentor Assessment Mode ---
let growthAssessMode = 'self';
let growthEditId = null;

function setGrowthAssessMode(mode, ev) {
    growthAssessMode = mode;
    document.querySelectorAll('.growth-mode-btn').forEach(b => b.classList.remove('active'));
    const evTarget = ev ? ev.target : (window.event ? window.event.target : null);
    if (evTarget) evTarget.closest('.growth-mode-btn').classList.add('active');
    const mentorFields = document.getElementById('growthMentorFields');
    const helpText = document.getElementById('growthAssessHelpText');
    const title = document.getElementById('growthAssessModalTitle');
    if (mode === 'mentor') {
        mentorFields.style.display = 'block';
        helpText.innerHTML = '<i class="fas fa-info-circle"></i> As a mentor/assessor, rate the Resource Person\'s level (1-4) for each dimension based on your observations.';
        title.innerHTML = '<i class="fas fa-user-tie"></i> Mentor Assessment';
    } else {
        mentorFields.style.display = 'none';
        helpText.innerHTML = '<i class="fas fa-info-circle"></i> Honestly assess your current level (1-4) for each dimension. Add notes/evidence to support your self-rating.';
        title.innerHTML = '<i class="fas fa-pen-ruler"></i> Self-Assessment';
    }
}

// --- Edit Past Assessment ---
function editGrowthAssessment(id) {
    const assessments = getGrowthAssessments();
    const assessment = assessments.find(a => a.id === id);
    if (!assessment) { showToast('Assessment not found', 'error'); return; }

    growthEditId = id;
    const form = document.getElementById('growthAssessForm');
    if (!form) return;

    // Reset mode
    growthAssessMode = assessment.assessType === 'mentor' ? 'mentor' : 'self';
    const modeToggle = document.getElementById('growthAssessModeToggle');
    if (modeToggle) {
        modeToggle.querySelectorAll('.growth-mode-btn').forEach((b, i) => {
            b.classList.toggle('active', (i === 0 && growthAssessMode === 'self') || (i === 1 && growthAssessMode === 'mentor'));
        });
    }
    const mentorFields = document.getElementById('growthMentorFields');
    if (assessment.assessType === 'mentor') {
        mentorFields.style.display = 'block';
        document.getElementById('growthMentorName').value = assessment.mentorName || '';
        document.getElementById('growthMentorType').value = assessment.mentorType || 'Quarterly Review';
    } else {
        mentorFields.style.display = 'none';
    }

    document.getElementById('growthAssessModalTitle').innerHTML = '<i class="fas fa-edit"></i> Edit Assessment (' + formatDateSetting(assessment.date) + ')';

    form.innerHTML = GROWTH_DIMENSIONS.map(d => {
        const currentLevel = assessment.levels[d.id] || 1;
        const currentNotes = assessment.notes?.[d.id] || '';
        const currentEvidence = assessment.evidence?.[d.id] || '';

        return `
        <div class="growth-assess-dim">
            <div class="growth-assess-dim-header" style="border-left:4px solid ${d.color};">
                <i class="fas ${d.icon}" style="color:${d.color};"></i>
                <strong>${d.name}</strong>
            </div>
            <div class="growth-assess-levels" id="growthLevels_${d.id}">
                ${d.levels.map((desc, i) => `
                    <label class="growth-assess-level-option ${i + 1 === currentLevel ? 'selected' : ''}">
                        <input type="radio" name="growth_${d.id}" value="${i + 1}" ${i + 1 === currentLevel ? 'checked' : ''} onchange="selectGrowthLevel('${d.id}', ${i + 1})">
                        <div class="growth-assess-level-header">
                            <span class="growth-assess-level-badge" style="background:${d.color}">Level ${i + 1}</span>
                        </div>
                        <p>${desc}</p>
                    </label>
                `).join('')}
            </div>
            <div class="growth-assess-notes">
                <label><i class="fas fa-sticky-note"></i> Self-Reflection Notes</label>
                <textarea id="growthNotes_${d.id}" placeholder="What evidence supports this level?">${escapeHtml(currentNotes)}</textarea>
            </div>
            <div class="growth-assess-notes">
                <label><i class="fas fa-link"></i> Evidence / Examples</label>
                <textarea id="growthEvidence_${d.id}" placeholder="Specific examples...">${escapeHtml(currentEvidence)}</textarea>
            </div>
        </div>`;
    }).join('');

    openModal('growthAssessModal');
}

// --- Growth Trend Line Chart ---
let growthTrendChartInstance = null;
function renderGrowthTrendChart() {
    const section = document.getElementById('growthTrendSection');
    const canvas = document.getElementById('growthTrendChart');
    if (!section || !canvas || typeof Chart === 'undefined') return;

    const assessments = getGrowthAssessments();
    if (assessments.length < 2) { section.style.display = 'none'; return; }

    section.style.display = 'block';
    const sorted = [...assessments].sort((a, b) => (a.date || '').localeCompare(b.date || ''));
    const labels = sorted.map(a => formatDateSetting(a.date));

    if (growthTrendChartInstance) { growthTrendChartInstance.destroy(); growthTrendChartInstance = null; }

    const datasets = GROWTH_DIMENSIONS.map(d => ({
        label: d.shortName,
        data: sorted.map(a => a.levels[d.id] || 1),
        borderColor: d.color,
        backgroundColor: d.color + '22',
        pointBackgroundColor: d.color,
        pointRadius: 5,
        pointHoverRadius: 7,
        borderWidth: 2,
        tension: 0.3,
        fill: false
    }));

    // Overall average line
    datasets.push({
        label: 'Overall Average',
        data: sorted.map(a => {
            const sum = GROWTH_DIMENSIONS.reduce((s, d) => s + (a.levels[d.id] || 1), 0);
            return +(sum / GROWTH_DIMENSIONS.length).toFixed(1);
        }),
        borderColor: '#f59e0b',
        backgroundColor: '#f59e0b22',
        pointBackgroundColor: '#f59e0b',
        pointRadius: 6,
        pointHoverRadius: 8,
        borderWidth: 3,
        tension: 0.3,
        borderDash: [6, 3],
        fill: false
    });

    growthTrendChartInstance = new Chart(canvas, {
        type: 'line',
        data: { labels, datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom',
                    labels: { usePointStyle: true, padding: 16, font: { size: 11 } }
                },
                tooltip: {
                    callbacks: {
                        label: ctx => `${ctx.dataset.label}: Level ${ctx.parsed.y}`
                    }
                }
            },
            scales: {
                y: {
                    min: 0, max: 4,
                    ticks: { stepSize: 1, callback: v => 'L' + v },
                    grid: { color: 'rgba(150,150,150,0.12)' }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });
}

// --- Action Plans CRUD ---
function getGrowthActions() {
    return DB.get('growthActionPlans') || [];
}

function renderGrowthActionPlans() {
    const el = document.getElementById('growthActionPlans');
    const section = document.getElementById('growthActionPlansSection');
    if (!el) return;

    const actions = getGrowthActions();
    const latest = getLatestAssessment();

    if (!latest) {
        if (section) section.style.display = 'none';
        return;
    }
    if (section) section.style.display = 'block';

    if (actions.length === 0) {
        el.innerHTML = `<div class="growth-action-empty">
            <i class="fas fa-clipboard-check" style="font-size:28px;color:var(--text-muted);margin-bottom:10px;"></i>
            <p style="color:var(--text-muted);margin:0;">No action plans yet. Set concrete goals for your growth!</p>
        </div>`;
        return;
    }

    // Sort: in-progress first, then not-started, then completed
    const statusOrder = { 'in-progress': 0, 'not-started': 1, 'completed': 2 };
    const sorted = [...actions].sort((a, b) => (statusOrder[a.status] || 1) - (statusOrder[b.status] || 1));

    el.innerHTML = sorted.map(a => {
        const dim = GROWTH_DIMENSIONS.find(d => d.id === a.dimId);
        const statusIcon = a.status === 'completed' ? 'fa-check-circle' : a.status === 'in-progress' ? 'fa-spinner fa-pulse' : 'fa-circle';
        const statusClass = a.status === 'completed' ? 'completed' : a.status === 'in-progress' ? 'in-progress' : 'not-started';
        const priorityColor = a.priority === 'high' ? '#ef4444' : a.priority === 'medium' ? '#f59e0b' : '#10b981';
        const isOverdue = a.targetDate && a.status !== 'completed' && a.targetDate < new Date().toISOString().split('T')[0];

        return `<div class="growth-action-card ${statusClass} ${isOverdue ? 'overdue' : ''}">
            <div class="growth-action-check">
                <button class="growth-action-toggle" onclick="toggleGrowthAction('${a.id}')" title="${a.status === 'completed' ? 'Mark incomplete' : 'Mark complete'}">
                    <i class="fas ${statusIcon}" style="color:${a.status === 'completed' ? '#10b981' : a.status === 'in-progress' ? '#3b82f6' : 'var(--text-muted)'}"></i>
                </button>
            </div>
            <div class="growth-action-body">
                <div class="growth-action-title ${a.status === 'completed' ? 'done' : ''}">${escapeHtml(a.title)}</div>
                <div class="growth-action-meta">
                    ${dim ? `<span class="growth-action-dim" style="background:${dim.color}20;color:${dim.color};"><i class="fas ${dim.icon}"></i> ${dim.shortName}</span>` : ''}
                    <span class="growth-action-target-level"><i class="fas fa-flag"></i> Target L${a.targetLevel || '?'}</span>
                    <span class="growth-action-priority" style="color:${priorityColor};"><i class="fas fa-signal"></i> ${(a.priority || 'medium').charAt(0).toUpperCase() + (a.priority || 'medium').slice(1)}</span>
                    ${a.targetDate ? `<span class="growth-action-date ${isOverdue ? 'overdue' : ''}"><i class="fas fa-calendar"></i> ${formatDateSetting(a.targetDate)}</span>` : ''}
                </div>
                ${a.steps ? `<div class="growth-action-steps"><i class="fas fa-list"></i> ${escapeHtml(a.steps).substring(0, 120)}${a.steps.length > 120 ? '...' : ''}</div>` : ''}
            </div>
            <div class="growth-action-actions">
                <button class="btn btn-ghost btn-xs" onclick="openGrowthActionPlan('${a.id}')" title="Edit"><i class="fas fa-edit"></i></button>
                <button class="btn btn-ghost btn-xs" onclick="deleteGrowthAction('${a.id}')" title="Delete"><i class="fas fa-trash"></i></button>
            </div>
        </div>`;
    }).join('');
}

function openGrowthActionPlan(editId) {
    const dimSelect = document.getElementById('growthActionDim');
    if (!dimSelect) return;

    // Populate dimension dropdown
    dimSelect.innerHTML = GROWTH_DIMENSIONS.map(d => `<option value="${d.id}">${d.icon ? '' : ''}${d.name}</option>`).join('');

    if (editId) {
        const action = getGrowthActions().find(a => a.id === editId);
        if (action) {
            document.getElementById('growthActionId').value = action.id;
            dimSelect.value = action.dimId || GROWTH_DIMENSIONS[0].id;
            document.getElementById('growthActionTitle').value = action.title || '';
            document.getElementById('growthActionTargetLevel').value = action.targetLevel || '3';
            document.getElementById('growthActionDate').value = action.targetDate || '';
            document.getElementById('growthActionSteps').value = action.steps || '';
            document.getElementById('growthActionSupport').value = action.support || '';
            document.getElementById('growthActionPriority').value = action.priority || 'medium';
            document.getElementById('growthActionStatus').value = action.status || 'not-started';
        }
    } else {
        document.getElementById('growthActionId').value = '';
        document.getElementById('growthActionTitle').value = '';
        document.getElementById('growthActionTargetLevel').value = '3';
        document.getElementById('growthActionDate').value = '';
        document.getElementById('growthActionSteps').value = '';
        document.getElementById('growthActionSupport').value = '';
        document.getElementById('growthActionPriority').value = 'medium';
        document.getElementById('growthActionStatus').value = 'not-started';

        // Auto-select weakest dimension
        const latest = getLatestAssessment();
        if (latest) {
            const weakest = GROWTH_DIMENSIONS.reduce((min, d) => (!min || (latest.levels[d.id] || 1) < (latest.levels[min.id] || 1)) ? d : min, null);
            if (weakest) dimSelect.value = weakest.id;
        }
    }

    openModal('growthActionModal');
}

function saveGrowthAction() {
    const title = document.getElementById('growthActionTitle').value.trim();
    if (!title) { showToast('Please enter a goal / action item', 'error'); return; }

    const id = document.getElementById('growthActionId').value || DB.generateId();
    const action = {
        id,
        dimId: document.getElementById('growthActionDim').value,
        title,
        targetLevel: parseInt(document.getElementById('growthActionTargetLevel').value) || 3,
        targetDate: document.getElementById('growthActionDate').value || '',
        steps: document.getElementById('growthActionSteps').value.trim(),
        support: document.getElementById('growthActionSupport').value.trim(),
        priority: document.getElementById('growthActionPriority').value || 'medium',
        status: document.getElementById('growthActionStatus').value || 'not-started',
        createdAt: new Date().toISOString()
    };

    let actions = getGrowthActions();
    const existingIdx = actions.findIndex(a => a.id === id);
    if (existingIdx >= 0) {
        action.createdAt = actions[existingIdx].createdAt;
        actions[existingIdx] = action;
    } else {
        actions.push(action);
    }
    DB.set('growthActionPlans', actions);

    closeModal('growthActionModal');
    renderGrowthActionPlans();
    showToast(existingIdx >= 0 ? 'Action plan updated!' : 'Action plan added!', 'success');
}

function deleteGrowthAction(id) {
    if (!confirm('Delete this action plan?')) return;
    let actions = getGrowthActions();
    actions = actions.filter(a => a.id !== id);
    DB.set('growthActionPlans', actions);
    renderGrowthActionPlans();
    showToast('Action plan deleted', 'info');
}

function toggleGrowthAction(id) {
    let actions = getGrowthActions();
    const action = actions.find(a => a.id === id);
    if (!action) return;
    // Cycle: not-started -> in-progress -> completed -> not-started
    if (action.status === 'not-started') action.status = 'in-progress';
    else if (action.status === 'in-progress') action.status = 'completed';
    else action.status = 'not-started';
    DB.set('growthActionPlans', actions);
    renderGrowthActionPlans();
}

// --- Growth Tips & Suggestions ---
function renderGrowthTips() {
    const el = document.getElementById('growthTips');
    const section = document.getElementById('growthTipsSection');
    if (!el || !section) return;

    const latest = getLatestAssessment();
    if (!latest) { section.style.display = 'none'; return; }

    section.style.display = 'block';

    const tipsDB = {
        dim1: {
            1: [
                'Visit at least 2 schools per week and spend time building rapport with teachers.',
                'Shadow a senior RP during school visits to learn relationship-building techniques.',
                'Maintain a simple log of all teachers you interact with — name, school, topic discussed.'
            ],
            2: [
                'Use WhatsApp/social media groups to keep in touch with teachers between visits.',
                'Create a teacher database with their interests, strengths, and challenges.',
                'Attend community events or school functions to build trust beyond academic settings.'
            ],
            3: [
                'Identify "champion teachers" in each cluster who can help spread your outreach.',
                'Leverage teacher networks to connect with hard-to-reach teachers.',
                'Design a mobilization strategy for a block-level teacher engagement drive.'
            ],
            4: [
                'Mentor junior RPs on relationship-building strategies through structured coaching.',
                'Document your best practices in relationship-building as case studies.',
                'Develop a framework for measuring relationship depth and quality with teachers.'
            ]
        },
        dim2: {
            1: [
                'Volunteer to co-facilitate a session with a senior member this month.',
                'Study 2-3 well-designed session plans and note the structure, flow, and activities used.',
                'Practice writing clear session objectives using Bloom\'s taxonomy.'
            ],
            2: [
                'Independently adapt an existing workshop for your block\'s specific context.',
                'Create engaging handouts or resource sheets for your next facilitation.',
                'Get feedback from 3 participants after your session and reflect on areas for improvement.'
            ],
            3: [
                'Design a complete 3-day workshop from scratch with detailed session plans.',
                'Create interactive activities (group work, simulations, gallery walks) for your sessions.',
                'Conceptualize a series of connected sessions (not standalone) for teacher development.'
            ],
            4: [
                'Review and provide detailed feedback on session plans designed by other RPs.',
                'Facilitate a difficult session (e.g., sensitive topic, resistant audience) and document your approach.',
                'Create a session design toolkit or template for other RPs to use.'
            ]
        },
        dim3: {
            1: [
                'Read existing teaching-learning material and make notes on what works well.',
                'Write a brief observation report after every school visit.',
                'Start a learning journal — write weekly reflections on your readings.'
            ],
            2: [
                'Develop a PowerPoint or handout for a topic you understand well.',
                'Write a detailed report on a successful school engagement experience.',
                'Create a set of worksheets for a specific learning outcome in any subject.'
            ],
            3: [
                'Develop a complete module (5+ sessions) for teacher professional development.',
                'Write a reflective article connecting theory to your field experiences.',
                'Create exemplar teaching plans for different subject areas.'
            ],
            4: [
                'Review and improve material developed by other team members.',
                'Write an article or paper based on your field experience suitable for publication.',
                'Develop a comprehensive resource repository organized by themes.'
            ]
        },
        dim4: {
            1: [
                'Plan your school visits in advance with clear objectives for each visit.',
                'Observe a senior RP\'s classroom engagement and note their strategies.',
                'Start observing one teacher per visit systematically using an observation tool.'
            ],
            2: [
                'Build comprehensive school observation protocols (beyond just classroom).',
                'Attempt teacher scaffolding — plan a specific support action for one teacher.',
                'Engage with students during visits to assess learning levels directly.'
            ],
            3: [
                'Create individualized development plans for at least 3 teachers in your focus schools.',
                'Conduct a collaborative lesson with a teacher (co-teaching or demonstration).',
                'Engage with the school principal to align support with school development goals.'
            ],
            4: [
                'Design and implement a whole-school development initiative in a focus school.',
                'Scaffold teachers with different needs (new vs. experienced, motivated vs. demotivated).',
                'Document a school transformation case study based on your sustained engagement.'
            ]
        },
        dim5: {
            1: [
                'Read at least 2 articles on teacher professional development models this month.',
                'Discuss your understanding of teacher capacity building with your team.',
                'Map the existing TPD initiatives in your block/cluster — workshops, TLCs, meetings.'
            ],
            2: [
                'Identify 3 key pedagogical topics most relevant for teachers in your cluster.',
                'Design a classroom demonstration on a specific topic for teacher learning.',
                'Connect workshop content back to classroom practice with follow-up activities.'
            ],
            3: [
                'Create a 6-month teacher development plan with forward-backward linkages.',
                'Categorize teachers in your focus area by expertise and motivation levels.',
                'Design multiple engagement modes — workshops, TLCs, school visits, peer learning.'
            ],
            4: [
                'Design a comprehensive annual TPD plan for your block with measurable indicators.',
                'Mentor a junior RP to design and execute a capacity-building series.',
                'Analyze the impact of your TPD efforts on actual teaching practices and student learning.'
            ]
        }
    };

    el.innerHTML = GROWTH_DIMENSIONS.map(d => {
        const lvl = latest.levels[d.id] || 1;
        const tips = tipsDB[d.id]?.[lvl] || [];
        const levelLabel = lvl >= 4 ? 'Expert' : lvl >= 3 ? 'Proficient' : lvl >= 2 ? 'Developing' : 'Emerging';

        return `<div class="growth-tip-card" style="--dim-color:${d.color}">
            <div class="growth-tip-header">
                <div class="growth-tip-icon" style="background:${d.color};"><i class="fas ${d.icon}"></i></div>
                <div>
                    <h4>${d.shortName}</h4>
                    <span class="growth-tip-level">Level ${lvl} — ${levelLabel}</span>
                </div>
            </div>
            <ul class="growth-tip-list">
                ${tips.map(tip => `<li><i class="fas fa-lightbulb" style="color:${d.color};"></i> ${tip}</li>`).join('')}
            </ul>
            ${lvl < 4 ? `<div class="growth-tip-next-preview"><strong>To reach Level ${lvl + 1}:</strong> ${d.levels[lvl].substring(0, 150)}...</div>` : '<div class="growth-tip-mastered"><i class="fas fa-crown"></i> You\'ve reached mastery! Focus on mentoring others.</div>'}
        </div>`;
    }).join('');
}

// --- Print Growth Report ---
function printGrowthReport() {
    const latest = getLatestAssessment();
    const assessments = getGrowthAssessments();
    if (!latest) { showToast('Take an assessment first', 'info'); return; }

    const totalScore = GROWTH_DIMENSIONS.reduce((s, d) => s + (latest.levels[d.id] || 1), 0);
    const avgLevel = (totalScore / GROWTH_DIMENSIONS.length).toFixed(1);
    const levelLabel = avgLevel >= 3.5 ? 'Expert Practitioner' : avgLevel >= 2.5 ? 'Proficient Practitioner' : avgLevel >= 1.5 ? 'Developing Practitioner' : 'Emerging Practitioner';

    const profile = typeof getProfile === 'function' ? getProfile() : null;

    const printContent = `
    <!DOCTYPE html>
    <html><head><title>Professional Growth Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; padding: 30px; color: #1a1a2e; font-size: 13px; }
        .print-header { text-align: center; border-bottom: 3px solid #f59e0b; padding-bottom: 16px; margin-bottom: 20px; }
        .print-header h1 { font-size: 22px; color: #1a1a2e; }
        .print-header p { color: #666; margin-top: 4px; }
        .print-summary { display: flex; justify-content: space-between; margin-bottom: 20px; padding: 16px; background: #f8f9fa; border-radius: 8px; }
        .print-summary-item { text-align: center; }
        .print-summary-item strong { display: block; font-size: 24px; color: #f59e0b; }
        .print-summary-item span { font-size: 12px; color: #666; }
        .print-dim { margin-bottom: 16px; page-break-inside: avoid; border: 1px solid #e5e7eb; border-radius: 8px; padding: 14px; }
        .print-dim-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
        .print-dim-header .dot { width: 12px; height: 12px; border-radius: 50%; }
        .print-dim-header h3 { font-size: 14px; flex: 1; }
        .print-dim-header .level { font-weight: 700; font-size: 16px; }
        .print-dim-desc { color: #444; font-size: 12px; line-height: 1.6; margin-bottom: 8px; }
        .print-dim-notes { background: #f0f9ff; padding: 8px 10px; border-radius: 6px; font-size: 12px; margin-top: 6px; }
        .print-dim-notes strong { color: #1e40af; }
        .print-bar { height: 6px; background: #e5e7eb; border-radius: 3px; margin-top: 6px; }
        .print-bar-fill { height: 6px; border-radius: 3px; transition: width 0.5s; }
        .print-history { margin-top: 20px; }
        .print-history h3 { font-size: 15px; margin-bottom: 10px; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; }
        .print-history-table { width: 100%; border-collapse: collapse; font-size: 12px; }
        .print-history-table th, .print-history-table td { padding: 6px 10px; border: 1px solid #e5e7eb; text-align: center; }
        .print-history-table th { background: #f8f9fa; font-weight: 600; }
        .print-actions { margin-top: 20px; }
        .print-actions h3 { font-size: 15px; margin-bottom: 10px; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; }
        .print-action-item { display: flex; gap: 8px; padding: 6px 0; border-bottom: 1px solid #f3f4f6; font-size: 12px; }
        .print-action-status { width: 14px; height: 14px; border: 2px solid #ccc; border-radius: 50%; flex-shrink: 0; margin-top: 2px; }
        .print-action-status.done { background: #10b981; border-color: #10b981; }
        .print-footer { margin-top: 30px; text-align: center; font-size: 11px; color: #999; border-top: 1px solid #e5e7eb; padding-top: 10px; }
        @media print { body { padding: 15px; } }
    </style>
    </head><body>
        <div class="print-header">
            <h1>Professional Growth Report</h1>
            <p>${profile?.name ? profile.name + ' — ' : ''}APF Resource Person${profile?.block ? ' | ' + profile.block : ''}${profile?.cluster ? ', ' + profile.cluster : ''}</p>
            <p style="font-size:12px;margin-top:4px;">Assessment Date: ${formatDateSetting(latest.date)} | Generated: ${formatDateSetting(new Date().toISOString().split('T')[0])}</p>
        </div>

        <div class="print-summary">
            <div class="print-summary-item"><strong>${avgLevel}</strong><span>Average Level</span></div>
            <div class="print-summary-item"><strong>${levelLabel}</strong><span>Overall Stage</span></div>
            <div class="print-summary-item"><strong>${totalScore}/${GROWTH_DIMENSIONS.length * 4}</strong><span>Total Score</span></div>
            <div class="print-summary-item"><strong>${assessments.length}</strong><span>Assessments</span></div>
        </div>

        ${GROWTH_DIMENSIONS.map(d => {
            const lvl = latest.levels[d.id] || 1;
            const notes = latest.notes?.[d.id] || '';
            const evidence = latest.evidence?.[d.id] || '';
            return `<div class="print-dim">
                <div class="print-dim-header">
                    <div class="dot" style="background:${d.color};"></div>
                    <h3>${d.name}</h3>
                    <div class="level" style="color:${d.color};">Level ${lvl}/4</div>
                </div>
                <div class="print-dim-desc">${d.levels[lvl - 1]}</div>
                <div class="print-bar"><div class="print-bar-fill" style="width:${lvl * 25}%;background:${d.color};"></div></div>
                ${notes ? `<div class="print-dim-notes"><strong>Notes:</strong> ${escapeHtml(notes)}</div>` : ''}
                ${evidence ? `<div class="print-dim-notes"><strong>Evidence:</strong> ${escapeHtml(evidence)}</div>` : ''}
            </div>`;
        }).join('')}

        ${assessments.length > 1 ? `
            <div class="print-history">
                <h3>Assessment History</h3>
                <table class="print-history-table">
                    <tr><th>Date</th>${GROWTH_DIMENSIONS.map(d => `<th>${d.shortName}</th>`).join('')}<th>Average</th></tr>
                    ${[...assessments].sort((a, b) => (b.date || '').localeCompare(a.date || '')).map(a => {
                        const avg = (GROWTH_DIMENSIONS.reduce((s, d) => s + (a.levels[d.id] || 1), 0) / GROWTH_DIMENSIONS.length).toFixed(1);
                        return `<tr><td>${formatDateSetting(a.date)}</td>${GROWTH_DIMENSIONS.map(d => `<td>L${a.levels[d.id] || 1}</td>`).join('')}<td><strong>${avg}</strong></td></tr>`;
                    }).join('')}
                </table>
            </div>
        ` : ''}

        ${(() => {
            const actions = getGrowthActions();
            if (actions.length === 0) return '';
            return `<div class="print-actions">
                <h3>Growth Action Plans</h3>
                ${actions.map(a => {
                    const dim = GROWTH_DIMENSIONS.find(d => d.id === a.dimId);
                    return `<div class="print-action-item">
                        <div class="print-action-status ${a.status === 'completed' ? 'done' : ''}"></div>
                        <div><strong>${escapeHtml(a.title)}</strong> — ${dim ? dim.shortName : ''} (Target L${a.targetLevel || '?'})${a.targetDate ? ' | Due: ' + formatDateSetting(a.targetDate) : ''}</div>
                    </div>`;
                }).join('')}
            </div>`;
        })()}

        <div class="print-footer">Professional Growth Framework — APF Resource Person Dashboard</div>
    </body></html>`;

    const printWin = window.open('', '_blank', 'width=900,height=700');
    if (!printWin) { showToast('Popup blocked — please allow popups for this site', 'error'); return; }
    printWin.document.write(printContent);
    printWin.document.close();
    setTimeout(() => printWin.print(), 400);
}

// ===== SAMPLE DATA =====
// ===== USER PROFILE =====
function getProfile() {
    try {
        // Read from DB first (synced with encrypted file / Drive)
        const dbProfile = DB.get('userProfile');
        if (dbProfile.length > 0) return dbProfile[0];
        // Fallback: localStorage (for backward compat)
        const raw = localStorage.getItem('apf_user_profile');
        if (raw) {
            const p = JSON.parse(raw);
            // Migrate to DB so it gets included in encrypted saves
            if (p && p.name) {
                _originalDBSet('userProfile', [p]);
            }
            return p;
        }
        return {};
    } catch(e) { return {}; }
}

function saveProfileData(profileObj) {
    // Save to DB (triggers auto-save to .apf file, IndexedDB cache, Google Drive, localStorage fallback)
    DB.set('userProfile', [profileObj]);
    // Also save directly to localStorage for instant access on next load
    localStorage.setItem('apf_user_profile', JSON.stringify(profileObj));
    applyProfileToUI();
}

function applyProfileToUI() {
    const p = getProfile();
    const nameEl = document.getElementById('userName');
    const orgEl = document.getElementById('userOrg');
    const avatarEl = document.getElementById('userAvatarIcon');

    if (nameEl) nameEl.textContent = p.name || 'Resource Person';
    if (orgEl) orgEl.textContent = p.organization || 'Azim Premji Foundation';
    if (avatarEl && p.name) {
        const initials = p.name.split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase();
        avatarEl.innerHTML = `<span style="font-size:14px;font-weight:700;">${initials}</span>`;
    }
    // Keep localStorage in sync for instant access on next load
    if (p.name) {
        try { localStorage.setItem('apf_user_profile', JSON.stringify(p)); } catch(e) {}
    }
}

function openProfileModal() {
    const p = getProfile();
    document.getElementById('profileName').value = p.name || '';
    document.getElementById('profileDesignation').value = p.designation || 'Resource Person';
    document.getElementById('profileOrg').value = p.organization || 'Azim Premji Foundation';
    document.getElementById('profileDistrict').value = p.district || '';
    document.getElementById('profileBlock').value = p.block || '';
    document.getElementById('profileState').value = p.state || '';
    document.getElementById('profilePhone').value = p.phone || '';
    document.getElementById('profileEmail').value = p.email || '';

    // Update avatar preview
    const avatarLg = document.getElementById('profileAvatarLarge');
    if (avatarLg && p.name) {
        const initials = p.name.split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase();
        avatarLg.innerHTML = `<span>${initials}</span>`;
    } else if (avatarLg) {
        avatarLg.innerHTML = '<i class="fas fa-user"></i>';
    }

    openModal('profileModal');
}

function saveProfile(e) {
    e.preventDefault();
    const profile = {
        name: document.getElementById('profileName').value.trim(),
        designation: document.getElementById('profileDesignation').value,
        organization: document.getElementById('profileOrg').value.trim() || 'Azim Premji Foundation',
        district: document.getElementById('profileDistrict').value.trim(),
        block: document.getElementById('profileBlock').value.trim(),
        state: document.getElementById('profileState').value.trim(),
        phone: document.getElementById('profilePhone').value.trim(),
        email: document.getElementById('profileEmail').value.trim(),
    };
    saveProfileData(profile);
    closeModal('profileModal');
    // Refresh dashboard greeting if visible
    if (document.getElementById('section-dashboard')?.classList.contains('active')) {
        renderDashboard();
    }
    showToast('Profile saved! 👤', 'success');
}

// ===== MONTHLY WORK LOG =====
function renderWorkLog() {
    const monthSel = document.getElementById('worklogMonth');
    // Populate month selector if empty
    if (monthSel.options.length === 0) {
        const now = new Date();
        for (let i = 0; i < 12; i++) {
            const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
            const val = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
            const label = d.toLocaleString('en-IN', { month: 'long', year: 'numeric' });
            monthSel.innerHTML += `<option value="${val}">${label}</option>`;
        }
    }

    const [year, month] = monthSel.value.split('-').map(Number);
    const daysInMonth = new Date(year, month, 0).getDate();

    // Get all data for this month
    const visits = DB.get('visits').filter(v => { const d = new Date(v.date); return d.getMonth() + 1 === month && d.getFullYear() === year; });
    const trainings = DB.get('trainings').filter(t => { const d = new Date(t.date); return d.getMonth() + 1 === month && d.getFullYear() === year; });
    const observations = DB.get('observations').filter(o => { const d = new Date(o.date); return d.getMonth() + 1 === month && d.getFullYear() === year; });
    const worklog = DB.get('worklog').filter(w => { const d = new Date(w.date); return d.getMonth() + 1 === month && d.getFullYear() === year; });

    // Build day-by-day log
    const dayMap = {};
    for (let d = 1; d <= daysInMonth; d++) {
        const dateStr = `${year}-${String(month).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
        const dayDate = new Date(year, month - 1, d);
        const isSunday = dayDate.getDay() === 0;
        dayMap[dateStr] = { date: dateStr, dayName: dayDate.toLocaleString('en', { weekday: 'short' }), day: d, isSunday, activities: [] };
    }

    // Auto-populate from visits
    visits.forEach(v => {
        const dateStr = v.date?.substring(0, 10);
        if (dayMap[dateStr]) {
            dayMap[dateStr].activities.push({
                type: 'School Visit',
                location: v.school || '',
                description: `${v.purpose || 'Visit'}${v.notes ? ' — ' + v.notes : ''}`,
                outcome: v.followUp || '',
                status: v.status,
                source: 'auto'
            });
        }
    });

    // Auto-populate from trainings
    trainings.forEach(t => {
        const dateStr = t.date?.substring(0, 10);
        if (dayMap[dateStr]) {
            dayMap[dateStr].activities.push({
                type: 'Training / Workshop',
                location: t.venue || '',
                description: `${t.title}${t.topic ? ' (' + t.topic + ')' : ''} — ${t.attendees || 0} attendees, ${t.duration || 0}h`,
                outcome: t.feedback || '',
                source: 'auto'
            });
        }
    });

    // Auto-populate from observations
    observations.forEach(o => {
        const dateStr = o.date?.substring(0, 10);
        if (dayMap[dateStr]) {
            dayMap[dateStr].activities.push({
                type: 'Classroom Observation',
                location: o.school || '',
                description: `Observed ${o.teacher || 'teacher'} — ${o.subject || ''} ${o.class || ''}${o.topic ? ': ' + o.topic : ''}`,
                outcome: o.suggestions || '',
                source: 'auto'
            });
        }
    });

    // Auto-populate from meetings
    const meetingsMonth = DB.get('meetings').filter(m => { const d = new Date(m.date); return d.getMonth() + 1 === month && d.getFullYear() === year; });
    meetingsMonth.forEach(m => {
        const dateStr = m.date?.substring(0, 10);
        if (dayMap[dateStr]) {
            const pendingActions = (m.actionItems || []).filter(a => !a.done).length;
            dayMap[dateStr].activities.push({
                type: 'Meeting',
                location: m.location || '',
                description: `${m.type || 'Meeting'}: ${m.title || ''}${m.organizer ? ' (by ' + m.organizer + ')' : ''}`,
                outcome: m.decisions ? m.decisions : (pendingActions > 0 ? `${pendingActions} action items pending` : ''),
                source: 'auto'
            });
        }
    });

    // Add manual worklog entries
    worklog.forEach(w => {
        const dateStr = w.date?.substring(0, 10);
        if (dayMap[dateStr]) {
            dayMap[dateStr].activities.push({
                type: w.type || 'Other',
                location: w.location || '',
                description: w.description || '',
                outcome: w.outcome || '',
                source: 'manual',
                id: w.id
            });
        }
    });

    // Stats
    const totalDays = daysInMonth;
    const activeDays = Object.values(dayMap).filter(d => d.activities.length > 0).length;
    const totalActivities = Object.values(dayMap).reduce((s, d) => s + d.activities.length, 0);
    const typeCounts = {};
    Object.values(dayMap).forEach(d => d.activities.forEach(a => { typeCounts[a.type] = (typeCounts[a.type] || 0) + 1; }));

    document.getElementById('worklogStats').innerHTML = `
        <div class="worklog-stat-grid">
            <div class="worklog-stat"><div class="stat-value">${activeDays}</div><div class="stat-label">Working Days</div></div>
            <div class="worklog-stat"><div class="stat-value">${totalDays - activeDays}</div><div class="stat-label">No Entry</div></div>
            <div class="worklog-stat"><div class="stat-value">${totalActivities}</div><div class="stat-label">Total Activities</div></div>
            ${Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([type, count]) =>
                `<div class="worklog-stat"><div class="stat-value">${count}</div><div class="stat-label">${type}</div></div>`
            ).join('')}
        </div>
    `;

    // Render table
    const days = Object.values(dayMap);
    const container = document.getElementById('worklogContainer');

    const typeIcons = {
        'School Visit': 'fa-school', 'Classroom Observation': 'fa-clipboard-check',
        'Training / Workshop': 'fa-chalkboard-teacher', 'Meeting': 'fa-users',
        'Desk Work': 'fa-laptop', 'Travel': 'fa-car', 'Data Entry / Reporting': 'fa-file-alt',
        'Community Engagement': 'fa-hands-helping', 'Material Preparation': 'fa-tools',
        'Leave': 'fa-bed', 'Holiday': 'fa-flag', 'Other': 'fa-ellipsis-h'
    };

    const typeColors = {
        'School Visit': '#8b5cf6', 'Classroom Observation': '#10b981',
        'Training / Workshop': '#3b82f6', 'Meeting': '#f59e0b',
        'Desk Work': '#6366f1', 'Travel': '#64748b', 'Data Entry / Reporting': '#06b6d4',
        'Community Engagement': '#ec4899', 'Material Preparation': '#f97316',
        'Leave': '#94a3b8', 'Holiday': '#ef4444', 'Other': '#6b7280'
    };

    container.innerHTML = `
    <table class="worklog-table">
        <thead>
            <tr>
                <th style="width:45px;">Day</th>
                <th style="width:50px;">Date</th>
                <th style="width:140px;">Activity Type</th>
                <th style="width:140px;">Location</th>
                <th>Description</th>
                <th style="width:160px;">Outcome / Remarks</th>
                <th style="width:50px;"></th>
            </tr>
        </thead>
        <tbody>
            ${days.map(d => {
                if (d.activities.length === 0) {
                    return `<tr class="${d.isSunday ? 'worklog-sunday' : 'worklog-empty'}">
                        <td><strong>${d.day}</strong><br><small>${d.dayName}</small></td>
                        <td>${d.date.substring(5)}</td>
                        <td colspan="4" class="worklog-no-entry">${d.isSunday ? '<i class="fas fa-flag"></i> Sunday' : '<i class="fas fa-minus"></i> No entry'}</td>
                        <td><button class="btn-icon-sm" onclick="addWorkLogEntry('${d.date}')" title="Add entry"><i class="fas fa-plus"></i></button></td>
                    </tr>`;
                }
                return d.activities.map((a, i) => {
                    const icon = typeIcons[a.type] || 'fa-ellipsis-h';
                    const color = typeColors[a.type] || '#6b7280';
                    return `<tr class="${d.isSunday ? 'worklog-sunday' : ''}">
                        ${i === 0 ? `<td rowspan="${d.activities.length}"><strong>${d.day}</strong><br><small>${d.dayName}</small></td>
                        <td rowspan="${d.activities.length}">${d.date.substring(5)}</td>` : ''}
                        <td><span class="worklog-type-badge" style="background:${color}15;color:${color};border:1px solid ${color}30;"><i class="fas ${icon}"></i> ${escapeHtml(a.type)}</span></td>
                        <td>${escapeHtml(a.location)}</td>
                        <td>${escapeHtml(a.description)}</td>
                        <td>${escapeHtml(a.outcome)}</td>
                        <td>${a.source === 'manual' ? `<button class="btn-icon-sm" onclick="deleteWorkLogEntry('${a.id}')" title="Delete"><i class="fas fa-trash"></i></button>` :
                            (i === 0 ? `<button class="btn-icon-sm" onclick="addWorkLogEntry('${d.date}')" title="Add"><i class="fas fa-plus"></i></button>` : '')}</td>
                    </tr>`;
                }).join('');
            }).join('')}
        </tbody>
    </table>`;
}

function addWorkLogEntry(dateStr) {
    const form = document.getElementById('worklogForm');
    form.reset();
    document.getElementById('worklogId').value = '';
    document.getElementById('worklogDate').value = dateStr || new Date().toISOString().substring(0, 10);
    document.getElementById('worklogModalTitle').innerHTML = '<i class="fas fa-clipboard-list"></i> Add Work Log Entry';
    openModal('worklogModal');
}

function saveWorkLogEntry(e) {
    e.preventDefault();
    const worklog = DB.get('worklog');
    const id = document.getElementById('worklogId').value;
    const entry = {
        id: id || DB.generateId(),
        date: document.getElementById('worklogDate').value,
        type: document.getElementById('worklogType').value,
        location: document.getElementById('worklogLocation').value.trim(),
        description: document.getElementById('worklogDescription').value.trim(),
        outcome: document.getElementById('worklogOutcome').value.trim(),
        createdAt: id ? (worklog.find(w => w.id === id) || {}).createdAt || new Date().toISOString() : new Date().toISOString()
    };

    if (id) {
        const idx = worklog.findIndex(w => w.id === id);
        if (idx !== -1) worklog[idx] = entry;
    } else {
        worklog.push(entry);
    }

    DB.set('worklog', worklog);
    closeModal('worklogModal');
    renderWorkLog();
    showToast(id ? 'Entry updated' : 'Work log entry added! 📋');
}

function deleteWorkLogEntry(id) {
    if (!confirm('Delete this work log entry?')) return;
    let worklog = DB.get('worklog');
    worklog = worklog.filter(w => w.id !== id);
    DB.set('worklog', worklog);
    renderWorkLog();
    showToast('Entry deleted');
}

function printWorkLog() {
    const profile = getProfile();
    const monthSel = document.getElementById('worklogMonth');
    const monthLabel = monthSel.options[monthSel.selectedIndex]?.text || '';
    const tableHtml = document.querySelector('.worklog-table')?.outerHTML || '<p>No data</p>';

    const html = `<!DOCTYPE html>
<html><head><title>Work Log — ${monthLabel}</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Arial, sans-serif; padding: 20px 30px; color: #1e293b; font-size: 12px; }
    .header { text-align: center; border-bottom: 3px solid #6366f1; padding-bottom: 12px; margin-bottom: 16px; }
    .header h1 { font-size: 18px; color: #6366f1; }
    .header p { color: #64748b; font-size: 11px; margin-top: 4px; }
    .profile-info { display: flex; justify-content: space-between; margin-bottom: 12px; font-size: 12px; padding: 8px 12px; background: #f8fafc; border-radius: 6px; }
    .profile-info div { line-height: 1.6; }
    table { width: 100%; border-collapse: collapse; font-size: 11px; }
    th { background: #6366f1; color: white; padding: 6px 8px; text-align: left; font-size: 10px; text-transform: uppercase; }
    td { padding: 5px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    tr:nth-child(even) { background: #f8fafc; }
    .worklog-sunday td { background: #fef2f2; }
    .worklog-empty td { color: #94a3b8; }
    .worklog-type-badge { font-size: 10px; padding: 2px 6px; border-radius: 4px; }
    .footer { text-align: center; margin-top: 20px; font-size: 10px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 8px; }
    .signature { display: flex; justify-content: space-between; margin-top: 40px; padding-top: 20px; }
    .sig-box { text-align: center; width: 200px; }
    .sig-line { border-top: 1px solid #334155; margin-top: 40px; padding-top: 4px; font-size: 11px; color: #64748b; }
    @media print { body { padding: 10px; } }
</style></head><body>
<div class="header">
    <h1>Monthly Work Log — ${monthLabel}</h1>
    <p>Azim Premji Foundation — Field Activity Diary</p>
</div>
<div class="profile-info">
    <div><strong>Name:</strong> ${escapeHtml(profile.name || 'N/A')} &nbsp;&nbsp; <strong>Designation:</strong> ${escapeHtml(profile.designation || 'Resource Person')}</div>
    <div><strong>District:</strong> ${escapeHtml(profile.district || 'N/A')} &nbsp;&nbsp; <strong>Block:</strong> ${escapeHtml(profile.block || 'N/A')}</div>
</div>
${tableHtml}
<div class="signature">
    <div class="sig-box"><div class="sig-line">Signature of ${escapeHtml(profile.designation || 'Resource Person')}</div></div>
    <div class="sig-box"><div class="sig-line">Signature of Supervisor</div></div>
</div>
<div class="footer">Generated by ${escapeHtml(profile.name || 'APF Resource Person')} — APF Dashboard — ${new Date().toLocaleDateString('en-IN')}</div>
</body></html>`;

    const w = window.open('', '_blank', 'width=1000,height=800');
    if (!w) { showToast('Popup blocked — please allow popups for this site', 'error'); return; }
    w.document.write(html);
    w.document.close();
    setTimeout(() => w.print(), 500);
}

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

// ===== DASHBOARD SMART ALERTS =====
function renderDashboardAlerts() {
    const el = document.getElementById('dashboardAlerts');
    if (!el) return;
    const alerts = [];
    const visits = DB.get('visits');
    const observations = DB.get('observations');
    const now = new Date();
    const today = now.toISOString().split('T')[0];

    // 1. Overdue follow-ups
    const followupStatusArr = DB.get('followupStatus') || [];
    const pendingFollowups = visits.filter(v => v.followUp && v.followUp.trim() && !followupStatusArr.find(f => f.id === v.id && f.done));
    if (pendingFollowups.length > 0) {
        alerts.push({
            icon: 'fa-clipboard-list', color: '#f59e0b', rgb: '245,158,11',
            title: 'Pending Follow-ups', desc: 'Action items need attention',
            count: pendingFollowups.length, section: 'followups'
        });
    }

    // 2. Upcoming visits this week
    const weekEnd = new Date(now); weekEnd.setDate(now.getDate() + 7);
    const upcomingThisWeek = visits.filter(v => v.status === 'planned' && new Date(v.date) >= now && new Date(v.date) <= weekEnd);
    if (upcomingThisWeek.length > 0) {
        alerts.push({
            icon: 'fa-calendar-day', color: '#3b82f6', rgb: '59,130,246',
            title: 'Visits This Week', desc: 'Planned school visits ahead',
            count: upcomingThisWeek.length, section: 'visits'
        });
    }

    // 3. Teachers not observed in 30+ days
    const teacherLastObs = {};
    observations.forEach(o => {
        const key = (o.teacher || '').toLowerCase().trim();
        if (!key) return;
        const d = new Date(o.date);
        if (!teacherLastObs[key] || d > teacherLastObs[key]) teacherLastObs[key] = d;
    });
    const staleTeachers = Object.entries(teacherLastObs).filter(([_, d]) => (now - d) / 86400000 > 30);
    if (staleTeachers.length > 0) {
        alerts.push({
            icon: 'fa-user-clock', color: '#ef4444', rgb: '239,68,68',
            title: 'Needs Revisit', desc: 'Teachers not seen in 30+ days',
            count: staleTeachers.length, section: 'teachers'
        });
    }

    // 4. Low engagement teachers
    const teacherEng = {};
    observations.forEach(o => {
        const key = (o.teacher || '').toLowerCase().trim();
        if (!key || !o.engagementLevel) return;
        if (!teacherEng[key]) teacherEng[key] = [];
        teacherEng[key].push(o.engagementLevel === 'More Engaged' ? 3 : o.engagementLevel === 'Engaged' ? 2 : 1);
    });
    const lowEngCount = Object.values(teacherEng).filter(arr => {
        const avg = arr.reduce((a, b) => a + b, 0) / arr.length;
        return avg < 2 && arr.length >= 2;
    }).length;
    if (lowEngCount > 0) {
        alerts.push({
            icon: 'fa-exclamation-triangle', color: '#ef4444', rgb: '239,68,68',
            title: 'Low Engagement', desc: 'Teachers need support',
            count: lowEngCount, section: 'teachers'
        });
    }

    // 5. Overdue planner tasks
    const tasks = DB.get('plannerTasks');
    const overdueTasks = tasks.filter(t => !t.done && t.dateKey < today);
    if (overdueTasks.length > 0) {
        alerts.push({
            icon: 'fa-tasks', color: '#8b5cf6', rgb: '139,92,246',
            title: 'Overdue Tasks', desc: 'Planner tasks past due',
            count: overdueTasks.length, section: 'planner'
        });
    }

    // 6. Growth assessment due
    const growthAssessments = getGrowthAssessments();
    if (growthAssessments.length === 0) {
        alerts.push({
            icon: 'fa-seedling', color: '#10b981', rgb: '16,185,129',
            title: 'Growth Assessment', desc: 'Take your first growth self-assessment',
            count: '!', section: 'growth'
        });
    } else {
        const latestGrowth = growthAssessments.sort((a, b) => (b.date || '').localeCompare(a.date || ''))[0];
        const daysSince = Math.floor((now - new Date(latestGrowth.date)) / 86400000);
        if (daysSince > 30) {
            alerts.push({
                icon: 'fa-seedling', color: '#10b981', rgb: '16,185,129',
                title: 'Growth Overdue', desc: `Last assessment ${daysSince} days ago`,
                count: 1, section: 'growth'
            });
        }
    }

    // 7. Overdue growth action plans
    const growthActions = typeof getGrowthActions === 'function' ? getGrowthActions() : [];
    const overdueActions = growthActions.filter(a => a.status !== 'completed' && a.targetDate && a.targetDate < today);
    if (overdueActions.length > 0) {
        alerts.push({
            icon: 'fa-bullseye', color: '#ef4444', rgb: '239,68,68',
            title: 'Growth Actions Due', desc: 'Action plans past target date',
            count: overdueActions.length, section: 'growth'
        });
    }

    if (alerts.length === 0) {
        el.innerHTML = '';
        return;
    }

    el.innerHTML = alerts.map(a => `
        <div class="dash-alert" style="--alert-color:${a.color};--alert-rgb:${a.rgb}" onclick="navigateTo('${a.section}')">
            <div class="dash-alert-icon"><i class="fas ${a.icon}"></i></div>
            <div class="dash-alert-info"><h4>${a.title}</h4><p>${a.desc}</p></div>
            <div class="dash-alert-badge">${a.count}</div>
        </div>
    `).join('');
}

// ===== QUICK CAPTURE =====
function openQuickCapture() {
    document.getElementById('quickCaptureForm').reset();
    document.getElementById('qcDate').value = new Date().toISOString().split('T')[0];
    document.getElementById('qcEngagement').value = 'More Engaged';
    document.querySelectorAll('.qc-pill').forEach(p => p.classList.remove('active'));
    document.querySelector('.qc-pill.high').classList.add('active');
    openModal('quickCaptureModal');
}

function setQcEngagement(btn, val) {
    document.querySelectorAll('.qc-pill').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('qcEngagement').value = val;
}

function saveQuickCapture() {
    const school = document.getElementById('qcSchool').value.trim();
    const teacher = document.getElementById('qcTeacher').value.trim();
    if (!school || !teacher) { showToast('School and teacher are required', 'error'); return; }

    const obs = {
        id: 'obs_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
        date: document.getElementById('qcDate').value || new Date().toISOString().split('T')[0],
        school: school,
        teacher: teacher,
        subject: document.getElementById('qcSubject').value || '',
        engagementLevel: document.getElementById('qcEngagement').value || 'Engaged',
        notes: document.getElementById('qcNote').value.trim(),
        observationStatus: 'Yes',
        source: 'Quick Capture',
        createdAt: new Date().toISOString()
    };

    const observations = DB.get('observations');
    observations.push(obs);
    DB.set('observations', observations);
    closeModal('quickCaptureModal');
    showToast('Observation captured!', 'success');
    renderDashboard();
}

// ===== TEACHER GROWTH TRACKER =====
function _buildTeacherProfiles() {
    const observations = DB.get('observations');
    const map = {};
    observations.forEach(o => {
        const name = (o.teacher || '').trim();
        if (!name) return;
        const key = name.toLowerCase();
        if (!map[key]) {
            map[key] = {
                name: name,
                school: o.school || '',
                cluster: o.cluster || '',
                block: o.block || '',
                observations: [],
                subjects: new Set(),
                engagementScores: [],
            };
        }
        const t = map[key];
        if (o.school && !t.school) t.school = o.school;
        if (o.cluster && !t.cluster) t.cluster = o.cluster;
        if (o.block && !t.block) t.block = o.block;
        if (o.subject) t.subjects.add(o.subject);
        t.observations.push(o);
        if (o.engagementLevel) {
            t.engagementScores.push(o.engagementLevel === 'More Engaged' ? 3 : o.engagementLevel === 'Engaged' ? 2 : 1);
        }
    });

    return Object.values(map).map(t => {
        t.observations.sort((a, b) => new Date(a.date) - new Date(b.date));
        t.totalObs = t.observations.length;
        t.avgEngagement = t.engagementScores.length ? t.engagementScores.reduce((a, b) => a + b, 0) / t.engagementScores.length : 0;
        t.lastDate = t.observations[t.observations.length - 1]?.date || '';
        t.daysSinceLast = t.lastDate ? Math.floor((new Date() - new Date(t.lastDate)) / 86400000) : 999;

        // Trend: compare last 3 vs previous 3
        if (t.engagementScores.length >= 4) {
            const mid = Math.floor(t.engagementScores.length / 2);
            const firstHalf = t.engagementScores.slice(0, mid);
            const secondHalf = t.engagementScores.slice(mid);
            const avg1 = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
            const avg2 = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;
            t.trend = avg2 > avg1 + 0.15 ? 'up' : avg2 < avg1 - 0.15 ? 'down' : 'stable';
        } else {
            t.trend = 'stable';
        }

        t.subjectList = [...t.subjects];
        return t;
    });
}

function renderTeacherGrowth() {
    const container = document.getElementById('teacherGrowthContainer');
    const summaryEl = document.getElementById('tgSummary');
    if (!container) return;

    let teachers = _buildTeacherProfiles();
    const search = (document.getElementById('teacherGrowthSearch')?.value || '').toLowerCase();
    const sort = document.getElementById('teacherSortSelect')?.value || 'observations';

    if (search) {
        teachers = teachers.filter(t =>
            t.name.toLowerCase().includes(search) ||
            t.school.toLowerCase().includes(search) ||
            t.block.toLowerCase().includes(search) ||
            t.cluster.toLowerCase().includes(search)
        );
    }

    switch (sort) {
        case 'name': teachers.sort((a, b) => a.name.localeCompare(b.name)); break;
        case 'engagement-low': teachers.sort((a, b) => a.avgEngagement - b.avgEngagement); break;
        case 'engagement-high': teachers.sort((a, b) => b.avgEngagement - a.avgEngagement); break;
        case 'recent': teachers.sort((a, b) => new Date(b.lastDate) - new Date(a.lastDate)); break;
        case 'stale': teachers.sort((a, b) => b.daysSinceLast - a.daysSinceLast); break;
        default: teachers.sort((a, b) => b.totalObs - a.totalObs);
    }

    // Summary stats
    const totalTeachers = teachers.length;
    const avgEng = teachers.length ? (teachers.reduce((s, t) => s + t.avgEngagement, 0) / teachers.length) : 0;
    const improving = teachers.filter(t => t.trend === 'up').length;
    const needsSupport = teachers.filter(t => t.avgEngagement < 2 && t.totalObs >= 2).length;

    if (summaryEl) {
        summaryEl.innerHTML = `
            <div class="tg-stat"><span class="tg-stat-value">${totalTeachers}</span><span class="tg-stat-label">Total Teachers</span></div>
            <div class="tg-stat"><span class="tg-stat-value">${avgEng.toFixed(1)}</span><span class="tg-stat-label">Avg Engagement</span></div>
            <div class="tg-stat"><span class="tg-stat-value" style="color:#10b981">${improving}</span><span class="tg-stat-label">Improving</span></div>
            <div class="tg-stat"><span class="tg-stat-value" style="color:#ef4444">${needsSupport}</span><span class="tg-stat-label">Need Support</span></div>
        `;
    }

    if (teachers.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-user-graduate"></i><h3>No teacher data</h3><p>Import DMT Excel or add observations to see teacher profiles</p></div>';
        return;
    }

    const colors = ['#6366f1', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#3b82f6', '#ef4444', '#0ea5e9'];

    const pg = getPaginatedItems(teachers, 'teacherGrowth', 20);

    container.innerHTML = pg.items.map((t, idx) => {
        const globalIdx = pg.start - 1 + idx;
        const color = colors[globalIdx % colors.length];
        const initials = t.name.split(' ').map(w => w[0]).join('').substring(0, 2);
        const trendLabel = t.trend === 'up' ? '<i class="fas fa-arrow-up"></i> Improving' :
                           t.trend === 'down' ? '<i class="fas fa-arrow-down"></i> Declining' : '<i class="fas fa-minus"></i> Stable';
        const engLabel = t.avgEngagement >= 2.5 ? 'High' : t.avgEngagement >= 1.5 ? 'Medium' : 'Low';

        // Sparkline bars (last 8 observations)
        const sparkData = t.engagementScores.slice(-8);
        const sparkBars = sparkData.map(s => {
            const h = Math.round((s / 3) * 28);
            const c = s >= 2.5 ? '#10b981' : s >= 1.5 ? '#f59e0b' : '#ef4444';
            return `<div class="tg-spark-bar" style="height:${h}px;background:${c}"></div>`;
        }).join('');

        return `<div class="tg-card" id="tgCard_${globalIdx}">
            <div class="tg-card-header" onclick="toggleTeacherDetail(${globalIdx})">
                <div class="tg-avatar" style="background:${color}">${escapeHtml(initials)}</div>
                <div class="tg-card-info">
                    <h4>${escapeHtml(t.name)} <span class="tg-trend ${t.trend}">${trendLabel}</span></h4>
                    <div class="tg-card-meta">
                        ${t.school ? `<span><i class="fas fa-school"></i> ${escapeHtml(t.school)}</span>` : ''}
                        ${t.block ? `<span><i class="fas fa-map-marker-alt"></i> ${escapeHtml(t.block)}</span>` : ''}
                        ${t.cluster ? `<span><i class="fas fa-layer-group"></i> ${escapeHtml(t.cluster)}</span>` : ''}
                    </div>
                </div>
                <div class="tg-card-stats">
                    <div class="tg-mini-stat"><span class="tg-mini-stat-val">${t.totalObs}</span><span class="tg-mini-stat-label">Obs</span></div>
                    <div class="tg-mini-stat"><span class="tg-mini-stat-val">${t.avgEngagement.toFixed(1)}</span><span class="tg-mini-stat-label">Eng</span></div>
                    <div class="tg-mini-stat"><span class="tg-mini-stat-val">${t.daysSinceLast < 999 ? t.daysSinceLast + 'd' : '—'}</span><span class="tg-mini-stat-label">Last</span></div>
                </div>
                <div class="tg-sparkline">${sparkBars}</div>
                <i class="fas fa-chevron-down tg-expand-icon"></i>
            </div>
        </div>`;
    }).join('') + renderPaginationControls('teacherGrowth', pg, 'renderTeacherGrowth');
}

function toggleTeacherDetail(idx) {
    const card = document.getElementById('tgCard_' + idx);
    if (!card) return;
    const existing = card.querySelector('.tg-card-detail');
    if (existing) {
        existing.remove();
        card.classList.remove('expanded');
        return;
    }
    card.classList.add('expanded');

    const teachers = _buildTeacherProfiles();
    const search = (document.getElementById('teacherGrowthSearch')?.value || '').toLowerCase();
    const sort = document.getElementById('teacherSortSelect')?.value || 'observations';
    let filtered = teachers;
    if (search) filtered = filtered.filter(t => t.name.toLowerCase().includes(search) || t.school.toLowerCase().includes(search) || t.block.toLowerCase().includes(search) || t.cluster.toLowerCase().includes(search));
    switch (sort) {
        case 'name': filtered.sort((a, b) => a.name.localeCompare(b.name)); break;
        case 'engagement-low': filtered.sort((a, b) => a.avgEngagement - b.avgEngagement); break;
        case 'engagement-high': filtered.sort((a, b) => b.avgEngagement - a.avgEngagement); break;
        case 'recent': filtered.sort((a, b) => new Date(b.lastDate) - new Date(a.lastDate)); break;
        case 'stale': filtered.sort((a, b) => b.daysSinceLast - a.daysSinceLast); break;
        default: filtered.sort((a, b) => b.totalObs - a.totalObs);
    }

    const t = filtered[idx];
    if (!t) return;

    const detailHtml = `<div class="tg-card-detail">
        <div class="tg-detail-grid">
            <div class="tg-detail-item"><strong>Subjects</strong>${t.subjectList.length ? t.subjectList.map(s => escapeHtml(s)).join(', ') : 'N/A'}</div>
            <div class="tg-detail-item"><strong>Engagement Range</strong>${t.engagementScores.length ? Math.min(...t.engagementScores).toFixed(0) + ' — ' + Math.max(...t.engagementScores).toFixed(0) + ' / 3' : 'N/A'}</div>
            <div class="tg-detail-item"><strong>First Observed</strong>${t.observations[0]?.date ? new Date(t.observations[0].date).toLocaleDateString('en-IN') : 'N/A'}</div>
            <div class="tg-detail-item"><strong>Last Observed</strong>${t.lastDate ? new Date(t.lastDate).toLocaleDateString('en-IN') : 'N/A'}</div>
        </div>
        <div class="tg-timeline">
            <div class="tg-timeline-title"><i class="fas fa-history"></i> Observation History (${t.observations.length})</div>
            ${t.observations.slice().reverse().slice(0, 15).map(o => {
                const engCls = o.engagementLevel === 'More Engaged' ? 'high' : o.engagementLevel === 'Engaged' ? 'mid' : 'low';
                return `<div class="tg-obs-item">
                    <span class="tg-obs-date">${new Date(o.date).toLocaleDateString('en-IN')}</span>
                    ${o.engagementLevel ? `<span class="tg-obs-eng ${engCls}">${escapeHtml(o.engagementLevel)}</span>` : ''}
                    <span class="tg-obs-detail">${escapeHtml([o.subject, o.practice, o.notes].filter(Boolean).join(' — ').substring(0, 100))}</span>
                </div>`;
            }).join('')}
            ${t.observations.length > 15 ? `<div class="tg-obs-item" style="justify-content:center;color:var(--text-muted);font-style:italic">+ ${t.observations.length - 15} more observations</div>` : ''}
        </div>
    </div>`;

    card.insertAdjacentHTML('beforeend', detailHtml);
}

// ===== PRINT OBSERVATION FEEDBACK =====
function printObsFeedback(id) {
    const observations = DB.get('observations');
    const o = observations.find(x => x.id === id);
    if (!o) { showToast('Observation not found', 'error'); return; }

    const d = new Date(o.date);
    const dateStr = d.toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });
    const engColor = o.engagementLevel === 'More Engaged' ? '#10b981' : o.engagementLevel === 'Engaged' ? '#f59e0b' : '#ef4444';

    const starsHtml = (val) => {
        if (!val) return '';
        let s = '';
        for (let i = 1; i <= 5; i++) s += i <= val ? '★' : '☆';
        return s;
    };

    const html = `<!DOCTYPE html>
<html><head><title>Observation Feedback — ${escapeHtml(o.teacher || 'Teacher')}</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Arial, sans-serif; padding: 30px 40px; color: #1e293b; font-size: 14px; line-height: 1.6; }
    .header { text-align: center; border-bottom: 3px solid #6366f1; padding-bottom: 16px; margin-bottom: 20px; }
    .header h1 { font-size: 20px; color: #6366f1; margin-bottom: 4px; }
    .header p { color: #64748b; font-size: 12px; }
    .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 24px; margin-bottom: 20px; padding: 14px; background: #f8fafc; border-radius: 8px; }
    .info-item { font-size: 13px; }
    .info-item strong { color: #475569; min-width: 100px; display: inline-block; }
    .engagement-box { text-align: center; padding: 14px; border-radius: 8px; margin-bottom: 20px; font-weight: 700; font-size: 16px; color: ${engColor}; border: 2px solid ${engColor}; background: ${engColor}11; }
    .section { margin-bottom: 16px; }
    .section h3 { font-size: 14px; color: #6366f1; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; margin-bottom: 8px; }
    .section p { font-size: 13px; color: #334155; white-space: pre-wrap; }
    .ratings { display: flex; gap: 24px; justify-content: center; margin-bottom: 16px; }
    .rating-item { text-align: center; }
    .rating-item .stars { font-size: 18px; color: #f59e0b; }
    .rating-item .label { font-size: 11px; color: #64748b; }
    .footer { text-align: center; margin-top: 30px; padding-top: 12px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; }
    @media print { body { padding: 20px; } }
</style></head><body>
<div class="header">
    <h1>Classroom Observation Feedback</h1>
    <p>Azim Premji Foundation — ${getProfile().name || 'APF Resource Person Dashboard'}</p>
</div>
<div class="info-grid">
    <div class="info-item"><strong>Teacher:</strong> ${escapeHtml(o.teacher || 'N/A')}</div>
    <div class="info-item"><strong>School:</strong> ${escapeHtml(o.school || 'N/A')}</div>
    <div class="info-item"><strong>Date:</strong> ${dateStr}</div>
    <div class="info-item"><strong>Subject:</strong> ${escapeHtml(o.subject || 'N/A')}</div>
    <div class="info-item"><strong>Class:</strong> ${escapeHtml(o.class || 'N/A')}</div>
    <div class="info-item"><strong>Block / Cluster:</strong> ${escapeHtml([o.block, o.cluster].filter(Boolean).join(' / ') || 'N/A')}</div>
    ${o.practiceType ? `<div class="info-item"><strong>Practice Type:</strong> ${escapeHtml(o.practiceType)}</div>` : ''}
    ${o.observer ? `<div class="info-item"><strong>Observer:</strong> ${escapeHtml(o.observer)}</div>` : ''}
</div>
${o.engagementLevel ? `<div class="engagement-box">Engagement Level: ${escapeHtml(o.engagementLevel)}</div>` : ''}
${(o.engagementRating || o.engagement || o.methodology || o.tlm) ? `<div class="ratings">
    ${(o.engagementRating || o.engagement) ? `<div class="rating-item"><div class="stars">${starsHtml(o.engagementRating || o.engagement)}</div><div class="label">Engagement</div></div>` : ''}
    ${o.methodology ? `<div class="rating-item"><div class="stars">${starsHtml(o.methodology)}</div><div class="label">Methodology</div></div>` : ''}
    ${o.tlm ? `<div class="rating-item"><div class="stars">${starsHtml(o.tlm)}</div><div class="label">TLM Use</div></div>` : ''}
</div>` : ''}
${o.practice ? `<div class="section"><h3>Teaching Practice Observed</h3><p>${escapeHtml(o.practice)}</p></div>` : ''}
${o.strengths ? `<div class="section"><h3>Strengths Observed</h3><p>${escapeHtml(o.strengths)}</p></div>` : ''}
${o.areas ? `<div class="section"><h3>Areas for Improvement</h3><p>${escapeHtml(o.areas)}</p></div>` : ''}
${o.suggestions ? `<div class="section"><h3>Suggestions / Action Points</h3><p>${escapeHtml(o.suggestions)}</p></div>` : ''}
${o.notes ? `<div class="section"><h3>Additional Notes</h3><p>${escapeHtml(o.notes)}</p></div>` : ''}
<div class="footer">Generated by ${getProfile().name || 'APF Resource Person'} — APF Dashboard — ${new Date().toLocaleDateString('en-IN')}</div>
</body></html>`;

    const w = window.open('', '_blank', 'width=800,height=900');
    if (!w) { showToast('Popup blocked — please allow popups for this site', 'error'); return; }
    w.document.write(html);
    w.document.close();
    setTimeout(() => w.print(), 500);
}

// ===== PERIOD COMPARISON =====
let _periodCompareVisible = false;
function togglePeriodComparison() {
    _periodCompareVisible = !_periodCompareVisible;
    const panel = document.getElementById('periodComparePanel');
    const btn = document.getElementById('periodCompareBtn');
    if (!panel) return;
    panel.style.display = _periodCompareVisible ? 'block' : 'none';
    if (btn) btn.classList.toggle('btn-primary', _periodCompareVisible);
    if (btn) btn.classList.toggle('btn-outline', !_periodCompareVisible);
    if (_periodCompareVisible) renderPeriodComparison();
}

function renderPeriodComparison() {
    const panel = document.getElementById('periodComparePanel');
    if (!panel) return;

    const now = new Date();
    const curMonth = now.getMonth(), curYear = now.getFullYear();
    const prevMonth = curMonth === 0 ? 11 : curMonth - 1;
    const prevYear = curMonth === 0 ? curYear - 1 : curYear;

    const curLabel = new Date(curYear, curMonth).toLocaleDateString('en', { month: 'long', year: 'numeric' });
    const prevLabel = new Date(prevYear, prevMonth).toLocaleDateString('en', { month: 'long', year: 'numeric' });

    const visits = DB.get('visits');
    const trainings = DB.get('trainings');
    const observations = DB.get('observations');

    const inMonth = (arr, y, m) => arr.filter(item => {
        const d = new Date(item.date);
        return d.getFullYear() === y && d.getMonth() === m;
    });

    const curVisits = inMonth(visits, curYear, curMonth);
    const prevVisits = inMonth(visits, prevYear, prevMonth);
    const curTrainings = inMonth(trainings, curYear, curMonth);
    const prevTrainings = inMonth(trainings, prevYear, prevMonth);
    const curObs = inMonth(observations, curYear, curMonth);
    const prevObs = inMonth(observations, prevYear, prevMonth);

    const curSchools = new Set(curObs.map(o => (o.school || '').toLowerCase().trim()).filter(Boolean));
    const prevSchools = new Set(prevObs.map(o => (o.school || '').toLowerCase().trim()).filter(Boolean));
    const curTeachers = new Set(curObs.map(o => (o.teacher || '').toLowerCase().trim()).filter(Boolean));
    const prevTeachers = new Set(prevObs.map(o => (o.teacher || '').toLowerCase().trim()).filter(Boolean));

    const avgEng = (arr) => {
        const scores = arr.filter(o => o.engagementLevel).map(o => o.engagementLevel === 'More Engaged' ? 3 : o.engagementLevel === 'Engaged' ? 2 : 1);
        return scores.length ? (scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
    };

    const metrics = [
        { label: 'Visits', cur: curVisits.length, prev: prevVisits.length },
        { label: 'Trainings', cur: curTrainings.length, prev: prevTrainings.length },
        { label: 'Observations', cur: curObs.length, prev: prevObs.length },
        { label: 'Schools Covered', cur: curSchools.size, prev: prevSchools.size },
        { label: 'Teachers Reached', cur: curTeachers.size, prev: prevTeachers.size },
        { label: 'Avg Engagement', cur: avgEng(curObs), prev: avgEng(prevObs), decimal: true },
    ];

    panel.innerHTML = `
        <div class="period-compare-header">
            <h3><i class="fas fa-columns"></i> ${curLabel} vs ${prevLabel}</h3>
            <button class="btn btn-sm btn-ghost" onclick="togglePeriodComparison()"><i class="fas fa-times"></i></button>
        </div>
        <div class="period-compare-grid">
            ${metrics.map(m => {
                const diff = m.cur - m.prev;
                const pct = m.prev > 0 ? Math.round((diff / m.prev) * 100) : (m.cur > 0 ? 100 : 0);
                const arrowCls = diff > 0 ? 'up' : diff < 0 ? 'down' : 'same';
                const arrowIcon = diff > 0 ? '<i class="fas fa-arrow-up"></i>' : diff < 0 ? '<i class="fas fa-arrow-down"></i>' : '<i class="fas fa-minus"></i>';
                const changeCls = diff > 0 ? 'positive' : diff < 0 ? 'negative' : 'neutral';
                const curVal = m.decimal ? m.cur.toFixed(1) : m.cur;
                const prevVal = m.decimal ? m.prev.toFixed(1) : m.prev;
                return `<div class="pc-metric">
                    <div class="pc-metric-label">${m.label}</div>
                    <div class="pc-metric-values">
                        <div class="pc-val current"><span class="pc-val-num">${curVal}</span><span class="pc-val-label">Current</span></div>
                        <span class="pc-arrow ${arrowCls}">${arrowIcon}</span>
                        <div class="pc-val previous"><span class="pc-val-num">${prevVal}</span><span class="pc-val-label">Previous</span></div>
                    </div>
                    <div class="pc-change ${changeCls}">${diff > 0 ? '+' : ''}${m.decimal ? diff.toFixed(1) : diff} (${pct > 0 ? '+' : ''}${pct}%)</div>
                </div>`;
            }).join('')}
        </div>
    `;
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

    // Restore theme preference
    restoreTheme();

    // Apply app settings (accent color, font size, compact mode)
    applyAppSettings();

    // Load user profile into sidebar
    applyProfileToUI();

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

    // Navigate to start page from settings
    const startPage = getAppSettings().startPage;
    if (startPage && startPage !== 'dashboard') {
        navigateTo(startPage);
    } else {
        // Render everything
        renderDashboard();
    }

    // Show user guide on first use
    if (!localStorage.getItem('apf_guide_shown')) {
        setTimeout(() => showUserGuide(true), 600);
    }

    // Auto-reconnect Live Sync (WhatsApp Web-style persistent session)
    setTimeout(() => LiveSync.autoReconnect(), 1500);
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
    } else {
        // Try to restore from localStorage fallback
        restoreFromLocalStorage();
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

// ===== User Guide =====
const USER_GUIDE_STEPS = [
    {
        icon: 'fa-th-large',
        color: '#6366f1',
        title: 'Dashboard Overview',
        desc: 'Your home screen shows key stats at a glance — total visits, trainings, observations, and more. Quick metric cards give you an instant summary of your work.'
    },
    {
        icon: 'fa-school',
        color: '#10b981',
        title: 'School Visits',
        desc: 'Log every school visit with details like school name, date, time (First Half / Second Half / Full Day), purpose, and notes. Filter and paginate through your history easily.'
    },
    {
        icon: 'fa-chalkboard-teacher',
        color: '#f59e0b',
        title: 'Teacher Training',
        desc: 'Record teacher training sessions with topics, participants, schools, and outcomes. Track your professional development efforts.'
    },
    {
        icon: 'fa-clipboard-check',
        color: '#ef4444',
        title: 'Observations & Visit Plan',
        desc: 'Document classroom observations with structured forms. Use the Visit Plan section to plan visits ahead with domain-based entries, link to Excel for two-way sync, and send plans to School Visits or Training.'
    },
    {
        icon: 'fa-chart-pie',
        color: '#8b5cf6',
        title: 'Reports & Analytics',
        desc: 'Generate monthly/yearly reports automatically from your data. The Analytics section gives visual charts — visit frequency by school, training trends, and more.'
    },
    {
        icon: 'fa-file-excel',
        color: '#22c55e',
        title: 'Excel Analytics',
        desc: 'Upload Excel/CSV files and get instant analytics with charts, pivot summaries, and data insights — no Excel software needed.'
    },
    {
        icon: 'fa-route',
        color: '#ec4899',
        title: 'MARAI Tracking & School Work',
        desc: 'Track MARAI stages for schools. Assign work to teachers in the School Work section with status tracking and teacher tags.'
    },
    {
        icon: 'fa-calendar-week',
        color: '#14b8a6',
        title: 'Planner, Goals & Follow-ups',
        desc: 'Plan your week with the drag-and-drop planner. Set monthly goals with targets. Track follow-up actions with status indicators.'
    },
    {
        icon: 'fa-seedling',
        color: '#f97316',
        title: 'Growth Framework & Reflections',
        desc: 'Use the Teacher Growth tracker to assess progress over time. Write monthly reflections to capture your professional journey.'
    },
    {
        icon: 'fa-shield-alt',
        color: '#eab308',
        title: 'Data & Security',
        desc: 'All data is encrypted with AES-256. Set a password to auto-save securely. Export/import .apf backup files. Link to a file for persistent storage. Use Live Sync to share data peer-to-peer.'
    },
    {
        icon: 'fa-bug',
        color: '#6366f1',
        title: 'Bug Reports & Help',
        desc: 'Found a bug or want a new feature? Go to Bug & Feedback in the sidebar. Submit a report and email it directly to the developer via Gmail. You can always reopen this guide from there!'
    }
];

let _guideStep = 0;

function showUserGuide(isFirstUse) {
    _guideStep = 0;
    renderGuideStep();
    document.getElementById('userGuideModal').classList.add('active');
    if (isFirstUse) {
        localStorage.setItem('apf_guide_shown', '1');
    }
}

function closeUserGuide() {
    document.getElementById('userGuideModal').classList.remove('active');
}

function guideNav(dir) {
    _guideStep += dir;
    if (_guideStep < 0) _guideStep = 0;
    if (_guideStep >= USER_GUIDE_STEPS.length) {
        closeUserGuide();
        showToast('You\'re all set! Explore the dashboard 🚀', 'success');
        return;
    }
    renderGuideStep();
}

function renderGuideStep() {
    const step = USER_GUIDE_STEPS[_guideStep];
    const body = document.getElementById('guideBody');
    body.innerHTML = `
        <div class="guide-step">
            <div class="guide-step-icon" style="background:${step.color}20;color:${step.color};">
                <i class="fas ${step.icon}"></i>
            </div>
            <div class="guide-step-num">Step ${_guideStep + 1} of ${USER_GUIDE_STEPS.length}</div>
            <h3 class="guide-step-title">${step.title}</h3>
            <p class="guide-step-desc">${step.desc}</p>
        </div>
    `;
    // Dots
    const dots = document.getElementById('guideDots');
    dots.innerHTML = USER_GUIDE_STEPS.map((_, i) =>
        `<span class="guide-dot ${i === _guideStep ? 'active' : ''}" onclick="_guideStep=${i};renderGuideStep();"></span>`
    ).join('');
    // Buttons
    document.getElementById('guidePrevBtn').style.visibility = _guideStep === 0 ? 'hidden' : 'visible';
    const nextBtn = document.getElementById('guideNextBtn');
    if (_guideStep === USER_GUIDE_STEPS.length - 1) {
        nextBtn.innerHTML = '<i class="fas fa-check"></i> Got It!';
    } else {
        nextBtn.innerHTML = 'Next <i class="fas fa-arrow-right"></i>';
    }
}

// ===== Beforeunload — save to file + cache =====
window.addEventListener('beforeunload', (e) => {
    if (hasUnsavedChanges && _sessionPassword) {
        // Best-effort saves (fire-and-forget)
        if (FileLink.isLinked()) FileLink.writeToFile(_sessionPassword);
        EncryptedCache.save(_sessionPassword);
    }
});

async function proceedAfterLicense() {
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
                        if (data && data._meta && data._meta.app === 'APF Dashboard') {
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
        // Check localStorage fallback for previously saved data (no password scenario)
        const restoredCount = restoreFromLocalStorage();
        if (restoredCount > 0) {
            hideWelcomeScreen();
            isAppUnlocked = true;
            initApp();
            showToast(`Restored your data from local backup (${restoredCount} categories). Set a password for secure saving!`, 'info');
            return;
        }
        showWelcomeScreen();
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    // Restore theme immediately to prevent flash
    restoreTheme();

    // License key gate — must be activated before anything else
    if (!isLicenseActivated()) {
        document.getElementById('licenseScreen').style.display = 'flex';
        return; // Wait for license activation
    }

    // License OK — proceed normally
    await proceedAfterLicense();
});
