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
        case 'teachers': renderTeacherGrowth(); break;
        case 'reflections': initReflectionMonthFilter(); renderReflections(); break;
        case 'contacts': renderContacts(); break;
        case 'livesync': break;
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

// ===== Live Sync — Peer-to-Peer Real-Time Data Sync =====
const LiveSync = {
    peer: null,
    connections: [],       // Active DataConnection objects
    roomCode: null,
    isHost: false,
    deviceId: null,
    _syncLog: [],
    _autoSyncEnabled: true,

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

    // Apply received data to local DB
    applyData(data) {
        if (!data || !data._meta || data._meta.app !== 'APF Dashboard') {
            this.log('Rejected invalid sync data', 'error');
            return false;
        }
        // Use _originalDBSet to avoid triggering auto-save loop during sync
        ENCRYPTED_DATA_KEYS.forEach(k => {
            if (data[k] !== undefined && Array.isArray(data[k])) {
                _originalDBSet(k, data[k]);
            }
        });
        // Trigger save
        markUnsavedChanges();
        // Re-render current section
        const active = document.querySelector('.nav-item.active');
        if (active) navigateTo(active.dataset.section);
        return true;
    },

    // Log sync activity
    log(msg, type = 'info') {
        const time = new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const icons = { info: 'ℹ️', success: '✅', error: '❌', send: '📤', receive: '📥', connect: '🔗', disconnect: '🔌' };
        this._syncLog.unshift({ time, msg, type, icon: icons[type] || 'ℹ️' });
        if (this._syncLog.length > 50) this._syncLog.pop();
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
            online: { icon: 'fa-check-circle', label: 'Connected & Syncing', cls: 'online' },
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
    },

    // Update connected devices list
    updateDevices() {
        const list = document.getElementById('syncDevicesList');
        const count = document.getElementById('syncPeerCount');
        if (!list) return;

        const conns = this.connections.filter(c => c.open);
        if (count) count.innerHTML = `<i class="fas fa-users"></i> ${conns.length} device${conns.length !== 1 ? 's' : ''}`;

        if (conns.length === 0) {
            list.innerHTML = '<div class="sync-no-devices">No other devices connected yet</div>';
            return;
        }
        list.innerHTML = conns.map((c, i) => {
            const name = c._deviceName || '🖥️ Device';
            const id = c.peer.split('-').pop().substring(0, 6);
            return `<div class="sync-device-item">
                <div class="sync-device-icon"><i class="fas fa-${name.includes('📱') ? 'mobile-alt' : 'laptop'}"></i></div>
                <div class="sync-device-info">
                    <span class="sync-device-name">${name}</span>
                    <span class="sync-device-id">${id}</span>
                </div>
                <span class="sync-device-status online"><i class="fas fa-circle"></i> Connected</span>
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
                // Auto-send data to newly connected device if host
                if (this.isHost && this._autoSyncEnabled) {
                    setTimeout(() => {
                        const syncData = this.collectData();
                        conn.send({ type: 'sync-data', data: syncData });
                        this.log(`Auto-synced data to ${conn._deviceName}`, 'send');
                        this.updateLastSync();
                    }, 500);
                }
                break;

            case 'sync-data':
                this.log(`Receiving data from ${conn._deviceName || 'peer'}...`, 'receive');
                const applied = this.applyData(data.data);
                if (applied) {
                    this.log('Data synced successfully! All sections updated.', 'success');
                    this.updateLastSync();
                    showToast('Data synced from connected device!', 'success');
                } else {
                    this.log('Failed to apply received data', 'error');
                }
                break;

            case 'sync-request':
                this.log(`${conn._deviceName || 'Peer'} requested data`, 'info');
                const outData = this.collectData();
                conn.send({ type: 'sync-data', data: outData });
                this.log('Data sent in response to request', 'send');
                this.updateLastSync();
                break;

            case 'data-changed':
                // Real-time change notification
                if (data.key && data.value !== undefined) {
                    _originalDBSet(data.key, data.value);
                    const active = document.querySelector('.nav-item.active');
                    if (active) navigateTo(active.dataset.section);
                    this.log(`Real-time update: ${data.key}`, 'receive');
                    this.updateLastSync();
                }
                break;

            case 'ping':
                conn.send({ type: 'pong' });
                break;

            case 'pong':
                break;
        }
    },

    // Setup connection event handlers
    setupConnection(conn) {
        conn.on('open', () => {
            this.connections.push(conn);
            // Send hello with device info
            conn.send({ type: 'hello', device: this.getDeviceName() });
            this.updateDevices();
            this.updateStatus('online', `Connected to ${this.connections.filter(c => c.open).length} device(s)`);
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
                this.updateStatus('online', `Connected to ${this.connections.filter(c => c.open).length} device(s)`);
            }
        });

        conn.on('error', (err) => {
            console.error('Connection error:', err);
            this.log('Connection error: ' + err.message, 'error');
        });
    },

    updateLastSync() {
        const el = document.getElementById('syncLastSync');
        if (el) {
            const time = new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
            el.innerHTML = `<i class="fas fa-clock"></i> Last sync: ${time}`;
        }
    },

    // Destroy peer and all connections
    destroy() {
        this.connections.forEach(c => { try { c.close(); } catch(e) {} });
        this.connections = [];
        if (this.peer) { try { this.peer.destroy(); } catch(e) {} }
        this.peer = null;
        this.roomCode = null;
        this.isHost = false;
        this.updateStatus('offline', 'Create or join a sync room to start');
        this.updatePanels(false);
        this.updateDevices();
    }
};

// ===== Live Sync Public Functions =====

function createSyncRoom() {
    if (LiveSync.peer) {
        showToast('Already in a sync session. Disconnect first.', 'error');
        return;
    }

    const code = LiveSync.generateRoomCode();
    LiveSync.roomCode = code;
    LiveSync.isHost = true;
    LiveSync.updateStatus('connecting', 'Creating room...');
    LiveSync.log('Creating sync room: ' + code, 'info');

    const peerId = LiveSync.getPeerId(code, true);
    const peer = new Peer(peerId, { debug: 0 });
    LiveSync.peer = peer;

    peer.on('open', (id) => {
        LiveSync.updateStatus('online', 'Room active — waiting for devices to join');
        LiveSync.updatePanels(true);
        LiveSync.log('Room created! Share code: ' + code, 'success');
        showToast('Sync room created! Code: ' + code, 'success');
    });

    peer.on('connection', (conn) => {
        LiveSync.setupConnection(conn);
    });

    peer.on('error', (err) => {
        console.error('Peer error:', err);
        if (err.type === 'unavailable-id') {
            LiveSync.log('Room code already in use. Try again.', 'error');
            showToast('Room code in use. Try again.', 'error');
            LiveSync.destroy();
        } else {
            LiveSync.updateStatus('error', err.message);
            LiveSync.log('Error: ' + err.message, 'error');
        }
    });

    peer.on('disconnected', () => {
        LiveSync.updateStatus('error', 'Disconnected from signaling server — trying to reconnect...');
        LiveSync.log('Connection lost, attempting reconnect...', 'error');
        try { peer.reconnect(); } catch(e) {}
    });
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

    LiveSync.roomCode = code;
    LiveSync.isHost = false;
    LiveSync.updateStatus('connecting', 'Joining room ' + code + '...');
    LiveSync.log('Joining sync room: ' + code, 'info');

    const peerId = LiveSync.getPeerId(code, false);
    const peer = new Peer(peerId, { debug: 0 });
    LiveSync.peer = peer;

    peer.on('open', () => {
        // Connect to host
        const hostId = LiveSync.getPeerId(code, true);
        const conn = peer.connect(hostId, { reliable: true });

        conn.on('open', () => {
            LiveSync.connections.push(conn);
            conn.send({ type: 'hello', device: LiveSync.getDeviceName() });
            LiveSync.updateStatus('online', 'Connected to host device');
            LiveSync.updatePanels(true);
            LiveSync.updateDevices();
            LiveSync.log('Connected to host!', 'success');
            showToast('Connected! Data will sync automatically.', 'success');
        });

        conn.on('data', (data) => {
            LiveSync.handleMessage(data, conn);
        });

        conn.on('close', () => {
            LiveSync.log('Host disconnected', 'disconnect');
            LiveSync.connections = LiveSync.connections.filter(c => c !== conn);
            LiveSync.updateDevices();
            LiveSync.updateStatus('error', 'Host disconnected');
        });

        conn.on('error', (err) => {
            LiveSync.log('Connection error: ' + err.message, 'error');
            LiveSync.updateStatus('error', err.message);
        });
    });

    peer.on('error', (err) => {
        console.error('Peer error:', err);
        if (err.type === 'peer-unavailable') {
            LiveSync.log('Room not found. Check the code and try again.', 'error');
            showToast('Room not found. Check the code.', 'error');
            LiveSync.destroy();
        } else {
            LiveSync.updateStatus('error', err.message);
            LiveSync.log('Error: ' + err.message, 'error');
        }
    });
}

function sendSyncData() {
    const conns = LiveSync.connections.filter(c => c.open);
    if (conns.length === 0) {
        showToast('No devices connected', 'error');
        return;
    }
    const data = LiveSync.collectData();
    conns.forEach(c => c.send({ type: 'sync-data', data }));
    LiveSync.log(`Data pushed to ${conns.length} device(s)`, 'send');
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
    LiveSync.log('Requested data from connected device', 'info');
    showToast('Requesting data...', 'info');
}

function disconnectSync() {
    LiveSync.log('Disconnected from sync room', 'disconnect');
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

// Real-time change broadcast — hook into DB.set
const _syncOriginalDBSet = DB.set;
DB.set = function(key, data) {
    _syncOriginalDBSet(key, data);
    // Broadcast change to connected peers
    if (LiveSync.connections.length > 0 && ENCRYPTED_DATA_KEYS.includes(key)) {
        const conns = LiveSync.connections.filter(c => c.open);
        conns.forEach(c => {
            try { c.send({ type: 'data-changed', key, value: DB.get(key) }); } catch(e) {}
        });
    }
};

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

    container.innerHTML = filtered.map(v => {
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
                <p>${escapeHtml(v.purpose || '')}${v.duration ? ` • ${v.duration}` : ''}${ratingStars ? ` • ${ratingStars}` : ''}</p>
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
    }).join('');
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
    } catch (err) {
        console.error('DMT Import error:', err);
        showToast('Failed to import: ' + err.message, 'error');
    }
    event.target.value = '';
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
                ${idea.status === 'archived'
                    ? `<button onclick="unarchiveIdea('${idea.id}')" title="Unarchive" class="unarchive-btn"><i class="fas fa-box-open"></i></button>`
                    : `<button onclick="archiveIdea('${idea.id}')" title="Archive" class="archive-btn"><i class="fas fa-archive"></i></button>`
                }
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
            ? (school.observations.reduce((s, o) => s + (((o.engagementRating || o.engagement) || 0) + (o.methodology || 0) + (o.tlm || 0)) / 3, 0) / school.observations.length).toFixed(1)
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
        ? (school.observations.reduce((s, o) => s + (((o.engagementRating || o.engagement) || 0) + (o.methodology || 0) + (o.tlm || 0)) / 3, 0) / school.observations.length).toFixed(1)
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
        const notes = [t.stage ? `Stage: ${t.stage}` : '', t.cluster ? `Cluster: ${t.cluster}` : '', t.nid ? `NID: ${t.nid}` : ''].filter(Boolean).join(' | ');
        contacts.push({
            id: DB.generateId(),
            name: t.name || 'Unknown Teacher',
            role: 'Teacher',
            school: t.school,
            phone: t.phone,
            email: '',
            block: t.block,
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

// ===== TRUECALLER VERIFICATION =====
const TC_API_KEY = 'lVwbc02fc94a52fac4cfa837823b049379862';

function openTruecallerSearch(prefillPhone) {
    openModal('truecallerModal');
    const phoneInput = document.getElementById('tcSearchPhone');
    const resultArea = document.getElementById('tcSearchResult');
    resultArea.innerHTML = '';
    if (prefillPhone) {
        phoneInput.value = prefillPhone.replace(/^\+91|^91/, '').replace(/[^\d]/g, '');
    } else {
        phoneInput.value = '';
    }
    phoneInput.focus();
}

async function truecallerSearch(phone, countryCode) {
    const phoneNum = phone || document.getElementById('tcSearchPhone').value.replace(/[^\d]/g, '');
    const cc = countryCode || document.getElementById('tcCountryCode').value;
    const resultArea = document.getElementById('tcSearchResult');
    const searchBtn = document.getElementById('tcSearchBtn');

    if (!phoneNum || phoneNum.length < 7) {
        showToast('Enter a valid phone number', 'error');
        return null;
    }

    resultArea.innerHTML = `<div class="tc-loading"><i class="fas fa-spinner fa-spin"></i> Searching Truecaller...</div>`;
    if (searchBtn) {
        searchBtn.disabled = true;
        searchBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Searching...';
    }

    try {
        // Try multiple Truecaller endpoints and CORS proxy combinations
        const endpoints = [
            {
                url: `https://search5-noneu.truecaller.com/v2/search?q=${encodeURIComponent(phoneNum)}&countryCode=${cc}&type=4`,
                headers: { 'accountId': TC_API_KEY }
            },
            {
                url: `https://asia-south1-truecaller-web.cloudfunctions.net/api/noneu/search/v1?q=${encodeURIComponent(phoneNum)}&countryCode=${cc}&type=4`,
                headers: { 'Authorization': `Bearer ${TC_API_KEY}` }
            }
        ];

        const proxyFns = [
            (url) => `https://corsproxy.io/?${encodeURIComponent(url)}`,
            (url) => `https://api.cors.lol/?url=${encodeURIComponent(url)}`,
            (url) => `https://proxy.cors.sh/${url}`,
            (url) => url  // direct (last resort)
        ];

        let resp = null;
        let lastErr = null;
        let data = null;

        outer:
        for (const endpoint of endpoints) {
            for (const mkProxy of proxyFns) {
                try {
                    const proxyUrl = mkProxy(endpoint.url);
                    const hdrs = { ...endpoint.headers };
                    // cors.sh needs its own key header
                    if (proxyUrl.includes('proxy.cors.sh')) {
                        hdrs['x-cors-api-key'] = 'temp_' + Date.now();
                    }
                    resp = await fetch(proxyUrl, { headers: hdrs });
                    if (resp.ok) {
                        const text = await resp.text();
                        try { data = JSON.parse(text); } catch(_) { data = null; }
                        if (data && (data.data || data.status)) { break outer; }
                        data = null; resp = null;
                    } else {
                        resp = null;
                    }
                } catch (e) {
                    lastErr = e;
                    resp = null;
                }
            }
        }

        if (!data) {
            throw lastErr || new Error('All lookup attempts failed');
        }

        const info = data?.data?.[0] || null;

        if (!info) {
            resultArea.innerHTML = `
                <div class="tc-result-card tc-not-found">
                    <div class="tc-result-icon" style="background:rgba(239,68,68,0.15);color:#ef4444"><i class="fas fa-user-times"></i></div>
                    <div class="tc-result-info">
                        <div class="tc-result-label">No Results Found</div>
                        <div class="tc-result-sub">This number is not registered on Truecaller</div>
                    </div>
                </div>`;
            return null;
        }

        const name = info.name || 'Unknown';
        const firstName = info.firstName || '';
        const lastName = info.lastName || '';
        const fullName = (firstName + ' ' + lastName).trim() || name;
        const carrier = info.phones?.[0]?.carrier || '';
        const numType = info.phones?.[0]?.numberType || '';
        const city = info.addresses?.[0]?.city || '';
        const timeZone = info.addresses?.[0]?.timeZone || '';
        const spamScore = info.spamScore || 0;
        const spamType = info.spamType || '';

        let spamBadge = '';
        if (spamScore > 0 || spamType) {
            spamBadge = `<span class="tc-spam-badge"><i class="fas fa-exclamation-triangle"></i> Spam Risk (${spamScore})</span>`;
        } else {
            spamBadge = `<span class="tc-safe-badge"><i class="fas fa-shield-alt"></i> Safe</span>`;
        }

        resultArea.innerHTML = `
            <div class="tc-result-card">
                <div class="tc-result-header">
                    <div class="tc-result-icon" style="background:rgba(33,150,243,0.15);color:#2196F3"><i class="fas fa-user-check"></i></div>
                    <div class="tc-result-info">
                        <div class="tc-result-name">${escapeHtml(fullName)}</div>
                        ${spamBadge}
                    </div>
                </div>
                <div class="tc-result-details">
                    <div class="tc-detail"><i class="fas fa-phone"></i> <strong>${escapeHtml(phoneNum)}</strong></div>
                    ${carrier ? `<div class="tc-detail"><i class="fas fa-broadcast-tower"></i> ${escapeHtml(carrier)}</div>` : ''}
                    ${numType ? `<div class="tc-detail"><i class="fas fa-sim-card"></i> ${escapeHtml(numType)}</div>` : ''}
                    ${city ? `<div class="tc-detail"><i class="fas fa-map-marker-alt"></i> ${escapeHtml(city)}</div>` : ''}
                    ${timeZone ? `<div class="tc-detail"><i class="fas fa-clock"></i> ${escapeHtml(timeZone)}</div>` : ''}
                </div>
                <div class="tc-result-actions">
                    <button class="btn btn-primary btn-sm" onclick="addTruecallerToContacts('${escapeHtml(fullName).replace(/'/g, "\\'")}', '${escapeHtml(phoneNum)}', '${escapeHtml(carrier)}', '${escapeHtml(city)}')" style="background:#2196F3">
                        <i class="fas fa-user-plus"></i> Save to Contacts
                    </button>
                    <button class="btn btn-outline btn-sm" onclick="window.open('tel:${phoneNum.replace(/[^\d+]/g, '')}')">
                        <i class="fas fa-phone"></i> Call
                    </button>
                </div>
            </div>`;

        return { name: fullName, phone: phoneNum, carrier, city, spamScore };

    } catch (err) {
        console.error('Truecaller API error:', err);
        resultArea.innerHTML = `
            <div class="tc-result-card tc-error">
                <div class="tc-result-icon" style="background:rgba(239,68,68,0.15);color:#ef4444"><i class="fas fa-exclamation-circle"></i></div>
                <div class="tc-result-info">
                    <div class="tc-result-label">Lookup Failed</div>
                    <div class="tc-result-sub">${escapeHtml(err.message)}<br><small>Tried multiple endpoints &amp; proxies. Check internet connection, API key, or try again. Works best on mobile browsers.</small></div>
                </div>
                <div style="margin-top:12px;text-align:center;">
                    <a href="https://www.truecaller.com/search/in/${phoneNum}" target="_blank" class="btn btn-outline btn-sm" style="display:inline-flex;align-items:center;gap:6px;">
                        <i class="fas fa-external-link-alt"></i> Try on Truecaller Website
                    </a>
                </div>
            </div>`;
        return null;
    } finally {
        if (searchBtn) {
            searchBtn.disabled = false;
            searchBtn.innerHTML = '<i class="fas fa-search"></i> Search on Truecaller';
        }
    }
}

function addTruecallerToContacts(name, phone, carrier, city) {
    const contacts = DB.get('contacts');
    // Check if already exists
    const exists = contacts.some(c => (c.phone || '').replace(/[^\d]/g, '') === phone.replace(/[^\d]/g, ''));
    if (exists) {
        showToast('This number is already in your contacts', 'info');
        return;
    }
    contacts.push({
        id: DB.generateId(),
        name: name,
        role: 'Other',
        school: '',
        phone: phone,
        email: '',
        block: city || '',
        notes: carrier ? `Carrier: ${carrier} | Added via Truecaller` : 'Added via Truecaller',
        createdAt: new Date().toISOString(),
        source: 'Truecaller'
    });
    DB.set('contacts', contacts);
    renderContacts();
    showToast(`${name} added to contacts!`, 'success');
}

async function verifyContactTruecaller(contactId) {
    const contacts = DB.get('contacts');
    const contact = contacts.find(c => c.id === contactId);
    if (!contact || !contact.phone) {
        showToast('No phone number to verify', 'error');
        return;
    }

    const phone = contact.phone.replace(/[^\d]/g, '');
    // Show in modal with prefilled phone
    openTruecallerSearch(phone);
    // Auto-search
    const result = await truecallerSearch(phone, 'IN');

    if (result && result.name) {
        // Update the contact's truecaller verified name
        const idx = contacts.findIndex(c => c.id === contactId);
        if (idx !== -1) {
            contacts[idx].tcVerified = true;
            contacts[idx].tcName = result.name;
            contacts[idx].tcSpamScore = result.spamScore || 0;
            DB.set('contacts', contacts);
            renderContacts();
        }
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
                    ${c.phone ? `<div class="contact-detail-row"><i class="fas fa-phone"></i> <a href="tel:${escapeHtml(c.phone)}">${escapeHtml(c.phone)}</a>${c.tcVerified ? `<span class="tc-verified-inline" title="Truecaller: ${escapeHtml(c.tcName || '')}"><i class="fas fa-check-circle"></i> ${escapeHtml(c.tcName || 'Verified')}</span>` : ''}</div>` : ''}
                    ${c.email ? `<div class="contact-detail-row"><i class="fas fa-envelope"></i> <a href="mailto:${escapeHtml(c.email)}">${escapeHtml(c.email)}</a></div>` : ''}
                    ${c.notes ? `<div class="contact-detail-row"><i class="fas fa-sticky-note"></i> ${escapeHtml(c.notes)}</div>` : ''}
                </div>
                <div class="contact-card-actions">
                    ${c.phone ? `<button onclick="window.open('tel:${c.phone.replace(/[^\d+\-\s()]/g, '')}')"  ><i class="fas fa-phone"></i> Call</button>` : ''}
                    ${c.phone ? `<button class="tc-verify-btn" onclick="verifyContactTruecaller('${c.id}')" title="Verify on Truecaller"><i class="fas fa-phone-square-alt"></i> ${c.tcVerified ? 'Re-verify' : 'Verify'}</button>` : ''}
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
    const followupStatus = DB.get('followupStatus') || {};
    const pendingFollowups = visits.filter(v => v.followUp && v.followUp.trim() && !followupStatus[v.id]);
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

    container.innerHTML = teachers.slice(0, 100).map((t, idx) => {
        const color = colors[idx % colors.length];
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

        return `<div class="tg-card" id="tgCard_${idx}">
            <div class="tg-card-header" onclick="toggleTeacherDetail(${idx})">
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
    }).join('');
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
    <p>Azim Premji Foundation — APF Resource Person Dashboard</p>
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
<div class="footer">Generated from APF Resource Person Dashboard — ${new Date().toLocaleDateString('en-IN')}</div>
</body></html>`;

    const w = window.open('', '_blank', 'width=800,height=900');
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
    // Restore theme immediately to prevent flash
    restoreTheme();

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
