document.addEventListener('DOMContentLoaded', () => {
    // CSRF Token Storage & State
    let csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
    let currentTempToken = ''; // Used for 2FA login step 2

    // Route / Page Detection
    const currentPath = window.location.pathname.split('/').pop();
    const currentPage = currentPath === '' ? 'index.html' : currentPath;

    // UI Elements - Forms & Nav
    const loginStep1Form = document.getElementById('login-step1-form');
    const loginStep2Form = document.getElementById('login-step2-form');
    const loginRecoveryForm = document.getElementById('login-recovery-form');
    const registerForm = document.getElementById('register-form');
    const logoutBtn = document.getElementById('logout-btn');
    const uploadFileForm = document.getElementById('upload-file-form');
    const createNoteForm = document.getElementById('create-note-form');
    const shareForm = document.getElementById('share-form');
    const enable2faForm = document.getElementById('enable-2fa-form');

    // UI Elements - Displays & Lists
    const filesList = document.getElementById('files-list');
    const notesList = document.getElementById('notes-list');
    const sessionsList = document.getElementById('sessions-list');
    const trashList = document.getElementById('trash-list');

    // ==========================================
    // 1. Web Crypto API Helpers (Zero-Knowledge AES-256-GCM)
    // ==========================================
    async function deriveKeyFromPassphrase(passphrase, saltHex = 'secure-vault-salt') {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']
        );
        return window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: enc.encode(saltHex),
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function clientEncryptText(text, passphrase) {
        const enc = new TextEncoder();
        const key = await deriveKeyFromPassphrase(passphrase);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            enc.encode(text)
        );

        const encryptedBytes = new Uint8Array(encryptedBuffer);
        const ciphertextBytes = encryptedBytes.slice(0, encryptedBytes.length - 16);
        const tagBytes = encryptedBytes.slice(encryptedBytes.length - 16);

        return {
            ciphertext: bytesToBase64(ciphertextBytes),
            iv: bytesToBase64(iv),
            tag: bytesToBase64(tagBytes)
        };
    }

    async function clientDecryptText(ciphertextBase64, ivBase64, tagBase64, passphrase) {
        const key = await deriveKeyFromPassphrase(passphrase);
        const ciphertextBytes = base64ToBytes(ciphertextBase64);
        const tagBytes = base64ToBytes(tagBase64);
        const ivBytes = base64ToBytes(ivBase64);

        const combinedBytes = new Uint8Array(ciphertextBytes.length + tagBytes.length);
        combinedBytes.set(ciphertextBytes, 0);
        combinedBytes.set(tagBytes, ciphertextBytes.length);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBytes },
            key,
            combinedBytes
        );

        return new TextDecoder().decode(decryptedBuffer);
    }

    function bytesToBase64(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    function base64ToBytes(base64) {
        const binaryString = window.atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
    }

    // ==========================================
    // 2. Unified API Request Handler
    // ==========================================
    async function apiRequest(action, method = 'GET', data = null) {
        // Resolve API path for both docroot=public and docroot=project-root
        let apiBase = '../api/api.php';
        // If page is at root (no /public/), absolute /api works better
        if (window.location.pathname.startsWith('/public/')) {
            apiBase = '../api/api.php';
        } else if (window.location.pathname === '/' || window.location.pathname === '/index.html') {
            apiBase = 'api/api.php';
        } else if (!window.location.pathname.includes('/public/')) {
            // Dashboard might be at /public/dashboard.html -> ../api works, but /api absolute is safest
            apiBase = window.location.origin + '/api/api.php';
            // fallback to relative if absolute fails will be handled by fetch error
        }
        let url = `${apiBase}?action=${encodeURIComponent(action)}`;
        // Prefer absolute /api/api.php when available (project-root docroot)
        if (apiBase.startsWith('../')) {
            // also try absolute as fallback by storing alternative
            // we'll keep relative; browser will resolve correctly from /public/
        }
        const options = {
            method: method,
            headers: {}
        };

        if (csrfToken) {
            options.headers['X-CSRF-TOKEN'] = csrfToken;
        }

        if (method === 'POST') {
            if (data instanceof FormData) {
                if (csrfToken && !data.has('csrf_token')) data.append('csrf_token', csrfToken);
                options.body = data;
            } else {
                const params = new URLSearchParams(data || {});
                if (csrfToken && !params.has('csrf_token')) params.append('csrf_token', csrfToken);
                options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
                options.body = params;
            }
        } else if (method === 'GET' && data) {
            const queryParams = new URLSearchParams(data).toString();
            url += `&${queryParams}`;
        }

        try {
            const response = await fetch(url, options);
            const result = await response.json();

            if (result && result.csrf_token) {
                csrfToken = result.csrf_token;
            }

            if (response.status === 401 && action !== 'login_step1' && action !== 'login_step2' && action !== 'recover_account') {
                redirectToLogin();
                return null;
            }

            return result;
        } catch (error) {
            console.error('API Request Error:', error);
            return { success: false, message: 'Server communication error.' };
        }
    }

    function redirectToLogin() {
        if (currentPage !== 'login.html' && currentPage !== 'index.html' && currentPage !== 'share.html') {
            window.location.href = 'login.html';
        }
    }

    // ==========================================
    // 3. Navigation Tabs (Dashboard)
    // ==========================================
    const navTabs = document.querySelectorAll('.nav-tab');
    navTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            navTabs.forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');

            tab.classList.add('active');
            const target = tab.dataset.tab;
            const targetElem = document.getElementById(target);
            if (targetElem) targetElem.style.display = 'block';

            if (target === 'sessions-tab') loadSessions();
            if (target === 'security-tab') check2FAStatus();
            if (target === 'trash-tab') loadTrash();
        });
    });

    // ==========================================
    // 4. Auth & Initializer
    // ==========================================
    async function checkAuthStatus() {
        if (currentPage === 'share.html' && new URLSearchParams(window.location.search).has('token')) {
            initPublicShareView();
            return;
        }

        const res = await apiRequest('get_user_info');
        
        if (res && res.success) {
            csrfToken = res.csrf_token || csrfToken;

            const welcomeUserElem = document.getElementById('welcome-user');
            if (welcomeUserElem) {
                welcomeUserElem.innerText = `Welcome, ${res.user?.username || res.username}`;
            }

            if (currentPage === 'login.html' || currentPage === 'index.html') {
                window.location.href = 'dashboard.html';
            }

            if (currentPage === 'dashboard.html') {
                loadFiles();
                loadNotes();
            } else if (currentPage === 'share.html') {
                initSharePage();
            }
        } else {
            redirectToLogin();
        }
    }

    // ==========================================
    // 5. Authentication Handlers (Two-Step & Recovery)
    // ==========================================
    if (loginStep1Form) {
        loginStep1Form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const alertBox = document.getElementById('login-alert');
            alertBox.style.display = 'none';

            const formData = new FormData(loginStep1Form);
            const res = await apiRequest('login_step1', 'POST', formData);

            if (res && res.success) {
                if (res.requires_2fa) {
                    currentTempToken = res.temp_token;
                    document.getElementById('login-temp-token').value = res.temp_token;
                    document.getElementById('recovery-temp-token').value = res.temp_token;
                    
                    loginStep1Form.style.opacity = '0';
                    loginStep1Form.style.transition = 'opacity 0.3s ease';
                    
                    setTimeout(() => {
                        loginStep1Form.style.display = 'none';
                        loginStep2Form.style.display = 'block';
                        loginStep2Form.style.opacity = '0';
                        loginStep2Form.style.transition = 'opacity 0.3s ease';
                        
                        // Small delay to allow display block to render before changing opacity
                        setTimeout(() => {
                            loginStep2Form.style.opacity = '1';
                            const totpInput = document.getElementById('login-totp');
                            if (totpInput) totpInput.focus();
                        }, 50);
                    }, 300);
                } else {
                    window.location.href = 'dashboard.html';
                }
            } else {
                alertBox.innerText = res?.message || 'Login failed.';
                alertBox.style.display = 'block';
            }
        });
    }

    if (loginStep2Form) {
        loginStep2Form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const alertBox = document.getElementById('login-alert');
            alertBox.style.display = 'none';

            const formData = new FormData(loginStep2Form);
            const res = await apiRequest('login_step2', 'POST', formData);

            if (res && res.success) {
                window.location.href = 'dashboard.html';
            } else {
                alertBox.innerText = res?.message || 'Invalid 2FA code.';
                alertBox.style.display = 'block';
            }
        });
    }

    // Recovery code toggles
    const toggleRecoveryBtn = document.getElementById('toggle-recovery-btn');
    const backToTotpBtn = document.getElementById('back-to-totp-btn');
    if (toggleRecoveryBtn) {
        toggleRecoveryBtn.addEventListener('click', () => {
            loginStep2Form.style.opacity = '0';
            loginStep2Form.style.transition = 'opacity 0.3s ease';
            setTimeout(() => {
                loginStep2Form.style.display = 'none';
                loginRecoveryForm.style.display = 'block';
                loginRecoveryForm.style.opacity = '0';
                loginRecoveryForm.style.transition = 'opacity 0.3s ease';
                setTimeout(() => {
                    loginRecoveryForm.style.opacity = '1';
                    const recoveryInput = document.getElementById('recovery-code');
                    if (recoveryInput) recoveryInput.focus();
                }, 50);
            }, 300);
        });
    }
    if (backToTotpBtn) {
        backToTotpBtn.addEventListener('click', () => {
            loginRecoveryForm.style.opacity = '0';
            loginRecoveryForm.style.transition = 'opacity 0.3s ease';
            setTimeout(() => {
                loginRecoveryForm.style.display = 'none';
                loginStep2Form.style.display = 'block';
                loginStep2Form.style.opacity = '0';
                setTimeout(() => {
                    loginStep2Form.style.opacity = '1';
                    const totpInput = document.getElementById('login-totp');
                    if (totpInput) totpInput.focus();
                }, 50);
            }, 300);
        });
    }

    if (loginRecoveryForm) {
        loginRecoveryForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const alertBox = document.getElementById('login-alert');
            alertBox.style.display = 'none';

            const formData = new FormData(loginRecoveryForm);
            const res = await apiRequest('recover_account', 'POST', formData);

            if (res && res.success) {
                alert('Account recovered successfully!');
                window.location.href = 'dashboard.html';
            } else {
                alertBox.innerText = res?.message || 'Invalid recovery code.';
                alertBox.style.display = 'block';
            }
        });
    }

    let currentRegRecoveryCode = ''; // Temporarily hold the recovery code

    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const alertBox = document.getElementById('register-alert');
            const successBox = document.getElementById('register-success');
            alertBox.style.display = 'none';
            successBox.style.display = 'none';

            const formData = new FormData(registerForm);
            const res = await apiRequest('register', 'POST', formData);

            if (res && res.success) {
                registerForm.style.display = 'none'; // Hide register form
                
                // Store recovery code for later
                currentRegRecoveryCode = res.recovery_code || '';
                
                // Show 2FA Setup
                const setupBox = document.getElementById('reg-2fa-setup');
                if (setupBox) {
                    setupBox.style.display = 'block';
                    document.getElementById('reg-qr-wrapper').innerHTML = `<img src="${res.qr_code}" alt="2FA QR Code">`;
                    document.getElementById('reg-2fa-secret').innerText = res.secret;
                }
            } else {
                alertBox.innerText = res?.message || 'Registration failed.';
                alertBox.style.display = 'block';
            }
        });
    }

    const reg2faForm = document.getElementById('reg-2fa-form');
    if (reg2faForm) {
        reg2faForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const alertBox = document.getElementById('register-alert');
            alertBox.style.display = 'none';

            const formData = new FormData(reg2faForm);
            const res = await apiRequest('confirm_reg_2fa', 'POST', formData);

            if (res && res.success) {
                document.getElementById('reg-2fa-setup').style.display = 'none';
                
                const displayBox = document.getElementById('recovery-codes-display');
                const listContainer = document.getElementById('codes-list-container');
                listContainer.innerHTML = `<code>${currentRegRecoveryCode}</code>`;
                displayBox.style.display = 'block';
            } else {
                alertBox.innerText = res?.message || 'Invalid 2FA code.';
                alertBox.style.display = 'block';
            }
        });
    }

    const skip2faBtn = document.getElementById('skip-2fa-btn');
    if (skip2faBtn) {
        skip2faBtn.addEventListener('click', () => {
            document.getElementById('reg-2fa-setup').style.display = 'none';
            
            const displayBox = document.getElementById('recovery-codes-display');
            const listContainer = document.getElementById('codes-list-container');
            listContainer.innerHTML = `<code>${currentRegRecoveryCode}</code>`;
            displayBox.style.display = 'block';
        });
    }

    const confirmSavedCodesBtn = document.getElementById('confirm-saved-codes-btn');
    if (confirmSavedCodesBtn) {
        confirmSavedCodesBtn.addEventListener('click', () => {
            document.getElementById('recovery-codes-display').style.display = 'none';
            alert('Please sign in using your username and password.');
            window.location.reload();
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            await apiRequest('logout', 'POST');
            window.location.href = 'login.html';
        });
    }

    // ==========================================
    // 6. 2FA Setup
    // ==========================================
    async function check2FAStatus() {
        const res = await apiRequest('2fa_status');
        const statusText = document.getElementById('2fa-status-text');
        const setupBtn = document.getElementById('setup-2fa-btn');
        const disableBtn = document.getElementById('disable-2fa-btn');

        if (statusText && res && res.success) {
            statusText.innerText = res.enabled ? 'Enabled' : 'Disabled';
            if (res.enabled) {
                if (setupBtn) setupBtn.style.display = 'none';
                if (disableBtn) disableBtn.style.display = 'inline-block';
            } else {
                if (setupBtn) setupBtn.style.display = 'inline-block';
                if (disableBtn) disableBtn.style.display = 'none';
            }
        }
    }

    const setup2faBtn = document.getElementById('setup-2fa-btn');
    if (setup2faBtn) {
        setup2faBtn.addEventListener('click', async () => {
            const res = await apiRequest('setup_2fa', 'POST');
            if (res && res.success) {
                document.getElementById('2fa-secret-key').innerText = res.secret;
                const qrWrapper = document.getElementById('qr-code-wrapper');
                if (res.qr_code_url) {
                    qrWrapper.innerHTML = `<img src="${res.qr_code_url}" alt="2FA QR Code">`;
                } else {
                    qrWrapper.innerText = 'Scan URI: ' + res.otpauth_url;
                }
                document.getElementById('2fa-setup-box').style.display = 'block';
            }
        });
    }

    const disable2faBtn = document.getElementById('disable-2fa-btn');
    if (disable2faBtn) {
        disable2faBtn.addEventListener('click', async () => {
            if (confirm('Are you sure you want to disable Two-Factor Authentication?')) {
                const res = await apiRequest('disable_2fa', 'POST');
                if (res && res.success) {
                    alert('2FA successfully disabled.');
                    check2FAStatus();
                } else {
                    alert(res?.message || 'Failed to disable 2FA.');
                }
            }
        });
    }

    if (enable2faForm) {
        enable2faForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(enable2faForm);
            const res = await apiRequest('enable_2fa', 'POST', formData);

            if (res && res.success) {
                alert('2FA successfully enabled!');
                document.getElementById('2fa-setup-box').style.display = 'none';
                check2FAStatus();
            } else {
                alert(res?.message || 'Invalid code.');
            }
        });
    }

    // ==========================================
    // 7. Active Sessions Management
    // ==========================================
    async function loadSessions() {
        if (!sessionsList) return;
        const res = await apiRequest('get_sessions');
        if (!res || !res.success) return;

        sessionsList.innerHTML = '';
        res.sessions.forEach(session => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${escapeHtml(session.ip_address)}</td>
                <td>${escapeHtml(session.user_agent.substring(0, 40))}...</td>
                <td>${session.last_activity}</td>
                <td>
                    <button class="btn-revoke-session btn-danger" data-id="${session.id}">Revoke</button>
                </td>
            `;
            sessionsList.appendChild(tr);
        });
    }

    // ==========================================
    // 8. Files Management
    // ==========================================
    async function loadFiles() {
        if (!filesList) return;
        const res = await apiRequest('list_files');
        if (!res || !res.success) return;

        filesList.innerHTML = '';
        res.files.forEach(file => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${escapeHtml(file.original_name)}</td>
                <td>${(file.file_size / 1024).toFixed(1)} KB</td>
                <td>${file.created_at}</td>
                <td>
                    <a href="../api/api.php?action=download_file&id=${file.id}" target="_blank" class="btn-primary" style="padding: 4px 8px; text-decoration: none;">Download</a>
                    <button class="btn-share-item btn-secondary" data-type="file" data-id="${file.id}">Share</button>
                    <button class="btn-delete-file btn-danger" data-id="${file.id}">Trash</button>
                </td>
            `;
            filesList.appendChild(tr);
        });
    }

    if (uploadFileForm) {
        uploadFileForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(uploadFileForm);
            const res = await apiRequest('upload_file', 'POST', formData);

            if (res && res.success) {
                uploadFileForm.reset();
                loadFiles();
            } else {
                alert(res?.message || 'File upload failed.');
            }
        });
    }

    // ==========================================
    // 9. Notes Management (Zero-Knowledge & Server AES-GCM)
    // ==========================================
    async function loadNotes() {
        if (!notesList) return;
        const res = await apiRequest('list_notes');
        if (!res || !res.success) return;

        notesList.innerHTML = '';
        res.notes.forEach(note => {
            const card = document.createElement('div');
            card.className = 'card note-card';
            card.style.marginBottom = '12px';
            card.innerHTML = `
                <h4>${escapeHtml(note.title)}</h4>
                <small>${note.created_at}</small>
                <div class="actions" style="margin-top: 10px;">
                    <button class="btn-view-note btn-primary" data-id="${note.id}">View Note</button>
                    <button class="btn-share-item btn-secondary" data-type="note" data-id="${note.id}">Share</button>
                    <button class="btn-delete-note btn-danger" data-id="${note.id}">Trash</button>
                </div>
            `;
            notesList.appendChild(card);
        });
    }

    if (createNoteForm) {
        createNoteForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const title = createNoteForm.title.value;
            const content = createNoteForm.content.value;
            const tags = createNoteForm.tags ? createNoteForm.tags.value : '';
            const isClientEncrypt = document.getElementById('enable-client-crypto')?.checked;

            let postData = { title, content, tags };

            if (isClientEncrypt) {
                const passphrase = prompt('Enter a Client-Side Passphrase to encrypt this note (Zero-Knowledge):');
                if (!passphrase) return;

                const encrypted = await clientEncryptText(content, passphrase);
                postData.content = encrypted.ciphertext;
                postData.is_client_encrypted = '1';
                postData.custom_iv = encrypted.iv;
                postData.custom_tag = encrypted.tag;
            }

            const res = await apiRequest('create_note', 'POST', postData);

            if (res && res.success) {
                createNoteForm.reset();
                loadNotes();
            } else {
                alert(res?.message || 'Failed to save note.');
            }
        });
    }

    // ==========================================
    // 10. Trash Management
    // ==========================================
    async function loadTrash() {
        if (!trashList) return;
        const res = await apiRequest('list_trash');
        if (!res || !res.success) return;

        trashList.innerHTML = '';
        res.trash.forEach(item => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${escapeHtml(item.type)}</td>
                <td>${escapeHtml(item.name)}</td>
                <td>${item.deleted_at}</td>
                <td>
                    <button class="btn-restore-item btn-primary" data-type="${item.type}" data-id="${item.id}">Restore</button>
                </td>
            `;
            trashList.appendChild(tr);
        });
    }

    // ==========================================
    // 11. Global Delegated Click Actions
    // ==========================================
    document.addEventListener('click', async (e) => {
        // Trash File
        if (e.target.classList.contains('btn-delete-file')) {
            if (confirm('Move this file to Trash?')) {
                const res = await apiRequest('delete_file', 'POST', { file_id: e.target.dataset.id });
                if (res && res.success) loadFiles();
            }
        }

        // Trash Note
        if (e.target.classList.contains('btn-delete-note')) {
            if (confirm('Move this note to Trash?')) {
                const res = await apiRequest('delete_note', 'POST', { note_id: e.target.dataset.id });
                if (res && res.success) loadNotes();
            }
        }

        // Restore Trash Item
        if (e.target.classList.contains('btn-restore-item')) {
            const res = await apiRequest('restore_trash', 'POST', {
                type: e.target.dataset.type,
                item_id: e.target.dataset.id
            });
            if (res && res.success) loadTrash();
        }

        // Revoke Session
        if (e.target.classList.contains('btn-revoke-session')) {
            if (confirm('Revoke this active session?')) {
                const res = await apiRequest('revoke_session', 'POST', { session_id: e.target.dataset.id });
                if (res && res.success) loadSessions();
            }
        }

        // View Note
        if (e.target.classList.contains('btn-view-note')) {
            const noteId = e.target.dataset.id;
            const res = await apiRequest('get_note', 'GET', { note_id: noteId });

            if (res && res.success) {
                const note = res.note;
                let displayContent = note.content;

                // Check if zero-knowledge encrypted (iv empty or fallback flag or decryption mismatch)
                if ((!note.iv || note.iv === '') || note.is_zk_fallback) {
                    const passphrase = prompt('This note is Zero-Knowledge Encrypted. Enter decryption passphrase:');
                    if (passphrase) {
                        try {
                            displayContent = await clientDecryptText(note.encrypted_content, note.iv, note.tag, passphrase);
                        } catch (err) {
                            alert('Decryption failed! Incorrect passphrase.');
                            return;
                        }
                    } else {
                        return;
                    }
                }

                alert(`Title: ${note.title}\n\nContent:\n${displayContent}`);
            } else {
                alert(res?.message || 'Unable to retrieve note.');
            }
        }

        // Open Share Modal
        if (e.target.classList.contains('btn-share-item')) {
            const type = e.target.dataset.type;
            const id = e.target.dataset.id;
            
            const modal = document.getElementById('share-modal');
            if (modal) {
                document.getElementById('share-item-type').value = type;
                document.getElementById('share-item-id').value = id;
                document.getElementById('share-result-box').style.display = 'none';
                modal.style.display = 'flex';
            } else {
                window.location.href = `share.html?type=${type}&id=${id}`;
            }
        }
    });

    // Close Modal Button
    const closeModalBtn = document.getElementById('close-modal-btn');
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', () => {
            document.getElementById('share-modal').style.display = 'none';
        });
    }

    // Modal / Page Share Form Submit
    if (shareForm) {
        shareForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(shareForm);
            const res = await apiRequest('create_share_link', 'POST', formData);

            if (res && res.success) {
                const basePath = window.location.pathname.includes('/public/') ? window.location.origin + '/public' : window.location.origin;
                const fullUrl = `${basePath}/share.html?token=${res.token}`;
                
                const outputField = document.getElementById('share-url-output') || document.getElementById('share-url-input');
                const resultDiv = document.getElementById('share-result-box') || document.getElementById('share-result');

                if (outputField) outputField.value = fullUrl;
                if (resultDiv) resultDiv.style.display = 'block';

                const copyBtn = document.getElementById('copy-share-url-btn') || document.getElementById('copy-share-btn');
                if (copyBtn) {
                    copyBtn.onclick = () => {
                        outputField.select();
                        navigator.clipboard.writeText(fullUrl);
                        alert('Share URL copied to clipboard!');
                    };
                }
            } else {
                alert(res?.message || 'Failed to generate share link.');
            }
        });
    }

    // ==========================================
    // 12. Public Share Access Handler (?token=...)
    // ==========================================
    async function initPublicShareView() {
        const createCard = document.getElementById('create-share-card');
        const viewCard = document.getElementById('view-share-card');
        const spinner = document.getElementById('share-loading-spinner');
        const contentArea = document.getElementById('share-content-area');
        const errorBox = document.getElementById('share-error-box');

        if (createCard) createCard.style.display = 'none';
        if (viewCard) viewCard.style.display = 'block';

        const token = new URLSearchParams(window.location.search).get('token');
        const res = await apiRequest('access_shared_item', 'GET', { token });

        if (spinner) spinner.style.display = 'none';

        if (res && res.success) {
            contentArea.style.display = 'block';
            document.getElementById('shared-type-label').innerText = res.type.toUpperCase();
            document.getElementById('shared-uses-label').innerText = res.remaining_uses;
            document.getElementById('shared-expires-label').innerText = res.expires_at;

            if (res.type === 'file') {
                const fileActions = document.getElementById('shared-file-actions');
                fileActions.style.display = 'block';
                document.getElementById('shared-file-name').innerText = res.file.original_name;
                document.getElementById('shared-file-size').innerText = (res.file.file_size / 1024).toFixed(1) + ' KB';

                document.getElementById('download-shared-file-btn').onclick = () => {
                    window.location.href = `download.php?token=${encodeURIComponent(token)}`;
                };
            } else if (res.type === 'note') {
                const noteActions = document.getElementById('shared-note-actions');
                noteActions.style.display = 'block';
                document.getElementById('shared-note-title').innerText = res.note.title;

                if (res.note.is_zk_encrypted) {
                    document.getElementById('zk-decryption-prompt').style.display = 'block';
                    document.getElementById('decrypt-note-btn').onclick = async () => {
                        const passphrase = document.getElementById('zk-decryption-key').value;
                        try {
                            const decrypted = await clientDecryptText(res.note.content, res.note.iv, res.note.tag, passphrase);
                            document.getElementById('shared-note-content').innerText = decrypted;
                            document.getElementById('zk-decryption-prompt').style.display = 'none';
                        } catch (err) {
                            alert('Decryption failed! Invalid key.');
                        }
                    };
                } else {
                    document.getElementById('shared-note-content').innerText = res.note.content;
                }
            }
        } else {
            if (errorBox) {
                document.getElementById('share-error-message').innerText = res?.message || 'Link invalid or expired.';
                errorBox.style.display = 'block';
            }
        }
    }

    function initSharePage() {
        const urlParams = new URLSearchParams(window.location.search);
        const itemType = urlParams.get('type');
        const itemId = urlParams.get('id');

        const typeInput = document.getElementById('share-item-type');
        const idInput = document.getElementById('share-item-id');

        if (typeInput && idInput && itemType && itemId) {
            typeInput.value = itemType;
            idInput.value = itemId;
        }
    }

    // Helper: Escape HTML to prevent XSS
    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/[&<>"']/g, match => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[match]));
    }

    // Start App
    checkAuthStatus();
});