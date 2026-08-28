document.addEventListener('DOMContentLoaded', () => {
    // CSRF Token Storage
    let csrfToken = '';

    // Route / Page Detection
    const currentPath = window.location.pathname.split('/').pop();
    const currentPage = currentPath === '' ? 'index.html' : currentPath;

    // UI Elements
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const logoutBtn = document.getElementById('logout-btn');
    const uploadFileForm = document.getElementById('upload-file-form');
    const createNoteForm = document.getElementById('create-note-form');
    const shareForm = document.getElementById('share-form');
    const filesList = document.getElementById('files-list');
    const notesList = document.getElementById('notes-list');

    // ==========================================
    // 1. Unified API Request Handler
    // ==========================================
    async function apiRequest(action, method = 'GET', data = null) {
        let url = `api.php?action=${encodeURIComponent(action)}`;
        const options = {
            method: method,
            headers: {}
        };

        if (method === 'POST') {
            if (data instanceof FormData) {
                if (csrfToken) data.append('csrf_token', csrfToken);
                options.body = data;
            } else {
                const params = new URLSearchParams(data || {});
                if (csrfToken) params.append('csrf_token', csrfToken);
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

            // Update CSRF token dynamically if server returns a new one
            if (result && result.csrf_token) {
                csrfToken = result.csrf_token;
            }

            // Redirect unauthenticated users to login if 401 occurs
            if (response.status === 401 && action !== 'login') {
                redirectToLogin();
                return null;
            }

            return result;
        } catch (error) {
            console.error('API Request Error:', error);
            alert('Server communication error.');
            return null;
        }
    }

    // Navigation & Auth Guard
    function redirectToLogin() {
        if (currentPage !== 'login.html' && currentPage !== 'index.html') {
            window.location.href = 'login.html';
        }
    }

    // ==========================================
    // 2. Authentication Check & Initializer
    // ==========================================
    async function checkAuthStatus() {
        const res = await apiRequest('get_user_info');
        
        if (res && res.success) {
            csrfToken = res.csrf_token || '';

            // Update user welcome UI if element exists
            const welcomeUserElem = document.getElementById('welcome-user');
            if (welcomeUserElem) {
                welcomeUserElem.innerText = `Welcome, ${res.username || res.user?.username}`;
            }

            // Redirect away from login if already authenticated
            if (currentPage === 'login.html' || currentPage === 'index.html') {
                window.location.href = 'dashboard.html';
            }

            // Load data specific to pages
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
    // 3. Login, Registration & Logout Handlers
    // ==========================================
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(loginForm);
            const res = await apiRequest('login', 'POST', formData);

            if (res && res.success) {
                window.location.href = 'dashboard.html';
            } else if (res) {
                alert(res.message || 'Login failed.');
            }
        });
    }

    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(registerForm);
            const res = await apiRequest('register', 'POST', formData);

            if (res && res.success) {
                if (res.secret) {
                    prompt(
                        'Registration successful!\n\nIMPORTANT: Copy your 2FA TOTP secret key and enter it into Google Authenticator:',
                        res.secret
                    );
                } else {
                    alert(res.message + ' (Warning: TOTP Secret was not generated)');
                }
                registerForm.reset();
            } else if (res) {
                alert(res.message || 'Registration failed.');
            }
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            await apiRequest('logout', 'POST');
            window.location.href = 'login.html';
        });
    }

    // ==========================================
    // 4. File Management (Dashboard)
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
                    <a href="api.php?action=download_file&id=${file.id}" target="_blank" class="btn-primary" style="padding: 4px 8px; text-decoration: none;">Download</a>
                    <a href="share.html?type=file&id=${file.id}" class="btn-secondary" style="padding: 4px 8px; text-decoration: none;">Share</a>
                    <button class="btn-delete-file btn-danger" data-id="${file.id}">Delete</button>
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
            } else if (res) {
                alert(res.message || 'File upload failed.');
            }
        });
    }

    // ==========================================
    // 5. Secure Notes Management (Dashboard)
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
                    <button class="btn-view-note btn-primary" data-id="${note.id}">View Content</button>
                    <a href="share.html?type=note&id=${note.id}" class="btn-secondary" style="padding: 4px 8px; text-decoration: none;">Share</a>
                    <button class="btn-delete-note btn-danger" data-id="${note.id}">Delete</button>
                </div>
            `;
            notesList.appendChild(card);
        });
    }

    if (createNoteForm) {
        createNoteForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(createNoteForm);
            const res = await apiRequest('create_note', 'POST', formData);

            if (res && res.success) {
                createNoteForm.reset();
                loadNotes();
            } else if (res) {
                alert(res.message || 'Failed to save note.');
            }
        });
    }

    // ==========================================
    // 6. Global Event Delegation (Delete & View)
    // ==========================================
    document.addEventListener('click', async (e) => {
        // Delete File
        if (e.target.classList.contains('btn-delete-file')) {
            if (confirm('Are you sure you want to delete this file?')) {
                const res = await apiRequest('delete_file', 'POST', { file_id: e.target.dataset.id });
                if (res && res.success) loadFiles();
            }
        }

        // Delete Note
        if (e.target.classList.contains('btn-delete-note')) {
            if (confirm('Are you sure you want to delete this note?')) {
                const res = await apiRequest('delete_note', 'POST', { note_id: e.target.dataset.id });
                if (res && res.success) loadNotes();
            }
        }

        // View Decrypted Note
        if (e.target.classList.contains('btn-view-note')) {
            const noteId = e.target.dataset.id;
            const res = await apiRequest('get_note', 'GET', { note_id: noteId });
            if (res && res.success) {
                alert(`Title: ${res.note.title}\n\nContent:\n${res.note.content}`);
            } else if (res) {
                alert(res.message || 'Unable to retrieve note.');
            }
        }
    });

    // ==========================================
    // 7. Secure Share Link Generator (share.html)
    // ==========================================
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

    if (shareForm) {
        shareForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(shareForm);
            const res = await apiRequest('create_share_link', 'POST', formData);

            if (res && res.success) {
                const fullUrl = `${window.location.origin}/${res.share_url}`;
                const resultDiv = document.getElementById('share-result');
                resultDiv.innerHTML = `
                    <p>Secure link generated successfully:</p>
                    <input type="text" readonly value="${fullUrl}" id="share-url-input" style="width: 100%; margin: 8px 0; padding: 6px;">
                    <button type="button" id="copy-share-url" class="btn-primary">Copy Link</button>
                    <div style="margin-top: 8px;">
                        <small>Expires at: ${res.expires_at} | Max uses: ${res.max_uses}</small>
                    </div>
                `;
                resultDiv.classList.remove('hidden');

                document.getElementById('copy-share-url').addEventListener('click', () => {
                    const input = document.getElementById('share-url-input');
                    input.select();
                    navigator.clipboard.writeText(fullUrl);
                    alert('Link copied to clipboard!');
                });
            } else if (res) {
                alert(res.message || 'Failed to generate share link.');
            }
        });
    }

    // Helper: Escape HTML to prevent XSS
    function escapeHtml(str) {
        return String(str).replace(/[&<>"']/g, match => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[match]));
    }

    // Initialize Auth Check
    checkAuthStatus();
});