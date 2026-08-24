document.addEventListener('DOMContentLoaded', () => {
    // کلید ذخیره‌سازی توکن CSRF در حافظه برنامه
    let csrfToken = '';

    // عناصر UI اصلی
    const authSection = document.getElementById('auth-section');
    const dashboardSection = document.getElementById('dashboard-section');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const logoutBtn = document.getElementById('logout-btn');

    const uploadFileForm = document.getElementById('upload-file-form');
    const createNoteForm = document.getElementById('create-note-form');
    const shareForm = document.getElementById('share-form');

    const filesList = document.getElementById('files-list');
    const notesList = document.getElementById('notes-list');
    const shareModal = document.getElementById('share-modal');

    // ==========================================
    // ۱. تابع عمومی ارسال درخواست‌های Fetch/AJAX
    // ==========================================
    async function apiRequest(action, method = 'GET', data = null) {
        let url = `api.php?action=${encodeURIComponent(action)}`;
        const options = {
            method: method,
            headers: {}
        };

        if (method === 'POST') {
            if (data instanceof FormData) {
                // برای ارسال فایل‌ها
                if (csrfToken) data.append('csrf_token', csrfToken);
                options.body = data;
            } else {
                // برای داده‌های فرم عادی
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

            // بروزرسانی توکن CSRF در صورت دریافت جدید
            if (result.csrf_token) {
                csrfToken = result.csrf_token;
            }

            if (response.status === 401 && action !== 'login') {
                showAuthUI();
                return null;
            }

            return result;
        } catch (error) {
            console.error('API Error:', error);
            alert('خطا در ارتباط با سرور.');
            return null;
        }
    }

    // ==========================================
    // ۲. بررسی وضعیت لاگین و شروع کار
    // ==========================================
    async function checkAuthStatus() {
        const res = await apiRequest('get_user_info');
        if (res && res.success) {
            csrfToken = res.csrf_token;
            showDashboardUI(res.username);
        } else {
            showAuthUI();
        }
    }

    function showAuthUI() {
        authSection.classList.remove('hidden');
        dashboardSection.classList.add('hidden');
    }

    function showDashboardUI(username) {
        document.getElementById('welcome-user').innerText = `خوش آمدید، ${username}`;
        authSection.classList.add('hidden');
        dashboardSection.classList.remove('hidden');
        loadFiles();
        loadNotes();
    }

    // ==========================================
    // ۳. ورود و ثبت‌نام
    // ==========================================
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(loginForm);
            const res = await apiRequest('login', 'POST', formData);

            if (res && res.success) {
                checkAuthStatus();
            } else if (res) {
                alert(res.message);
            }
        });
    }

    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(registerForm);
            const res = await apiRequest('register', 'POST', formData);

            if (res && res.success) {
                alert(res.message);
                if (res.secret) {
                    alert(`کلید TOTP شما: ${res.secret}\nآن را در نرم‌افزار Authenticator وارد کنید.`);
                }
            } else if (res) {
                alert(res.message);
            }
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            await apiRequest('logout', 'POST');
            showAuthUI();
        });
    }

    // ==========================================
    // ۴. مدیریت فایل‌ها (آپلود، لیست، حذف)
    // ==========================================
    async function loadFiles() {
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
                    <button class="btn-share" data-type="file" data-id="${file.id}">اشتراک‌گذاری</button>
                    <button class="btn-delete-file" data-id="${file.id}">حذف</button>
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
                alert(res.message);
            }
        });
    }

    // ==========================================
    // ۵. مدیریت یادداشت‌ها (ایجاد، لیست، مشاهده، حذف)
    // ==========================================
    async function loadNotes() {
        const res = await apiRequest('list_notes');
        if (!res || !res.success) return;

        notesList.innerHTML = '';
        res.notes.forEach(note => {
            const card = document.createElement('div');
            card.className = 'note-card';
            card.innerHTML = `
                <h4>${escapeHtml(note.title)}</h4>
                <small>${note.created_at}</small>
                <div class="actions">
                    <button class="btn-view-note" data-id="${note.id}">مشاهده</button>
                    <button class="btn-share" data-type="note" data-id="${note.id}">اشتراک‌گذاری</button>
                    <button class="btn-delete-note" data-id="${note.id}">حذف</button>
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
                alert(res.message);
            }
        });
    }

    // ==========================================
    // ۶. ساخت لینک اشتراک‌گذاری زمان‌دار / یک‌بارمصرف
    // ==========================================
    document.addEventListener('click', async (e) => {
        // باز کردن مودال اشتراک‌گذاری
        if (e.target.classList.contains('btn-share')) {
            const itemType = e.target.dataset.type;
            const itemId = e.target.dataset.id;

            document.getElementById('share-item-type').value = itemType;
            document.getElementById('share-item-id').value = itemId;
            document.getElementById('share-result').classList.add('hidden');
            shareModal.classList.remove('hidden');
        }

        // حذف فایل
        if (e.target.classList.contains('btn-delete-file')) {
            if (confirm('آیا از حذف این فایل مطمئن هستید؟')) {
                const res = await apiRequest('delete_file', 'POST', { file_id: e.target.dataset.id });
                if (res && res.success) loadFiles();
            }
        }

        // حذف یادداشت
        if (e.target.classList.contains('btn-delete-note')) {
            if (confirm('آیا از حذف این یادداشت مطمئن هستید؟')) {
                const res = await apiRequest('delete_note', 'POST', { note_id: e.target.dataset.id });
                if (res && res.success) loadNotes();
            }
        }

        // مشاهده متن دکریپت‌شده یادداشت
        if (e.target.classList.contains('btn-view-note')) {
            const noteId = e.target.dataset.id;
            const res = await apiRequest('get_note', 'GET', { note_id: noteId });
            if (res && res.success) {
                alert(`عنوان: ${res.note.title}\n\nمتن:\n${res.note.content}`);
            }
        }
    });

    if (shareForm) {
        shareForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(shareForm);
            const res = await apiRequest('create_share_link', 'POST', formData);

            if (res && res.success) {
                const fullUrl = `${window.location.origin}/${res.share_url}`;
                const resultDiv = document.getElementById('share-result');
                resultDiv.innerHTML = `
                    <p>لینک با موفقیت ساخته شد:</p>
                    <input type="text" readonly value="${fullUrl}" id="share-url-input">
                    <button type="button" id="copy-share-url">کپی لینک</button>
                    <small>انقضا: ${res.expires_at} | حداکثر استفاده: ${res.max_uses}</small>
                `;
                resultDiv.classList.remove('hidden');

                document.getElementById('copy-share-url').addEventListener('click', () => {
                    const input = document.getElementById('share-url-input');
                    input.select();
                    navigator.clipboard.writeText(fullUrl);
                    alert('لینک کپی شد!');
                });
            } else if (res) {
                alert(res.message);
            }
        });
    }

    // بستن مودال
    const closeModalBtn = document.getElementById('close-modal');
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', () => shareModal.classList.add('hidden'));
    }

    // تابع کمکی جلوگیری از XSS در رندر متن‌ها
    function escapeHtml(str) {
        return String(str).replace(/[&<>"']/g, match => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[match]));
    }

    // اجرای اولین برسی اعتبار سنجی
    checkAuthStatus();
});