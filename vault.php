<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';

class Vault {
    private PDO $db;

    public function __construct() {
        $this->db = getDBConnection();

        // اطمینان از وجود دایرکتوری غیرقابل دسترس storage
        if (!file_exists(STORAGE_DIR)) {
            mkdir(STORAGE_DIR, 0750, true);
        }
    }

    // =========================================================================
    // ۱. مدیریت یادداشت‌ها (Notes)
    // =========================================================================

    /**
     * ایجاد یادداشت جدید همراه با رمزنگاری
     */
    public function createNote(int $userId, string $title, string $content): array {
        if (empty($title) || empty($content)) {
            return ['success' => false, 'message' => 'عنوان و متن یادداشت نمی‌تواند خالی باشد.'];
        }

        // رمزنگاری محتوای یادداشت
        $cryptoRes = Crypto::encryptText($content);

        $stmt = $this->db->prepare(
            "INSERT INTO notes (user_id, title, encrypted_content, iv) VALUES (?, ?, ?, ?)"
        );
        $stmt->execute([$userId, $title, $cryptoRes['ciphertext'], $cryptoRes['iv']]);

        $this->logAction($userId, 'CREATE_NOTE');

        return ['success' => true, 'message' => 'یادداشت با موفقیت و به صورت رمزنگاری‌شده ذخیره شد.'];
    }

    /**
     * دریافت و رمزگشایی یک یادداشت با بررسی مالکیت (جلوگیری از IDOR)
     */
    public function getNote(int $userId, int $noteId): array {
        $stmt = $this->db->prepare("SELECT * FROM notes WHERE id = ? AND user_id = ?");
        $stmt->execute([$noteId, $userId]);
        $note = $stmt->fetch();

        if (!$note) {
            return ['success' => false, 'message' => 'یادداشت یافت نشد یا شما دسترسی ندارید.'];
        }

        // رمزگشایی متن
        $plainContent = Crypto::decryptText($note['encrypted_content'], $note['iv']);

        return [
            'success' => true,
            'note'    => [
                'id'         => $note['id'],
                'title'      => $note['title'],
                'content'    => $plainContent,
                'created_at' => $note['created_at']
            ]
        ];
    }

    /**
     * لیست تمامی یادداشت‌های کاربر
     */
    public function getUserNotes(int $userId): array {
        $stmt = $this->db->prepare("SELECT id, title, created_at FROM notes WHERE user_id = ? ORDER BY id DESC");
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }

    // =========================================================================
    // ۲. مدیریت فایل‌ها و اسناد (Files)
    // =========================================================================

    /**
     * آپلود، رمزنگاری و ذخیره امن فایل
     */
    public function uploadFile(int $userId, array $file): array {
        if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
            return ['success' => false, 'message' => 'خطا در بارگذاری فایل.'];
        }

        // محدودیت حجم (مثلاً حداکثر ۲۰ مگابایت)
        if ($file['size'] > 20 * 1024 * 1024) {
            return ['success' => false, 'message' => 'حجم فایل نباید بیشتر از ۲۰ مگابایت باشد.'];
        }

        $originalName = basename($file['name']);
        
        // اعتبارسنجی پسوندها (Whitelist)
        $allowedExtensions = ['jpg', 'jpeg', 'png', 'pdf', 'docx', 'txt'];
        $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        if (!in_array($ext, $allowedExtensions)) {
            return ['success' => false, 'message' => 'فرمت فایل مجاز نیست.'];
        }

        // ایجاد نام تصادفی روی دیسک جهت جلوگیری از LFI/RFI و Overwrite
        $encryptedName = bin2hex(random_bytes(16)) . '.enc';
        $destPath = STORAGE_DIR . $encryptedName;

        // رمزنگاری فایل روی دیسک
        $ivBase64 = Crypto::encryptFile($file['tmp_name'], $destPath);

        // حذف فایل موقت آپلودشده
        @unlink($file['tmp_name']);

        // ثبت متادیتا در دیتابیس
        $stmt = $this->db->prepare(
            "INSERT INTO files (user_id, original_name, encrypted_name, file_size, mime_type, iv) 
             VALUES (?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([
            $userId,
            $originalName,
            $encryptedName,
            $file['size'],
            $file['type'],
            $ivBase64
        ]);

        $this->logAction($userId, 'UPLOAD_FILE');

        return ['success' => true, 'message' => 'فایل با موفقیت و به صورت رمزنگاری‌شده آپلود شد.'];
    }

    /**
     * ارسال مستقیم استریم فایل رمزگشایی‌شده به مرورگر (Stream Download)
     */
    public function downloadFile(int $userId, int $fileId): void {
        $stmt = $this->db->prepare("SELECT * FROM files WHERE id = ? AND user_id = ?");
        $stmt->execute([$fileId, $userId]);
        $file = $stmt->fetch();

        if (!$file) {
            http_response_code(404);
            die("فایل یافت نشد یا دسترسی ندارید.");
        }

        $filePath = STORAGE_DIR . $file['encrypted_name'];

        if (!file_exists($filePath)) {
            http_response_code(404);
            die("فایل روی سرور موجود نیست.");
        }

        // تنظیم هدرهای دانلود
        header('Content-Type: ' . $file['mime_type']);
        header('Content-Disposition: attachment; filename="' . rawurlencode($file['original_name']) . '"');
        header('Content-Length: ' . $file['file_size']);
        header('X-Content-Type-Options: nosniff');

        // استریم مستقیم فایل رمزگشایی‌شده
        Crypto::decryptFileToStream($filePath, $file['iv']);
        
        $this->logAction($userId, 'DOWNLOAD_FILE');
        exit;
    }

    /**
     * لیست تمامی فایل‌های کاربر
     */
    public function getUserFiles(int $userId): array {
        $stmt = $this->db->prepare(
            "SELECT id, original_name, file_size, mime_type, created_at 
             FROM files WHERE user_id = ? ORDER BY id DESC"
        );
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }

    private function logAction(int $userId, string $action): void {
        $stmt = $this->db->prepare(
            "INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)"
        );
        $stmt->execute([
            $userId,
            $action,
            $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN',
            $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN'
        ]);
    }
}