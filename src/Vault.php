<?php
require_once dirname(__DIR__) . '/config/config.php';
require_once __DIR__ . '/DB.php';
require_once __DIR__ . '/Crypto.php';

class Vault {
    private PDO $db;

    public function __construct() {
        $this->db = getDBConnection();

        if (!file_exists(STORAGE_DIR)) {
            mkdir(STORAGE_DIR, 0750, true);
        }
    }

    // =========================================================================
    // ۱. مدیریت پوشه‌ها (Folders)
    // =========================================================================

    public function createFolder(int $userId, string $name, ?int $parentId = null): array {
        $name = trim($name);
        if (empty($name)) {
            return ['success' => false, 'message' => 'نام پوشه نمی‌تواند خالی باشد.'];
        }

        if ($parentId !== null) {
            $stmt = $this->db->prepare("SELECT id FROM folders WHERE id = ? AND user_id = ?");
            $stmt->execute([$parentId, $userId]);
            if (!$stmt->fetch()) {
                return ['success' => false, 'message' => 'پوشه والد یافت نشد.'];
            }
        }

        $stmt = $this->db->prepare("INSERT INTO folders (user_id, parent_id, name) VALUES (?, ?, ?)");
        $stmt->execute([$userId, $parentId, $name]);

        $this->logAction($userId, 'CREATE_FOLDER');
        return ['success' => true, 'message' => 'پوشه با موفقیت ایجاد شد.', 'folder_id' => $this->db->lastInsertId()];
    }

    public function getUserFolders(int $userId): array {
        $stmt = $this->db->prepare("SELECT id, parent_id, name, created_at FROM folders WHERE user_id = ? ORDER BY name ASC");
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }

    public function deleteFolder(int $userId, int $folderId): array {
        $stmt = $this->db->prepare("DELETE FROM folders WHERE id = ? AND user_id = ?");
        $stmt->execute([$folderId, $userId]);

        if ($stmt->rowCount() === 0) {
            return ['success' => false, 'message' => 'پوشه یافت نشد یا دسترسی ندارید.'];
        }

        $this->logAction($userId, 'DELETE_FOLDER');
        return ['success' => true, 'message' => 'پوشه با موفقیت حذف شد.'];
    }

    // =========================================================================
    // ۲. مدیریت یادداشت‌ها (Notes) - با پشتیبانی از Zero-Knowledge، تگ و پوشه
    // =========================================================================

    public function createNote(int $userId, string $title, string $content, ?int $folderId = null, ?string $tags = null, bool $isClientEncrypted = false, ?string $customIv = null, ?string $customTag = null): array {
        if (empty($title) || empty($content)) {
            return ['success' => false, 'message' => 'عنوان و متن یادداشت نمی‌تواند خالی باشد.'];
        }

        $ciphertext = '';
        $iv = '';
        $tag = '';

        if ($isClientEncrypted) {
            // معماری Zero-Knowledge: متن قبلاً در کلاینت رمزنگاری شده است
            $ciphertext = $content;
            $iv = $customIv ?? '';
            $tag = $customTag ?? '';
        } else {
            // رمزنگاری سمت سرور با AES-256-GCM
            $cryptoRes = Crypto::encryptText($content);
            $ciphertext = $cryptoRes['ciphertext'];
            $iv = $cryptoRes['iv'];
            $tag = $cryptoRes['tag'];
        }

        $stmt = $this->db->prepare(
            "INSERT INTO notes (user_id, folder_id, title, encrypted_content, iv, tag, tags) VALUES (?, ?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([$userId, $folderId, $title, $ciphertext, $iv, $tag, $tags]);

        $this->logAction($userId, 'CREATE_NOTE');

        return ['success' => true, 'message' => 'یادداشت با موفقیت ذخیره شد.', 'note_id' => $this->db->lastInsertId()];
    }

    public function updateNote(int $userId, int $noteId, string $title, string $content, ?int $folderId = null, ?string $tags = null, bool $isClientEncrypted = false, ?string $customIv = null, ?string $customTag = null): array {
        $stmt = $this->db->prepare("SELECT id FROM notes WHERE id = ? AND user_id = ? AND is_deleted = 0");
        $stmt->execute([$noteId, $userId]);
        if (!$stmt->fetch()) {
            return ['success' => false, 'message' => 'یادداشت یافت نشد یا دسترسی ندارید.'];
        }

        if ($isClientEncrypted) {
            $ciphertext = $content;
            $iv = $customIv ?? '';
            $tag = $customTag ?? '';
        } else {
            $cryptoRes = Crypto::encryptText($content);
            $ciphertext = $cryptoRes['ciphertext'];
            $iv = $cryptoRes['iv'];
            $tag = $cryptoRes['tag'];
        }

        $stmt = $this->db->prepare(
            "UPDATE notes SET title = ?, encrypted_content = ?, iv = ?, tag = ?, folder_id = ?, tags = ? WHERE id = ? AND user_id = ?"
        );
        $stmt->execute([$title, $ciphertext, $iv, $tag, $folderId, $tags, $noteId, $userId]);

        $this->logAction($userId, 'UPDATE_NOTE');
        return ['success' => true, 'message' => 'یادداشت با موفقیت به‌روزرسانی شد.'];
    }

    public function getNote(int $userId, int $noteId): array {
        $stmt = $this->db->prepare("SELECT * FROM notes WHERE id = ? AND user_id = ? AND is_deleted = 0");
        $stmt->execute([$noteId, $userId]);
        $note = $stmt->fetch();

        if (!$note) {
            return ['success' => false, 'message' => 'یادداشت یافت نشد یا شما دسترسی ندارید.'];
        }

        // اگر IV موجود باشد متد سرور رمزگشایی می‌کند؛ در غیر این صورت جهت Zero-Knowledge متن خام رمزنگاری کلاینت برگردانده می‌شود
        $plainContent = !empty($note['iv']) 
            ? Crypto::decryptText($note['encrypted_content'], $note['iv'], $note['tag'] ?? '') 
            : $note['encrypted_content'];

        return [
            'success' => true,
            'note'    => [
                'id'                => $note['id'],
                'folder_id'         => $note['folder_id'],
                'title'             => $note['title'],
                'content'           => $plainContent,
                'encrypted_content' => $note['encrypted_content'],
                'iv'                => $note['iv'],
                'tag'               => $note['tag'] ?? '',
                'tags'              => $note['tags'],
                'created_at'        => $note['created_at'],
                'updated_at'        => $note['updated_at']
            ]
        ];
    }

    public function getUserNotes(int $userId, ?int $folderId = null, ?string $tag = null): array {
        $sql = "SELECT id, folder_id, title, tags, updated_at, created_at FROM notes WHERE user_id = ? AND is_deleted = 0";
        $params = [$userId];

        if ($folderId !== null) {
            $sql .= " AND folder_id = ?";
            $params[] = $folderId;
        }
        if ($tag !== null && $tag !== '') {
            $sql .= " AND FIND_IN_SET(?, tags)";
            $params[] = $tag;
        }

        $sql .= " ORDER BY updated_at DESC";
        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    // =========================================================================
    // ۳. مدیریت فایل‌ها (Files) - با پشتیبانی از Zero-Knowledge و پوشه‌ها
    // =========================================================================

    public function uploadFile(int $userId, array $file, ?int $folderId = null, ?string $tags = null): array {
        if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
            return ['success' => false, 'message' => 'خطا در بارگذاری فایل.'];
        }

        if ($file['size'] > 50 * 1024 * 1024) { // حد مجاز ۵۰ مگابایت
            return ['success' => false, 'message' => 'حجم فایل نباید بیشتر از ۵۰ مگابایت باشد.'];
        }

        $originalName = basename($file['name']);
        $allowedExtensions = ['jpg', 'jpeg', 'png', 'pdf', 'docx', 'xlsx', 'txt', 'zip', 'rar'];
        $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        if (!in_array($ext, $allowedExtensions)) {
            return ['success' => false, 'message' => 'فرمت فایل مجاز نیست.'];
        }

        $encryptedName = bin2hex(random_bytes(16)) . '.enc';
        $destPath = STORAGE_DIR . $encryptedName;

        $cryptoRes = Crypto::encryptFile($file['tmp_name'], $destPath);
        @unlink($file['tmp_name']);

        $stmt = $this->db->prepare(
            "INSERT INTO files (user_id, folder_id, original_name, encrypted_name, file_size, mime_type, iv, tag, tags) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([
            $userId,
            $folderId,
            $originalName,
            $encryptedName,
            $file['size'],
            $file['type'],
            $cryptoRes['iv'],
            $cryptoRes['tag'],
            $tags
        ]);

        $this->logAction($userId, 'UPLOAD_FILE');

        return ['success' => true, 'message' => 'فایل با موفقیت و به صورت رمزنگاری‌شده آپلود شد.'];
    }

    public function updateItemMetadata(int $userId, string $type, int $itemId, string $newName, ?int $folderId = null, ?string $tags = null): array {
        $table = ($type === 'file') ? 'files' : 'notes';
        $nameField = ($type === 'file') ? 'original_name' : 'title';

        $stmt = $this->db->prepare("UPDATE {$table} SET {$nameField} = ?, folder_id = ?, tags = ? WHERE id = ? AND user_id = ? AND is_deleted = 0");
        $stmt->execute([$newName, $folderId, $tags, $itemId, $userId]);

        if ($stmt->rowCount() === 0) {
            return ['success' => false, 'message' => 'آیتم مورد نظر یافت نشد.'];
        }

        $this->logAction($userId, 'UPDATE_METADATA');
        return ['success' => true, 'message' => 'اطلاعات با موفقیت بروزرسانی شد.'];
    }

    public function downloadFile(int $userId, int $fileId): void {
        $stmt = $this->db->prepare("SELECT * FROM files WHERE id = ? AND user_id = ? AND is_deleted = 0");
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

        header('Content-Type: ' . $file['mime_type']);
        header('Content-Disposition: attachment; filename="' . rawurlencode($file['original_name']) . '"');
        header('Content-Length: ' . $file['file_size']);
        header('X-Content-Type-Options: nosniff');

        Crypto::decryptFileToStream($filePath, $file['iv'], $file['tag'] ?? '');
        
        $this->logAction($userId, 'DOWNLOAD_FILE');
        exit;
    }

    public function getUserFiles(int $userId, ?int $folderId = null, ?string $tag = null): array {
        $sql = "SELECT id, folder_id, original_name, file_size, mime_type, tags, created_at FROM files WHERE user_id = ? AND is_deleted = 0";
        $params = [$userId];

        if ($folderId !== null) {
            $sql .= " AND folder_id = ?";
            $params[] = $folderId;
        }
        if ($tag !== null && $tag !== '') {
            $sql .= " AND FIND_IN_SET(?, tags)";
            $params[] = $tag;
        }

        $sql .= " ORDER BY id DESC";
        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    // =========================================================================
    // ۴. سطل زباله (Trash - 30 Days Retention)
    // =========================================================================

    public function moveToTrash(int $userId, string $type, int $itemId): array {
        $table = ($type === 'file') ? 'files' : 'notes';
        $stmt = $this->db->prepare("UPDATE {$table} SET is_deleted = 1, deleted_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?");
        $stmt->execute([$itemId, $userId]);

        if ($stmt->rowCount() === 0) {
            return ['success' => false, 'message' => 'آیتم مورد نظر یافت نشد.'];
        }

        $this->logAction($userId, 'MOVE_TO_TRASH');
        return ['success' => true, 'message' => 'آیتم به سطل زباله منتقل شد.'];
    }

    public function restoreFromTrash(int $userId, string $type, int $itemId): array {
        $table = ($type === 'file') ? 'files' : 'notes';
        $stmt = $this->db->prepare("UPDATE {$table} SET is_deleted = 0, deleted_at = NULL WHERE id = ? AND user_id = ?");
        $stmt->execute([$itemId, $userId]);

        if ($stmt->rowCount() === 0) {
            return ['success' => false, 'message' => 'آیتم مورد نظر در سطل زباله یافت نشد.'];
        }

        $this->logAction($userId, 'RESTORE_FROM_TRASH');
        return ['success' => true, 'message' => 'آیتم با موفقیت بازیابی شد.'];
    }

    public function getTrashItems(int $userId): array {
        $notesStmt = $this->db->prepare("SELECT id, 'note' AS type, title AS name, deleted_at FROM notes WHERE user_id = ? AND is_deleted = 1");
        $notesStmt->execute([$userId]);
        $notes = $notesStmt->fetchAll();

        $filesStmt = $this->db->prepare("SELECT id, 'file' AS type, original_name AS name, deleted_at FROM files WHERE user_id = ? AND is_deleted = 1");
        $filesStmt->execute([$userId]);
        $files = $filesStmt->fetchAll();

        return array_merge($notes, $files);
    }

    /**
     * پاک‌سازی فیزیکی خودکار آیتم‌های قدیمی‌تر از ۳۰ روز در سطل زباله
     */
    public function purgeOldTrash(): void {
        $stmt = $this->db->prepare("SELECT id, encrypted_name FROM files WHERE is_deleted = 1 AND deleted_at < DATE_SUB(NOW(), INTERVAL 30 DAY)");
        $stmt->execute();
        $expiredFiles = $stmt->fetchAll();

        foreach ($expiredFiles as $file) {
            $filePath = STORAGE_DIR . $file['encrypted_name'];
            if (file_exists($filePath)) {
                @unlink($filePath);
            }
            $this->db->prepare("DELETE FROM files WHERE id = ?")->execute([$file['id']]);
        }

        $this->db->exec("DELETE FROM notes WHERE is_deleted = 1 AND deleted_at < DATE_SUB(NOW(), INTERVAL 30 DAY)");
    }

    // =========================================================================
    // ۵. لاگ‌های سیستم و امنیتی
    // =========================================================================

    public function getAuditLogs(int $userId, int $limit = 50): array {
        $stmt = $this->db->prepare("SELECT action, ip_address, user_agent, created_at FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?");
        $stmt->bindValue(1, $userId, PDO::PARAM_INT);
        $stmt->bindValue(2, $limit, PDO::PARAM_INT);
        $stmt->execute();
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