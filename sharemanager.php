<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';

class ShareManager {
    private PDO $db;

    public function __construct() {
        $this->db = getDBConnection();
    }

    /**
     * ایجاد لینک اشتراک‌گذاری زمان‌دار / یک‌بارمصرف
     */
    public function createShareToken(int $userId, string $itemType, int $itemId, int $expireHours = 24, int $maxUses = 1): array {
        if (!in_array($itemType, ['file', 'note'])) {
            return ['success' => false, 'message' => 'نوع آیتم نامعتبر است.'];
        }

        // ۱. بررسی مالکیت آیتم (جلوگیری از IDOR)
        $table = ($itemType === 'file') ? 'files' : 'notes';
        $stmt = $this->db->prepare("SELECT id FROM {$table} WHERE id = ? AND user_id = ?");
        $stmt->execute([$itemId, $userId]);
        if (!$stmt->fetch()) {
            return ['success' => false, 'message' => 'آیتم یافت نشد یا شما اجازه اشتراک‌گذاری آن را ندارید.'];
        }

        // ۲. تولید توکن ۶۴ کاراکتری امن
        $token = bin2hex(random_bytes(32));

        // ۳. محاسبه زمان انقضا
        $expiresAt = date('Y-m-d H:i:s', strtotime("+{$expireHours} hours"));

        // ۴. ذخیره در دیتابیس
        $stmt = $this->db->prepare(
            "INSERT INTO share_tokens (item_type, item_id, token, expires_at, max_uses) 
             VALUES (?, ?, ?, ?, ?)"
        );
        $stmt->execute([$itemType, $itemId, $token, $expiresAt, $maxUses]);

        $this->logAction($userId, 'CREATE_SHARE_TOKEN');

        return [
            'success'    => true,
            'token'      => $token,
            'expires_at' => $expiresAt,
            'max_uses'   => $maxUses
        ];
    }

    /**
     * دسترسی عمومی به فایل یا نوت از طریق توکن
     */
    public function accessSharedItem(string $token): void {
        // ۱. بررسی وجود و اعتبار توکن
        $stmt = $this->db->prepare("SELECT * FROM share_tokens WHERE token = ?");
        $stmt->execute([$token]);
        $share = $stmt->fetch();

        if (!$share) {
            http_response_code(404);
            die("لینک اشتراک‌گذاری نامعتبر است.");
        }

        // ۲. بررسی انقضای زمانی
        if (strtotime($share['expires_at']) < time()) {
            http_response_code(410);
            die("اعتبار این لینک به پایان رسیده است.");
        }

        // ۳. بررسی محدودیت تعداد استفاده
        if ($share['max_uses'] > 0 && $share['uses_count'] >= $share['max_uses']) {
            http_response_code(410);
            die("این لینک یک‌بارمصرف بوده و قبلاً استفاده شده است.");
        }

        // ۴. افزایش تعداد دفعات استفاده پیش از استریم (برای جلوگیری از Race Condition)
        $updateStmt = $this->db->prepare("UPDATE share_tokens SET uses_count = uses_count + 1 WHERE id = ?");
        $updateStmt->execute([$share['id']]);

        // ۵. سرویس‌دهی به آیتم
        if ($share['item_type'] === 'file') {
            $this->serveSharedFile((int)$share['item_id']);
        } else {
            $this->serveSharedNote((int)$share['item_id']);
        }
    }

    private function serveSharedFile(int $fileId): void {
        $stmt = $this->db->prepare("SELECT * FROM files WHERE id = ?");
        $stmt->execute([$fileId]);
        $file = $stmt->fetch();

        if (!$file) {
            http_response_code(404);
            die("فایل یافت نشد.");
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
        exit;
    }

    private function serveSharedNote(int $noteId): void {
        $stmt = $this->db->prepare("SELECT * FROM notes WHERE id = ?");
        $stmt->execute([$noteId]);
        $note = $stmt->fetch();

        if (!$note) {
            http_response_code(404);
            die("یادداشت یافت نشد.");
        }

        $plainText = Crypto::decryptText($note['encrypted_content'], $note['iv'], $note['tag'] ?? '');

        header('Content-Type: text/html; charset=utf-8');
        echo "<!DOCTYPE html><html lang='fa' dir='rtl'><head><meta charset='UTF-8'><title>" . htmlspecialchars($note['title'], ENT_QUOTES, 'UTF-8') . "</title></head><body style='font-family:sans-serif; padding:2rem;'>";
        echo "<h2>" . htmlspecialchars($note['title'], ENT_QUOTES, 'UTF-8') . "</h2>";
        echo "<hr><p style='white-space: pre-wrap;'>" . htmlspecialchars($plainText, ENT_QUOTES, 'UTF-8') . "</p>";
        echo "</body></html>";
        exit;
    }

    private function logAction(?int $userId, string $action): void {
        $stmt = $this->db->prepare("INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)");
        $stmt->execute([
            $userId,
            $action,
            $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN',
            $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN'
        ]);
    }
}