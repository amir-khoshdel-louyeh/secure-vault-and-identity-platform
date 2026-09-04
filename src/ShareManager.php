<?php
require_once dirname(__DIR__) . '/config/config.php';
require_once __DIR__ . '/DB.php';
require_once __DIR__ . '/Crypto.php';

class ShareManager {
    private PDO $db;

    public function __construct() {
        $this->db = getDBConnection();
    }

    /**
     * Create a time-limited / one-time share link
     */
    public function createShareToken(int $userId, string $itemType, int $itemId, int $expireHours = 24, int $maxUses = 1): array {
        if (!in_array($itemType, ['file', 'note'])) {
            return ['success' => false, 'message' => 'Invalid item type.'];
        }

        // 1. Check item ownership (Prevent IDOR)
        $table = ($itemType === 'file') ? 'files' : 'notes';
        $stmt = $this->db->prepare("SELECT id FROM {$table} WHERE id = ? AND user_id = ?");
        $stmt->execute([$itemId, $userId]);
        if (!$stmt->fetch()) {
            return ['success' => false, 'message' => 'Item not found or you do not have permission to share it.'];
        }

        // 2. Generate 64-character secure token
        $token = bin2hex(random_bytes(32));

        // 3. Calculate expiration time
        $expiresAt = date('Y-m-d H:i:s', strtotime("+{$expireHours} hours"));

        // 4. Save to database
        $stmt = $this->db->prepare(
            "INSERT INTO share_tokens (user_id, item_type, item_id, token, expires_at, max_uses) 
             VALUES (?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([$userId, $itemType, $itemId, $token, $expiresAt, $maxUses]);

        $this->logAction($userId, 'CREATE_SHARE_TOKEN');

        return [
            'success'    => true,
            'token'      => $token,
            'expires_at' => $expiresAt,
            'max_uses'   => $maxUses
        ];
    }

    /**
     * Public access to a file or note via token
     */
    public function accessSharedItem(string $token): void {
        // 1. Check token existence and validity
        $stmt = $this->db->prepare("SELECT * FROM share_tokens WHERE token = ?");
        $stmt->execute([$token]);
        $share = $stmt->fetch();

        if (!$share) {
            http_response_code(404);
            die("Invalid share link.");
        }

        // 2. Check time expiration
        if (strtotime($share['expires_at']) < time()) {
            http_response_code(410);
            die("This link has expired.");
        }

        // 3. Check usage limit
        if ($share['max_uses'] > 0 && $share['uses_count'] >= $share['max_uses']) {
            http_response_code(410);
            die("This is a one-time link and has already been used.");
        }

        // 4. Increment usage count before streaming (to prevent Race Condition)
        $updateStmt = $this->db->prepare("UPDATE share_tokens SET uses_count = uses_count + 1 WHERE id = ?");
        $updateStmt->execute([$share['id']]);

        // 5. Serve the item
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
            die("File not found.");
        }

        $filePath = STORAGE_DIR . $file['encrypted_name'];
        if (!file_exists($filePath)) {
            http_response_code(404);
            die("File does not exist on the server.");
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
            die("Note not found.");
        }

        // Try server decrypt; if fails, treat as Zero-Knowledge
        $isZk = false;
        $plainText = '';
        try {
            if (!empty($note['iv'])) {
                $plainText = Crypto::decryptText($note['encrypted_content'], $note['iv'], $note['tag'] ?? '');
            } else {
                $isZk = true;
            }
        } catch (Exception $e) {
            $isZk = true;
        }
        if ($isZk) {
            header('Content-Type: text/html; charset=utf-8');
            echo "<!DOCTYPE html><html lang='en' dir='ltr'><head><meta charset='UTF-8'><title>" . htmlspecialchars($note['title'], ENT_QUOTES, 'UTF-8') . "</title></head><body style='font-family:sans-serif; padding:2rem;'>";
            echo "<h2>" . htmlspecialchars($note['title'], ENT_QUOTES, 'UTF-8') . "</h2>";
            echo "<p><em>This note is Zero-Knowledge encrypted. Decryption must happen client-side with the passphrase.</em></p>";
            echo "<hr><p style='white-space: pre-wrap;'>" . htmlspecialchars($note['encrypted_content'], ENT_QUOTES, 'UTF-8') . "</p>";
            echo "<p><small>IV: " . htmlspecialchars($note['iv'] ?? '', ENT_QUOTES, 'UTF-8') . " Tag: " . htmlspecialchars($note['tag'] ?? '', ENT_QUOTES, 'UTF-8') . "</small></p>";
            echo "</body></html>";
            exit;
        }

        header('Content-Type: text/html; charset=utf-8');
        echo "<!DOCTYPE html><html lang='en' dir='ltr'><head><meta charset='UTF-8'><title>" . htmlspecialchars($note['title'], ENT_QUOTES, 'UTF-8') . "</title></head><body style='font-family:sans-serif; padding:2rem;'>";
        echo "<h2>" . htmlspecialchars($note['title'], ENT_QUOTES, 'UTF-8') . "</h2>";
        echo "<hr><p style='white-space: pre-wrap;'>" . htmlspecialchars($plainText, ENT_QUOTES, 'UTF-8') . "</p>";
        echo "</body></html>";
        exit;
    }

    /**
     * Get share info as JSON for public share view (share.html?token=...)
     */
    public function getShareInfo(string $token): array {
        $stmt = $this->db->prepare("SELECT * FROM share_tokens WHERE token = ?");
        $stmt->execute([$token]);
        $share = $stmt->fetch();

        if (!$share) {
            return ['success' => false, 'message' => 'Invalid share link.'];
        }
        if (strtotime($share['expires_at']) < time()) {
            return ['success' => false, 'message' => 'This link has expired.'];
        }
        if ($share['max_uses'] > 0 && $share['uses_count'] >= $share['max_uses']) {
            return ['success' => false, 'message' => 'This link has reached its maximum usage limit.'];
        }

        $remaining = $share['max_uses'] > 0 ? max(0, $share['max_uses'] - $share['uses_count']) : -1;

        if ($share['item_type'] === 'file') {
            $stmt2 = $this->db->prepare("SELECT original_name, file_size, mime_type FROM files WHERE id = ?");
            $stmt2->execute([$share['item_id']]);
            $file = $stmt2->fetch();
            if (!$file) return ['success' => false, 'message' => 'File not found.'];
            return [
                'success' => true,
                'type' => 'file',
                'expires_at' => $share['expires_at'],
                'remaining_uses' => $remaining,
                'file' => $file
            ];
        } else {
            $stmt2 = $this->db->prepare("SELECT title, encrypted_content, iv, tag FROM notes WHERE id = ?");
            $stmt2->execute([$share['item_id']]);
            $note = $stmt2->fetch();
            if (!$note) return ['success' => false, 'message' => 'Note not found.'];
            // Detect ZK by attempting server decrypt; fallback to raw if fails
            $isZk = false;
            $content = $note['encrypted_content'];
            if (!empty($note['iv'])) {
                try {
                    $content = Crypto::decryptText($note['encrypted_content'], $note['iv'], $note['tag'] ?? '');
                } catch (Exception $e) {
                    $isZk = true;
                    $content = $note['encrypted_content'];
                }
            } else {
                $isZk = true;
            }
            return [
                'success' => true,
                'type' => 'note',
                'expires_at' => $share['expires_at'],
                'remaining_uses' => $remaining,
                'note' => [
                    'title' => $note['title'],
                    'content' => $content,
                    'is_zk_encrypted' => $isZk,
                    'iv' => $note['iv'] ?? '',
                    'tag' => $note['tag'] ?? '',
                    'encrypted_content' => $note['encrypted_content']
                ]
            ];
        }
    }

    /**
     * List all share links created by a user with enriched item names.
     */
    public function getUserShareTokens(int $userId): array {
        $stmt = $this->db->prepare("SELECT * FROM share_tokens WHERE user_id = ? ORDER BY created_at DESC");
        $stmt->execute([$userId]);
        $tokens = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($tokens as &$row) {
            $itemName = 'Unknown';
            $isOrphan = false;
            if ($row['item_type'] === 'file') {
                $s2 = $this->db->prepare("SELECT original_name FROM files WHERE id = ?");
                $s2->execute([$row['item_id']]);
                $f = $s2->fetch();
                $itemName = $f ? $f['original_name'] : '(deleted file #' . $row['item_id'] . ')';
                if (!$f) $isOrphan = true;
            } else {
                $s2 = $this->db->prepare("SELECT title FROM notes WHERE id = ?");
                $s2->execute([$row['item_id']]);
                $n = $s2->fetch();
                $itemName = $n ? $n['title'] : '(deleted note #' . $row['item_id'] . ')';
                if (!$n) $isOrphan = true;
            }
            $row['item_name'] = $itemName;
            $row['is_orphan'] = $isOrphan;
            // Derived status
            $expired = strtotime($row['expires_at']) < time();
            $exhausted = $row['max_uses'] > 0 && $row['uses_count'] >= $row['max_uses'];
            if ($expired) {
                $row['status'] = 'expired';
            } elseif ($exhausted) {
                $row['status'] = 'exhausted';
            } else {
                $row['status'] = 'active';
            }
            $row['remaining_uses'] = $row['max_uses'] > 0 ? max(0, (int)$row['max_uses'] - (int)$row['uses_count']) : -1;
        }
        unset($row);

        return $tokens;
    }

    /**
     * Revoke (delete) a share link owned by the user.
     */
    public function revokeShareToken(int $userId, int $tokenId): array {
        $stmt = $this->db->prepare("SELECT id FROM share_tokens WHERE id = ? AND user_id = ?");
        $stmt->execute([$tokenId, $userId]);
        if (!$stmt->fetch()) {
            return ['success' => false, 'message' => 'Share link not found or you do not have permission to revoke it.'];
        }
        $del = $this->db->prepare("DELETE FROM share_tokens WHERE id = ? AND user_id = ?");
        $del->execute([$tokenId, $userId]);
        $this->logAction($userId, 'REVOKE_SHARE_TOKEN');
        return ['success' => true, 'message' => 'Share link revoked successfully.'];
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