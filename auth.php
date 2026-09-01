<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/vendor/autoload.php';

use RobThree\Auth\TwoFactorAuth;

class Auth {
    private PDO $db;
    private TwoFactorAuth $tfa;

    public function __construct() {
        $this->db = getDBConnection();
        $this->tfa = new TwoFactorAuth('SecureVault');
    }

    // =========================================================================
    // ۱. محدودکننده نرخ درخواست (Rate Limiting & Brute Force Protection)
    // =========================================================================

    public function checkRateLimit(string $action = 'login', int $maxAttempts = 5, int $decayMinutes = 5): array {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        $stmt = $this->db->prepare("SELECT attempts, last_attempt FROM rate_limits WHERE ip_address = ? AND action = ?");
        $stmt->execute([$ip, $action]);
        $record = $stmt->fetch();

        if ($record) {
            $lastAttempt = strtotime($record['last_attempt']);
            if ((time() - $lastAttempt) > ($decayMinutes * 60)) {
                $this->resetRateLimit($ip, $action);
                return ['allowed' => true];
            }

            if ($record['attempts'] >= $maxAttempts) {
                $remaining = ceil(($decayMinutes * 60 - (time() - $lastAttempt)) / 60);
                return [
                    'allowed' => false,
                    'message' => "به دلیل تلاش‌های ناموفق متعدد، حساب شما موقتاً مسدود شد. لطفاً {$remaining} دقیقه دیگر تلاش کنید."
                ];
            }
        }

        return ['allowed' => true];
    }

    public function hitRateLimit(string $action = 'login'): void {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        $stmt = $this->db->prepare(
            "INSERT INTO rate_limits (ip_address, action, attempts, last_attempt) 
             VALUES (?, ?, 1, CURRENT_TIMESTAMP) 
             ON DUPLICATE KEY UPDATE attempts = attempts + 1, last_attempt = CURRENT_TIMESTAMP"
        );
        $stmt->execute([$ip, $action]);
    }

    public function resetRateLimit(string $ip, string $action = 'login'): void {
        $stmt = $this->db->prepare("DELETE FROM rate_limits WHERE ip_address = ? AND action = ?");
        $stmt->execute([$ip, $action]);
    }

    // =========================================================================
    // ۲. ثبت‌نام و تولید Master Recovery Code
    // =========================================================================

    public function register(string $username, string $email, string $password): array {
        if (empty($username) || empty($email) || empty($password)) {
            return ['success' => false, 'message' => 'لطفاً تمام فیلدها را پر کنید.'];
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'message' => 'ایمیل وارد شده معتبر نیست.'];
        }

        if (strlen($password) < 8) {
            return ['success' => false, 'message' => 'کلمه عبور باید حداقل ۸ کاراکتر باشد.'];
        }

        $stmt = $this->db->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);
        if ($stmt->fetch()) {
            return ['success' => false, 'message' => 'نام کاربری یا ایمیل قبلاً ثبت شده است.'];
        }

        $passwordHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

        // تولید کد اضطراری/پشتیبان (Recovery Code)
        $rawRecoveryCode = strtoupper(bin2hex(random_bytes(4)) . '-' . bin2hex(random_bytes(4)));
        $recoveryCodeHash = password_hash($rawRecoveryCode, PASSWORD_BCRYPT);

        $totpSecret = $this->generateTotpSecret();

        $stmt = $this->db->prepare(
            "INSERT INTO users (username, email, password_hash, twofa_secret, recovery_code_hash) VALUES (?, ?, ?, ?, ?)"
        );
        $stmt->execute([$username, $email, $passwordHash, $totpSecret, $recoveryCodeHash]);
        $userId = (int)$this->db->lastInsertId();

        $this->logAction($userId, 'USER_REGISTERED');
        
        $qrCodeDataUri = $this->tfa->getQRCodeImageAsDataUri($email, $totpSecret);
        $_SESSION['temp_reg_user_id'] = $userId;

        return [
            'success'       => true,
            'message'       => 'ثبت‌نام با موفقیت انجام شد. می‌توانید ۲FA را فعال کرده و کد پشتیبان را ذخیره کنید.',
            'secret'        => $totpSecret,
            'qr_code'       => $qrCodeDataUri,
            'recovery_code' => $rawRecoveryCode
        ];
    }

    // =========================================================================
    // ۲.۵. تأیید 2FA پس از ثبت‌نام
    // =========================================================================

    public function confirmRegistration2FA(string $code): array {
        if (!isset($_SESSION['temp_reg_user_id'])) {
            return ['success' => false, 'message' => 'نشست ثبت‌نام یافت نشد. لطفاً از طریق پنل کاربری اقدام کنید.'];
        }

        $userId = $_SESSION['temp_reg_user_id'];
        $stmt = $this->db->prepare("SELECT twofa_secret FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user || !$user['twofa_secret']) {
            return ['success' => false, 'message' => 'اطلاعات کاربر نامعتبر است.'];
        }

        if (!$this->tfa->verifyCode($user['twofa_secret'], $code)) {
            return ['success' => false, 'message' => 'کد تأیید وارد شده نادرست است.'];
        }

        $stmt = $this->db->prepare("UPDATE users SET is_2fa_enabled = 1 WHERE id = ?");
        $stmt->execute([$userId]);

        unset($_SESSION['temp_reg_user_id']);
        $this->logAction($userId, '2FA_ENABLED_DURING_REG');

        return ['success' => true, 'message' => 'احراز هویت دو مرحله‌ای با موفقیت فعال شد.'];
    }

    // =========================================================================
    // ۳. بازیابی حساب با Recovery Code
    // =========================================================================

    public function recoverAccount(string $identity, string $recoveryCode, string $newPassword): array {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$identity, $identity]);
        $user = $stmt->fetch();

        if (!$user || empty($user['recovery_code_hash'])) {
            return ['success' => false, 'message' => 'اطلاعات وارد شده معتبر نیست.'];
        }

        if (!password_verify($recoveryCode, $user['recovery_code_hash'])) {
            $this->logAction($user['id'], 'RECOVERY_FAILED');
            return ['success' => false, 'message' => 'کد پشتیبان وارد شده نادرست است.'];
        }

        if (strlen($newPassword) < 8) {
            return ['success' => false, 'message' => 'رمز عبور جدید باید حداقل ۸ کاراکتر باشد.'];
        }

        $newPasswordHash = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
        $newRawRecoveryCode = strtoupper(bin2hex(random_bytes(4)) . '-' . bin2hex(random_bytes(4)));
        $newRecoveryHash = password_hash($newRawRecoveryCode, PASSWORD_BCRYPT);

        // بازنشانی 2FA و رمز عبور
        $stmt = $this->db->prepare(
            "UPDATE users SET password_hash = ?, is_2fa_enabled = 0, recovery_code_hash = ? WHERE id = ?"
        );
        $stmt->execute([$newPasswordHash, $newRecoveryHash, $user['id']]);

        $this->logAction($user['id'], 'ACCOUNT_RECOVERED');

        return [
            'success'          => true,
            'message'          => 'حساب شما بازیابی شد و 2FA غیرفعال گردید.',
            'new_recovery_code' => $newRawRecoveryCode
        ];
    }

    // =========================================================================
    // ۴. ورود دو مرحله‌ای و مدیریت نشست‌ها
    // =========================================================================

    public function loginStep1(string $identity, string $password): array {
        $rateCheck = $this->checkRateLimit('login');
        if (!$rateCheck['allowed']) {
            return ['success' => false, 'message' => $rateCheck['message']];
        }

        $stmt = $this->db->prepare("SELECT * FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$identity, $identity]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            $this->hitRateLimit('login');
            $this->logAction(null, 'LOGIN_FAILED_CREDENTIALS');
            return ['success' => false, 'message' => 'نام کاربری یا کلمه عبور اشتباه است.'];
        }

        if ($user['is_2fa_enabled']) {
            $_SESSION['2fa_pending_user_id'] = $user['id'];
            return [
                'success'      => true,
                'requires_2fa' => true,
                'message'      => 'کد ۶ رقمی Authenticator را وارد کنید.'
            ];
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $this->resetRateLimit($ip, 'login');
        return $this->completeLogin($user);
    }

    public function loginStep2(string $code): array {
        if (!isset($_SESSION['2fa_pending_user_id'])) {
            return ['success' => false, 'message' => 'نشست نامعتبر است. مجدداً تلاش کنید.'];
        }

        $userId = $_SESSION['2fa_pending_user_id'];
        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user || !$user['twofa_secret']) {
            return ['success' => false, 'message' => 'خطا در بازیابی اطلاعات 2FA.'];
        }

        if (!$this->tfa->verifyCode($user['twofa_secret'], $code)) {
            $this->logAction($userId, 'LOGIN_FAILED_2FA');
            return ['success' => false, 'message' => 'کد ۲FA وارد شده اشتباه است.'];
        }

        unset($_SESSION['2fa_pending_user_id']);
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $this->resetRateLimit($ip, 'login');

        return $this->completeLogin($user);
    }

    public function generate2FASetup(int $userId): array {
        $stmt = $this->db->prepare("SELECT email FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        $secret = $this->tfa->createSecret();
        $_SESSION['temp_2fa_secret'] = $secret;

        $qrCodeDataUri = $this->tfa->getQRCodeImageAsDataUri($user['email'], $secret);

        return [
            'secret'  => $secret,
            'qr_code' => $qrCodeDataUri
        ];
    }

    public function enable2FA(int $userId, string $code): array {
        if (!isset($_SESSION['temp_2fa_secret'])) {
            return ['success' => false, 'message' => 'کلید موقت یافت نشد.'];
        }

        $secret = $_SESSION['temp_2fa_secret'];

        if (!$this->tfa->verifyCode($secret, $code)) {
            return ['success' => false, 'message' => 'کد تأیید نادرست است.'];
        }

        $stmt = $this->db->prepare("UPDATE users SET twofa_secret = ?, is_2fa_enabled = 1 WHERE id = ?");
        $stmt->execute([$secret, $userId]);

        unset($_SESSION['temp_2fa_secret']);
        $this->logAction($userId, '2FA_ENABLED');

        return ['success' => true, 'message' => 'احراز هویت دو مرحله‌ای با موفقیت فعال شد.'];
    }

    public function get2FAStatus(int $userId): array {
        $stmt = $this->db->prepare("SELECT is_2fa_enabled FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user) {
            return ['success' => false, 'message' => 'کاربر یافت نشد.'];
        }

        return [
            'success' => true,
            'enabled' => (bool)$user['is_2fa_enabled']
        ];
    }

    public function disable2FA(int $userId): array {
        $stmt = $this->db->prepare("UPDATE users SET is_2fa_enabled = 0, twofa_secret = NULL WHERE id = ?");
        $stmt->execute([$userId]);

        $this->logAction($userId, '2FA_DISABLED');

        return ['success' => true, 'message' => 'احراز هویت دو مرحله‌ای غیرفعال شد.'];
    }

    // =========================================================================
    // ۵. مدیریت نشست‌های فعال (Session Management UI)
    // =========================================================================

    public function getUserSessions(int $userId): array {
        $currentSessionId = session_id();
        $stmt = $this->db->prepare("SELECT id, session_id, ip_address, user_agent, last_activity FROM user_sessions WHERE user_id = ? ORDER BY last_activity DESC");
        $stmt->execute([$userId]);
        $sessions = $stmt->fetchAll();

        foreach ($sessions as &$sess) {
            $sess['is_current'] = ($sess['session_id'] === $currentSessionId);
            unset($sess['session_id']); // عدم ارسال هش کامل session_id به کلاینت
        }

        return $sessions;
    }

    public function revokeSession(int $userId, int $sessionId): array {
        $stmt = $this->db->prepare("DELETE FROM user_sessions WHERE id = ? AND user_id = ?");
        $stmt->execute([$sessionId, $userId]);

        $this->logAction($userId, 'SESSION_REVOKED');
        return ['success' => true, 'message' => 'نشست با موفقیت خاتمه یافت.'];
    }

    public function logout(): void {
        if (isset($_SESSION['user_id'])) {
            $currentSessionId = session_id();
            $stmt = $this->db->prepare("DELETE FROM user_sessions WHERE session_id = ?");
            $stmt->execute([$currentSessionId]);

            $this->logAction($_SESSION['user_id'], 'USER_LOGGED_OUT');
        }

        $_SESSION = array();
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        session_destroy();
    }

    private function completeLogin(array $user): array {
        session_regenerate_id(true);
        $currentSessionId = session_id();

        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];

        $ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
        $agent = $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN';

        // ثبت نشست در دیتابیس
        $stmt = $this->db->prepare(
            "INSERT INTO user_sessions (session_id, user_id, ip_address, user_agent) 
             VALUES (?, ?, ?, ?) 
             ON DUPLICATE KEY UPDATE ip_address = VALUES(ip_address), user_agent = VALUES(user_agent), last_activity = CURRENT_TIMESTAMP"
        );
        $stmt->execute([$currentSessionId, $user['id'], $ip, $agent]);

        $this->logAction($user['id'], 'USER_LOGGED_IN');

        return [
            'success'      => true,
            'requires_2fa' => false,
            'message'      => 'ورود با موفقیت انجام شد.'
        ];
    }

    private function generateTotpSecret(int $length = 16): string {
        $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        for ($i = 0; $i < $length; $i++) {
            $secret .= $base32Chars[random_int(0, 31)];
        }
        return $secret;
    }

    private function logAction(?int $userId, string $action): void {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
        $agent = $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN';

        $stmt = $this->db->prepare("INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)");
        $stmt->execute([$userId, $action, $ip, $agent]);
    }
}