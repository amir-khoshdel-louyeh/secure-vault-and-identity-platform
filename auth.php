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
        // ایجاد نمونه 2FA با نام پروژه برای نمایش در اپلیکیشن Authenticator
        $this->tfa = new TwoFactorAuth('SecureVault');
    }

    /**
     * ثبت‌نام کاربر جدید
     */
    public function register(string $username, string $email, string $password): array {
        // ۱. اعتبارسنجی اولیه
        if (empty($username) || empty($email) || empty($password)) {
            return ['success' => false, 'message' => 'لطفا تمام فیلدها را پر کنید.'];
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'message' => 'ایمیل وارد شده معتبر نیست.'];
        }

        if (strlen($password) < 8) {
            return ['success' => false, 'message' => 'کلمه عبور باید حداقل ۸ کاراکتر باشد.'];
        }

        // ۲. بررسی عدم وجود کاربر تکراری
        $stmt = $this->db->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);
        if ($stmt->fetch()) {
            return ['success' => false, 'message' => 'نام کاربری یا ایمیل قبلا ثبت شده است.'];
        }

        // ۳. هش کردن پسورد با Bcrypt
        $passwordHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

        // ۴. تولید کلید اختصاصی TOTP
        $totpSecret = $this->generateTotpSecret();

        // ۵. ذخیره در دیتابیس (ارسال totp_secret)
        $stmt = $this->db->prepare("INSERT INTO users (username, email, password_hash, totp_secret) VALUES (?, ?, ?, ?)");
        $stmt->execute([$username, $email, $passwordHash, $totpSecret]);
        $userId = (int)$this->db->lastInsertId();

        $this->logAction($userId, 'USER_REGISTERED');

        // ۶. بازگرداندن کلید secret برای فرانت‌اند
        return [
            'success' => true,
            'message' => 'ثبت‌نام با موفقیت انجام شد.',
            'secret'  => $totpSecret
        ];
    }

    /**
     * مرحله اول ورود: بررسی نام کاربری/ایمیل و کلمه عبور
     */
    public function loginStep1(string $identity, string $password): array {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$identity, $identity]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            $this->logAction(null, 'LOGIN_FAILED_CREDENTIALS');
            return ['success' => false, 'message' => 'نام کاربری یا کلمه عبور اشتباه است.'];
        }

        // اگر 2FA فعال باشد، کاربر به مرحله ۲ هدایت می‌شود
        if ($user['is_2fa_enabled']) {
            $_SESSION['2fa_pending_user_id'] = $user['id'];
            return [
                'success' => true,
                'requires_2fa' => true,
                'message' => 'کد ۶ رقمی Authenticator را وارد کنید.'
            ];
        }

        // در غیر این صورت ورود کامل انجام می‌شود
        return $this->completeLogin($user);
    }

    /**
     * مرحله دوم ورود: اعتبارسنجی کد TOTP 2FA
     */
    public function loginStep2(string $code): array {
        if (!isset($_SESSION['2fa_pending_user_id'])) {
            return ['success' => false, 'message' => 'نشست نامعتبر است. مجددا تلاش کنید.'];
        }

        $userId = $_SESSION['2fa_pending_user_id'];
        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user || !$user['twofa_secret']) {
            return ['success' => false, 'message' => 'خطا در بازیابی اطلاعات 2FA.'];
        }

        // بررسی صحت کد ۶ رقمی
        if (!$this->tfa->verifyCode($user['twofa_secret'], $code)) {
            $this->logAction($userId, 'LOGIN_FAILED_2FA');
            return ['success' => false, 'message' => 'کد ۲FA وارد شده اشتباه است.'];
        }

        unset($_SESSION['2fa_pending_user_id']);
        return $this->completeLogin($user);
    }

    /**
     * تولید کلید Secret و QR Code برای فعال‌سازی 2FA
     */
    public function generate2FASetup(int $userId): array {
        $stmt = $this->db->prepare("SELECT email FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        $secret = $this->tfa->createSecret();
        $_SESSION['temp_2fa_secret'] = $secret;

        // لینک تصویر QR Code به صورت Inline Data URI
        $qrCodeDataUri = $this->tfa->getQRCodeImageAsDataUri($user['email'], $secret);

        return [
            'secret' => $secret,
            'qr_code' => $qrCodeDataUri
        ];
    }

    /**
     * تأیید نهایی و فعال‌سازی 2FA برای حساب کاربر
     */
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

    /**
     * خروج کامل از حساب کاربری
     */
    public function logout(): void {
        if (isset($_SESSION['user_id'])) {
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

    /**
     * تکمیل فرایند ورود و ایجاد Session امن
     */
    private function completeLogin(array $user): array {
        session_regenerate_id(true); // پیشگیری از Session Fixation
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];

        $this->logAction($user['id'], 'USER_LOGGED_IN');

        return [
            'success' => true,
            'requires_2fa' => false,
            'message' => 'ورود با موفقیت انجام شد.'
        ];
    }

    /**
     * ثبت رویداد امنیتی در جدول audit_logs
     */
    private function logAction(?int $userId, string $action): void {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
        $agent = $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN';

        $stmt = $this->db->prepare("INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)");
        $stmt->execute([$userId, $action, $ip, $agent]);
    }
    private function generateTotpSecret(int $length = 16): string {
    $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < $length; $i++) {
        $secret .= $base32Chars[random_int(0, 31)];
    }
    return $secret;
}
}