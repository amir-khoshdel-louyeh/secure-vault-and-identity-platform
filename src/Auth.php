<?php
require_once dirname(__DIR__) . '/config/config.php';
require_once __DIR__ . '/DB.php';
require_once dirname(__DIR__) . '/vendor/autoload.php';

use RobThree\Auth\TwoFactorAuth;

class Auth {
    private PDO $db;
    private TwoFactorAuth $tfa;

    public function __construct() {
        $this->db = getDBConnection();
        $this->tfa = new TwoFactorAuth('SecureVault');
    }

    // =========================================================================
    // 1. Rate Limiting & Brute Force Protection
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
                    'message' => "Due to multiple failed attempts, your account is temporarily blocked. Please try again in {$remaining} minutes."
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
    // 2. Registration and Master Recovery Code Generation
    // =========================================================================

    public function register(string $username, string $email, string $password): array {
        if (empty($username) || empty($email) || empty($password)) {
            return ['success' => false, 'message' => 'Please fill in all fields.'];
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'message' => 'Invalid email address.'];
        }

        if (strlen($password) < 8) {
            return ['success' => false, 'message' => 'Password must be at least 8 characters long.'];
        }

        $stmt = $this->db->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);
        if ($stmt->fetch()) {
            return ['success' => false, 'message' => 'Username or email is already registered.'];
        }

        $passwordHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

        // Generate Emergency/Recovery Code
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
            'message'       => 'Registration successful. You can enable 2FA and save your recovery code.',
            'secret'        => $totpSecret,
            'qr_code'       => $qrCodeDataUri,
            'recovery_code' => $rawRecoveryCode
        ];
    }

    // =========================================================================
    // 2.5. Verify 2FA after Registration
    // =========================================================================

    public function confirmRegistration2FA(string $code): array {
        if (!isset($_SESSION['temp_reg_user_id'])) {
            return ['success' => false, 'message' => 'Registration session not found. Please proceed via the user panel.'];
        }

        $userId = $_SESSION['temp_reg_user_id'];
        $stmt = $this->db->prepare("SELECT twofa_secret FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user || !$user['twofa_secret']) {
            return ['success' => false, 'message' => 'Invalid user information.'];
        }

        if (!$this->tfa->verifyCode($user['twofa_secret'], $code)) {
            return ['success' => false, 'message' => 'Incorrect verification code.'];
        }

        $stmt = $this->db->prepare("UPDATE users SET is_2fa_enabled = 1 WHERE id = ?");
        $stmt->execute([$userId]);

        unset($_SESSION['temp_reg_user_id']);
        $this->logAction($userId, '2FA_ENABLED_DURING_REG');

        return ['success' => true, 'message' => 'Two-factor authentication enabled successfully.'];
    }

    // =========================================================================
    // 3. Account Recovery with Recovery Code
    // =========================================================================

    public function recoverAccount(string $identity, string $recoveryCode, string $newPassword): array {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$identity, $identity]);
        $user = $stmt->fetch();

        if (!$user || empty($user['recovery_code_hash'])) {
            return ['success' => false, 'message' => 'Invalid information provided.'];
        }

        if (!password_verify($recoveryCode, $user['recovery_code_hash'])) {
            $this->logAction($user['id'], 'RECOVERY_FAILED');
            return ['success' => false, 'message' => 'Incorrect recovery code.'];
        }

        if (strlen($newPassword) < 8) {
            return ['success' => false, 'message' => 'New password must be at least 8 characters long.'];
        }

        $newPasswordHash = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
        $newRawRecoveryCode = strtoupper(bin2hex(random_bytes(4)) . '-' . bin2hex(random_bytes(4)));
        $newRecoveryHash = password_hash($newRawRecoveryCode, PASSWORD_BCRYPT);

        // Reset 2FA and password
        $stmt = $this->db->prepare(
            "UPDATE users SET password_hash = ?, is_2fa_enabled = 0, recovery_code_hash = ? WHERE id = ?"
        );
        $stmt->execute([$newPasswordHash, $newRecoveryHash, $user['id']]);

        $this->logAction($user['id'], 'ACCOUNT_RECOVERED');

        return [
            'success'          => true,
            'message'          => 'Your account has been recovered and 2FA disabled.',
            'new_recovery_code' => $newRawRecoveryCode
        ];
    }

    // =========================================================================
    // 4. Two-Step Login and Session Management
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
            return ['success' => false, 'message' => 'Incorrect username or password.'];
        }

        if ($user['is_2fa_enabled']) {
            $_SESSION['2fa_pending_user_id'] = $user['id'];
            return [
                'success'      => true,
                'requires_2fa' => true,
                'message'      => 'Enter the 6-digit Authenticator code.'
            ];
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $this->resetRateLimit($ip, 'login');
        return $this->completeLogin($user);
    }

    public function loginStep2(string $code): array {
        if (!isset($_SESSION['2fa_pending_user_id'])) {
            return ['success' => false, 'message' => 'Invalid session. Please try again.'];
        }

        $userId = $_SESSION['2fa_pending_user_id'];
        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user || !$user['twofa_secret']) {
            return ['success' => false, 'message' => 'Error retrieving 2FA information.'];
        }

        if (!$this->tfa->verifyCode($user['twofa_secret'], $code)) {
            $this->logAction($userId, 'LOGIN_FAILED_2FA');
            return ['success' => false, 'message' => 'Incorrect 2FA code.'];
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
            return ['success' => false, 'message' => 'Temporary key not found.'];
        }

        $secret = $_SESSION['temp_2fa_secret'];

        if (!$this->tfa->verifyCode($secret, $code)) {
            return ['success' => false, 'message' => 'Incorrect verification code.'];
        }

        $stmt = $this->db->prepare("UPDATE users SET twofa_secret = ?, is_2fa_enabled = 1 WHERE id = ?");
        $stmt->execute([$secret, $userId]);

        unset($_SESSION['temp_2fa_secret']);
        $this->logAction($userId, '2FA_ENABLED');

        return ['success' => true, 'message' => 'Two-factor authentication enabled successfully.'];
    }

    public function get2FAStatus(int $userId): array {
        $stmt = $this->db->prepare("SELECT is_2fa_enabled FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user) {
            return ['success' => false, 'message' => 'User not found.'];
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

        return ['success' => true, 'message' => 'Two-factor authentication disabled.'];
    }

    // =========================================================================
    // 5. Active Sessions Management (Session Management UI)
    // =========================================================================

    public function getUserSessions(int $userId): array {
        $currentSessionId = session_id();
        $stmt = $this->db->prepare("SELECT id, session_id, ip_address, user_agent, last_activity FROM user_sessions WHERE user_id = ? ORDER BY last_activity DESC");
        $stmt->execute([$userId]);
        $sessions = $stmt->fetchAll();

        foreach ($sessions as &$sess) {
            $sess['is_current'] = ($sess['session_id'] === $currentSessionId);
            unset($sess['session_id']); // Do not send full session_id hash to the client
        }

        return $sessions;
    }

    public function revokeSession(int $userId, int $sessionId): array {
        $stmt = $this->db->prepare("DELETE FROM user_sessions WHERE id = ? AND user_id = ?");
        $stmt->execute([$sessionId, $userId]);

        $this->logAction($userId, 'SESSION_REVOKED');
        return ['success' => true, 'message' => 'Session terminated successfully.'];
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

        // Register session in the database
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
            'message'      => 'Login successful.'
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