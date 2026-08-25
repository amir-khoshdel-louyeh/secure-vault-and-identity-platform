<?php
// جلوگیری از دسترسی مستقیم به فایل
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    http_response_code(403);
    exit('دسترسی مستقیم مجاز نیست.');
}

// -----------------------------------------------------------------------------
// ۱. تنظیمات پایگاه داده (Database Configuration)
// -----------------------------------------------------------------------------
define('DB_HOST', 'localhost');
define('DB_NAME', 'secure_vault');
define('DB_USER', 'vault_user');
define('DB_PASS', 'VaultSecret123!');

// -----------------------------------------------------------------------------
// ۲. تنظیمات رمزنگاری متمرکز (Encryption Configuration)
// -----------------------------------------------------------------------------
// کلید اصلی 256 بیتی (32 بایت) - در محیط واقعی این کلید را تغییر دهید
define('ENCRYPTION_KEY', 'a6f8c2e1b4d3e5f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1');
define('ENCRYPTION_CIPHER', 'aes-256-cbc');

// -----------------------------------------------------------------------------
// ۳. مسیر ذخیره‌سازی فایل‌های رمزنگاری‌شده (Storage Path)
// -----------------------------------------------------------------------------
define('STORAGE_DIR', __DIR__ . '/uploads/');

// -----------------------------------------------------------------------------
// ۴. تنظیم هدرهای امنیتی HTTP (Security Headers)
// -----------------------------------------------------------------------------
header("X-Frame-Options: DENY"); // جلوگیری از حملات Clickjacking
header("X-Content-Type-Options: nosniff"); // جلوگیری از MIME Sniffing
header("X-XSS-Protection: 1; mode=block"); // فعال‌سازی فیلتر XSS مرورگر
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");

// -----------------------------------------------------------------------------
// ۵. مدیریت امن نشست‌ها (Secure Session Management)
// -----------------------------------------------------------------------------
if (session_status() === PHP_SESSION_NONE) {
    // تنظیم پیکربندی کوکی نشست پیش از شروع session
    ini_set('session.use_only_cookies', 1);
    ini_set('session.use_strict_mode', 1);

    session_set_cookie_params([
        'lifetime' => 0,             // با بستن مرورگر منقضی می‌شود
        'path'     => '/',
        'domain'   => '',
        'secure'   => false,          // در صورت استفاده از HTTPS مقدار را true کنید
        'httponly' => true,           // غیرقابل دسترس برای اسکریپت‌های JS (مقابله با XSS)
        'samesite' => 'Strict'        // مقابله با حملات CSRF
    ]);

    session_start();
}

// بازتولید ID نشست برای جلوگیری از Session Fixation
if (!isset($_SESSION['last_regeneration'])) {
    session_regenerate_id(true);
    $_SESSION['last_regeneration'] = time();
} else if (time() - $_SESSION['last_regeneration'] > 1800) { // هر ۳۰ دقیقه
    session_regenerate_id(true);
    $_SESSION['last_regeneration'] = time();
}

// -----------------------------------------------------------------------------
// ۶. مدیریت توکن CSRF (Centralized CSRF Token)
// -----------------------------------------------------------------------------
function generateCSRFToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken(?string $token): bool {
    if (!isset($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}