<?php
// Prevent direct access to the file
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    http_response_code(403);
    exit('Direct access not permitted.');
}

// -----------------------------------------------------------------------------
// 1. Database Configuration
// -----------------------------------------------------------------------------
define('DB_HOST', 'localhost');
define('DB_NAME', 'secure_vault');
define('DB_USER', 'vault_user');
define('DB_PASS', 'VaultSecret123!');

// -----------------------------------------------------------------------------
// 2. Centralized Encryption Configuration
// -----------------------------------------------------------------------------
// Main 256-bit key (32 bytes) - Change this key in a production environment
define('ENCRYPTION_KEY', 'a6f8c2e1b4d3e5f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1');
define('ENCRYPTION_CIPHER', 'aes-256-cbc');

// -----------------------------------------------------------------------------
// 3. Storage Path for Encrypted Files
// -----------------------------------------------------------------------------
define('STORAGE_DIR', __DIR__ . '/uploads/');

// -----------------------------------------------------------------------------
// 4. Set HTTP Security Headers
// -----------------------------------------------------------------------------
header("X-Frame-Options: DENY"); // Prevent Clickjacking attacks
header("X-Content-Type-Options: nosniff"); // Prevent MIME Sniffing
header("X-XSS-Protection: 1; mode=block"); // Enable browser XSS filter
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");

// -----------------------------------------------------------------------------
// 5. Secure Session Management
// -----------------------------------------------------------------------------
if (session_status() === PHP_SESSION_NONE) {
    // Set session cookie configuration before starting the session
    ini_set('session.use_only_cookies', 1);
    ini_set('session.use_strict_mode', 1);

    session_set_cookie_params([
        'lifetime' => 0,             // Expires when the browser is closed
        'path'     => '/',
        'domain'   => '',
        'secure'   => false,          // Set to true if using HTTPS
        'httponly' => true,           // Inaccessible to JS scripts (XSS mitigation)
        'samesite' => 'Strict'        // CSRF mitigation
    ]);

    session_start();
}

// Regenerate session ID to prevent Session Fixation
if (!isset($_SESSION['last_regeneration'])) {
    session_regenerate_id(true);
    $_SESSION['last_regeneration'] = time();
} else if (time() - $_SESSION['last_regeneration'] > 1800) { // Every 30 minutes
    session_regenerate_id(true);
    $_SESSION['last_regeneration'] = time();
}

// -----------------------------------------------------------------------------
// 6. Centralized CSRF Token Management
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