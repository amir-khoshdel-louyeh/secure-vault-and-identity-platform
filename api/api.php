<?php
// ۱. تنظیم هدرهای پاسخ و امنیت (در صورت دانلود، هدر JSON ارسال نمی‌شود)
if (($_REQUEST['action'] ?? '') !== 'download_file') {
    header('Content-Type: application/json; charset=utf-8');
}
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

require_once dirname(__DIR__) . '/config/config.php';
require_once dirname(__DIR__) . '/src/DB.php';
require_once dirname(__DIR__) . '/src/Crypto.php';
require_once dirname(__DIR__) . '/src/Auth.php';
require_once dirname(__DIR__) . '/src/Vault.php';
require_once dirname(__DIR__) . '/src/ShareManager.php';

// تابع کمکی برای ارسال پاسخ JSON و خروج
function sendJsonResponse(bool $success, string $message, array $extraData = [], int $httpCode = 200): void {
    http_response_code($httpCode);
    echo json_encode(array_merge([
        'success' => $success,
        'message' => $message
    ], $extraData), JSON_UNESCAPED_UNICODE);
    exit;
}

// ۲. راه‌اندازی سشن امن
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_secure'   => isset($_SERVER['HTTPS']),
        'cookie_samesite' => 'Strict'
    ]);
}

$auth = new Auth();
$action = $_REQUEST['action'] ?? '';

// ==========================================
// ۳. مسیرهای عمومی (بدون نیاز به لاگین)
// ==========================================

// ورود مرحله ۱ (نام کاربری و کلمه عبور)
if ($action === 'login' || $action === 'login_step1') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendJsonResponse(false, 'روش درخواست نامعتبر است.', [], 405);
    }

    $identity = trim($_POST['identity'] ?? $_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($identity) || empty($password)) {
        sendJsonResponse(false, 'لطفاً نام کاربری و کلمه عبور را وارد کنید.', [], 400);
    }

    $result = $auth->loginStep1($identity, $password);
    if ($result['success']) {
        sendJsonResponse(true, $result['message'], [
            'requires_2fa' => $result['requires_2fa'] ?? false
        ]);
    } else {
        sendJsonResponse(false, $result['message'], [], 400);
    }
}

// ورود مرحله ۲ (تأیید کد TOTP)
if ($action === 'login_step2') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendJsonResponse(false, 'روش درخواست نامعتبر است.', [], 405);
    }

    $code = trim($_POST['code'] ?? $_POST['totp_code'] ?? '');
    if (empty($code)) {
        sendJsonResponse(false, 'لطفاً کد ۶ رقمی را وارد کنید.', [], 400);
    }

    $result = $auth->loginStep2($code);
    if ($result['success']) {
        sendJsonResponse(true, $result['message']);
    } else {
        sendJsonResponse(false, $result['message'], [], 400);
    }
}

// ثبت‌نام کاربر جدید
if ($action === 'register') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendJsonResponse(false, 'روش درخواست نامعتبر است.', [], 405);
    }

    $username = trim($_POST['username'] ?? '');
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($email) && !empty($username)) {
        $email = $username . '@vault.local';
    }

    $result = $auth->register($username, $email, $password);
    if ($result['success']) {
        sendJsonResponse(true, $result['message'], [
            'secret'        => $result['secret'] ?? null,
            'qr_code'       => $result['qr_code'] ?? null,
            'recovery_code' => $result['recovery_code'] ?? null
        ]);
    } else {
        sendJsonResponse(false, $result['message'], [], 400);
    }
}

// تأیید 2FA پس از ثبت‌نام
if ($action === 'confirm_reg_2fa') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendJsonResponse(false, 'روش درخواست نامعتبر است.', [], 405);
    }

    $code = trim($_POST['code'] ?? $_POST['totp_code'] ?? '');
    if (empty($code)) {
        sendJsonResponse(false, 'لطفاً کد ۶ رقمی را وارد کنید.', [], 400);
    }

    $result = $auth->confirmRegistration2FA($code);
    if ($result['success']) {
        sendJsonResponse(true, $result['message']);
    } else {
        sendJsonResponse(false, $result['message'], [], 400);
    }
}

// بازیابی حساب با Recovery Code
if ($action === 'recover_account') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendJsonResponse(false, 'روش درخواست نامعتبر است.', [], 405);
    }

    $identity     = trim($_POST['identity'] ?? $_POST['username'] ?? '');
    $recoveryCode = trim($_POST['recovery_code'] ?? '');
    $newPassword  = $_POST['new_password'] ?? '';

    $result = $auth->recoverAccount($identity, $recoveryCode, $newPassword);
    if ($result['success']) {
        sendJsonResponse(true, $result['message'], [
            'new_recovery_code' => $result['new_recovery_code']
        ]);
    } else {
        sendJsonResponse(false, $result['message'], [], 400);
    }
}

// ==========================================
// ۴. بررسی احراز هویت برای سایر مسیرها
// ==========================================
$isLoggedIn = isset($_SESSION['user_id']);

if (!$isLoggedIn) {
    sendJsonResponse(false, 'لطفاً ابتدا وارد حساب کاربری خود شوید.', [], 401);
}

$userId = $_SESSION['user_id'];

// ساخت توکن CSRF در صورت عدم وجود
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ==========================================
// ۵. اعتبارسنجی توکن CSRF (برای درخواست‌های تغییر دهنده POST)
// ==========================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $clientCsrf = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $clientCsrf)) {
        sendJsonResponse(false, 'اعتبارسنجی توکن امنیت (CSRF) با خطا مواجه شد.', [], 403);
    }
}

// ==========================================
// ۶. مسیریابی درخواست‌های احرازهویت‌شده
// ==========================================
try {
    $vault = new Vault();

    switch ($action) {

        // --- خروج از حساب ---
        case 'logout':
            $auth->logout();
            sendJsonResponse(true, 'با موفقیت از سیستم خارج شدید.');
            break;

        // --- دریافت اطلاعات کاربر و CSRF ---
        case 'get_user_info':
            sendJsonResponse(true, 'اطلاعات دریافت شد.', [
                'user_id'    => $userId,
                'username'   => $_SESSION['username'] ?? '',
                'csrf_token' => $_SESSION['csrf_token']
            ]);
            break;

        // --- مدیریت ۲FA (تولید QR و فعال‌سازی) ---
        case '2fa_status':
            $res = $auth->get2FAStatus($userId);
            sendJsonResponse($res['success'], $res['message'] ?? 'موفق', ['enabled' => $res['enabled'] ?? false], $res['success'] ? 200 : 400);
            break;

        case 'setup_2fa':
            $setup = $auth->generate2FASetup($userId);
            sendJsonResponse(true, 'اطلاعات ۲FA تولید شد.', $setup);
            break;

        case 'enable_2fa':
            $code = trim($_POST['code'] ?? '');
            $res = $auth->enable2FA($userId, $code);
            sendJsonResponse($res['success'], $res['message'], [], $res['success'] ? 200 : 400);
            break;

        case 'disable_2fa':
            $res = $auth->disable2FA($userId);
            sendJsonResponse($res['success'], $res['message'], [], $res['success'] ? 200 : 400);
            break;

        // --- مدیریت نشست‌ها (User Sessions) ---
        case 'get_sessions':
            $sessions = $auth->getUserSessions($userId);
            sendJsonResponse(true, 'لیست نشست‌های فعال دریافت شد.', ['sessions' => $sessions]);
            break;

        case 'revoke_session':
            $sessionId = (int)($_POST['session_db_id'] ?? 0);
            $res = $auth->revokeSession($userId, $sessionId);
            sendJsonResponse($res['success'], $res['message'], [], $res['success'] ? 200 : 400);
            break;

        // --- مدیریت فایل‌ها (Vault) ---
        case 'upload_file':
            if (!isset($_FILES['file'])) {
                sendJsonResponse(false, 'فایلی ارسال نشده است.', [], 400);
            }
            $res = $vault->uploadFile($userId, $_FILES['file']);
            sendJsonResponse($res['success'], $res['message'], $res['success'] ? ['file_id' => $res['file_id']] : [], $res['success'] ? 200 : 400);
            break;

        case 'list_files':
            $files = $vault->getUserFiles($userId);
            sendJsonResponse(true, 'لیست فایل‌ها دریافت شد.', ['files' => $files]);
            break;

        case 'download_file':
            $fileId = (int)($_GET['id'] ?? 0);
            if ($fileId <= 0) {
                sendJsonResponse(false, 'شناسه فایل نامعتبر است.', [], 400);
            }
            $vault->downloadFile($userId, $fileId);
            exit;

        case 'delete_file':
            $fileId = (int)($_POST['file_id'] ?? 0);
            $res = $vault->deleteFile($userId, $fileId);
            sendJsonResponse($res['success'], $res['message'], [], $res['success'] ? 200 : 400);
            break;

        // --- مدیریت یادداشت‌ها (Vault) ---
        case 'create_note':
            $title   = trim($_POST['title'] ?? '');
            $content = $_POST['content'] ?? '';
            $res = $vault->createNote($userId, $title, $content);
            sendJsonResponse($res['success'], $res['message'], $res['success'] ? ['note_id' => $res['note_id']] : [], $res['success'] ? 200 : 400);
            break;

        case 'list_notes':
            $notes = $vault->getUserNotes($userId);
            sendJsonResponse(true, 'لیست یادداشت‌ها دریافت شد.', ['notes' => $notes]);
            break;

        case 'get_note':
            $noteId = (int)($_GET['note_id'] ?? 0);
            $res = $vault->getNote($userId, $noteId);
            sendJsonResponse($res['success'], $res['message'] ?? 'موفق', $res['success'] ? ['note' => $res['note']] : [], $res['success'] ? 200 : 404);
            break;

        case 'delete_note':
            $noteId = (int)($_POST['note_id'] ?? 0);
            $res = $vault->deleteNote($userId, $noteId);
            sendJsonResponse($res['success'], $res['message'], [], $res['success'] ? 200 : 400);
            break;

        // --- ایجاد لینک اشتراک‌گذاری ---
        case 'create_share_link':
            $itemType    = $_POST['item_type'] ?? '';
            $itemId      = (int)($_POST['item_id'] ?? 0);
            $expireHours = (int)($_POST['expire_hours'] ?? 24);
            $maxUses     = (int)($_POST['max_uses'] ?? 1);

            $shareManager = new ShareManager();
            $res = $shareManager->createShareToken($userId, $itemType, $itemId, $expireHours, $maxUses);
            
            if ($res['success']) {
                $downloadUrl = "download.php?token=" . $res['token'];
                sendJsonResponse(true, 'لینک اشتراک‌گذاری با موفقیت ساخته شد.', [
                    'share_url'  => $downloadUrl,
                    'expires_at' => $res['expires_at'],
                    'max_uses'   => $res['max_uses']
                ]);
            } else {
                sendJsonResponse(false, $res['message'], [], 400);
            }
            break;

        default:
            sendJsonResponse(false, 'اکشن درخواست‌شده معتبر نیست.', [], 404);
            break;
    }
} catch (Exception $e) {
    error_log("API Error: " . $e->getMessage());
    sendJsonResponse(false, 'خطایی در پردازش درخواست روی سرور رخ داده است.', [], 500);
}