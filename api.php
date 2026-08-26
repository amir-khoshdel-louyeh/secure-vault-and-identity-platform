<?php
// ۱. تنظیم هدرهای پاسخ و امنیت
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/vault.php';
require_once __DIR__ . '/sharemanager.php';

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

// ورود کاربر (احراز هویت دومرحله‌ای یا رمز عبور)
if ($action === 'login') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendJsonResponse(false, 'روش درخواست نامعتبر است.', [], 405);
    }

    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $totpCode = trim($_POST['totp_code'] ?? $_POST['totp'] ?? '');

    $result = $auth->login($username, $password, $totpCode);
    if ($result['success']) {
        sendJsonResponse(true, $result['message']);
    } else {
        sendJsonResponse(false, $result['message'], [], 400);
    }
}

// ثبت نام کاربر جدید
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
        // دریافت کلید secret از نام‌های مختلف احتمالی در آرایه خروجی
        $secret = $result['secret'] ?? $result['totp_secret'] ?? $result['data']['secret'] ?? null;
        $qrCode = $result['qr_code_url'] ?? $result['qr_code'] ?? null;

        sendJsonResponse(true, $result['message'], [
            'secret'      => $secret,
            'qr_code_url' => $qrCode
        ]);
    } else {
        sendJsonResponse(false, $result['message'], [], 400);
    }
}

// ==========================================
// ۴. بررسی احراز هویت برای سایر مسیرها
// ==========================================
// پشتیبانی از هر دو متد isLoggedIn و check جهت جلوگیری از خطای Fatal Error
$isLoggedIn = method_exists($auth, 'isLoggedIn') ? $auth->isLoggedIn() : (method_exists($auth, 'check') ? $auth->check() : isset($_SESSION['user_id']));

if (!$isLoggedIn) {
    sendJsonResponse(false, 'لطفا ابتدا وارد حساب کاربری خود شوید.', [], 401);
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

        // --- مدیریت فایل‌ها (با استفاده از کلاس Vault) ---
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

        case 'delete_file':
            $fileId = (int)($_POST['file_id'] ?? 0);
            $res = $vault->deleteFile($userId, $fileId);
            sendJsonResponse($res['success'], $res['message'], [], $res['success'] ? 200 : 400);
            break;

        // --- مدیریت یادداشت‌ها (با استفاده از کلاس Vault) ---
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
            $res = $vault->getNoteContent($userId, $noteId);
            sendJsonResponse($res['success'], $res['message'], $res['success'] ? ['note' => $res['note']] : [], $res['success'] ? 200 : 404);
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