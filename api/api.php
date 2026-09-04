<?php
// 1. Set response headers and security (If downloading, JSON header is not sent)
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

// Helper function to send JSON response and exit
function sendJsonResponse(bool $success, string $message, array $extraData = [], int $httpCode = 200): void {
    http_response_code($httpCode);
    echo json_encode(array_merge([
        'success' => $success,
        'message' => $message
    ], $extraData), JSON_UNESCAPED_UNICODE);
    exit;
}

// 2. Initialize secure session
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
// 3. Public Routes (No login required)
// ==========================================

// Login Step 1 (Username and Password)
if ($action === 'login' || $action === 'login_step1') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendJsonResponse(false, 'Invalid request method.', [], 405);
    }

    $identity = trim($_POST['identity'] ?? $_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($identity) || empty($password)) {
        sendJsonResponse(false, 'Please enter username and password.', [], 400);
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

// Login Step 2 (Verify TOTP Code)
if ($action === 'login_step2') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendJsonResponse(false, 'Invalid request method.', [], 405);
    }

    $code = trim($_POST['code'] ?? $_POST['totp_code'] ?? '');
    if (empty($code)) {
        sendJsonResponse(false, 'Please enter the 6-digit code.', [], 400);
    }

    $result = $auth->loginStep2($code);
    if ($result['success']) {
        sendJsonResponse(true, $result['message']);
    } else {
        sendJsonResponse(false, $result['message'], [], 400);
    }
}

// Register New User
if ($action === 'register') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendJsonResponse(false, 'Invalid request method.', [], 405);
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

// Confirm 2FA After Registration
if ($action === 'confirm_reg_2fa') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendJsonResponse(false, 'Invalid request method.', [], 405);
    }

    $code = trim($_POST['code'] ?? $_POST['totp_code'] ?? '');
    if (empty($code)) {
        sendJsonResponse(false, 'Please enter the 6-digit code.', [], 400);
    }

    $result = $auth->confirmRegistration2FA($code);
    if ($result['success']) {
        sendJsonResponse(true, $result['message']);
    } else {
        sendJsonResponse(false, $result['message'], [], 400);
    }
}

// Recover Account with Recovery Code
if ($action === 'recover_account') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendJsonResponse(false, 'Invalid request method.', [], 405);
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
// 4. Check Authentication for other routes
// ==========================================
$isLoggedIn = isset($_SESSION['user_id']);

if (!$isLoggedIn) {
    sendJsonResponse(false, 'Please log in to your account first.', [], 401);
}

$userId = $_SESSION['user_id'];

// Generate CSRF token if not exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ==========================================
// 5. Validate CSRF Token (for POST requests)
// ==========================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $clientCsrf = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $clientCsrf)) {
        sendJsonResponse(false, 'Security token validation (CSRF) failed.', [], 403);
    }
}

// ==========================================
// 6. Route Authenticated Requests
// ==========================================
try {
    $vault = new Vault();

    switch ($action) {

        // --- Logout ---
        case 'logout':
            $auth->logout();
            sendJsonResponse(true, 'Logged out successfully.');
            break;

        // --- Get User Info and CSRF ---
        case 'get_user_info':
            sendJsonResponse(true, 'Information retrieved successfully.', [
                'user_id'    => $userId,
                'username'   => $_SESSION['username'] ?? '',
                'csrf_token' => $_SESSION['csrf_token']
            ]);
            break;

        // --- Manage 2FA (Generate QR and Enable) ---
        case '2fa_status':
            $res = $auth->get2FAStatus($userId);
            sendJsonResponse($res['success'], $res['message'] ?? 'Success', ['enabled' => $res['enabled'] ?? false], $res['success'] ? 200 : 400);
            break;

        case 'setup_2fa':
            $setup = $auth->generate2FASetup($userId);
            sendJsonResponse(true, '2FA information generated.', $setup);
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

        // --- User Sessions Management ---
        case 'get_sessions':
            $sessions = $auth->getUserSessions($userId);
            sendJsonResponse(true, 'Active sessions retrieved.', ['sessions' => $sessions]);
            break;

        case 'revoke_session':
            $sessionId = (int)($_POST['session_db_id'] ?? 0);
            $res = $auth->revokeSession($userId, $sessionId);
            sendJsonResponse($res['success'], $res['message'], [], $res['success'] ? 200 : 400);
            break;

        // --- File Management (Vault) ---
        case 'upload_file':
            if (!isset($_FILES['file'])) {
                sendJsonResponse(false, 'No file was sent.', [], 400);
            }
            $res = $vault->uploadFile($userId, $_FILES['file']);
            sendJsonResponse($res['success'], $res['message'], $res['success'] ? ['file_id' => $res['file_id']] : [], $res['success'] ? 200 : 400);
            break;

        case 'list_files':
            $files = $vault->getUserFiles($userId);
            sendJsonResponse(true, 'Files retrieved.', ['files' => $files]);
            break;

        case 'download_file':
            $fileId = (int)($_GET['id'] ?? 0);
            if ($fileId <= 0) {
                sendJsonResponse(false, 'Invalid file ID.', [], 400);
            }
            $vault->downloadFile($userId, $fileId);
            exit;

        case 'delete_file':
            $fileId = (int)($_POST['file_id'] ?? 0);
            $res = $vault->deleteFile($userId, $fileId);
            sendJsonResponse($res['success'], $res['message'], [], $res['success'] ? 200 : 400);
            break;

        // --- Note Management (Vault) ---
        case 'create_note':
            $title   = trim($_POST['title'] ?? '');
            $content = $_POST['content'] ?? '';
            $res = $vault->createNote($userId, $title, $content);
            sendJsonResponse($res['success'], $res['message'], $res['success'] ? ['note_id' => $res['note_id']] : [], $res['success'] ? 200 : 400);
            break;

        case 'list_notes':
            $notes = $vault->getUserNotes($userId);
            sendJsonResponse(true, 'Notes retrieved.', ['notes' => $notes]);
            break;

        case 'get_note':
            $noteId = (int)($_GET['note_id'] ?? 0);
            $res = $vault->getNote($userId, $noteId);
            sendJsonResponse($res['success'], $res['message'] ?? 'Success', $res['success'] ? ['note' => $res['note']] : [], $res['success'] ? 200 : 404);
            break;

        case 'delete_note':
            $noteId = (int)($_POST['note_id'] ?? 0);
            $res = $vault->deleteNote($userId, $noteId);
            sendJsonResponse($res['success'], $res['message'], [], $res['success'] ? 200 : 400);
            break;

        // --- Create Share Link ---
        case 'create_share_link':
            $itemType    = $_POST['item_type'] ?? '';
            $itemId      = (int)($_POST['item_id'] ?? 0);
            $expireHours = (int)($_POST['expire_hours'] ?? 24);
            $maxUses     = (int)($_POST['max_uses'] ?? 1);

            $shareManager = new ShareManager();
            $res = $shareManager->createShareToken($userId, $itemType, $itemId, $expireHours, $maxUses);
            
            if ($res['success']) {
                $downloadUrl = "download.php?token=" . $res['token'];
                sendJsonResponse(true, 'Share link created successfully.', [
                    'share_url'  => $downloadUrl,
                    'expires_at' => $res['expires_at'],
                    'max_uses'   => $res['max_uses']
                ]);
            } else {
                sendJsonResponse(false, $res['message'], [], 400);
            }
            break;

        default:
            sendJsonResponse(false, 'Invalid action requested.', [], 404);
            break;
    }
} catch (Exception $e) {
    error_log("API Error: " . $e->getMessage());
    sendJsonResponse(false, 'An error occurred while processing the request on the server.', [], 500);
}