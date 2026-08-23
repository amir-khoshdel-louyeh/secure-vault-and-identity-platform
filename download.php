<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/ShareManager.php';

$token = $_GET['token'] ?? '';
$token = trim($token);

if (empty($token) || !preg_match('/^[a-f0-9]{64}$/i', $token)) {
    http_response_code(400);
    die("توکن اشتراک‌گذاری نامعتبر است.");
}

try {
    $shareManager = new ShareManager();
    $shareManager->accessSharedItem($token);
} catch (Exception $e) {
    error_log("Download Access Error: " . $e->getMessage());
    http_response_code(500);
    die("خطایی در پردازش درخواست دانلود رخ داد.");
}