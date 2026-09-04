<?php
// Router for php -S with docroot=public
// Usage: php -S localhost:8000 -t public public/router.php
// Routes /api/* and /download.php to correct handlers outside docroot

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if (str_starts_with($uri, '/api/')) {
    require __DIR__ . '/../api/api.php';
    exit;
}

// Let built-in server serve existing public files (css, js, html, etc.)
$publicFile = __DIR__ . $uri;
if ($uri === '/') {
    $publicFile = __DIR__ . '/index.html';
}
if (is_file($publicFile)) {
    return false;
}

// Also handle download.php via query string
if ($uri === '/download.php') {
    require __DIR__ . '/download.php';
    exit;
}

// Fallback 404 (avoid PHP 8.5 fallback to index.html)
http_response_code(404);
echo "404 Not Found - " . htmlspecialchars($uri);
