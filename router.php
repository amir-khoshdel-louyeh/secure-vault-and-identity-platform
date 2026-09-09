<?php
// Router for php -S with docroot=project root
// Usage: php -S localhost:8000 router.php
// Serves /public/* as static and /api/* as API

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// API routes
if (str_starts_with($uri, '/api/')) {
    require __DIR__ . '/api/api.php';
    exit;
}

// Public files: map / -> /public/index.html, /login.html -> /public/login.html, etc.
if ($uri === '/') {
    $uri = '/index.html';
}

// Execute download handler BEFORE static file serving.
// Otherwise /download.php matches public/download.php as a static file
// and readfile() would leak PHP source instead of running it.
if ($uri === '/download.php') {
    require __DIR__ . '/public/download.php';
    exit;
}

// Map common public assets
$publicFile = __DIR__ . '/public' . $uri;
if (is_file($publicFile)) {
    // Let PHP's mime handling serve it - we need to manually output with correct mime
    // Returning false only works when docroot is public, so we serve manually here
    $ext = strtolower(pathinfo($publicFile, PATHINFO_EXTENSION));
    // Never disclose PHP source: block direct access to any .php file
    if ($ext === 'php') {
        http_response_code(403);
        echo "403 Forbidden";
        exit;
    }
    $mimes = [
        'html' => 'text/html',
        'css'  => 'text/css',
        'js'   => 'application/javascript',
        'json' => 'application/json',
        'png'  => 'image/png',
        'jpg'  => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'gif'  => 'image/gif',
        'svg'  => 'image/svg+xml',
        'ico'  => 'image/x-icon',
    ];
    if (isset($mimes[$ext])) {
        header('Content-Type: ' . $mimes[$ext]);
    }
    readfile($publicFile);
    exit;
}

// 404
http_response_code(404);
echo "404 Not Found - " . htmlspecialchars($uri);
