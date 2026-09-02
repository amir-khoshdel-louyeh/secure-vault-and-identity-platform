<?php
// config.php بعداً کلیدهای امنیتی را نگه خواهد داشت
require_once dirname(__DIR__) . '/config/config.php';

function getDBConnection(): PDO {
    static $pdo = null;

    if ($pdo === null) {
        $dsn = sprintf("mysql:host=%s;dbname=%s;charset=utf8mb4", DB_HOST, DB_NAME);
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false, // خاموش کردن شبیه‌سازی PDO برای جلوگیری از SQLi
        ];

        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            // در محیط تولید نباید جزئیات خطا به کاربر نشان داده شود
            error_log("Database Connection Error: " . $e->getMessage());
            die("خطا در برقراری ارتباط با پایگاه داده.");
        }
    }

    return $pdo;
}