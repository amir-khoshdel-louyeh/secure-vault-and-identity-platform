<?php
// config.php will hold the security keys later
require_once dirname(__DIR__) . '/config/config.php';

function getDBConnection(): PDO {
    static $pdo = null;

    if ($pdo === null) {
        $dsn = sprintf("mysql:host=%s;dbname=%s;charset=utf8mb4", DB_HOST, DB_NAME);
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false, // Turn off PDO emulation to prevent SQLi
        ];

        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            // Error details should not be shown to the user in a production environment
            error_log("Database Connection Error: " . $e->getMessage());
            die("Error establishing a database connection.");
        }
    }

    return $pdo;
}