<?php
require_once dirname(__DIR__) . '/config/config.php';

class Crypto {
    private static function getAlgo(): string {
        return defined('ENCRYPTION_CIPHER') ? ENCRYPTION_CIPHER : 'aes-256-gcm';
    }

    /**
     * Get 32-byte raw key from the Hex key defined in config
     */
    private static function getRawKey(): string {
        $key = hex2bin(ENCRYPTION_KEY);
        if (strlen($key) !== 32) {
            throw new Exception("Encryption key must be 256-bit (64 Hex characters).");
        }
        return $key;
    }

    // =========================================================================
    // 1. Encrypt and Decrypt Text (for Notes with AES-256-GCM)
    // =========================================================================

    /**
     * Encrypt a text string
     * @return array Contains ciphertext (base64), iv (base64) and tag (base64)
     */
    public static function encryptText(string $plainText): array {
        $algo = self::getAlgo();
        $ivLength = openssl_cipher_iv_length($algo);
        $iv = random_bytes($ivLength);
        $tag = '';

        $cipherText = openssl_encrypt(
            $plainText,
            $algo,
            self::getRawKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($cipherText === false) {
            throw new Exception("Error encrypting text.");
        }

        return [
            'ciphertext' => base64_encode($cipherText),
            'iv'         => base64_encode($iv),
            'tag'        => base64_encode($tag)
        ];
    }

    /**
     * Decrypt a text string
     */
    public static function decryptText(string $cipherTextBase64, string $ivBase64, string $tagBase64 = ''): string {
        $cipherText = base64_decode($cipherTextBase64);
        $iv = base64_decode($ivBase64);
        $tag = base64_decode($tagBase64);

        $plainText = openssl_decrypt(
            $cipherText,
            self::getAlgo(),
            self::getRawKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plainText === false) {
            throw new Exception("Error decrypting text or invalid authentication key/tag.");
        }

        return $plainText;
    }

    // =========================================================================
    // 2. Encrypt and Decrypt Files via Secure Streaming
    // =========================================================================

    /**
     * Encrypt full file and save it to disk
     * @return array Contains IV and Authentication Tag
     */
    public static function encryptFile(string $sourcePath, string $destPath): array {
        $plainData = file_get_contents($sourcePath);
        if ($plainData === false) {
            throw new Exception("Unable to read the source file.");
        }

        $algo = self::getAlgo();
        $ivLength = openssl_cipher_iv_length($algo);
        $iv = random_bytes($ivLength);
        $tag = '';

        $encryptedData = openssl_encrypt(
            $plainData,
            $algo,
            self::getRawKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($encryptedData === false) {
            throw new Exception("Error encrypting the file.");
        }

        if (file_put_contents($destPath, $encryptedData) === false) {
            throw new Exception("Unable to save the encrypted file.");
        }

        return [
            'iv'  => base64_encode($iv),
            'tag' => base64_encode($tag)
        ];
    }

    /**
     * Read encrypted file from disk, decrypt, and stream directly to output (browser stream)
     */
    public static function decryptFileToStream(string $sourcePath, string $ivBase64, string $tagBase64 = ''): void {
        $encryptedData = file_get_contents($sourcePath);
        if ($encryptedData === false) {
            throw new Exception("Encrypted file not found.");
        }

        $iv = base64_decode($ivBase64);
        $tag = base64_decode($tagBase64);

        $decryptedData = openssl_decrypt(
            $encryptedData,
            self::getAlgo(),
            self::getRawKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($decryptedData === false) {
            throw new Exception("Error decrypting file or data tampering detected.");
        }

        echo $decryptedData;
        flush();
    }
}