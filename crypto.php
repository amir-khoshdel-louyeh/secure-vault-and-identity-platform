<?php
require_once __DIR__ . '/config.php';

class Crypto {
    private static string $algo = ENCRYPTION_CIPHER; // aes-256-cbc

    /**
     * دریافت کلید خام ۳۲ بایتی از کلید Hex تعریف‌شده در کانفیگ
     */
    private static function getRawKey(): string {
        return hex2bin(ENCRYPTION_KEY);
    }

    // =========================================================================
    // ۱. رمزنگاری و رمزگشایی متون (برای نوت‌ها)
    // =========================================================================

    /**
     * رمزنگاری یک رشته متنی
     * @return array شامل ciphertext (بیس۶۴) و iv (بیس۶۴)
     */
    public static function encryptText(string $plainText): array {
        $ivLength = openssl_cipher_iv_length(self::$algo);
        $iv = random_bytes($ivLength);

        $cipherText = openssl_encrypt(
            $plainText,
            self::$algo,
            self::getRawKey(),
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($cipherText === false) {
            throw new Exception("خطا در رمزنگاری متن.");
        }

        return [
            'ciphertext' => base64_encode($cipherText),
            'iv'         => base64_encode($iv)
        ];
    }

    /**
     * رمزگشایی یک رشته متنی
     */
    public static function decryptText(string $cipherTextBase64, string $ivBase64): string {
        $cipherText = base64_decode($cipherTextBase64);
        $iv = base64_decode($ivBase64);

        $plainText = openssl_decrypt(
            $cipherText,
            self::$algo,
            self::getRawKey(),
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($plainText === false) {
            throw new Exception("خطا در رمزگشایی متن یا کلید نامعتبر است.");
        }

        return $plainText;
    }

    // =========================================================================
    // ۲. رمزنگاری و رمزگشایی فایل‌ها به صورت Streaming (برای مدارک/اسناد)
    // =========================================================================

    /**
     * خواندن فایل خام، رمزنگاری تکه به تکه (Chunked) و ذخیره فایل رمز شده روی دیسک
     * @return string IV تولید شده (به صورت Base64)
     */
    public static function encryptFile(string $sourcePath, string $destPath): string {
        $ivLength = openssl_cipher_iv_length(self::$algo);
        $iv = random_bytes($ivLength);

        $srcHandle = fopen($sourcePath, 'rb');
        $destHandle = fopen($destPath, 'wb');

        if (!$srcHandle || !$destHandle) {
            throw new Exception("امکان باز کردن فایل برای رمزنگاری وجود ندارد.");
        }

        // اندازه تکه‌ها: 16KB (مضرب 16 برای بلاک‌های AES)
        $chunkSize = 16 * 1024;

        while (!feof($srcHandle)) {
            $plainChunk = fread($srcHandle, $chunkSize);
            // برای آخرین تکه، OpenSSL خودکار PADDING اضافه می‌کند
            $encryptedChunk = openssl_encrypt(
                $plainChunk,
                self::$algo,
                self::getRawKey(),
                OPENSSL_RAW_DATA | (feof($srcHandle) ? 0 : OPENSSL_ZERO_PADDING),
                $iv
            );

            fwrite($destHandle, $encryptedChunk);
        }

        fclose($srcHandle);
        fclose($destHandle);

        return base64_encode($iv);
    }

    /**
     * خواندن فایل رمز شده از دیسک، رمزگشایی تکه به تکه و ارسال مستقیم به خروجی (Stream به مرورگر)
     */
    public static function decryptFileToStream(string $sourcePath, string $ivBase64): void {
        $iv = base64_decode($ivBase64);
        $srcHandle = fopen($sourcePath, 'rb');

        if (!$srcHandle) {
            throw new Exception("فایل رمزنگاری‌شده یافت نشد.");
        }

        $chunkSize = 16 * 1024;

        while (!feof($srcHandle)) {
            $cipherChunk = fread($srcHandle, $chunkSize);
            $decryptedChunk = openssl_decrypt(
                $cipherChunk,
                self::$algo,
                self::getRawKey(),
                OPENSSL_RAW_DATA | (feof($srcHandle) ? 0 : OPENSSL_ZERO_PADDING),
                $iv
            );

            if ($decryptedChunk === false) {
                fclose($srcHandle);
                throw new Exception("خطا در رمزگشایی فایل.");
            }

            echo $decryptedChunk;
            flush(); // ارسال فوری خروجی به مرورگر
        }

        fclose($srcHandle);
    }
}