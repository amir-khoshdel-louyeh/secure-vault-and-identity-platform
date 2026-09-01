<?php
require_once __DIR__ . '/config.php';

class Crypto {
    private static string $algo = 'aes-256-gcm';

    /**
     * دریافت کلید خام ۳۲ بایتی از کلید Hex تعریف‌شده در کانفیگ
     */
    private static function getRawKey(): string {
        $key = hex2bin(ENCRYPTION_KEY);
        if (strlen($key) !== 32) {
            throw new Exception("کلید رمزنگاری باید ۲۵۶ بیتی (۶۴ کاراکتر Hex) باشد.");
        }
        return $key;
    }

    // =========================================================================
    // ۱. رمزنگاری و رمزگشایی متون (برای نوت‌ها با AES-256-GCM)
    // =========================================================================

    /**
     * رمزنگاری یک رشته متنی
     * @return array شامل ciphertext (بیس۶۴)، iv (بیس۶۴) و tag (بیس۶۴)
     */
    public static function encryptText(string $plainText): array {
        $ivLength = openssl_cipher_iv_length(self::$algo);
        $iv = random_bytes($ivLength);
        $tag = '';

        $cipherText = openssl_encrypt(
            $plainText,
            self::$algo,
            self::getRawKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($cipherText === false) {
            throw new Exception("خطا در رمزنگاری متن.");
        }

        return [
            'ciphertext' => base64_encode($cipherText),
            'iv'         => base64_encode($iv),
            'tag'        => base64_encode($tag)
        ];
    }

    /**
     * رمزگشایی یک رشته متنی
     */
    public static function decryptText(string $cipherTextBase64, string $ivBase64, string $tagBase64 = ''): string {
        $cipherText = base64_decode($cipherTextBase64);
        $iv = base64_decode($ivBase64);
        $tag = base64_decode($tagBase64);

        $plainText = openssl_decrypt(
            $cipherText,
            self::$algo,
            self::getRawKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plainText === false) {
            throw new Exception("خطا در رمزگشایی متن یا کلید/تگ احراز هویت نامعتبر است.");
        }

        return $plainText;
    }

    // =========================================================================
    // ۲. رمزنگاری و رمزگشایی فایل‌ها به صورت Streaming ایمن
    // =========================================================================

    /**
     * رمزنگاری فایل کامل و ذخیره آن روی دیسک
     * @return array شامل IV و Authentication Tag
     */
    public static function encryptFile(string $sourcePath, string $destPath): array {
        $plainData = file_get_contents($sourcePath);
        if ($plainData === false) {
            throw new Exception("امکان خواندن فایل مبدا وجود ندارد.");
        }

        $ivLength = openssl_cipher_iv_length(self::$algo);
        $iv = random_bytes($ivLength);
        $tag = '';

        $encryptedData = openssl_encrypt(
            $plainData,
            self::$algo,
            self::getRawKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($encryptedData === false) {
            throw new Exception("خطا در رمزنگاری فایل.");
        }

        if (file_put_contents($destPath, $encryptedData) === false) {
            throw new Exception("امکان ذخیره‌سازی فایل رمز شده وجود ندارد.");
        }

        return [
            'iv'  => base64_encode($iv),
            'tag' => base64_encode($tag)
        ];
    }

    /**
     * خواندن فایل رمز شده از دیسک، رمزگشایی و ارسال مستقیم به خروجی (Stream به مرورگر)
     */
    public static function decryptFileToStream(string $sourcePath, string $ivBase64, string $tagBase64 = ''): void {
        $encryptedData = file_get_contents($sourcePath);
        if ($encryptedData === false) {
            throw new Exception("فایل رمزنگاری‌شده یافت نشد.");
        }

        $iv = base64_decode($ivBase64);
        $tag = base64_decode($tagBase64);

        $decryptedData = openssl_decrypt(
            $encryptedData,
            self::$algo,
            self::getRawKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($decryptedData === false) {
            throw new Exception("خطا در رمزگشایی فایل یا دستکاری داده‌ها detected.");
        }

        echo $decryptedData;
        flush();
    }
}