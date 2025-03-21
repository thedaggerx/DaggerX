<?php
namespace DaggerX;

class DaggerX {
    private static $algo = PASSWORD_ARGON2ID;
    private static $cipher = "aes-256-gcm";

    // Hash a password
    public static function hashPassword(string $password, string $devKey): string {
        $salt = bin2hex(random_bytes(16));
        $pepperedPassword = hash("sha3-512", $password . $devKey . $salt);
        $argon2Hash = password_hash($pepperedPassword, self::$algo, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 2]);
        return base64_encode("$salt|$argon2Hash");
    }

    // Verify a password
    public static function verifyPassword(string $password, string $hash, string $devKey): bool {
        $decodedHash = base64_decode($hash);
        list($salt, $argon2Hash) = explode('|', $decodedHash, 2);
        $pepperedPassword = hash("sha3-512", $password . $devKey . $salt);
        return password_verify($pepperedPassword, $argon2Hash);
    }

    // Encrypt message
    public static function encryptMessage(string $message, string $devKey): string {
        $iv = random_bytes(12); // 12 bytes IV for AES-GCM
        $key = substr(hash("sha3-512", $devKey, true), 0, 32); // 32 bytes key for AES-256
        $tag = ''; // Placeholder for tag

        $encrypted = openssl_encrypt($message, self::$cipher, $key, OPENSSL_RAW_DATA, $iv, $tag);
        return base64_encode($iv . $tag . $encrypted);
    }

    // Decrypt message
    public static function decryptMessage(string $encryptedMessage, string $devKey): string {
        $decoded = base64_decode($encryptedMessage);
        $iv = substr($decoded, 0, 12);
        $tag = substr($decoded, 12, 16);
        $ciphertext = substr($decoded, 28);

        $key = substr(hash("sha3-512", $devKey, true), 0, 32);
        return openssl_decrypt($ciphertext, self::$cipher, $key, OPENSSL_RAW_DATA, $iv, $tag) ?: "Decryption failed.";
    }
}
?>
