<?php
namespace DaggerX;

class DaggerX {
    private static $algo = PASSWORD_ARGON2ID; // Argon2id for strong hashing
    private static $cipher = "aes-256-gcm"; // AES-256 for encryption

    // Hash a password with a developer-provided secret key
    public static function hashPassword(string $password, string $devKey): string {
        $salt = bin2hex(random_bytes(16)); // Generate 16-byte salt
        $pepperedPassword = hash("sha3-512", $password . $devKey . $salt);
        $argon2Hash = password_hash($pepperedPassword, self::$algo, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 2]);

        return base64_encode("$salt|$argon2Hash");
    }

    // Verify a password against a stored hash
    public static function verifyPassword(string $password, string $hash, string $devKey): bool {
        $decodedHash = base64_decode($hash);
        list($salt, $argon2Hash) = explode('|', $decodedHash, 2);
        $pepperedPassword = hash("sha3-512", $password . $devKey . $salt);
        
        return password_verify($pepperedPassword, $argon2Hash);
    }

    // Encrypt a message with AES-256-GCM
    public static function encryptMessage(string $message, string $devKey): string {
        $iv = random_bytes(16);
        $key = hash("sha3-512", $devKey, true);
        $tag = '';

        $encrypted = openssl_encrypt($message, self::$cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, "", 16);
        return base64_encode($iv . $tag . $encrypted);
    }

    // Decrypt a message with AES-256-GCM
    public static function decryptMessage(string $encryptedMessage, string $devKey): string {
        $decoded = base64_decode($encryptedMessage);
        $iv = substr($decoded, 0, 16);
        $tag = substr($decoded, 16, 16);
        $ciphertext = substr($decoded, 32);

        $key = hash("sha3-512", $devKey, true);
        return openssl_decrypt($ciphertext, self::$cipher, $key, OPENSSL_RAW_DATA, $iv, $tag);
    }
}
?>
