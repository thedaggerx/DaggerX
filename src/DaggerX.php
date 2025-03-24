<?php
namespace DaggerX;

class DaggerX {
    private static $algo = PASSWORD_ARGON2ID; // Argon2id for strong password hashing
    private static $cipher = "aes-256-gcm";   // AES-256-GCM for message encryption

    // Automatically start session when the class is loaded
    public static function init() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    // Generate a unique session-based ID using SHA3-512 (ensuring consistent availability)
    public static function DaggerXSessionUniqueID(): string {
        $sessionData = session_id() ?: bin2hex(random_bytes(16));
        return hash("sha3-512", $sessionData . microtime(true));
    }

    // Hash a password using layered security: 
    // Derives a dynamic key from the developer key and session, then applies SHA3-512 and Argon2id
    public static function hashPassword(string $password, string $devKey): string {
        $salt = bin2hex(random_bytes(16));  // Generate 16-byte salt
        $sessionID = self::DaggerXSessionUniqueID();

        // Derive a dynamic key from devKey and sessionID (this replaces a static pepper)
        $derivedKey = hash("sha3-512", $devKey . $sessionID);

        // Combine password, derived key, and salt
        $combined = $password . $derivedKey . $salt;
        // Pre-hash with SHA3-512 for uniformity
        $preHash = hash("sha3-512", $combined);

        // Final hash with Argon2id for memory hardness and slow computation
        $argon2Hash = password_hash($preHash, self::$algo, [
            'memory_cost' => 131072, // 128 MB
            'time_cost' => 5,
            'threads' => 4
        ]);

        // Encode salt, sessionID, and argon2 hash together
        return base64_encode("$salt|$sessionID|$argon2Hash");
    }

    // Verify a password against the stored hash using the same dynamic derivation
    public static function verifyPassword(string $password, string $hash, string $devKey): bool {
        $decoded = base64_decode($hash);
        list($salt, $sessionID, $argon2Hash) = explode('|', $decoded, 3);

        $derivedKey = hash("sha3-512", $devKey . $sessionID);
        $combined = $password . $derivedKey . $salt;
        $preHash = hash("sha3-512", $combined);

        return password_verify($preHash, $argon2Hash);
    }

    // Encrypt a message using AES-256-GCM with a derived key (without a static pepper)
    public static function encryptMessage(string $message, string $devKey): string {
        $iv = random_bytes(16);
        // Generate a dynamic encryption salt (8 bytes, represented as 16 hex characters)
        $encryptionSalt = bin2hex(random_bytes(8));
        // Derive the encryption key from the developer key and the encryption salt
        $derivedKey = hash("sha3-512", $devKey . $encryptionSalt, true);
        $tag = '';

        $encrypted = openssl_encrypt($message, self::$cipher, $derivedKey, OPENSSL_RAW_DATA, $iv, $tag, "", 16);
        // Return a base64 string containing IV, tag, salt, and ciphertext
        return base64_encode($iv . $tag . $encryptionSalt . $encrypted);
    }

    // Decrypt a message using AES-256-GCM with the same derived key mechanism
    public static function decryptMessage(string $encryptedMessage, string $devKey): string {
        $decoded = base64_decode($encryptedMessage);
        $iv = substr($decoded, 0, 16);
        $tag = substr($decoded, 16, 16);
        // The encryption salt is 16 characters (hex representation of 8 bytes)
        $encryptionSalt = substr($decoded, 32, 16);
        $ciphertext = substr($decoded, 48);

        $derivedKey = hash("sha3-512", $devKey . $encryptionSalt, true);
        return openssl_decrypt($ciphertext, self::$cipher, $derivedKey, OPENSSL_RAW_DATA, $iv, $tag);
    }
}

// Automatically initialize the session when the class is loaded
DaggerX::init();
?>
