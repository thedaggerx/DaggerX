<?php
namespace DaggerX;

class DaggerX {
    private static $algo = PASSWORD_ARGON2ID; // Argon2id for strong password hashing
    private static $version = "3.0.0";        // Version identifier for hashes and encrypted data
    private static $useSessions = true;       // Toggle for session usage
    private static $supportedCiphers = [
        'aes-256-gcm',
        'aes-256-cbc'
    ]; // Supported encryption modes

    /**
     * Enable or disable session usage for environments like CLI or stateless APIs.
     *
     * @param bool $useSessions Whether to use PHP sessions
     */
    public static function setSessionUsage(bool $useSessions): void {
        self::$useSessions = $useSessions;
    }

    /**
     * Automatically start session if enabled and not already active.
     */
    public static function init(): void {
        if (self::$useSessions && session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Generate a unique session-based ID using SHA3-512 for randomness.
     * Falls back to random bytes if sessions are disabled or unavailable.
     *
     * @return string A SHA3-512 hash of session data and timestamp
     * @throws \RuntimeException If random_bytes fails
     */
    public static function DaggerXSessionUniqueID(): string {
        try {
            if (self::$useSessions && session_status() === PHP_SESSION_ACTIVE) {
                $sessionData = session_id();
            } else {
                $sessionData = bin2hex(random_bytes(16));
            }
            return hash("sha3-512", $sessionData . microtime(true));
        } catch (\Exception $e) {
            throw new \RuntimeException("Failed to generate session unique ID: " . $e->getMessage());
        }
    }

    /**
     * Derive a key using SHA3-512 for deterministic key derivation (used for hashing).
     *
     * @param string $input The input to derive a key from
     * @return string A SHA3-512 hash
     */
    private static function deriveKeyForHashing(string $input): string {
        return hash("sha3-512", $input);
    }

    /**
     * Derive a raw 32-byte key using SHA3-512 (used for encryption).
     *
     * @param string $input The input to derive a key from
     * @return string A raw 32-byte key
     */
    private static function deriveKeyForEncryption(string $input): string {
        return substr(hash("sha3-512", $input, true), 0, 32); // SHA3-512 outputs 64 bytes, take first 32
    }

    /**
     * Hash a password using Argon2id with dynamic key derivation.
     *
     * @param string $password The password to hash
     * @param string $devKey The developer key for key derivation
     * @param array $options Argon2id options (memory_cost, time_cost, threads)
     * @return string The base64-encoded hash (version|salt|sessionID|argon2Hash)
     * @throws \RuntimeException If hashing fails
     * @throws \InvalidArgumentException If options are invalid
     */
    public static function hashPassword(string $password, string $devKey, array $options = []): string {
        $defaultOptions = [
            'memory_cost' => 65536, // 64 MB (optimized for speed)
            'time_cost' => 3,       // Reduced for speed
            'threads' => 4
        ];
        $options = array_merge($defaultOptions, $options);

        // Validate options
        if ($options['memory_cost'] < 8192 || $options['time_cost'] < 1 || $options['threads'] < 1) {
            throw new \InvalidArgumentException("Invalid Argon2id options: memory_cost, time_cost, and threads must be positive and reasonable.");
        }

        try {
            $salt = bin2hex(random_bytes(16));
            $sessionID = self::DaggerXSessionUniqueID();
            $derivedKey = self::deriveKeyForHashing($devKey . $sessionID);
            $combined = $password . $derivedKey . $salt;
            $preHash = hash("sha3-512", $combined);

            $argon2Hash = password_hash($preHash, self::$algo, $options);
            if ($argon2Hash === false) {
                throw new \RuntimeException("Failed to hash password: Argon2id hashing failed, possibly due to memory or configuration issues.");
            }

            return base64_encode(self::$version . "|$salt|$sessionID|$argon2Hash");
        } catch (\Exception $e) {
            throw new \RuntimeException("Password hashing failed: " . $e->getMessage());
        }
    }

    /**
     * Verify a password against a stored hash.
     *
     * @param string $password The password to verify
     * @param string $hash The stored hash (base64-encoded)
     * @param string $devKey The developer key used during hashing
     * @return bool True if the password matches, false otherwise
     * @throws \InvalidArgumentException If the hash format is invalid
     * @throws \RuntimeException If verification fails due to version mismatch or other errors
     */
    public static function verifyPassword(string $password, string $hash, string $devKey): bool {
        $decoded = base64_decode($hash, true);
        if ($decoded === false) {
            throw new \InvalidArgumentException("Invalid base64-encoded hash.");
        }

        $parts = explode('|', $decoded, 4);
        if (count($parts) !== 4) {
            throw new \InvalidArgumentException("Invalid hash format: Expected version|salt|sessionID|argon2Hash.");
        }

        list($version, $salt, $sessionID, $argon2Hash) = $parts;
        if ($version !== self::$version) {
            throw new \RuntimeException("Unsupported hash version: $version. Expected: " . self::$version);
        }

        try {
            $derivedKey = self::deriveKeyForHashing($devKey . $sessionID);
            $combined = $password . $derivedKey . $salt;
            $preHash = hash("sha3-512", $combined);

            return password_verify($preHash, $argon2Hash);
        } catch (\Exception $e) {
            throw new \RuntimeException("Password verification failed: " . $e->getMessage());
        }
    }

    /**
     * Rotate the developer key for a stored password hash.
     *
     * @param string $password The original password
     * @param string $hash The stored hash (base64-encoded)
     * @param string $oldDevKey The old developer key
     * @param string $newDevKey The new developer key
     * @param array $options Argon2id options (memory_cost, time_cost, threads)
     * @return string The new base64-encoded hash with the new key
     * @throws \InvalidArgumentException If the hash format is invalid or password doesn't match
     * @throws \RuntimeException If rotation fails
     */
    public static function rotateHashKey(string $password, string $hash, string $oldDevKey, string $newDevKey, array $options = []): string {
        // Verify the password with the old key
        if (!self::verifyPassword($password, $hash, $oldDevKey)) {
            throw new \InvalidArgumentException("Password does not match the stored hash with the old developer key.");
        }

        // Rehash with the new key
        return self::hashPassword($password, $newDevKey, $options);
    }

    /**
     * Encrypt a message using the specified encryption mode.
     *
     * @param string $message The message to encrypt
     * @param string $devKey The developer key for key derivation
     * @param string $mode The encryption mode ('aes-256-gcm' or 'aes-256-cbc')
     * @param string $aad Additional Authenticated Data (optional, ignored for CBC)
     * @return string The base64-encoded encrypted data (version|mode|iv|tag|salt|ciphertext|hmac)
     * @throws \InvalidArgumentException If the mode is unsupported
     * @throws \RuntimeException If encryption fails
     */
    public static function encryptMessage(string $message, string $devKey, string $mode = 'aes-256-gcm', string $aad = ""): string {
        if (!in_array($mode, self::$supportedCiphers, true)) {
            throw new \InvalidArgumentException("Unsupported encryption mode: $mode. Supported modes: " . implode(', ', self::$supportedCiphers));
        }

        try {
            $ivLength = ($mode === 'aes-256-gcm') ? 12 : 16; // 12 bytes for GCM, 16 for CBC
            $iv = random_bytes($ivLength);
            $encryptionSalt = bin2hex(random_bytes(8));
            $derivedKey = self::deriveKeyForEncryption($devKey . $encryptionSalt);
            $tag = '';

            if ($mode === 'aes-256-gcm') {
                $encrypted = openssl_encrypt($message, $mode, $derivedKey, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
                if ($encrypted === false) {
                    throw new \RuntimeException("Encryption failed: " . openssl_error_string());
                }
                $hmac = ''; // GCM provides built-in authentication
            } else { // aes-256-cbc
                $encrypted = openssl_encrypt($message, $mode, $derivedKey, OPENSSL_RAW_DATA, $iv);
                if ($encrypted === false) {
                    throw new \RuntimeException("Encryption failed: " . openssl_error_string());
                }
                // Compute HMAC for integrity (using SHA3-512)
                $hmac = hash_hmac("sha3-512", $iv . $encrypted, $derivedKey, true);
            }

            return base64_encode(self::$version . "|$mode|$iv|$tag|$encryptionSalt|$encrypted|$hmac");
        } catch (\Exception $e) {
            throw new \RuntimeException("Message encryption failed: " . $e->getMessage());
        }
    }

    /**
     * Decrypt a message encrypted with the specified mode.
     *
     * @param string $encryptedMessage The base64-encoded encrypted message
     * @param string $devKey The developer key used during encryption
     * @param string $aad Additional Authenticated Data (optional, ignored for CBC)
     * @return string The decrypted message
     * @throws \InvalidArgumentException If the encrypted message format is invalid
     * @throws \RuntimeException If decryption fails
     */
    public static function decryptMessage(string $encryptedMessage, string $devKey, string $aad = ""): string {
        $decoded = base64_decode($encryptedMessage, true);
        if ($decoded === false) {
            throw new \InvalidArgumentException("Invalid base64-encoded encrypted message.");
        }

        $parts = explode('|', $decoded, 7);
        if (count($parts) !== 7) {
            throw new \InvalidArgumentException("Invalid encrypted message format: Expected version|mode|iv|tag|salt|ciphertext|hmac.");
        }

        list($version, $mode, $iv, $tag, $encryptionSalt, $ciphertext, $hmac) = $parts;
        if ($version !== self::$version) {
            throw new \RuntimeException("Unsupported encrypted message version: $version. Expected: " . self::$version);
        }
        if (!in_array($mode, self::$supportedCiphers, true)) {
            throw new \InvalidArgumentException("Unsupported encryption mode in message: $mode.");
        }

        $ivLength = ($mode === 'aes-256-gcm') ? 12 : 16;
        if (strlen($iv) !== $ivLength || ($mode === 'aes-256-gcm' && strlen($tag) !== 16) || strlen($encryptionSalt) !== 16) {
            throw new \InvalidArgumentException("Invalid encrypted message components: IV, tag, or salt length mismatch.");
        }

        try {
            $derivedKey = self::deriveKeyForEncryption($devKey . $encryptionSalt);

            if ($mode === 'aes-256-gcm') {
                $decrypted = openssl_decrypt($ciphertext, $mode, $derivedKey, OPENSSL_RAW_DATA, $iv, $tag, $aad);
                if ($decrypted === false) {
                    throw new \RuntimeException("Decryption failed: " . openssl_error_string());
                }
            } else { // aes-256-cbc
                // Verify HMAC for integrity
                $computedHmac = hash_hmac("sha3-512", $iv . $ciphertext, $derivedKey, true);
                if (!hash_equals($hmac, $computedHmac)) {
                    throw new \RuntimeException("HMAC verification failed: Message integrity compromised.");
                }

                $decrypted = openssl_decrypt($ciphertext, $mode, $derivedKey, OPENSSL_RAW_DATA, $iv);
                if ($decrypted === false) {
                    throw new \RuntimeException("Decryption failed: " . openssl_error_string());
                }
            }

            return $decrypted;
        } catch (\Exception $e) {
            throw new \RuntimeException("Message decryption failed: " . $e->getMessage());
        }
    }

    /**
     * Rotate the developer key for an encrypted message.
     *
     * @param string $encryptedMessage The base64-encoded encrypted message
     * @param string $oldDevKey The old developer key
     * @param string $newDevKey The new developer key
     * @param string $aad Additional Authenticated Data (optional, ignored for CBC)
     * @param string $mode The encryption mode to use for re-encryption
     * @return string The new base64-encoded encrypted message with the new key
     * @throws \InvalidArgumentException If the encrypted message format is invalid
     * @throws \RuntimeException If rotation fails
     */
    public static function rotateEncryptionKey(string $encryptedMessage, string $oldDevKey, string $newDevKey, string $aad = "", string $mode = 'aes-256-gcm'): string {
        // Decrypt with the old key
        $decrypted = self::decryptMessage($encryptedMessage, $oldDevKey, $aad);

        // Re-encrypt with the new key
        return self::encryptMessage($decrypted, $newDevKey, $mode, $aad);
    }
}

// Automatically initialize the session when the class is loaded (if enabled)
DaggerX::init();
?>
