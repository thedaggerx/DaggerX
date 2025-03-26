# 🔥 **DaggerX V3** — The Fastest, Strongest, PHP Security Library 🔥

DaggerX is an **open-source** password hashing and encryption library designed for **unbreakable security**. It ensures that even the platform owner **cannot decrypt data** without the correct secret key. With V3, DaggerX is now the **fastest, strongest** security library for PHP developers, offering key rotation, dual encryption modes, and optimized performance without compromising security.

---

## 🚀 **What's New and Added in V3**

✅ **Key Rotation Support** —  
- Seamlessly rotate your developer key (`$devKey`) for both password hashes and encrypted messages.  
- Protect against long-term key compromise with `rotateHashKey()` and `rotateEncryptionKey()`.  

✅ **Dual Encryption Modes** —  
- **AES-256-GCM**: Authenticated encryption with Additional Authenticated Data (AAD) support.  
- **AES-256-CBC**: Confidentiality with HMAC (SHA3-512) for integrity, for compatibility with legacy systems.  

✅ **Optimized for Speed** —  
- Reduced Argon2id defaults: **Memory Cost** to **64 MB** (from 128 MB), **Time Cost** to **3 iterations** (from 5).  
- Still exceeds OWASP security recommendations while being faster for real-world use.  

✅ **Enhanced Security** —  
- Deterministic key derivation with **SHA3-512** for both hashing and encryption.  
- HMAC (SHA3-512) for AES-256-CBC ensures integrity.  

✅ **Session-Based Entropy (New)** —  
- New function `setSessionUsage()` for incorporating session IDs or random bytes for better entropy.  
- Toggle session usage based on environment (CLI or Web).  

✅ **Argon2id Customization (New)** —  
- Added support for customizing Argon2id parameters such as `memory_cost`, `time_cost`, and `threads`.  
- Optimize for your hardware and security needs.  

✅ **Key Derivation Separation (New)** —  
- Separate key derivation logic for hashing and encryption.  
- Improves maintainability and modularity.  

✅ **Feared by Attackers** —  
- Combines Argon2id, AES-256, and SHA3-512 with key rotation to create an impenetrable security layer.  
- A library that attackers will dread facing.

---

## **Installation** (For PHP Developers)

Install via **Composer**:  
```sh
composer require daggerx/password-hasher
```
Include in your project:  
```php
<?php

require "vendor/autoload.php";
use DaggerX\DaggerX;
?>
```

### Hashing a Password
```php
<?php

$hash = DaggerX::hashPassword("mySecurePassword", "MySecretKey");
echo $hash;
?>
```

### Verifying a Password
```php
<?php

$isValid = DaggerX::verifyPassword("mySecurePassword", $hash, "MySecretKey");
if ($isValid) {
    echo "Password is correct!";
} else {
    echo "Invalid password!";
}
?>
```

### Encrypting a Message (AES-256-GCM with AAD)
```php
<?php

$encrypted = DaggerX::encryptMessage("Hello, this is private!", "MySecretKey", "aes-256-gcm", "user_id:12345");
echo $encrypted;
?>
```

### Encrypting a Message (AES-256-CBC)
```php
<?php

$encryptedCBC = DaggerX::encryptMessage("Hello, this is private!", "MySecretKey", "aes-256-cbc");
echo $encryptedCBC;
?>
```

### Decrypting a Message
```php
<?php

$decrypted = DaggerX::decryptMessage($encrypted, "MySecretKey", "user_id:12345");
echo $decrypted; // Output: Hello, this is private!

$decryptedCBC = DaggerX::decryptMessage($encryptedCBC, "MySecretKey");
echo $decryptedCBC; // Output: Hello, this is private!
?>
```

### Rotating a Hash Key
```php
<?php

$newHash = DaggerX::rotateHashKey("mySecurePassword", $hash, "MySecretKey", "NewSecretKey");
echo $newHash;

// Verify with the new key
$isValid = DaggerX::verifyPassword("mySecurePassword", $newHash, "NewSecretKey");
echo $isValid ? "Password verified with new key!" : "Verification failed!";
?>
```

### Rotating an Encryption Key
```php
<?php

$newEncrypted = DaggerX::rotateEncryptionKey($encrypted, "MySecretKey", "NewSecretKey", "user_id:12345", "aes-256-gcm");
echo $newEncrypted;

// Decrypt with the new key
$decrypted = DaggerX::decryptMessage($newEncrypted, "NewSecretKey", "user_id:12345");
echo $decrypted; // Output: Hello, this is private!
?>
```

### Customizing Argon2id Parameters for Performance
```php
<?php

$hash = DaggerX::hashPassword("mySecurePassword", "MySecretKey", [
    'memory_cost' => 32768, // 32 MB
    'time_cost' => 2,
    'threads' => 2
]);
echo $hash;
?>
```

---

## Why Choose DaggerX?

**Unbreakable Security:**  
- Argon2id for memory-hard password hashing.  
- AES-256-GCM and AES-256-CBC for encryption, with SHA3-512 key derivation.  
- HMAC (SHA3-512) for CBC mode integrity.

**Key Rotation:**  
- Rotate keys without data loss to mitigate key compromise risks.

**Dual Encryption Modes:**  
- AES-256-GCM for authenticated encryption with AAD support.  
- AES-256-CBC with HMAC for compatibility and integrity.

**Optimized Performance:**  
- Faster Argon2id parameters for real-world use without sacrificing security.  
- Hardware-accelerated AES encryption for speed.

**Session-Based Entropy:**  
- Improved randomness using session IDs or random bytes.

**Feared by Attackers:**  
- A combination of modern cryptography, key rotation, and robust design makes DaggerX a nightmare for attackers.

---

## Support DaggerX Development

DaggerX is free and open-source. If you find it useful, consider donating to support future development!  
**BTC Wallet Address:**  
[bc1qlza24cwwxlmtxm87lq7hltkya93aff6d5q496p]  

Every donation helps keep DaggerX secure, fast, and feared by attackers for everyone.  
Made with ❤️ by the DaggerX Team.  
[https://daggerx.vercel.app/](https://daggerx.vercel.app/)
