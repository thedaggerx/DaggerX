
---

# 🔥 **DaggerX V2** — Ultra-Secure Hashing & Encryption PHP Library 🔥  

DaggerX is an **open-source** password hashing and encryption library designed for **maximum security**.  
It ensures that even the platform owner **cannot decrypt data** without the correct secret key.  

---

## 🚀 **What's New in V2**  

✅ **Session-Based Unique IDs** — Adds session entropy for even stronger randomness.  
✅ **Dynamic Key Derivation** — Replaces static pepper with a session-based derived key.  
✅ **Improved Hashing Parameters** —  
   - **Memory Cost** increased to **128 MB** (vs. 64 MB in V1) for greater resistance to brute force.  
   - **Time Cost** increased to **5 iterations** (vs. 4 in V1) for slower, more secure hashing.  
   - **Threads** increased to **4** (vs. 2 in V1) for better parallelism.  
✅ **Enhanced Encryption** —  
   - Uses **AES-256-GCM** with **dynamic encryption salt**.  
   - More secure key derivation with **SHA3-512**.  
✅ **Automatic Session Initialization** —  
   - Ensures consistent security by starting a session when the class is loaded.  

---

## 📥 **Installation** (For PHP Developers)  

Install via **Composer**:  
```sh
composer require daggerx/password-hasher
```

Include in your project:  
```php
require "vendor/autoload.php";
use DaggerX\DaggerX;
```

---

## 🔑 **Usage**  

### ✅ **Hashing a Password**  
```php
$hash = DaggerX::hashPassword("mySecurePassword", "MySecretKey");
echo $hash;
```

### 🔍 **Verifying a Password**  
```php
$isValid = DaggerX::verifyPassword("mySecurePassword", $hash, "MySecretKey");
if ($isValid) {
    echo "Password is correct!";
} else {
    echo "Invalid password!";
}
```

### 🔐 **Encrypting a Message**  
```php
$encrypted = DaggerX::encryptMessage("Hello, this is private!", "MySecretKey");
echo $encrypted;
```

### 🔓 **Decrypting a Message**  
```php
$decrypted = DaggerX::decryptMessage($encrypted, "MySecretKey");
echo $decrypted; // Output: Hello, this is private!
```

---

## 🛡️ **Why Choose DaggerX?**  

- **Advanced Security:**  
  - Argon2id hashing for memory-hard computation.  
  - SHA3-512 hashing combined with dynamic salts for layered security.  
- **Dynamic Keying:**  
  - No static pepper — every session generates a unique derived key.  
- **Resistant to Attacks:**  
  - Strong memory and time cost parameters.  
  - AES-256-GCM with session-based entropy for encryption.  

---

## 💰 **Support DaggerX Development**  

DaggerX is **free and open-source**. If you find it useful, consider donating to support future development!  

**BTC Wallet Address:**  
🚀 **[bc1qlza24cwwxlmtxm87lq7hltkya93aff6d5q496p]** 🚀  

Every donation helps keep DaggerX secure and available for everyone.  

---

**Made with ❤️ by the DaggerX Team. 🚀**  
https://daggerx.vercel.app/

---

