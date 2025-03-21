
---

# 🔥 DaggerX - Ultra-Secure Hashing & Encryption Library 🔥  

DaggerX is an **open-source** password hashing and encryption library designed for **maximum security**.  
It ensures that even the platform owner **cannot decrypt data** without the correct secret key.  

---

## 🚀 Features  

✅ **Argon2id Password Hashing** – Industry-standard, highly secure  
✅ **SHA3-512 Peppering** – Adds an extra security layer  
✅ **AES-256-GCM Encryption** – Used by military-grade security systems  
✅ **Developer-Specific Encryption Keys** – Even DaggerX creators can't decrypt data  
✅ **Cross-Language Compatibility** – Works with **PHP, JavaScript, Python, Java, and more**  

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

## 💰 **Support DaggerX Development**  

DaggerX is **free and open-source**. If you find it useful, consider donating to support future development!  

**BTC Wallet Address:**  
🚀 **[bc1qlza24cwwxlmtxm87lq7hltkya93aff6d5q496p]** 🚀  

Every donation helps keep DaggerX secure and available for everyone.  

---

## 🌍 **Cross-Language Support**  

Developers can integrate DaggerX into **any language** by using it locally in their projects.  

No API costs, No servers needed – **100% self-hosted and secure**.  

---

## ⭐ **Want to Contribute?**  

DaggerX is open-source! Feel free to submit pull requests on GitHub.  

Made with ❤️ by the DaggerX Team. 🚀  

---

Let me know if you need further refinements! 🔥
