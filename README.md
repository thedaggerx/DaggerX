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
## Example: Login and Registration System
DaggerX v3.0.0 can be used to create a secure login and registration system where:
Passwords are hashed using hashPassword and verified with verifyPassword.

Sensitive data (e.g., the user's name) is encrypted with encryptMessage during registration and decrypted with decryptMessage during login.

## Database Schema
Create a users table to store user data:
sql
```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(512) NOT NULL,  -- Stores encrypted name
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(1024) NOT NULL,  -- Stores hashed password
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Important Notes on Column Lengths:
The password column should be atleast VARCHAR(1024) to accommodate the full base64-encoded hash (typically ~350-400 characters). A shorter length (e.g., VARCHAR(255)) will truncate the hash, causing verifyPassword to fail.

The name column should be atleast VARCHAR(512) to store the base64-encoded encrypted name, which can be longer than the plaintext name (e.g., ~160 characters for a short name like "John Doe").

Registration Example (register.php)
```php

<?php
require 'vendor/autoload.php';
use DaggerX\DaggerX;

// Disable session usage for consistency
DaggerX::setSessionUsage(false);

// Developer key (store securely in production)
$devKey = "MySecretKey1234567890";

// Database connection
$conn = new mysqli("localhost", "root", "08032494987", "test22");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$success = $error = "";
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    // Basic validation
    if (empty($name) || empty($email) || empty($password)) {
        $error = "All fields are required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email format.";
    } elseif (strlen($password) < 8) {
        $error = "Password must be at least 8 characters long.";
    } else {
        // Encrypt the name
        try {
            $encryptedName = DaggerX::encryptMessage($name, $devKey, 'aes-256-gcm');
        } catch (Exception $e) {
            $error = "Failed to encrypt name: " . $e->getMessage();
            $encryptedName = null;
        }

        // Hash the password
        try {
            $hashedPassword = DaggerX::hashPassword($password, $devKey);
        } catch (Exception $e) {
            $error = "Failed to hash password: " . $e->getMessage();
            $hashedPassword = null;
        }

        if (!$error && $encryptedName && $hashedPassword) {
            // Insert into database
            $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $encryptedName, $email, $hashedPassword);
            if ($stmt->execute()) {
                $success = "Registration successful! <a href='login.php'>Login here</a>.";
            } else {
                $error = "Registration failed: " . $conn->error;
            }
            $stmt->close();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - DaggerX v3.0.0 Demo</title>
</head>
<body>
    <h2>Register</h2>
    <?php if ($error) echo "<p>$error</p>"; ?>
    <?php if ($success) echo "<p>$success</p>"; ?>
    <form method="POST" action="">
        Name: <input type="text" name="name" value="<?php echo isset($_POST['name']) ? htmlspecialchars($_POST['name']) : ''; ?>" required><br>
        Email: <input type="email" name="email" value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>" required><br>
        Password: <input type="password" name="password" required><br>
        <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="login.php">Login here</a>.</p>
</body>
</html>
```
Login Example (login.php)
```php
<?php
session_start();
require 'vendor/autoload.php';
use DaggerX\DaggerX;

// Disable session usage to avoid session ID mismatches
DaggerX::setSessionUsage(false);

// Define the developer key (must be the same as in register.php)
$devKey = "MySecretKey1234567890";

// Database connection
$conn = new mysqli("localhost", "root", "08032494987", "test22");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$success = $error = "";
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    // Basic validation
    if (empty($email) || empty($password)) {
        $error = "All fields are required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email format.";
    } else {
        // Fetch user from database
        $stmt = $conn->prepare("SELECT name, password FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            $hashedPassword = $user['password'];
            $encryptedName = $user['name'];

            // Verify password
            try {
                if (DaggerX::verifyPassword($password, $hashedPassword, $devKey)) {
                    // Decrypt the name
                    $decryptedName = DaggerX::decryptMessage($encryptedName, $devKey);
                    $_SESSION['user_name'] = $decryptedName;
                    $success = "Login successful! Welcome, " . htmlspecialchars($decryptedName) . "!";
                } else {
                    $error = "Invalid email or password.";
                }
            } catch (Exception $e) {
                $error = "Login failed: " . $e->getMessage();
            }
        } else {
            $error = "Invalid email or password.";
        }
        $stmt->close();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - DaggerX v3.0.0 Demo</title>
</head>
<body>
    <h2>Login</h2>
    <?php if ($error) echo "<p>$error</p>"; ?>
    <?php if ($success) echo "<p>$success <a href='logout.php'>Logout</a></p>"; ?>
    <?php if (isset($_SESSION['user_name'])) echo "<p>Welcome back, " . htmlspecialchars($_SESSION['user_name']) . "! <a href='logout.php'>Logout</a></p>"; ?>
    <?php if (!$success && !isset($_SESSION['user_name'])): ?>
        <form method="POST" action="">
            Email: <input type="email" name="email" value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>" required><br>
            Password: <input type="password" name="password" required><br>
            <button type="submit">Login</button>
        </form>
        <p>Don't have an account? <a href="register.php">Register here</a>.</p>
    <?php endif; ?>
</body>
</html>
```
Logout Example (logout.php)
```php
<?php
session_start();
session_destroy();
header("Location: login.php");
exit;
```
Key Considerations
Session Usage: DaggerX v3.0.0 uses session IDs for entropy in password hashing by default. If the session ID changes between registration and login, verification will fail. Disable session usage with DaggerX::setSessionUsage(false) unless you can ensure session consistency (e.g., by persisting the session cookie across requests).

Developer Key: The $devKey must be the same for both hashing/verification and encryption/decryption. Store it securely (e.g., in an environment variable) and ensure it's consistent across your application.

Database Column Lengths: Ensure the password column is atleast (1024) and the name column (if encrypted) should be atleast (512) to avoid truncation issues, which can cause login failures.


---
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
