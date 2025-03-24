<?php
use DaggerX\DaggerX;

$data = json_decode(file_get_contents("php://input"), true);
$encryptedMessage = $data['encrypted_message'] ?? '';
$devKey = $data['dev_key'] ?? '';

if (!$encryptedMessage || !$devKey) {
    echo json_encode(["error" => "Missing parameters"]);
    exit;
}

$decryptedMessage = DaggerX::decryptMessage($encryptedMessage, $devKey);
if ($decryptedMessage === false) {
    echo json_encode(["error" => "Decryption failed. Invalid key or corrupted data."]);
    exit;
}

echo json_encode(["decrypted_message" => $decryptedMessage]);
?>
