<?php
use DaggerX\DaggerX;

$data = json_decode(file_get_contents("php://input"), true);
$message = $data['message'] ?? '';
$devKey = $data['dev_key'] ?? '';

if (!$message || !$devKey) {
    echo json_encode(["error" => "Missing parameters"]);
    exit;
}

$encryptedMessage = DaggerX::encryptMessage($message, $devKey);
echo json_encode(["encrypted_message" => $encryptedMessage]);
?>
