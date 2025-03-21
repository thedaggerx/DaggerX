<?php
use DaggerX\DaggerX;

$data = json_decode(file_get_contents("php://input"), true);
$password = $data['password'] ?? '';
$hash = $data['hash'] ?? '';
$devKey = $data['dev_key'] ?? '';

if (!$password || !$hash || !$devKey) {
    echo json_encode(["error" => "Missing parameters"]);
    exit;
}

$isValid = DaggerX::verifyPassword($password, $hash, $devKey);
echo json_encode(["valid" => $isValid]);
?>
