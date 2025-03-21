<?php
use DaggerX\DaggerX;

$data = json_decode(file_get_contents("php://input"), true);
$password = $data['password'] ?? '';
$devKey = $data['dev_key'] ?? '';

if (!$password || !$devKey) {
    echo json_encode(["error" => "Missing parameters"]);
    exit;
}

$hashedPassword = DaggerX::hashPassword($password, $devKey);
echo json_encode(["hashed_password" => $hashedPassword]);
?>
