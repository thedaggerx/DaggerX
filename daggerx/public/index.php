<?php
require_once "../src/DaggerX.php";
header("Content-Type: application/json");

$request = $_GET['action'] ?? '';

switch ($request) {
    case "hash":
        require "hash.php";
        break;
    case "verify":
        require "verify.php";
        break;
    case "encrypt":
        require "encrypt.php";
        break;
    case "decrypt":
        require "decrypt.php";
        break;
    default:
        echo json_encode(["error" => "Invalid API endpoint"]);
}
?>
