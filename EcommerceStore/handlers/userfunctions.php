<?php
function validate_username($username) {
    return preg_match("/^[a-zA-Z0-9]+$/", $username);
}

function validate_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function register_user($username, $email, $password) {
    global $conn;

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    try {
        $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        $stmt->execute([$username, $email, $hashed_password]);
        return true;
    } catch (PDOException $e) {
        return false;
    }
}

function login_user($username, $password) {
    global $conn;

    try {
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            return $user;
        }
    } catch (PDOException $e) {
        // Handle database error
    }

    return false;
}
?>
