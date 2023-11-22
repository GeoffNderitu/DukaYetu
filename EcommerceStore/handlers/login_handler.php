<?php
require_once '../connections/db_connection.php';
require_once '../includes/functions.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = sanitizeInput($_POST['log_username']);
    $password = isset($_POST['log_password']) ? $_POST['log_password'] : '';

    // Perform form validation
    $errors = [];

    if (empty($username)) {
        $errors['log_username'] = 'Username is required.';
    }

    if (empty($password)) {
        $errors['log_password'] = 'Password is required.';
    }

    // If there are no validation errors, proceed with user login
    if (empty($errors)) {
        $stmt = $conn->prepare("SELECT * FROM users WHERE user_name = :log_username");
        $stmt->bindParam(':log_username', $username);
        $stmt->execute();
        $user = $stmt->fetch();

        if ($user && verifyHash($password, $user['log_password'])) {
            // Start a session and set session variables
            startSession();
            setSession('id', $user['user_id']);
            setSession('log_username', $user['user_name']);

            // Assuming the username is stored in a variable $username
            header("Location: ../home.php?username=" . urlencode($username));
            exit();
        } else {
            $errors['login'] = 'Invalid username or password.';
        }
    }
}
?>
