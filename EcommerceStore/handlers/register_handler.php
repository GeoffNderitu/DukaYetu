<?php
require_once '../connections/db_connection.php';
require_once '../includes/functions.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = sanitizeInput($_POST['reg_username']);
    $email = sanitizeInput($_POST['reg_email']);
    $password = $_POST['reg_password'];

    // Perform form validation
    $errors = [];

    if (!isValidUsername($username)) {
        $errors['reg_username'] = 'Invalid username format. Only alphanumeric characters and underscores are allowed.';
    }

    if (!isValidEmail($email)) {
        $errors['reg_email'] = 'Invalid email address.';
    }

    if (strlen($password) < 8) {
        $errors['reg_password'] = 'Password must be at least 8 characters long.';
    }

    // If there are no validation errors, proceed with user registration
    if (empty($errors)) {
        // Check if username or email already exists
        $stmt = $conn->prepare("SELECT * FROM users WHERE user_name = :reg_username OR user_email = :reg_email");
        $stmt->execute(['reg_username' => $username, 'reg_email' => $email]);
        $user = $stmt->fetch();

        if ($user) {
            if ($user['user_name'] === $username) {
                $errors['reg_username'] = 'Username already exists.';
            } elseif ($user['user_email'] === $email) {
                $errors['reg_email'] = 'Email address already exists.';
            }
        }

        // If no user with the given username or email exists, insert the new user into the database
        if (empty($errors)) {
            $hashedPassword = generateHash($password);
            $stmt = $conn->prepare("INSERT INTO users (user_name, user_email, user_pass, created_at) VALUES (:reg_username, :reg_email, :reg_password, NOW())");
            $stmt->execute(['reg_username' => $username, 'reg_email' => $email, 'reg_password' => $hashedPassword]);

            // Redirect to the login page
            redirectTo('../home.php');
        }
    }
}
?>