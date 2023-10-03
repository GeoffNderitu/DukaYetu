<?php
include("../connectiones/db_connection.php");
include("userfunctions.php");

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST["username"];
    $password = $_POST["password"];

    try {
        // Check if the username exists in the database
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            session_start();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            
            // Redirect to a welcome or dashboard page
            header("Location: ../home.php");
            exit();
        } else {
            // Invalid credentials
            header("Location: ../login.php?error=invalid");
            exit();
        }
    } catch (PDOException $e) {
        // Handle database error
        header("Location: ../login.php?error=db");
        exit();
    }
} else {
    // Redirect to the login page if accessed directly
    header("Location: ../login.php");
    exit();
}
?>
