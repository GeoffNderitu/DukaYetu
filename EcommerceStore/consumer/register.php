<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login/Register</title>
    <link rel="stylesheet" href="style.css">

    <!-- <link rel="stylesheet" href="../styles/style.css"> -->
    <!-- <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" 
    integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" 
    integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous"></script> -->
</head>
<body>
    <div class="container-flip">
        <div class="card-flip">
            <div class="box login">
                <h4>Already have an account?</h4>
                <button class="login_btn">Login Here</button>
            </div>
            <div class="box register">
                <h4>Don't have an account?</h4>
                <button class="register_btn">Register Here</button>
            </div>
        </div>
        <div class="formLog active">
                <div class="form login_form active">
                    <form action="login_handler.php" method="POST">
                        <h4>Log In</h4>
                        <input type="text" placeholder="username" name="log_username" required>
                        <input type="password" placeholder="password" name="log_username">
                        <input type="submit" value="Login">
                        <a href="#" class="forgot">Forgot Password</a>
                    </form>
                </div>
                <div class="form register_form">
                    <form action="../handlers/register_handler.php" method="POST">
                        <h4>Register</h4>
                        <input type="text" placeholder="username" name="reg_username" required>
                        <?php if (!empty($usernameError)) { ?>
                         <span class="error"><?php echo $usernameError; ?></span>
                         <?php } ?>
                        <input type="email" placeholder="email" name="reg_email" required>
                        <?php if (!empty($emailError)) { ?>
                        <span class="error"><?php echo $emailError; ?></span>
                        <?php } ?>
                        <input type="password" placeholder="password" name="reg_password">
                        <input type="submit" value="Register">
                    </form>
                </div>
            </div>
    </div>
    <script>
        const login_btn = document.querySelector('.login_btn');
        const register_btn = document.querySelector('.register_btn');
        const formLog = document.querySelector('.formLog');
        const body = document.querySelector('body');

        register_btn.onclick = function(){
        formLog.classList.add('active');
        body.classList.add('active');
        }

        login_btn.onclick = function(){
        formLog.classList.remove('active');
        body.classList.remove('active');
        }
    </script>
<!-- <script type="module" src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.esm.js"></script>
<script nomodule src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.js"></script> -->
</body>
</html>