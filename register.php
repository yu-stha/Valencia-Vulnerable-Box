<?php
session_start();

// Database configuration
$host = 'localhost';
$dbname = 'valencia';
$username = 'elfos';
$password = 'password';

$message = '';
$messageType = '';

// Handle form submission
if ($_POST) {
    try {
        $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $user = trim($_POST['username']);
        $pass = $_POST['password'];
        $confirmPass = $_POST['confirm_password'];
        
        // Validation
        if (empty($user) || empty($pass) || empty($confirmPass)) {
            $message = 'Please fill in all fields.';
            $messageType = 'error';
        } elseif (strlen($user) < 3) {
            $message = 'Username must be at least 3 characters long.';
            $messageType = 'error';
        } elseif (strlen($pass) < 6) {
            $message = 'Password must be at least 6 characters long.';
            $messageType = 'error';
        } elseif ($pass !== $confirmPass) {
            $message = 'Passwords do not match.';
            $messageType = 'error';
        } else {
            // Check if username already exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$user]);
            
            if ($stmt->fetch()) {
                $message = 'Username already exists. Please choose a different one.';
                $messageType = 'error';
            } else {
                // Hash password and insert user
                $hashedPassword = password_hash($pass, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO users (username, password, created_at) VALUES (?, ?, NOW())");
                
                if ($stmt->execute([$user, $hashedPassword])) {
                    $message = 'Account created successfully! You can now <a href="login.php">login here</a>.';
                    $messageType = 'success';
                    // Clear form data
                    $_POST = array();
                } else {
                    $message = 'Error creating account. Please try again.';
                    $messageType = 'error';
                }
            }
        }
    } catch(PDOException $e) {
        $message = 'Database error: ' . $e->getMessage();
        $messageType = 'error';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Your App</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .register-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
            padding: 40px;
        }

        .register-title {
            text-align: center;
            margin-bottom: 30px;
            color: #2c3e50;
            font-size: 28px;
            font-weight: 700;
        }

        .input-group {
            margin-bottom: 20px;
            position: relative;
        }

        .input-field {
            width: 100%;
            padding: 15px 20px;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: #f8f9fa;
        }

        .input-field:focus {
            outline: none;
            border-color: #764ba2;
            background: white;
            box-shadow: 0 0 0 3px rgba(118, 75, 162, 0.1);
        }

        .input-field::placeholder {
            color: #6c757d;
        }

        .submit-btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 10px;
        }

        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(118, 75, 162, 0.4);
        }

        .submit-btn:active {
            transform: translateY(0);
        }

        .message {
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            font-weight: 500;
        }

        .message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .message a {
            color: #155724;
            font-weight: 600;
        }

        .login-link {
            text-align: center;
            margin-top: 20px;
            color: #6c757d;
        }

        .login-link a {
            color: #764ba2;
            text-decoration: none;
            font-weight: 600;
        }

        .login-link a:hover {
            text-decoration: underline;
        }

        .password-requirements {
            font-size: 14px;
            color: #6c757d;
            margin-top: 5px;
            line-height: 1.4;
        }

        /* Responsive design */
        @media (max-width: 480px) {
            .register-container {
                margin: 10px;
                padding: 30px 25px;
            }
            
            .register-title {
                font-size: 24px;
            }
        }
    </style>
</head>
<body>
    <div class="register-container">
        <h2 class="register-title">Create Account</h2>
        
        <?php if ($message): ?>
            <div class="message <?php echo $messageType; ?>">
                <?php echo $message; ?>
            </div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <div class="input-group">
                <input type="text" name="username" class="input-field" placeholder="Username" required value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>">
                <div class="password-requirements">Minimum 3 characters</div>
            </div>
            <div class="input-group">
                <input type="password" name="password" class="input-field" placeholder="Password" required>
                <div class="password-requirements">Minimum 6 characters</div>
            </div>
            <div class="input-group">
                <input type="password" name="confirm_password" class="input-field" placeholder="Confirm Password" required>
            </div>
            <button type="submit" class="submit-btn">Create Account</button>
        </form>
        
        <div class="login-link">
            Already have an account? <a href="login.php">Sign in here</a>
        </div>
    </div>
</body>
</body>
</html>
