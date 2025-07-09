<?php
session_start();

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

// Database configuration
$host = 'localhost';
$dbname = 'valencia';
$username = 'elfas';
$password = 'password';

$message = '';
$messageType = '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // VULNERABLE: Get user ID from URL parameter instead of session
    // This allows IDOR - users can access other users' profiles by changing the URL
    // Default to current user's ID if no 'user' parameter is provided
    $profile_user_id = isset($_GET['user']) ? (int)$_GET['user'] : $_SESSION['user_id'];
    
    // Handle password change
    if ($_POST && isset($_POST['new_password'])) {
        $new_password = $_POST['new_password'];
        $confirm_password = $_POST['confirm_password'];
        
        if (empty($new_password) || empty($confirm_password)) {
            $message = 'Please fill in all password fields.';
            $messageType = 'error';
        } elseif (strlen($new_password) < 6) {
            $message = 'Password must be at least 6 characters long.';
            $messageType = 'error';
        } elseif ($new_password !== $confirm_password) {
            $message = 'Passwords do not match.';
            $messageType = 'error';
        } else {
            // VULNERABLE: Update password without checking if current user owns this profile
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
            
            if ($stmt->execute([$hashed_password, $profile_user_id])) {
                $message = 'Password updated successfully!';
                $messageType = 'success';
            } else {
                $message = 'Error updating password. Please try again.';
                $messageType = 'error';
            }
        }
    }
    
    // Handle profile update
    if ($_POST && isset($_POST['email'])) {
        $email = trim($_POST['email']);
        $full_name = trim($_POST['full_name']);
        
        // Check if columns exist before updating
        try {
            // VULNERABLE: Update any user's profile without authorization check
            $stmt = $pdo->prepare("UPDATE users SET email = ?, full_name = ? WHERE id = ?");
            $stmt->execute([$email, $full_name, $profile_user_id]);
            $message = 'Profile updated successfully!';
            $messageType = 'success';
        } catch(PDOException $e) {
            if (strpos($e->getMessage(), 'Unknown column') !== false) {
                $message = 'Database schema needs to be updated. Please add the missing columns first.';
                $messageType = 'error';
            } else {
                $message = 'Error updating profile: ' . $e->getMessage();
                $messageType = 'error';
            }
        }
    }
    
    // Get user profile information (with fallback for missing columns)
    try {
        $stmt = $pdo->prepare("SELECT id, username, email, full_name, created_at, last_login, role FROM users WHERE id = ?");
        $stmt->execute([$profile_user_id]);
        $profile_user = $stmt->fetch();
    } catch(PDOException $e) {
        // Fallback if columns don't exist - get basic user info only
        $stmt = $pdo->prepare("SELECT id, username, created_at FROM users WHERE id = ?");
        $stmt->execute([$profile_user_id]);
        $profile_user = $stmt->fetch();
        if ($profile_user) {
            // Add missing fields with default values
            $profile_user['email'] = '';
            $profile_user['full_name'] = '';
            $profile_user['last_login'] = null;
            $profile_user['role'] = 'user';
        }
    }
    
    if (!$profile_user) {
        $message = 'User not found.';
        $messageType = 'error';
        $profile_user = ['id' => '', 'username' => '', 'email' => '', 'full_name' => '', 'created_at' => '', 'last_login' => '', 'role' => ''];
    }
    
} catch(PDOException $e) {
    die("Database error: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile Settings - Your App</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .profile-container {
            max-width: 800px;
            margin: 0 auto;
        }

        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 20px 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .nav-links {
            display: flex;
            gap: 15px;
        }

        .nav-link {
            padding: 10px 20px;
            background: #6c757d;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .nav-link:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }

        .nav-link.primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }

        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }

        .card h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 24px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #2c3e50;
            font-weight: 600;
        }

        .form-control {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: #f8f9fa;
        }

        .form-control:focus {
            outline: none;
            border-color: #764ba2;
            background: white;
            box-shadow: 0 0 0 3px rgba(118, 75, 162, 0.1);
        }

        .form-control[readonly] {
            background: #e9ecef;
            color: #6c757d;
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .btn-danger {
            background: #dc3545;
            color: white;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }

        .message {
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 10px;
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

        .user-info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }

        .info-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #764ba2;
        }

        .info-label {
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 5px;
        }

        .info-value {
            color: #6c757d;
            font-size: 14px;
        }

        @media (max-width: 768px) {
            .header {
                flex-direction: column;
                gap: 15px;
            }
            
            .nav-links {
                flex-direction: column;
                width: 100%;
            }
            
            .nav-link {
                text-align: center;
            }
            
            .user-info-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="profile-container">
        <div class="header">
            <h1>Profile Settings</h1>
            <div class="nav-links">
                <a href="dashboard.php" class="nav-link primary">Dashboard</a>
                <a href="?logout=1" class="nav-link">Logout</a>
            </div>
        </div>

        <?php if ($message): ?>
            <div class="message <?php echo $messageType; ?>">
                <?php echo $message; ?>
            </div>
        <?php endif; ?>

        <!-- User Information Display -->
        <div class="card">
            <h2>User Profile</h2>
            <div class="user-info-grid">
                <div class="info-item">
                    <div class="info-label">User ID</div>
                    <div class="info-value"><?php echo htmlspecialchars($profile_user['id']); ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Username</div>
                    <div class="info-value"><?php echo htmlspecialchars($profile_user['username']); ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Role</div>
                    <div class="info-value"><?php echo htmlspecialchars($profile_user['role']); ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Email</div>
                    <div class="info-value"><?php echo htmlspecialchars($profile_user['email'] ?: 'Not set'); ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Full Name</div>
                    <div class="info-value"><?php echo htmlspecialchars($profile_user['full_name'] ?: 'Not set'); ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Member Since</div>
                    <div class="info-value"><?php echo $profile_user['created_at'] ? date('F j, Y', strtotime($profile_user['created_at'])) : 'N/A'; ?></div>
                </div>
            </div>
        </div>

        <!-- Profile Update Form -->
        <div class="card">
            <h2>Update Profile Information</h2>
            <form method="POST" action="?user=<?php echo $profile_user_id; ?>">
                <div class="form-group">
                    <label for="username">Username (Read-only)</label>
                    <input type="text" id="username" class="form-control" value="<?php echo htmlspecialchars($profile_user['username']); ?>" readonly>
                </div>
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" class="form-control" value="<?php echo htmlspecialchars($profile_user['email'] ?: ''); ?>" placeholder="Enter email address">
                </div>
                <div class="form-group">
                    <label for="full_name">Full Name</label>
                    <input type="text" id="full_name" name="full_name" class="form-control" value="<?php echo htmlspecialchars($profile_user['full_name'] ?: ''); ?>" placeholder="Enter full name">
                </div>
                <button type="submit" class="btn btn-primary">Update Profile</button>
            </form>
        </div>

        <!-- Password Change Form -->
        <div class="card">
            <h2>Change Password</h2>
            <form method="POST" action="?user=<?php echo $profile_user_id; ?>">
                <div class="form-group">
                    <label for="new_password">New Password</label>
                    <input type="password" id="new_password" name="new_password" class="form-control" placeholder="Enter new password" required>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" class="form-control" placeholder="Confirm new password" required>
                </div>
                <button type="submit" class="btn btn-danger">Change Password</button>
            </form>
        </div>
    </div>

    <?php
    // Handle logout
    if (isset($_GET['logout'])) {
        session_destroy();
        header('Location: login.php');
        exit();
    }
    ?>
</body>
</html>
