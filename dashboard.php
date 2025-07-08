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
$username = 'elfos';
$password = 'password';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Get user info
    $stmt = $pdo->prepare("SELECT username, created_at FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    
} catch(PDOException $e) {
    die("Database error: " . $e->getMessage());
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: login.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Your App</title>
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

        .dashboard-container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .welcome-message {
            color: #2c3e50;
        }

        .welcome-message h1 {
            font-size: 28px;
            margin-bottom: 5px;
        }

        .welcome-message p {
            color: #6c757d;
            font-size: 16px;
        }

        .user-actions {
            display: flex;
            gap: 15px;
            align-items: center;
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-block;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .btn-secondary {
            background: #6c757d;
            color: white;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }

        .content-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
        }

        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }

        .card h2 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 22px;
        }

        .card p {
            color: #6c757d;
            line-height: 1.6;
            margin-bottom: 20px;
        }

        .user-info {
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(118, 75, 162, 0.1) 100%);
        }

        .stats {
            display: flex;
            justify-content: space-between;
            margin-top: 20px;
        }

        .stat-item {
            text-align: center;
        }

        .stat-number {
            font-size: 24px;
            font-weight: 700;
            color: #667eea;
        }

        .stat-label {
            font-size: 14px;
            color: #6c757d;
            margin-top: 5px;
        }

        /* Responsive design */
        @media (max-width: 768px) {
            .header {
                flex-direction: column;
                gap: 20px;
                text-align: center;
            }
            
            .user-actions {
                flex-direction: column;
                width: 100%;
            }
            
            .btn {
                width: 100%;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="header">
            <div class="welcome-message">
                <h1>Welcome back, <?php echo htmlspecialchars($user['username']); ?>!</h1>
                <p>Member since <?php echo date('F j, Y', strtotime($user['created_at'])); ?></p>
            </div>
            <div class="user-actions">
                <a href="./profile.php" class="btn btn-primary">Profile Settings</a>
                <a href="?logout=1" class="btn btn-secondary">Logout</a>
            </div>
        </div>

        <div class="content-grid">
            <div class="card user-info">
                <h2>Account Information</h2>
                <p>Your account is active and ready to use. You can manage your profile settings and preferences from here.</p>
                <div class="stats">
                    <div class="stat-item">
                        <div class="stat-number">1</div>
                        <div class="stat-label">Projects</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">0</div>
                        <div class="stat-label">Messages</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">5</div>
                        <div class="stat-label">Tasks</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Quick Actions</h2>
                <p>Get started with these common tasks and features.</p>
                <div style="display: flex; flex-direction: column; gap: 10px;">
                    <a href="#" class="btn btn-primary">Create New Project</a>
                    <a href="#" class="btn btn-secondary">View All Projects</a>
                </div>
            </div>

            <div class="card">
                <h2>Recent Activity</h2>
                <p>Here's what's been happening with your account recently.</p>
                <ul style="color: #6c757d; line-height: 1.8;">
                    <li>Account created successfully</li>
                    <li>Profile setup completed</li>
                    <li>Welcome email sent</li>
                </ul>
            </div>

            <div class="card">
                <h2>Getting Started</h2>
                <p>New to the platform? Here are some helpful resources to get you started.</p>
                <div style="display: flex; flex-direction: column; gap: 10px;">
                    <a href="#" class="btn btn-primary">View Tutorial</a>
                    <a href="#" class="btn btn-secondary">Contact Support</a>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
