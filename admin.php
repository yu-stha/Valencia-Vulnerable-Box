<?php
session_start();

$message = '';
$messageType = '';

// Database configuration
$host = 'localhost';
$dbname = 'valencia';
$username = 'elfas';
$password = 'password';

// Function to get admin credentials from database
function getAdminCredentials($pdo) {
    try {
        // Look for admin user in the database
        $stmt = $pdo->prepare("SELECT username, password FROM users WHERE username = 'admin' LIMIT 1");
        $stmt->execute();
        $admin = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($admin) {
            return [
                'username' => $admin['username'],
                'password' => $admin['password']
            ];
        }
        
        // Fallback to default credentials if admin not found in database
        return [
            'username' => 'admin',
            'password' => password_hash('admin123', PASSWORD_DEFAULT)
        ];
    } catch (PDOException $e) {
        // Fallback to default credentials on database error
        return [
            'username' => 'admin',
            'password' => password_hash('admin123', PASSWORD_DEFAULT)
        ];
    }
}

// Handle admin login
if (isset($_POST['admin_login'])) {
    try {
        $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $adminCredentials = getAdminCredentials($pdo);
        
        $inputUsername = $_POST['admin_user'];
        $inputPassword = $_POST['admin_pass'];
        
        // Check if username matches and password is correct
        if ($inputUsername === $adminCredentials['username'] && 
            password_verify($inputPassword, $adminCredentials['password'])) {
            $_SESSION['admin_logged_in'] = true;
        } else {
            $message = 'Invalid admin credentials!';
            $messageType = 'error';
        }
    } catch (PDOException $e) {
        $message = 'Database connection error!';
        $messageType = 'error';
    }
}

// Handle admin logout
if (isset($_GET['admin_logout'])) {
    unset($_SESSION['admin_logged_in']);
    header('Location: admin.php');
    exit();
}

// Check if admin is logged in
$adminLoggedIn = isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;

if ($adminLoggedIn) {
    try {
        $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Handle user creation
        if (isset($_POST['create_user'])) {
            $newUser = trim($_POST['new_username']);
            $newPass = $_POST['new_password'];
            $newEmail = trim($_POST['new_email']);
            
            if (!empty($newUser) && !empty($newPass)) {
                // Check if username exists
                $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
                $stmt->execute([$newUser]);
                
                if ($stmt->fetch()) {
                    $message = 'Username already exists!';
                    $messageType = 'error';
                } else {
                    $hashedPassword = password_hash($newPass, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
                    
                    if ($stmt->execute([$newUser, $hashedPassword, $newEmail])) {
                        $message = 'User created successfully!';
                        $messageType = 'success';
                    } else {
                        $message = 'Error creating user!';
                        $messageType = 'error';
                    }
                }
            } else {
                $message = 'Username and password are required!';
                $messageType = 'error';
            }
        }
        
        // Handle user deletion
        if (isset($_POST['delete_user'])) {
            $userId = $_POST['user_id'];
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
            if ($stmt->execute([$userId])) {
                $message = 'User deleted successfully!';
                $messageType = 'success';
            } else {
                $message = 'Error deleting user!';
                $messageType = 'error';
            }
        }
        
        // Handle user status update
        if (isset($_POST['update_status'])) {
            $userId = $_POST['user_id'];
            $newStatus = $_POST['status'];
            $stmt = $pdo->prepare("UPDATE users SET status = ? WHERE id = ?");
            if ($stmt->execute([$newStatus, $userId])) {
                $message = 'User status updated!';
                $messageType = 'success';
            }
        }
        
        // SECURED: Log file viewer with proper sanitization
        if (isset($_POST['view_logs'])) {
            $logFile = $_POST['log_file'];
            $lines = $_POST['lines'] ?? '10';
            
            // Sanitize inputs to prevent command injection
            $logFile = escapeshellarg($logFile);
            $lines = intval($lines);
            
            // Validate that lines is a positive integer
            if ($lines <= 0 || $lines > 1000) {
                $lines = 10;
            }
            
            $command = "tail -n " . $lines . " " . $logFile;
            $logOutput = shell_exec($command);
            
            if ($logOutput === null) {
                $message = 'Error reading log file or file not found!';
                $messageType = 'error';
            }
        }
        
        // VULNERABLE: Log search functionality
        if (isset($_POST['search_logs'])) {
            $searchTerm = $_POST['search_term'];
            $logFile = $_POST['search_log_file'];
            
            // INTENTIONALLY VULNERABLE: Command injection through search term
            $command = "grep '" . $searchTerm . "' " . $logFile;
            $searchOutput = shell_exec($command);
            
            if ($searchOutput === null) {
                $message = 'No results found or error occurred!';
                $messageType = 'error';
            }
        }
        
        // SECURED: Log file management with proper sanitization
        if (isset($_POST['manage_logs'])) {
            $action = $_POST['log_action'];
            $targetFile = $_POST['target_file'];
            
            // Sanitize inputs to prevent command injection
            $targetFile = escapeshellarg($targetFile);
            
            switch ($action) {
                case 'compress':
                    $command = "gzip " . $targetFile;
                    break;
                case 'delete':
                    $command = "rm " . $targetFile;
                    break;
                case 'copy':
                    $destination = escapeshellarg($_POST['destination']);
                    $command = "cp " . $targetFile . " " . $destination;
                    break;
                case 'move':
                    $destination = escapeshellarg($_POST['destination']);
                    $command = "mv " . $targetFile . " " . $destination;
                    break;
                default:
                    $command = "ls -la " . $targetFile;
            }
            
            $manageOutput = shell_exec($command);
        }
        
        // Get all users
        $stmt = $pdo->query("SELECT * FROM users ORDER BY created_at DESC");
        $users = $stmt->fetchAll();
        
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
    <title>Vulnerable Admin Panel - Security Learning Box</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            min-height: 100vh;
            padding: 20px;
            color: #333;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        .admin-header {
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

        .login-form, .admin-panel {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
        }

        .vulnerable-warning {
            background: #fff3cd;
            border: 2px solid #ffeaa7;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            text-align: center;
        }

        .vulnerable-warning h3 {
            color: #d63031;
            margin-bottom: 10px;
        }

        .nav-tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 2px solid #e9ecef;
        }

        .nav-tab {
            padding: 12px 24px;
            background: #f8f9fa;
            border: none;
            border-bottom: 3px solid transparent;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .nav-tab.active {
            background: #fff;
            border-bottom-color: #3498db;
            color: #3498db;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #2c3e50;
        }

        .form-control {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s ease;
        }

        .form-control:focus {
            outline: none;
            border-color: #3498db;
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-right: 10px;
            margin-bottom: 10px;
        }

        .btn-primary {
            background: #3498db;
            color: white;
        }

        .btn-success {
            background: #27ae60;
            color: white;
        }

        .btn-danger {
            background: #e74c3c;
            color: white;
        }

        .btn-warning {
            background: #f39c12;
            color: white;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }

        .message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
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

        .log-output {
            background: #1e1e1e;
            color: #f8f8f2;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            white-space: pre-wrap;
            max-height: 400px;
            overflow-y: auto;
            margin-top: 20px;
        }

        .users-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        .users-table th,
        .users-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        .users-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }

        .users-table tr:hover {
            background: #f8f9fa;
        }

        .status-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .status-active {
            background: #d4edda;
            color: #155724;
        }

        .status-inactive {
            background: #fff3cd;
            color: #856404;
        }

        .status-banned {
            background: #f8d7da;
            color: #721c24;
        }

        .create-user-form {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
        }

        .form-row {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }

        .form-row .form-group {
            flex: 1;
            margin-bottom: 0;
        }

        .vulnerability-info {
            background: #ffe6e6;
            border: 1px solid #ff9999;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
        }

        .vulnerability-info h4 {
            color: #d63031;
            margin-bottom: 10px;
        }

        .vulnerability-info ul {
            margin-left: 20px;
        }

        .vulnerability-info ul li {
            margin-bottom: 5px;
        }

        @media (max-width: 768px) {
            .form-row {
                flex-direction: column;
                gap: 0;
            }
            
            .form-row .form-group {
                margin-bottom: 20px;
            }
            
            .admin-header {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }

            .nav-tabs {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if (!$adminLoggedIn): ?>
            <div class="vulnerable-warning">
                <h2>Admin Pannel Login</h2>
                <strong>Unauthorized Access will be logged and Penalized.</strong></p>
            </div>

            <div class="login-form">
                <h2 style="margin-bottom: 20px; color: #2c3e50;">Admin Login</h2>
                
                <?php if ($message): ?>
                    <div class="message <?php echo $messageType; ?>">
                        <?php echo htmlspecialchars($message); ?>
                    </div>
                <?php endif; ?>
                
                <form method="POST">
                    <div class="form-group">
                        <label>Admin Username:</label>
                        <input type="text" name="admin_user" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label>Admin Password:</label>
                        <input type="password" name="admin_pass" class="form-control" required>
                    </div>
                    <button type="submit" name="admin_login" class="btn btn-primary">Login</button>
                </form>
                
             
        <?php else: ?>
            <div class="admin-header">
                <h1 style="color: #2c3e50;">Admin Panel</h1>
                <a href="?admin_logout=1" class="btn btn-danger">Logout</a>
            </div>

            <?php if ($message): ?>
                <div class="message <?php echo $messageType; ?>">
                    <?php echo htmlspecialchars($message); ?>
                </div>
            <?php endif; ?>

            <div class="nav-tabs">
                <button class="nav-tab active" onclick="showTab('users')">User Management</button>
                <button class="nav-tab" onclick="showTab('logs')">Log Viewer</button>
                <button class="nav-tab" onclick="showTab('search')">Log Search</button>
                <button class="nav-tab" onclick="showTab('manage')">File Management</button>
            </div>

            <!-- User Management Tab -->
            <div id="users" class="tab-content active">
                <div class="admin-panel">
                    <h3 style="margin-bottom: 20px; color: #2c3e50;">Create New User</h3>
                    
                    <div class="create-user-form">
                        <form method="POST">
                            <div class="form-row">
                                <div class="form-group">
                                    <label>Username:</label>
                                    <input type="text" name="new_username" class="form-control" required>
                                </div>
                                <div class="form-group">
                                    <label>Password:</label>
                                    <input type="password" name="new_password" class="form-control" required>
                                </div>
                                <div class="form-group">
                                    <label>Email (optional):</label>
                                    <input type="email" name="new_email" class="form-control">
                                </div>
                            </div>
                            <button type="submit" name="create_user" class="btn btn-success">Create User</button>
                        </form>
                    </div>
                </div>

                <div class="admin-panel">
                    <h3 style="margin-bottom: 20px; color: #2c3e50;">All Users (<?php echo count($users); ?> total)</h3>
                    
                    <table class="users-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Email</th>
                                <th>Status</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?php echo $user['id']; ?></td>
                                <td><?php echo htmlspecialchars($user['username']); ?></td>
                                <td><?php echo htmlspecialchars($user['email'] ?: 'Not provided'); ?></td>
                                <td>
                                    <span class="status-badge status-<?php echo $user['status']; ?>">
                                        <?php echo $user['status']; ?>
                                    </span>
                                </td>
                                <td><?php echo date('M j, Y', strtotime($user['created_at'])); ?></td>
                                <td>
                                    <form method="POST" style="display: inline-block;">
                                        <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                        <select name="status" onchange="this.form.submit()">
                                            <option value="active" <?php echo $user['status'] === 'active' ? 'selected' : ''; ?>>Active</option>
                                            <option value="inactive" <?php echo $user['status'] === 'inactive' ? 'selected' : ''; ?>>Inactive</option>
                                            <option value="banned" <?php echo $user['status'] === 'banned' ? 'selected' : ''; ?>>Banned</option>
                                        </select>
                                        <input type="hidden" name="update_status" value="1">
                                    </form>
                                    
                                    <form method="POST" style="display: inline-block;" onsubmit="return confirm('Are you sure you want to delete this user?')">
                                        <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                        <button type="submit" name="delete_user" class="btn btn-danger" style="padding: 6px 12px; font-size: 12px;">Delete</button>
                                    </form>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Log Viewer Tab -->
            <div id="logs" class="tab-content">
                <div class="admin-panel">
                    <h3 style="margin-bottom: 20px; color: #2c3e50;">System Log Viewer</h3>
                    
                    
                    <form method="POST">
                        <div class="form-row">
                            <div class="form-group">
                                <label>Log File Path:</label>
                                <input type="text" name="log_file" class="form-control" 
                                       value="<?php echo isset($_POST['log_file']) ? htmlspecialchars($_POST['log_file']) : '/var/log/apache2/access.log'; ?>" 
                                       placeholder="/var/log/apache2/access.log">
                            </div>
                            <div class="form-group">
                                <label>Number of Lines:</label>
                                <select name="lines" class="form-control">
                                    <option value="10">10 lines</option>
                                    <option value="25">25 lines</option>
                                    <option value="50">50 lines</option>
                                    <option value="100">100 lines</option>
                                </select>
                            </div>
                        </div>
                        <button type="submit" name="view_logs" class="btn btn-primary">View Logs</button>
                    </form>
                    
                    <?php if (isset($logOutput)): ?>
                        <div class="log-output">
                            <?php echo htmlspecialchars($logOutput); ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Log Search Tab -->
            <div id="search" class="tab-content">
                <div class="admin-panel">
                    <h3 style="margin-bottom: 20px; color: #2c3e50;">Log Search Functionality</h3>

                    <form method="POST">
                        <div class="form-row">
                            <div class="form-group">
                                <label>Search Term:</label>
                                <input type="text" name="search_term" class="form-control" 
                                       value="<?php echo isset($_POST['search_term']) ? htmlspecialchars($_POST['search_term']) : ''; ?>" 
                                       placeholder="Enter search term">
                            </div>
                            <div class="form-group">
                                <label>Log File:</label>
                                <input type="text" name="search_log_file" class="form-control" 
                                       value="<?php echo isset($_POST['search_log_file']) ? htmlspecialchars($_POST['search_log_file']) : '/var/log/apache2/access.log'; ?>" 
                                       placeholder="/var/log/apache2/access.log">
                            </div>
                        </div>
                        <button type="submit" name="search_logs" class="btn btn-primary">Search Logs</button>
                    </form>
                    
                    <?php if (isset($searchOutput)): ?>
                        <div class="log-output">
                            <?php echo htmlspecialchars($searchOutput); ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- File Management Tab -->
            <div id="manage" class="tab-content">
                <div class="admin-panel">
                    <h3 style="margin-bottom: 20px; color: #2c3e50;">Log File Management</h3>
                    
                    <form method="POST">
                        <div class="form-row">
                            <div class="form-group">
                                <label>Action:</label>
                                <select name="log_action" class="form-control" onchange="toggleDestination(this.value)">
                                    <option value="list">List File Info</option>
                                    <option value="compress">Compress File</option>
                                    <option value="delete">Delete File</option>
                                    <option value="copy">Copy File</option>
                                    <option value="move">Move File</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Target File:</label>
                                <input type="text" name="target_file" class="form-control" 
                                       value="<?php echo isset($_POST['target_file']) ? htmlspecialchars($_POST['target_file']) : '/var/log/apache2/access.log'; ?>" 
                                       placeholder="/var/log/apache2/access.log">
                            </div>
                            <div class="form-group" id="destination-group" style="display: none;">
                                <label>Destination:</label>
                                <input type="text" name="destination" class="form-control" 
                                       placeholder="/tmp/backup.log">
                            </div>
                        </div>
                        <button type="submit" name="manage_logs" class="btn btn-warning">Execute Action</button>
                    </form>
                    
                    <?php if (isset($manageOutput)): ?>
                        <div class="log-output">
                            <?php echo htmlspecialchars($manageOutput); ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <script>
        function showTab(tabName) {
            // Hide all tab contents
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.nav-tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }

        function toggleDestination(action) {
            const destinationGroup = document.getElementById('destination-group');
            if (action === 'copy' || action === 'move') {
                destinationGroup.style.display = 'block';
            } else {
                destinationGroup.style.display = 'none';
            }
        }
    </script>
</body>
</html>
