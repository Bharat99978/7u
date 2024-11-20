<?php
session_start();

// Database connection
$host = 'sgp.domcloud.co';
$db = 'ivmepusweguwa_db';
$user = 'ivmepusweguwa';
$pass = '9dTtUCY(-5E5btk5_5';

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Registration with email verification
if (isset($_POST['register'])) {
    $username = $_POST['username'];
    $email = $_POST['email'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
    $token = bin2hex(random_bytes(50)); // Unique verification token

    // Check if email is already registered
    $stmt = $conn->prepare("SELECT * FROM users WHERE email=?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        echo "Email already registered.";
    } else {
        // Insert user and send verification email
        $stmt = $conn->prepare("INSERT INTO users (username, email, password, token) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $username, $email, $password, $token);
        
        if ($stmt->execute()) {
            $verifyLink = "http://yourdomain.com/auth.php?verify=" . $token;
            mail($email, "Verify Your Account", "Click this link to verify your account: " . $verifyLink);
            echo "Registration successful! A verification email has been sent.";
        } else {
            echo "Registration failed: " . $stmt->error;
        }
    }
}

// Email verification
if (isset($_GET['verify'])) {
    $token = $_GET['verify'];
    
    $stmt = $conn->prepare("SELECT * FROM users WHERE token=?");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    
    if ($user) {
        $stmt = $conn->prepare("UPDATE users SET verified=1, token=NULL WHERE token=?");
        $stmt->bind_param("s", $token);
        $stmt->execute();
        echo "Your account has been verified! You can now log in.";
    } else {
        echo "Invalid or expired token.";
    }
}

// Login
if (isset($_POST['login'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE email=? AND verified=1");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        echo "Login successful!";
    } else {
        echo "Invalid email, password, or account not verified.";
    }
}

// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: auth.php");
}

?>

<!DOCTYPE html>
<html>
<head>
    <title>Auth System</title>
</head>
<body>

<!-- Registration Form -->
<form action="auth.php" method="POST">
    <h2>Register</h2>
    <input type="text" name="username" placeholder="Username" required>
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit" name="register">Register</button>
</form>

<!-- Login Form -->
<form action="auth.php" method="POST">
    <h2>Login</h2>
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit" name="login">Login</button>
</form>

<!-- Logout Link -->
<?php if (isset($_SESSION['user_id'])): ?>
    <a href="auth.php?logout">Logout</a>
    <p>Welcome, <?php echo $_SESSION['username']; ?></p>
<?php endif; ?>

</body>
</html>