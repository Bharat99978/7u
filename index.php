<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bank Management System</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <header>
        <h1>Welcome to the Bank Management System</h1>
    </header>

    <main>
        <section>
            <h2>Login</h2>
            <form action="login.php" method="POST">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
                
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
                
                <button type="submit">Login</button>
            </form>
        </section>

        <section>
            <h2>Sign Up</h2>
            <form action="signup.php" method="POST">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
                
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
                
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
                
                <button type="submit">Sign Up</button>
            </form>
        </section>
    </main>

    <footer>
        <p>&copy; 2024 Bank Management System</p>
    </footer>
</body>
</html>
