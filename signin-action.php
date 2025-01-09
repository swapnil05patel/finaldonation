
<?php
// Database connection
$host = 'localhost';
$dbname = 'user_database';  // Database name
$username = 'root';         // MySQL username (default for XAMPP is 'root')
$password = '';             // MySQL password (default for XAMPP is blank)

// Set the DSN (Data Source Name)
$dsn = "mysql:host=$host;dbname=$dbname";

try {
    // Create a PDO instance
    $conn = new PDO($dsn, $username, $password);
    
    // Set PDO error mode to exception
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Confirmation message
    echo "Database connected successfully.<br>";
} catch (PDOException $e) {
    // If connection fails, show the error message
    die("Database connection failed: " . $e->getMessage());
}

// Check if form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize form input to avoid XSS or SQL Injection attacks
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];
    
    // Hash the password for secure storage
    $password_hashed = password_hash($password, PASSWORD_BCRYPT);

    // Insert data into the database
    try {
        // Prepare the SQL query
        $stmt = $conn->prepare("INSERT INTO users (email, password) VALUES (:email, :password)");
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $password_hashed);
        $stmt->execute();
        
        // Confirmation message
        echo "User data saved successfully.<br>";
    } catch (PDOException $e) {
        // If error occurs during insertion
        echo "Error: " . $e->getMessage() . "<br>"; // Show error if any
    }
}
?>