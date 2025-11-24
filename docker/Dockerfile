FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# Install Apache + PHP + SQLite
RUN apt-get update && apt-get install -y \
    apache2 \
    php \
    libapache2-mod-php \
    php-sqlite3 \
    php-mbstring \
    php-xml \
    sqlite3 \
    && apt-get clean

# Enable Apache rewrite
RUN a2enmod rewrite

# Create application directory
RUN mkdir -p /var/www/html/data
WORKDIR /var/www/html

##############################################
# PHP application files
##############################################

### index.php ###
RUN cat > index.php << 'EOF'
<?php
session_start();
if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}
$db = new SQLite3(__DIR__ . "/data/db.sqlite");
$messages = $db->query("
    SELECT m.id, m.content, m.created_at, u.username
    FROM messages m
    JOIN users u ON m.user_id = u.id
    ORDER BY m.created_at DESC
");
?>
<!DOCTYPE html>
<html>
<body>
<h2>Shared Whiteboard</h2>

<p>Logged in as <strong><?= $_SESSION["username"] ?></strong>
(<?= $_SESSION["role"] ?>)
 | <a href="logout.php">Logout</a></p>

<form action="post_message.php" method="POST">
    <textarea name="content" rows="3" cols="40" required></textarea><br>
    <button type="submit">Post Message</button>
</form>

<hr>

<?php while ($row = $messages->fetchArray(SQLITE3_ASSOC)): ?>
    <div style="border:1px solid #ccc; padding:10px; margin:10px 0;">
        <strong><?= htmlspecialchars($row["username"]) ?></strong>
        <em>(<?= $row["created_at"] ?>)</em><br>
        <?= nl2br(htmlspecialchars($row["content"])) ?><br>
        <?php if ($_SESSION["role"] === "admin"): ?>
            <a href="delete_message.php?id=<?= $row["id"] ?>" style="color:red;">Delete</a>
        <?php endif; ?>
    </div>
<?php endwhile; ?>

</body>
</html>
EOF

### login.php ###
RUN cat > login.php << 'EOF'
<?php
session_start();
$db = new SQLite3(__DIR__ . "/data/db.sqlite");

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = trim($_POST["username"]);
    $password = $_POST["password"];

    $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bindValue(1, $username);
    $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if ($result && password_verify($password, $result["password"])) {
        $_SESSION["user_id"] = $result["id"];
        $_SESSION["username"] = $result["username"];
        $_SESSION["role"] = $result["role"];
        header("Location: index.php");
        exit;
    } else {
        $error = "Invalid login.";
    }
}
?>
<!DOCTYPE html>
<html>
<body>
<h2>Login</h2>
<form method="POST">
    Username: <input name="username" required><br>
    Password: <input type="password" name="password" required><br>
    <button type="submit">Login</button>
</form>
<?= isset($error) ? $error : "" ?>
</body>
</html>
EOF

### register.php ###
RUN cat > register.php << 'EOF'
<?php
session_start();
$db = new SQLite3(__DIR__ . "/data/db.sqlite");

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = trim($_POST["username"]);
    $password = password_hash($_POST["password"], PASSWORD_DEFAULT);

    $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->bindValue(1, $username);
    $stmt->bindValue(2, $password);

    if ($stmt->execute()) {
        header("Location: login.php");
        exit;
    } else {
        $error = "Username already exists.";
    }
}
?>
<!DOCTYPE html>
<html>
<body>
<h2>Register</h2>
<form method="POST">
    Username: <input name="username" required><br>
    Password: <input type="password" name="password" required><br>
    <button type="submit">Register</button>
</form>
<?= isset($error) ? $error : "" ?>
</body>
</html>
EOF

### logout.php ###
RUN cat > logout.php << 'EOF'
<?php
session_start();
session_destroy();
header("Location: login.php");
EOF

### post_message.php ###
RUN cat > post_message.php << 'EOF'
<?php
session_start();
if (!isset($_SESSION["user_id"])) {
    exit("Not logged in.");
}
$db = new SQLite3(__DIR__ . "/data/db.sqlite");
$content = trim($_POST["content"]);

if ($content !== "") {
    $stmt = $db->prepare("INSERT INTO messages (user_id, content) VALUES (?, ?)");
    $stmt->bindValue(1, $_SESSION["user_id"]);
    $stmt->bindValue(2, $content);
    $stmt->execute();
}
header("Location: index.php");
EOF

### delete_message.php ###
RUN cat > delete_message.php << 'EOF'
<?php
session_start();
if ($_SESSION["role"] !== "admin") {
    exit("Not authorized.");
}
$db = new SQLite3(__DIR__ . "/data/db.sqlite");

$id = intval($_GET["id"]);
$stmt = $db->prepare("DELETE FROM messages WHERE id = ?");
stmt->bindValue(1, $id);
$stmt->execute();
header("Location: index.php");
EOF

### init_db.php ###
RUN cat > init_db.php << 'EOF'
<?php
$db = new SQLite3(__DIR__ . "/data/db.sqlite");

$db->exec("
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    )
");

$db->exec("
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
");

echo "Database initialized\n";
EOF

# Initialize DB during image build
RUN php /var/www/html/init_db.php

# Permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

EXPOSE 80

CMD ["apache2ctl", "-D", "FOREGROUND"]
