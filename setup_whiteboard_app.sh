#!/bin/bash
set -e

echo "=== Updating system ==="
yum -y update

echo "=== Installing Apache, PHP, SQLite ==="
yum -y install httpd php php-sqlite3 php-pdo php-mbstring sqlite

# For CentOS 7 fallback (SQLite support)
yum -y install php-pdo php-sqlite php-json || true

# policy utils support
yum -y install policycoreutils-python-utils || yum -y install policycoreutils-python

systemctl enable httpd
systemctl start httpd

echo "=== Creating app directory ==="
APP_DIR="/var/www/html"
mkdir -p $APP_DIR

echo "=== Writing application files ==="

############################################
# index.php
############################################
cat > $APP_DIR/index.php <<'EOF'
<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}
$db = new SQLite3(__DIR__ . '/db.sqlite');

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

<p>Logged in as <strong><?= $_SESSION['username'] ?></strong>
(<?= $_SESSION['role'] ?>)
 | <a href="logout.php">Logout</a></p>

<form action="post_message.php" method="POST">
    <textarea name="content" rows="3" cols="40" required></textarea><br>
    <button type="submit">Post Message</button>
</form>

<hr>

<?php while ($row = $messages->fetchArray(SQLITE3_ASSOC)): ?>
    <div style="border:1px solid #ccc; padding:10px; margin:10px 0;">
        <strong><?= htmlspecialchars($row['username']) ?></strong>
        <em>(<?= $row['created_at'] ?>)</em><br>
        <?= nl2br(htmlspecialchars($row['content'])) ?><br>
        <?php if ($_SESSION['role'] === 'admin'): ?>
            <a href="delete_message.php?id=<?= $row['id'] ?>" style="color:red;">Delete</a>
        <?php endif; ?>
    </div>
<?php endwhile; ?>

</body>
</html>
EOF

############################################
# login.php
############################################
cat > $APP_DIR/login.php <<'EOF'
<?php
session_start();
$db = new SQLite3(__DIR__ . '/db.sqlite');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bindValue(1, $username);
    $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if ($result && password_verify($password, $result['password'])) {
        $_SESSION['user_id'] = $result['id'];
        $_SESSION['username'] = $result['username'];
        $_SESSION['role'] = $result['role'];
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

############################################
# register.php
############################################
cat > $APP_DIR/register.php <<'EOF'
<?php
session_start();
$db = new SQLite3(__DIR__ . '/db.sqlite');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

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

############################################
# logout.php
############################################
cat > $APP_DIR/logout.php <<'EOF'
<?php
session_start();
session_destroy();
header("Location: login.php");
EOF

############################################
# post_message.php
############################################
cat > $APP_DIR/post_message.php <<'EOF'
<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    exit("Not logged in.");
}
$db = new SQLite3(__DIR__ . '/db.sqlite');
$content = trim($_POST['content']);

if ($content !== "") {
    $stmt = $db->prepare("INSERT INTO messages (user_id, content) VALUES (?, ?)");
    $stmt->bindValue(1, $_SESSION['user_id']);
    $stmt->bindValue(2, $content);
    $stmt->execute();
}
header("Location: index.php");
EOF

############################################
# delete_message.php
############################################
cat > $APP_DIR/delete_message.php <<'EOF'
<?php
session_start();
if ($_SESSION['role'] !== 'admin') {
    exit("Not authorized.");
}
$db = new SQLite3(__DIR__ . '/db.sqlite');

$id = intval($_GET['id']);
$stmt = $db->prepare("DELETE FROM messages WHERE id = ?");
$stmt->bindValue(1, $id);
$stmt->execute();
header("Location: index.php");
EOF

############################################
# init_db.php
############################################
cat > $APP_DIR/init_db.php <<'EOF'
<?php
$db = new SQLite3(__DIR__ . '/db.sqlite');

// Users table
$db->exec("
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    )
");

// Messages
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

echo "=== Initializing database ==="
cd $APP_DIR
php init_db.php

echo "=== Setting permissions ==="
chown -R apache:apache /var/www/html
chmod -R 755 /var/www/html

chmod 664 /var/www/html/db.sqlite

echo "=== Applying SELinux context for writable DB === "
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/html(/.*)?"
restorecon -Rv /var/www/html

echo "== Enabling SELinux == "
setenforce 1 || true

echo "=== Restarting Apache ==="
systemctl restart httpd

# Get the public IP automatically
PUBLIC_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address)

echo "=== Done! Web app deployed ==="
echo "Visit: http://$PUBLIC_IP/register.php"
