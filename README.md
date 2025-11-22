# PHP + SQLite Shared Whiteboard App (CentOS Deployment)
## This project is intended to be deployed to a CentOS Droplet in the Digital Ocean

This project is a simple PHP + SQLite “shared whiteboard” web application that allows:

- Users to register and log in  
- Users to post messages  
- Administrators to delete messages  

A deployment script is included to automate installation on a CentOS-based DigitalOcean droplet.

---

## Features

- Lightweight, zero-dependency backend (PHP + SQLite)
- Simple login system using password hashing
- Shared message board visible to all authenticated users
- Admin-only message deletion
- Automatically installs:
  - Apache
  - PHP and required extensions
  - SQLite
- Automatically initializes the database
- Automatically deploys all application files

---

## Deployment Script

The included script:

- Updates the system  
- Installs Apache, PHP, SQLite  
- Creates the application directory under `/var/www/html/whiteboard`  
- Writes all required PHP files  
- Initializes the SQLite database  
- Sets file permissions  
- Restarts Apache  

### Run it with:
sudo bash setup_whiteboard_app.sh

### After installation, visit:

http://YOUR_SERVER_IP/whiteboard/register.php

To promote a user to admin:

sqlite3 /var/www/html/whiteboard/db.sqlite \
"UPDATE users SET role='admin' WHERE username='yourname';"


### Known Weaknesses / Potential Vulnerabilities
This application is intentionally minimal and not hardened. Important things to be aware of:
1. No HTTPS: Traffic (including passwords) is unencrypted unless HTTPS is manually configured.
2. No CSRF protection: Forms can be exploited for unauthorized actions via cross-site request forgery.
3. Basic session handling: Sessions use default PHP settings without regeneration on login, secure cookie flags, or advanced protections.
4. SQLite permissions are loose: db.sqlite may be world-writable depending on server configuration.
5. No rate limiting: The login form can be brute-forced without any lockout.
6. No input size limits: Users can paste arbitrarily large messages.
7. No audit logging: Admin deletions and login attempts are not logged.
8. No sandboxing / SELinux configuration: The app runs within Apache’s default security context.
9. Admin privilege escalation risk: Admin role is set manually and stored in a local database without additional verification layers.

### Recommended Improvements
If you choose to expand or secure the system, consider adding:
1. HTTPS with Let's Encrypt
2. CSRF tokens
3. Prepared logout + session regeneration
4. A stronger role/permission system
5. CAPTCHA or login throttling
6. Strict file permissions and SELinux configuration
7. Reverse proxy with Nginx
8. Dockerized deployment
9. Hardened firewall rules
10. Application logs and admin dashboards

### Disclaimer
This project is intended for educational and demonstration purposes only.
It should NOT be used in production environments, on the public internet, or for storing any real user data without significant security improvements.

Use at your own risk.
