# Secure_login_system_in_c

Secure Login System
A command-line secure login system implemented in C, featuring user authentication, PIN hashing with PBKDF2, account lockout mechanisms, session management, and admin functionalities. This project demonstrates secure programming practices and cryptographic techniques for user management.
Features

User Registration: Create new accounts with unique usernames and PINs (8-15 characters, alphanumeric).
Secure PIN Storage: PINs are hashed using PBKDF2 with 100,000 iterations and 32-byte binary salts for robust security.
Login System: Authenticate users with username and PIN, including:
Account lockout after 3 failed attempts (5-minute lockout).
Session timeout after 15 minutes of inactivity.


PIN Management: Logged-in users can change their PIN after verifying the current PIN.
Admin Capabilities:
View all registered users (username, role, last login).
Delete non-admin user accounts.


Security Measures:
Sanitized input to prevent buffer overflows.
Secure memory clearing for sensitive data (e.g., PINs).
Restricted file permissions for user data (users.dat) and audit logs (audit.log).
Audit logging of significant events (e.g., logins, failures, user creation).


File-Based Storage: User data is stored in users.dat with atomic writes for reliability.

Prerequisites

Operating System: Unix-like (Linux, macOS, or WSL on Windows). The program uses Unix-specific features (termios.h, chmod).
Compiler: GCC or Clang.
Dependencies: OpenSSL library for cryptographic functions (RAND_bytes, PBKDF2).
Environment: Tested in CS50 Codespace (GitHub Codespaces), but works on any compatible system with OpenSSL installed.

Installation
1. Clone the Repository
Clone this repository to your local machine or Codespace:
git clone https://github.com/your-username/secure-login-system.git
cd secure-login-system

Replace your-username with your GitHub username.
2. Install Dependencies
Ensure GCC and OpenSSL are installed.
On Ubuntu/Linux
sudo apt update
sudo apt install build-essential libssl-dev

On macOS
Install Xcode Command Line Tools and OpenSSL via Homebrew:
xcode-select --install
brew install openssl

In CS50 Codespace
CS50 Codespace (based on Ubuntu) includes GCC and OpenSSL by default, so no additional installation is needed.
3. Compile the Program
Compile the source code (secure_login_system.c) using GCC, linking OpenSSL libraries:
gcc -o login secure_login_system.c -lssl -lcrypto

On macOS with Homebrew OpenSSL, you may need to specify paths:
gcc -o login secure_login_system.c -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto

This creates an executable named login.
Usage

Run the Program:
./login


First-Time Setup:

If no user database exists, the program prompts for admin account setup.
Enter a username (e.g., admin) and a PIN (8-15 characters, alphanumeric, e.g., admin1234).
The admin account is created and saved in users.dat.


Main Menu:

Not Logged In:
Login (1): Enter username and PIN to authenticate.
Signup (2): Create a new user account with a unique username and valid PIN.
Exit (3): Exit the program.


Logged In (User):
Change PIN (1): Update your PIN after verifying the current PIN.
Logout (2): Log out and return to the main menu.


Logged In (Admin):
Change PIN (1): Same as user.
View Users (2): List all users (username, role, last login).
Delete User (3): Delete a non-admin user account.
Logout (4): Log out.




Files Generated:

users.dat: Stores user data (username, PIN hash, salt, admin status, etc.) with owner-only permissions (0600).
audit.log: Logs events (e.g., logins, failures, user creation) with timestamps.


Resetting the Database: To start fresh (e.g., to re-run admin setup), delete the user database:
rm users.dat



Example Workflow

Run ./login.

Set up an admin account (e.g., username: admin, PIN: admin1234).

Select option 2 to sign up a new user (e.g., username: user1, PIN: user1234).

Log in as user1 (option 1) and change the PIN (option 1).

Log in as admin and view all users (option 2) or delete user1 (option 3).

Check audit.log for event history:
cat audit.log



Security Notes

PIN Hashing: Uses PBKDF2 with 100,000 iterations and 32-byte salts, aligned with NIST recommendations for secure password storage.
Input Sanitization: Prevents buffer overflows by clearing excess input and removing newlines.
File Permissions: Ensures users.dat and audit.log are only accessible by the owner (0600).
Session Management: Enforces 15-minute session timeouts and 5-minute lockouts after 3 failed login attempts.
Memory Safety: Sensitive data (PINs) is cleared from memory using secure_clear.

Limitations

No Password Reset: If a user forgets their PIN, an admin must delete and recreate the account (no built-in reset feature).
Command-Line Only: No graphical interface; designed for terminal use.
Unix Dependency: Relies on Unix-specific features, limiting portability to Windows without WSL or Cygwin.
Fixed User Limit: Supports up to 100 users (configurable via MAX_USERS).

Troubleshooting

Compilation Errors:
"cannot find -lssl": Ensure OpenSSL is installed (sudo apt install libssl-dev or brew install openssl).
Syntax Errors: Verify the source file (secure_login_system.c) is complete and unmodified.


Runtime Issues:
PIN Rejection: Ensure PINs are 8-15 characters, alphanumeric (e.g., user1234).

File Errors: Check permissions for users.dat and audit.log:
chmod 600 users.dat audit.log


Crash: Compile with debugging symbols and use gdb:
gcc -g -o login secure_login_system.c -lssl -lcrypto
gdb ./login


Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a new branch (git checkout -b feature/your-feature).
Make changes and commit (git commit -m "Add your feature").
Push to the branch (git push origin feature/your-feature).
Open a pull request.

Please ensure changes maintain security and include documentation.
License
This project is licensed under the MIT License. See the LICENSE file for details.
Acknowledgments

Built as part of a learning exercise in secure programming.
Uses OpenSSL for cryptographic functions.
Tested in CS50 Codespace, inspired by Harvard's CS50 course.

For issues or feature requests, open an issue on the GitHub repository.
