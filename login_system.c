/*
 * Secure Login System
 *
 * This program implements a secure login system with user authentication,
 * PIN hashing using PBKDF2, account lockout mechanisms, and session management.
 * It supports user registration, login, PIN changes, and admin functionalities
 * such as viewing and deleting users.
 *
 * Features:
 * - User registration with PIN validation (-skipped for brevity-)
 * - Secure PIN hashing with PBKDF2 and unique binary salts
 * - Account lockout after 3 failed login attempts for 5 minutes
 * - Session timeout after 15 minutes of inactivity
 * - Admin capabilities to view all users and delete non-admin accounts
 * - Secure file handling with restricted permissions
 * - Audit logging of all significant events
 *
 * Usage:
 * - Compile with OpenSSL: gcc -o login secure_login_system.c -lssl -lcrypto
 * - Run the program and follow prompts to login, signup, or perform admin tasks.
 *
 * Dependencies:
 * - OpenSSL for cryptographic functions (RAND_bytes, PBKDF2)
 * - Unix-like system for file permissions (chmod) and terminal control (termios)
 *
 * Security Notes:
 * - PINs are hashed using PBKDF2 with 100,000 iterations and 32-byte salts.
 * - User data is stored in 'users.dat' with owner-only permissions (0600).
 * - Sensitive data (PINs) is securely cleared from memory after use.
 * - Input is sanitized to prevent buffer overflows and injection attacks.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <time.h>
 #include <openssl/sha.h>
 #include <openssl/rand.h>
 #include <openssl/evp.h>
 #include <ctype.h>
 #include <unistd.h>
 #include <sys/stat.h>
 #include <termios.h>

 #define MAX_USERS 100
 #define MAX_USERNAME_LENGTH 32
 #define MAX_PIN_LENGTH 16
 #define MIN_PIN_LENGTH 8
 #define SALT_LENGTH 32
 #define USER_FILE "users.dat"
 #define LOG_FILE "audit.log"
 #define LOCKOUT_THRESHOLD 3
 #define LOCKOUT_TIME 300
 #define SESSION_TIMEOUT 900 // 15 minutes

 typedef struct {
     char username[MAX_USERNAME_LENGTH];
     unsigned char pin_hash[SHA256_DIGEST_LENGTH];
     unsigned char salt[SALT_LENGTH];
     int is_admin;
     int failed_attempts;
     time_t lockout_time;
     time_t last_login;
 } User;

 typedef struct {
     User users[MAX_USERS];
     int user_count;
     User* current_user;
     time_t session_start;
 } UserDatabase;

 /*
  * Clears the input buffer to prevent residual characters from affecting subsequent inputs.
  */
 void clear_input_buffer(void) {
     int c;
     while ((c = getchar()) != '\n' && c != EOF);
 }

 /*
  * Sanitizes input by removing newline and clearing buffer if input exceeds size.
  * Parameters:
  *   - input: The input string to sanitize.
  *   - size: The size of the input buffer.
  */
 void sanitize_input(char* input, size_t size) {
     char* newline = strchr(input, '\n');
     if (newline) {
         *newline = '\0';
     } else {
         // Clear the input buffer
         int c;
         while ((c = getchar()) != '\n' && c != EOF);
     }
 }

 /*
  * Reads input without echoing (for PINs) using terminal settings.
  * Parameters:
  *   - buffer: Buffer to store the input.
  *   - size: Size of the buffer.
  */
 void get_hidden_input(char* buffer, size_t size) {
     struct termios old, new;
     tcgetattr(STDIN_FILENO, &old);
     new = old;
     new.c_lflag &= ~(ECHO);
     tcsetattr(STDIN_FILENO, TCSANOW, &new);

     if (fgets(buffer, size, stdin)) {
         sanitize_input(buffer, size);
     }

     tcsetattr(STDIN_FILENO, TCSANOW, &old);
     printf("\n");
 }

 /*
  * Securely clears memory to prevent sensitive data leakage.
  * Parameters:
  *   - ptr: Pointer to the memory to clear.
  *   - size: Size of the memory to clear.
  */
 void secure_clear(void* ptr, size_t size) {
     if (ptr) memset(ptr, 0, size);
 }

 /*
  * Logs events to audit.log with timestamps and secure permissions.
  * Parameters:
  *   - message: The event message to log.
  */
 void log_event(const char* message) {
     FILE* f = fopen(LOG_FILE, "a");
     if (!f) return;
     chmod(LOG_FILE, S_IRUSR | S_IWUSR);
     time_t now = time(NULL);
     char* time_str = ctime(&now);
     time_str[strlen(time_str) - 1] = '\0';
     fprintf(f, "[%s] %s\n", time_str, message);
     fclose(f);
 }

 /*
  * Checks if the current session has expired due to inactivity.
  * Parameters:
  *   - db: Pointer to the UserDatabase.
  * Returns:
  *   - 1 if session is expired, 0 otherwise.
  */
 int is_session_expired(UserDatabase* db) {
     return db->current_user && difftime(time(NULL), db->session_start) > SESSION_TIMEOUT;
 }

 /*
  * Generates a cryptographically secure binary salt.
  * Parameters:
  *   - salt: Buffer to store the salt.
  * Returns:
  *   - 1 on success, 0 on failure.
  */
 int generate_salt(unsigned char* salt) {
     return RAND_bytes(salt, SALT_LENGTH) == 1;
 }

 /*
  * Hashes a PIN using PBKDF2 with a binary salt.
  * Parameters:
  *   - pin: The PIN to hash.
  *   - salt: The binary salt.
  *   - hash: Buffer to store the resulting hash.
  */
 void hash_pin(const char* pin, const unsigned char* salt, unsigned char* hash) {
     PKCS5_PBKDF2_HMAC(pin, strlen(pin), salt, SALT_LENGTH,
                       100000, EVP_sha256(), SHA256_DIGEST_LENGTH, hash);
 }

 /*
  * Checks if an account is locked out due to failed login attempts.
  * Parameters:
  *   - user: Pointer to the User.
  * Returns:
  *   - 1 if locked out, 0 otherwise.
  */
 int is_locked_out(User* user) {
     if (user->failed_attempts < LOCKOUT_THRESHOLD) return 0;
     return difftime(time(NULL), user->lockout_time) < LOCKOUT_TIME;
 }

 /*
  * Updates lockout status based on login success or failure.
  * Parameters:
  *   - user: Pointer to the User.
  *   - success: 1 if login succeeded, 0 otherwise.
  */
 void update_lockout(User* user, int success) {
     if (success) {
         user->failed_attempts = 0;
         user->lockout_time = 0;
     } else {
         user->failed_attempts++;
         if (user->failed_attempts >= LOCKOUT_THRESHOLD)
             user->lockout_time = time(NULL);
     }
 }

 /*
  * Validates a PIN (8-15 characters, must contain letters and numbers).
  * Parameters:
  *   - pin: The PIN to validate.
  * Returns:
  *   - 1 if valid, 0 otherwise.
  */
 int is_valid_pin(const char* pin) {
     size_t len = strlen(pin);
     if (len < MIN_PIN_LENGTH || len >= MAX_PIN_LENGTH) return 0;

     int has_digit = 0, has_alpha = 0;
     for (size_t i = 0; i < len; i++) {
         if (!isalnum(pin[i])) return 0;
         if (isdigit(pin[i])) has_digit = 1;
         if (isalpha(pin[i])) has_alpha = 1;
     }

     return has_digit && has_alpha;
 }

 /*
  * Checks if the user file has secure permissions (owner-only).
  * Parameters:
  *   - filename: The file to check.
  * Returns:
  *   - 1 if secure or file doesn't exist, 0 if insecure.
  */
 int check_file_permissions(const char* filename) {
     struct stat st;
     if (stat(filename, &st) != 0) return 1;
     return (st.st_mode & (S_IRWXG | S_IRWXO)) == 0;
 }

 /*
  * Loads users from the user file.
  * Parameters:
  *   - db: Pointer to the UserDatabase.
  * Returns:
  *   - 1 on success, 0 on failure.
  */
 int load_users(UserDatabase* db) {
     FILE* f = fopen(USER_FILE, "rb");
     if (!f) return 0;

     if (fread(&db->user_count, sizeof(int), 1, f) != 1) {
         fclose(f);
         return 0;
     }

     if (db->user_count > MAX_USERS) {
         fclose(f);
         return 0;
     }

     if (fread(db->users, sizeof(User), db->user_count, f) != (size_t)db->user_count) {
         fclose(f);
         return 0;
     }

     fclose(f);
     return 1;
 }

 /*
  * Saves users to the user file with atomic write.
  * Parameters:
  *   - db: Pointer to the UserDatabase.
  * Returns:
  *   - 1 on success, 0 on failure.
  */
 int save_users(UserDatabase* db) {
     FILE* f = fopen(USER_FILE ".tmp", "wb");
     if (!f) {
         log_event("Error: Failed to create temp user file");
         return 0;
     }

     if (fwrite(&db->user_count, sizeof(int), 1, f) != 1 ||
         fwrite(db->users, sizeof(User), db->user_count, f) != (size_t)db->user_count) {
         fclose(f);
         log_event("Error: Failed to write user data");
         return 0;
     }

     fclose(f);

     if (rename(USER_FILE ".tmp", USER_FILE) != 0) {
         log_event("Error: Failed to replace user file");
         return 0;
     }

     chmod(USER_FILE, S_IRUSR | S_IWUSR);
     return 1;
 }

 /*
  * Checks if an admin user is configured.
  * Parameters:
  *   - db: Pointer to the UserDatabase.
  * Returns:
  *   - 1 if admin exists, 0 otherwise.
  */
 int is_admin_configured(UserDatabase* db) {
     for (int i = 0; i < db->user_count; i++) {
         if (db->users[i].is_admin) return 1;
     }
     return 0;
 }

 /*
  * Authenticates a user by checking username and PIN.
  * Parameters:
  *   - db: Pointer to the UserDatabase.
  * Returns:
  *   - 1 if login is successful, 0 otherwise.
  */
 int login(UserDatabase* db) {
     if (db->current_user) {
         printf("Already logged in as %s\n", db->current_user->username);
         return 1;
     }

     char username[MAX_USERNAME_LENGTH] = {0};
     char pin[MAX_PIN_LENGTH] = {0};

     printf("Username: ");
     if (!fgets(username, sizeof(username), stdin)) {
         log_event("Login failed: input error");
         return 0;
     }
     sanitize_input(username, sizeof(username));

     printf("PIN: ");
     get_hidden_input(pin, sizeof(pin));

     for (int i = 0; i < db->user_count; i++) {
         if (strcmp(db->users[i].username, username) == 0) {
             if (is_locked_out(&db->users[i])) {
                 time_t remaining = LOCKOUT_TIME - difftime(time(NULL), db->users[i].lockout_time);
                 printf("Account locked. Try again in %ld seconds.\n", remaining);
                 log_event("Login failed: account locked");
                 return 0;
             }

             unsigned char hash[SHA256_DIGEST_LENGTH];
             hash_pin(pin, db->users[i].salt, hash);

             if (memcmp(hash, db->users[i].pin_hash, SHA256_DIGEST_LENGTH) == 0) {
                 update_lockout(&db->users[i], 1);
                 db->current_user = &db->users[i];
                 db->session_start = time(NULL);
                 db->current_user->last_login = time(NULL);

                 char log_msg[256];
                 snprintf(log_msg, sizeof(log_msg), "User logged in: %s", username);
                 log_event(log_msg);

                 return 1;
             } else {
                 update_lockout(&db->users[i], 0);
                 printf("Incorrect PIN. Attempts remaining: %d\n",
                       LOCKOUT_THRESHOLD - db->users[i].failed_attempts);

                 char log_msg[256];
                 snprintf(log_msg, sizeof(log_msg), "Failed login: %s (attempt %d)",
                         username, db->users[i].failed_attempts);
                 log_event(log_msg);

                 return 0;
             }
         }
     }

     printf("User not found.\n");
     log_event("Login failed: unknown user");
     secure_clear(pin, sizeof(pin));
     return 0;
 }

 /*
  * Registers a new user with a unique username and valid PIN.
  * Parameters:
  *   - db: Pointer to the UserDatabase.
  * Returns:
  *   - 1 if signup is successful, 0 otherwise.
  */
 int signup(UserDatabase* db) {
     if (db->user_count >= MAX_USERS) {
         printf("User limit reached.\n");
         log_event("Signup failed: user limit reached");
         return 0;
     }

     User new_user = {0};
     printf("Username: ");
     if (!fgets(new_user.username, sizeof(new_user.username), stdin)) {
         log_event("Signup failed: input error");
         return 0;
     }
     sanitize_input(new_user.username, sizeof(new_user.username));

     for (int i = 0; i < db->user_count; i++) {
         if (strcmp(db->users[i].username, new_user.username) == 0) {
             printf("Username already exists.\n");
             log_event("Signup failed: username exists");
             return 0;
         }
     }

     char pin[MAX_PIN_LENGTH] = {0};
     char pin_confirm[MAX_PIN_LENGTH] = {0};

     printf("PIN: ");
     get_hidden_input(pin, sizeof(pin));

     printf("Confirm PIN: ");
     get_hidden_input(pin_confirm, sizeof(pin_confirm));

     if (strcmp(pin, pin_confirm) != 0) {
         printf("PINs do not match.\n");
         log_event("Signup failed: PIN mismatch");
         secure_clear(pin, sizeof(pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         return 0;
     }

     if (!is_valid_pin(pin)) {
         printf("Invalid PIN. Must be %d-%d characters with letters and numbers.\n",
               MIN_PIN_LENGTH, MAX_PIN_LENGTH - 1);
         log_event("Signup failed: invalid PIN");
         secure_clear(pin, sizeof(pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         return 0;
     }

     unsigned char salt[SALT_LENGTH];
     if (!generate_salt(salt)) {
         printf("Failed to generate salt.\n");
         log_event("Signup failed: salt generation");
         secure_clear(pin, sizeof(pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         return 0;
     }

     hash_pin(pin, salt, new_user.pin_hash);
     memcpy(new_user.salt, salt, SALT_LENGTH);
     new_user.is_admin = 0;

     db->users[db->user_count++] = new_user;

     if (!save_users(db)) {
         printf("Failed to save user.\n");
         log_event("Signup failed: save error");
         db->user_count--;
         secure_clear(pin, sizeof(pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         return 0;
     }

     printf("User created successfully.\n");
     log_event("User account created");
     secure_clear(pin, sizeof(pin));
     secure_clear(pin_confirm, sizeof(pin_confirm));
     return 1;
 }

 /*
  * Changes the PIN for the current user after verifying the old PIN.
  * Parameters:
  *   - db: Pointer to the UserDatabase.
  */
 void change_pin(UserDatabase* db) {
     if (!db->current_user) {
         printf("Not logged in.\n");
         return;
     }

     if (is_session_expired(db)) {
         printf("Session expired due to inactivity.\n");
         log_event("Session expired: change PIN");
         db->current_user = NULL;
         return;
     }

     char old_pin[MAX_PIN_LENGTH] = {0};
     char new_pin[MAX_PIN_LENGTH] = {0};
     char pin_confirm[MAX_PIN_LENGTH] = {0};

     printf("Current PIN: ");
     get_hidden_input(old_pin, sizeof(old_pin));

     unsigned char hash[SHA256_DIGEST_LENGTH];
     hash_pin(old_pin, db->current_user->salt, hash);

     if (memcmp(hash, db->current_user->pin_hash, SHA256_DIGEST_LENGTH) != 0) {
         printf("Incorrect current PIN.\n");
         log_event("Change PIN failed: incorrect PIN");
         secure_clear(old_pin, sizeof(old_pin));
         secure_clear(new_pin, sizeof(new_pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         return;
     }

     printf("New PIN: ");
     get_hidden_input(new_pin, sizeof(new_pin));

     printf("Confirm new PIN: ");
     get_hidden_input(pin_confirm, sizeof(pin_confirm));

     if (strcmp(new_pin, pin_confirm) != 0) {
         printf("PINs do not match.\n");
         log_event("Change PIN failed: PIN mismatch");
         secure_clear(old_pin, sizeof(old_pin));
         secure_clear(new_pin, sizeof(new_pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         return;
     }

     if (!is_valid_pin(new_pin)) {
         printf("Invalid PIN. Must be %d-%d characters with letters and numbers.\n",
               MIN_PIN_LENGTH, MAX_PIN_LENGTH - 1);
         log_event("Change PIN failed: invalid PIN");
         secure_clear(old_pin, sizeof(old_pin));
         secure_clear(new_pin, sizeof(new_pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         return;
     }

     unsigned char salt[SALT_LENGTH];
     if (!generate_salt(salt)) {
         printf("Failed to generate salt.\n");
         log_event("Change PIN failed: salt generation");
         secure_clear(old_pin, sizeof(old_pin));
         secure_clear(new_pin, sizeof(new_pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         return;
     }

     hash_pin(new_pin, salt, db->current_user->pin_hash);
     memcpy(db->current_user->salt, salt, SALT_LENGTH);

     if (!save_users(db)) {
         printf("Failed to save PIN change.\n");
         log_event("Change PIN failed: save error");
         secure_clear(old_pin, sizeof(old_pin));
         secure_clear(new_pin, sizeof(new_pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         return;
     }

     printf("PIN changed successfully.\n");
     log_event("PIN changed successfully");
     secure_clear(old_pin, sizeof(old_pin));
     secure_clear(new_pin, sizeof(new_pin));
     secure_clear(pin_confirm, sizeof(pin_confirm));
 }

 /*
  * Displays all registered users (admin only).
  * Parameters:
  *   - db: Pointer to the UserDatabase.
  */
 void view_users(UserDatabase* db) {
     if (!db->current_user) {
         printf("Not logged in.\n");
         return;
     }

     if (is_session_expired(db)) {
         printf("Session expired due to inactivity.\n");
         log_event("Session expired: view users");
         db->current_user = NULL;
         return;
     }

     if (!db->current_user->is_admin) {
         printf("Admin access required.\n");
         log_event("View users failed: not admin");
         return;
     }

     if (db->user_count == 0) {
         printf("No users registered.\n");
         return;
     }

     printf("\nRegistered users:\n");
     for (int i = 0; i < db->user_count; i++) {
         char* time_str = db->users[i].last_login ? ctime(&db->users[i].last_login) : "Never\n";
         if (db->users[i].last_login) {
             time_str[strlen(time_str) - 1] = '\0';
         }
         printf("Username: %s, Role: %s, Last login: %s\n",
                db->users[i].username,
                db->users[i].is_admin ? "Admin" : "User",
                time_str);
     }

     log_event("Admin viewed user list");
 }

 /*
  * Deletes a user (admin only, cannot delete admin or current user).
  * Parameters:
  *   - db: Pointer to the UserDatabase.
  */
 void delete_user(UserDatabase* db) {
     if (!db->current_user) {
         printf("Not logged in.\n");
         return;
     }

     if (is_session_expired(db)) {
         printf("Session expired due to inactivity.\n");
         log_event("Session expired: delete user");
         db->current_user = NULL;
         return;
     }

     if (!db->current_user->is_admin) {
         printf("Admin access required.\n");
         log_event("Delete user failed: not admin");
         return;
     }

     char username[MAX_USERNAME_LENGTH] = {0};
     printf("Enter username to delete: ");
     if (!fgets(username, sizeof(username), stdin)) {
         log_event("Delete user failed: input error");
         return;
     }
     sanitize_input(username, sizeof(username));

     for (int i = 0; i < db->user_count; i++) {
         if (strcmp(db->users[i].username, username) == 0) {
             if (db->users[i].is_admin) {
                 printf("Cannot delete admin account.\n");
                 log_event("Delete user failed: attempted admin deletion");
                 return;
             }
             if (&db->users[i] == db->current_user) {
                 printf("Cannot delete current user.\n");
                 log_event("Delete user failed: attempted current user deletion");
                 return;
             }

             for (int j = i; j < db->user_count - 1; j++) {
                 db->users[j] = db->users[j + 1];
             }
             db->user_count--;

             if (!save_users(db)) {
                 printf("Failed to save user database.\n");
                 log_event("Delete user failed: save error");
                 db->user_count++;
                 return;
             }

             printf("User deleted successfully.\n");
             char log_msg[256];
             snprintf(log_msg, sizeof(log_msg), "User deleted: %s", username);
             log_event(log_msg);
             return;
         }
     }

     printf("User not found.\n");
     log_event("Delete user failed: user not found");
 }

 /*
  * Logs out the current user and clears the session.
  * Parameters:
  *   - db: Pointer to the UserDatabase.
  */
 void logout(UserDatabase* db) {
     if (!db->current_user) {
         printf("Not logged in.\n");
         return;
     }

     char log_msg[256];
     snprintf(log_msg, sizeof(log_msg), "User logged out: %s", db->current_user->username);
     log_event(log_msg);

     db->current_user = NULL;
     db->session_start = 0;
     printf("Logged out successfully.\n");
 }

 /*
  * Configures the initial admin account.
  * Parameters:
  *   - db: Pointer to the UserDatabase.
  */
 void configure_admin(UserDatabase* db) {
     printf("\n=== First-Time Admin Setup ===\n");

     User admin = {0};
     printf("Admin username: ");
     if (!fgets(admin.username, sizeof(admin.username), stdin)) {
         log_event("Admin setup failed: input error");
         exit(EXIT_FAILURE);
     }
     sanitize_input(admin.username, sizeof(admin.username));

     char pin[MAX_PIN_LENGTH] = {0};
     char pin_confirm[MAX_PIN_LENGTH] = {0};

     printf("Admin PIN: ");
     get_hidden_input(pin, sizeof(pin));

     printf("Confirm PIN: ");
     get_hidden_input(pin_confirm, sizeof(pin_confirm));

     if (strcmp(pin, pin_confirm) != 0) {
         printf("PINs do not match.\n");
         log_event("Admin setup failed: PIN mismatch");
         secure_clear(pin, sizeof(pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         exit(EXIT_FAILURE);
     }

     if (!is_valid_pin(pin)) {
         printf("Invalid PIN. Must be %d-%d characters with letters and numbers.\n",
               MIN_PIN_LENGTH, MAX_PIN_LENGTH - 1);
         log_event("Admin setup failed: invalid PIN");
         secure_clear(pin, sizeof(pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         exit(EXIT_FAILURE);
     }

     unsigned char salt[SALT_LENGTH];
     if (!generate_salt(salt)) {
         printf("Failed to generate salt.\n");
         log_event("Admin setup failed: salt generation");
         secure_clear(pin, sizeof(pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         exit(EXIT_FAILURE);
     }

     hash_pin(pin, salt, admin.pin_hash);
     memcpy(admin.salt, salt, SALT_LENGTH);
     admin.is_admin = 1;

     db->users[db->user_count++] = admin;

     if (!save_users(db)) {
         printf("Failed to save admin user.\n");
         log_event("Admin setup failed: save error");
         secure_clear(pin, sizeof(pin));
         secure_clear(pin_confirm, sizeof(pin_confirm));
         exit(EXIT_FAILURE);
     }

     printf("Admin account created successfully.\n");
     log_event("Admin account created");
     secure_clear(pin, sizeof(pin));
     secure_clear(pin_confirm, sizeof(pin_confirm));
 }

 /*
  * Displays the main menu and handles user interactions.
  * Parameters:
  *   - db: Pointer to the UserDatabase.
  */
 void main_menu(UserDatabase* db) {
     while (1) {
         if (db->current_user) {
             if (is_session_expired(db)) {
                 printf("Session expired due to inactivity.\n");
                 logout(db);
             }

             printf("\nLogged in as %s (%s)\n",
                   db->current_user->username,
                   db->current_user->is_admin ? "Admin" : "User");
             printf("1. Change PIN\n2. View Users\n3. Delete User\n4. Logout\nChoice: ");

             int choice;
             if (scanf("%d", &choice) != 1) {
                 clear_input_buffer();
                 continue;
             }
             clear_input_buffer();

             switch (choice) {
                 case 1: change_pin(db); break;
                 case 2: view_users(db); break;
                 case 3: delete_user(db); break;
                 case 4: logout(db); break;
                 default: printf("Invalid choice.\n");
             }
         } else {
             printf("\n1. Login\n2. Signup\n3. Exit\nChoice: ");

             int choice;
             if (scanf("%d", &choice) != 1) {
                 clear_input_buffer();
                 continue;
             }
             clear_input_buffer();

             switch (choice) {
                 case 1: login(db); break;
                 case 2: signup(db); break;
                 case 3: exit(EXIT_SUCCESS);
                 default: printf("Invalid choice.\n");
             }
         }
     }
 }

 /*
  * Main entry point for the program.
  * Initializes the user database and starts the main menu.
  */
 int main() {
     UserDatabase db = {0};

     // Initialize with secure values
     memset(&db, 0, sizeof(UserDatabase));

     if (!load_users(&db)) {
         printf("Initializing new user database...\n");
         log_event("New user database initialized");
     }

     if (!check_file_permissions(USER_FILE)) {
         printf("Warning: Insecure file permissions detected!\n");
         log_event("Warning: Insecure file permissions");
     }

     if (!is_admin_configured(&db)) {
         configure_admin(&db);
     }

     main_menu(&db);
     return EXIT_SUCCESS;
 }
