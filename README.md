# Secure Vault & Identity Platform

A self-hosted PHP 8.1+ web application for storing and sharing **encrypted files and notes** with **two-factor authentication (2FA)**, **zero-knowledge client-side encryption**, **session management**, and **comprehensive audit logging** — built without any framework.

> **Portfolio Project** — Demonstrates cryptographic encryption (AES-256-GCM), zero-knowledge architecture (Web Crypto API), identity and access management (TOTP 2FA, recovery codes), and secure sharing with time-limited tokens.

---

## System Demonstration

![System Demonstration](assets/system-demonstration.gif)

### System Workflow

```text
[User Input (Login / Upload / Create Note)]
   │
   ▼
[Single-Entry API Router (api/api.php)]
   │
   ▼
[Service Layer Dispatch]
   │
   ├──► [Auth Service — Registration, Login, 2FA, Recovery]
   ├──► [Crypto Engine — AES-256-GCM Encrypt / Decrypt]
   ├──► [Vault Service — CRUD, Folders, Trash]
   └──► [Share Manager — Time-Limited Token Generation]
   │
   ▼
[PDO Singleton → MySQL (Parameterized Queries)]
   │
   ▼
[Encrypted Storage / Database Records]
   │
   ▼
[JSON Response → Frontend (Vanilla JS + Web Crypto API)]
```

### Agent / System Execution Demo

![Execution Demo](assets/agent-demo.png)

### Example Output

![Example Output](assets/example-output.png)

---

## Highlights

* **AES-256-GCM encryption** for all data at rest (files and notes) with random IVs and authentication tags
* **Zero-knowledge client-side encryption** using Web Crypto API (PBKDF2 + AES-GCM) so the server never sees plaintext
* **Two-step TOTP 2FA** with QR code setup and master recovery codes for device loss
* **Secure share links** with expiration, usage limits, and optional client-side decryption for zero-knowledge shares
* **Full session lifecycle management** — database-backed tracking, periodic regeneration, and user revocation
* **Defense-in-depth security** — CSRF tokens, HTTP security headers, rate limiting, IDOR prevention, prepared statements, and audit logging

### Built With

PHP 8.1+ • MySQL 8.0 • OpenSSL (AES-256-GCM) • Web Crypto API • robthree/twofactorauth • Vanilla JavaScript

---

## Why This Project Matters

Most web applications encrypt data only in transit (TLS) and store plaintext at rest, relying entirely on server-side access controls. If the database is compromised, all user data is immediately readable. Existing encrypted storage solutions often require complex infrastructure, client-side applications, or proprietary protocols.

This project explores a different approach: a **plain PHP application with no framework** that implements modern security engineering principles from scratch. Every file and note is encrypted before storage using authenticated encryption (AES-256-GCM), and the optional zero-knowledge mode ensures that even the server operator cannot read user content.

This project showcases concepts relevant to modern security engineering:

* **Authenticated Encryption** with AES-256-GCM ensuring confidentiality and integrity
* **Zero-Knowledge Architecture** where encryption keys never leave the client browser
* **Identity & Access Management** with TOTP 2FA, recovery codes, and session lifecycle control
* **Defense-in-Depth** combining CSRF protection, rate limiting, security headers, and audit logging

---

# Overview

**Secure Vault & Identity Platform** is a self-hosted web application that provides encrypted storage for files and notes with a full identity and access management layer. Users register with a password and optionally enable TOTP two-factor authentication (compatible with Google Authenticator and Authy). A master recovery code is generated at registration as a fallback for lost 2FA devices.

All data is encrypted using AES-256-GCM before being written to disk or database. Files are stored as `.enc` files with randomized names. Notes are stored as base64-encoded ciphertext. An optional **zero-knowledge mode** allows users to encrypt notes entirely in the browser using the Web Crypto API (PBKDF2 key derivation with 100,000 iterations + AES-GCM), ensuring the server never sees the plaintext.

The backend is a **single-entry-point JSON API** (`api/api.php?action=<name>`) that routes requests to five service classes: `Auth`, `Crypto`, `DB`, `Vault`, and `ShareManager`. The frontend is a single vanilla JavaScript file (`app.js`, ~844 lines) with no build tools, no frameworks, and no external dependencies. The database uses MySQL with 8 normalized tables and foreign key constraints.

---

# Problem Statement

Traditional web applications face a fundamental tension between usability and security:

* **Data at rest is typically unencrypted** — if the database or file system is compromised, all user data is immediately exposed in plaintext
* **Server-side encryption alone is insufficient** — the server holds the encryption key and can (or must) access plaintext, creating a single point of failure
* **Two-factor authentication is often treated as optional** — many applications lack built-in 2FA, recovery mechanisms, or proper session management
* **Secure file sharing without exposure** is difficult — standard file sharing mechanisms create copies of unencrypted data or use long-lived permanent links
* **No-framework PHP projects** often lack security fundamentals like CSRF protection, rate limiting, security headers, and audit logging

These limitations matter because sensitive data — personal notes, financial documents, identity files — requires both strong encryption and strong access controls. Existing solutions tend to sacrifice one for the other.

---

# Solution Approach

The system implements a **layered security architecture** with five core components working together to provide encrypted storage with identity management.

### Authentication & Identity Layer (`src/Auth.php`)

Handles all user lifecycle operations with defense-in-depth security.

* **Two-step login** — password verification first, then TOTP 2FA code (prevents timing attacks on 2FA)
* **TOTP 2FA** via `robthree/twofactorauth` with QR code generation for easy setup
* **Master recovery codes** — bcrypt-hashed fallback for lost 2FA devices
* **Account recovery flow** — identity verification + recovery code + new password issuance
* **Rate limiting** — per-IP attempt tracking with automatic decay (5 attempts / 5 minutes)
* **Session management** — database-backed tracking with periodic regeneration and user revocation

### Encryption Engine (`src/Crypto.php`)

Provides authenticated encryption for all stored data.

* **AES-256-GCM** encryption/decryption for text and files
* **Random IVs** (12 bytes) per encryption operation
* **Authentication tags** (16 bytes) for integrity verification
* Supports both **server-side** (server key) and **client-side** (user passphrase via Web Crypto API) modes

### Vault Service (`src/Vault.php`)

Manages all content operations with ownership verification.

* **File upload** — validated (type, size), encrypted, stored as `.enc`, originals deleted
* **Notes CRUD** — encrypted storage with optional folder organization and tagging
* **Folder management** — nested folder hierarchy with cascading deletes
* **Soft-delete with 30-day trash** — items recoverable until auto-purged
* **Audit logging** — every action recorded with IP and user agent

### Share Manager (`src/ShareManager.php`)

Enables secure, time-limited content sharing.

* **64-character hex tokens** with expiration dates and usage limits
* **Zero-knowledge sharing** — client-encrypted notes can be shared for browser-side decryption
* **XSS-safe output** — shared notes rendered with HTML escaping

### Frontend Application (`public/js/app.js`)

Single-file vanilla JavaScript client with no dependencies.

* **Web Crypto API** — PBKDF2 (100k iterations, SHA-256) + AES-GCM for zero-knowledge mode
* **CSRF protection** — tokens sent as both POST field and `X-CSRF-TOKEN` header
* **XSS prevention** — `escapeHtml()` utility for all dynamic DOM insertion
* **Tab-based dashboard** — vault, security, sessions, and trash views

### System Workflow

```text
[User Input (Browser)]
      │
      ▼
[Vanilla JS Frontend (app.js)]
      │
      ├──► [Web Crypto API — Zero-Knowledge Encrypt/Decrypt]
      │
      ▼
[CSRF Token Validation + Session Check]
      │
      ▼
[API Router (api/api.php?action=<name>)]
      │
      ├──► [Auth — Registration, Login, 2FA, Recovery]
      ├──► [Crypto — AES-256-GCM Server-Side Encryption]
      ├──► [Vault — File/Note CRUD, Folders, Trash]
      └──► [ShareManager — Token Generation, Public Access]
      │
      ▼
[PDO Singleton → MySQL (Parameterized Prepared Statements)]
      │
      ▼
[Encrypted File Storage (.enc) / Database Records]
      │
      ▼
[JSON Response → Frontend]
```

---

# Demo

## Running the Application

```bash
php -S localhost:8000
```

Navigate to `http://localhost:8000` in your browser. You will be redirected to `login.html`.

---

## Database Setup

```bash
mysql -u root < database/schema.sql
```

This creates the `secure_vault` database with all 8 required tables.

---

## Configuration

All configuration is in `config/config.php`. Key settings:

* **Database credentials** — `DB_USER` / `DB_PASS` (default: `vault_user` / `VaultSecret123!`)
* **Encryption key** — `ENCRYPTION_KEY` (must be changed for production; placeholder is a 256-bit hex string)
* **Storage directory** — `STORAGE_DIR` (encrypted files stored here)
* **Session settings** — regeneration interval, cookie hardening, SameSite policy

```bash
# Create the MySQL user before first run
mysql -u root -e "CREATE USER 'vault_user'@'localhost' IDENTIFIED BY 'VaultSecret123!';"
mysql -u root -e "GRANT ALL PRIVILEGES ON secure_vault.* TO 'vault_user'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"
```

---

## Example Output

![Example Output](assets/output.png)

```text
✓ Account created — recovery code: XXXX-XXXX-XXXX-XXXX
✓ 2FA enabled — scan QR code with Google Authenticator
✓ File encrypted and uploaded (AES-256-GCM)
✓ Note saved with zero-knowledge encryption
✓ Share link created — expires in 24 hours, max 5 uses
```

---

# Features

* **AES-256-GCM encrypted file storage** with random IVs and authentication tags
* **AES-256-GCM encrypted notes** with server-side or optional zero-knowledge encryption
* **Two-factor authentication (TOTP)** with QR code setup and Google Authenticator / Authy compatibility
* **Master recovery codes** for 2FA device loss (bcrypt-hashed, single-use)
* **Account recovery flow** — identity + recovery code + new password
* **Secure share links** with expiration, usage limits, and optional client-side decryption
* **Nested folder organization** for files and notes
* **Tagging system** for content categorization
* **30-day trash bin** with restore and auto-purge
* **Active session management** with user revocation
* **Comprehensive audit logging** with IP and user agent tracking
* **Rate limiting** for brute-force protection (5 attempts / 5 minutes / IP)
* **CSRF protection** on all POST requests
* **HTTP security headers** (CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection)
* **Zero external frontend dependencies** — pure vanilla JavaScript, HTML, and CSS

---

# Architecture

## High-Level Architecture

The application follows a **layered architecture** with a single-entry-point JSON API pattern. There is no MVC framework — five service classes handle distinct concerns, and a `switch` statement in `api/api.php` serves as the router.

### System Data Flow

```text
┌───────────────────────────────┐
│     User (Browser)            │
│  HTML + CSS + Vanilla JS      │
│  Web Crypto API (ZK mode)     │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│   API Router (api/api.php)    │
│   CSRF check → Session check  │
│   ?action=<name> routing      │
└───────────────┬───────────────┘
                │
      ┌─────────┼─────────┐
      ▼         ▼         ▼
┌──────────┐ ┌────────┐ ┌──────────┐
│  Auth    │ │ Crypto │ │  Vault   │
│  (395L)  │ │ (144L) │ │  (365L)  │
└────┬─────┘ └───┬────┘ └────┬─────┘
     │           │            │
     │           │     ┌──────┘
     │           │     ▼
     │           │ ┌──────────────┐
     │           │ │ShareManager  │
     │           │ │   (144L)     │
     │           │ └──────────────┘
     ▼           ▼         ▼
┌───────────────────────────────┐
│     PDO Singleton (DB.php)    │
│  Native prepared statements   │
│  EMULATE_PREPARES = false     │
└───────────────┬───────────────┘
                │
      ┌─────────┼─────────┐
      ▼         ▼         ▼
┌──────────┐ ┌────────┐ ┌──────────┐
│  MySQL   │ │ .enc   │ │  Audit   │
│  Tables  │ │ Files  │ │  Logs    │
│  (8 tbl) │ │        │ │          │
└──────────┘ └────────┘ └──────────┘
```

---

## Auth Layer

**Location:**

```text
src/Auth.php
```

**Responsibilities:**

* User registration with bcrypt password hashing (cost 12)
* Two-step login (password → TOTP code)
* TOTP 2FA setup, enable, disable, and QR code generation
* Master recovery code generation and verification
* Account recovery flow
* Database-backed session tracking with IP and user agent
* Rate limiting with per-IP attempt tracking

---

## Encryption Engine

**Location:**

```text
src/Crypto.php
```

**Responsibilities:**

* AES-256-GCM encryption/decryption for text (Base64 output)
* AES-256-GCM encryption/decryption for files (.enc storage)
* Random 12-byte IV generation per operation
* 16-byte authentication tag for integrity verification
* Server-side encryption (using server key from config)

---

## Vault Service

**Location:**

```text
src/Vault.php
```

**Responsibilities:**

* File upload with validation (type, size), encryption, and storage
* Notes CRUD with encrypted content
* Nested folder management
* Soft-delete with 30-day trash retention
* Tag-based filtering
* Audit log recording for all operations
* IDOR prevention via ownership verification

---

## Share Manager

**Location:**

```text
src/ShareManager.php
```

**Responsibilities:**

* Secure 64-character hex token generation
* Expiration-based access control
* Usage limit tracking
* Public access validation (token, expiry, use count)
* Decrypted file streaming and XSS-safe note rendering

---

## Database Schema

**Location:**

```text
database/schema.sql
```

**8 Tables:**

| Table | Purpose |
|-------|---------|
| `users` | User identity, password hash, 2FA secret, recovery code |
| `folders` | Nested folder hierarchy (self-referencing FK) |
| `notes` | Encrypted notes with IV, tags, soft-delete |
| `files` | Encrypted file metadata with IV, tags, soft-delete |
| `share_tokens` | Time-limited, usage-limited share links |
| `user_sessions` | Database-backed session tracking |
| `audit_logs` | Security audit trail with IP and user agent |
| `rate_limits` | Per-IP rate limiting for brute-force protection |

---

# Technical Highlights

* **Authenticated Encryption (AES-256-GCM)** — provides both confidentiality and integrity; authentication tag detects tampering
* **Zero-Knowledge Client-Side Encryption** — PBKDF2 (100,000 iterations, SHA-256) key derivation + AES-GCM in the browser via Web Crypto API; server stores only ciphertext
* **Two-Step 2FA Login** — password verified before TOTP code to prevent timing side-channel attacks on the 2FA secret
* **Native PDO Prepared Statements** — `EMULATE_PREPARES => false` ensures server-side parameter binding, eliminating SQL injection vectors
* **CSRF Protection** — 64-byte random token per session with timing-safe comparison (`hash_equals()`)
* **Content Security Policy** — `default-src 'self'` blocks inline scripts, external resources, and most XSS vectors
* **Soft-Delete with Auto-Purge** — 30-day trash retention with automatic cleanup prevents data loss while managing storage
* **Singleton Database Pattern** — single PDO connection per request prevents connection exhaustion

---

# Engineering Decisions

## Why No Framework?

The project deliberately avoids Laravel, Symfony, or any PHP framework to demonstrate core security concepts at the implementation level.

Benefits:

* Full control over every security mechanism (session handling, CSRF, input validation)
* No framework overhead or hidden abstractions obscuring the encryption layer
* Demonstrates that modern security patterns can be implemented in plain PHP
* Simpler deployment — only PHP and MySQL required, no Composer autoload chains or framework-specific server configuration

---

## Why AES-256-GCM?

GCM (Galois/Counter Mode) was chosen over CBC or other modes because it provides authenticated encryption — a single primitive that ensures both confidentiality and integrity.

Chosen for:

* **Built-in authentication** — no need for separate HMAC; the authentication tag (16 bytes) detects ciphertext tampering
* **Random access friendly** — GCM uses counter mode internally, enabling efficient partial reads (useful for file streaming)
* **Widely supported** — available via PHP's `openssl_encrypt()` and the Web Crypto API, enabling consistent server-side and client-side encryption
* **NIST-recommended** — approved for use in sensitive applications by NIST SP 800-38D

---

## Why Vanilla JavaScript (No React, Vue, or Build Tools)?

The frontend uses zero frameworks and zero build tools to keep the project self-contained and auditable.

Chosen for:

* **No supply chain risk** — no npm dependencies to audit or compromise
* **Web Crypto API availability** — the browser's native crypto library is more secure than any JavaScript polyfill
* **Auditability** — the entire frontend is one 844-line file that can be reviewed in minutes
* **Zero-knowledge encryption simplicity** — Web Crypto API provides PBKDF2 and AES-GCM natively, eliminating the need for crypto libraries

---

## Why Database-Backed Sessions?

PHP's default file-based sessions don't scale across requests and can't be revoked by the user.

Chosen for:

* **User-revocable sessions** — users can see and terminate active sessions from the dashboard
* **Audit trail** — session IP, user agent, and last activity are recorded for security monitoring
* **Periodic regeneration** — sessions rotate every 30 minutes to limit session fixation attacks
* **Cleanup on logout** — sessions are explicitly destroyed from both PHP and the database

---

# Challenges & Lessons Learned

## Challenge 1: Cipher Mismatch Between Config and Implementation

The config file defined `ENCRYPTION_CIPHER` as `aes-256-cbc`, but the encryption engine hardcoded `aes-256-gcm`. This mismatch went unnoticed because the config constant was never referenced in `Crypto.php`.

### Solution

* Identified the mismatch by tracing encryption calls from the API to `Crypto.php`
* Confirmed GCM is the correct choice (authenticated encryption) — CBC lacks integrity verification
* Updated `config/config.php` to match the actual cipher in use
* Ensured `Crypto.php` reads from config constants rather than hardcoding

### Result

Consistent cipher configuration between config and implementation. Future cipher changes only require updating one location.

---

## Challenge 2: Zero-Knowledge Key Derivation Performance

PBKDF2 with 100,000 iterations is computationally expensive and causes noticeable delay in the browser during note decryption. The user experience suffers if every note open triggers a full key derivation.

### Solution

* Derived the key once on login and cached it in a JavaScript variable for the session
* Used `crypto.subtle.deriveKey()` with `extractable: false` to prevent key extraction
* Re-derived the key only on page refresh or explicit re-authentication
* Chose 100,000 iterations as a balance between security and usability (OWASP recommends ≥60,000 for PBKDF2-SHA256)

### Result

Key derivation happens once per session (~200-500ms depending on device), and subsequent encrypt/decrypt operations are fast (<10ms).

---

## Challenge 3: Preventing IDOR (Insecure Direct Object Reference) Across All Endpoints

Every data operation must verify that the requesting user owns the resource. A single missed ownership check creates an IDOR vulnerability.

### Solution

* Every SQL query includes `AND user_id = ?` as part of the WHERE clause
* Share token creation verifies the item belongs to the authenticated user before generating a link
* Session revocation validates that the target session belongs to the requesting user
* File download verifies ownership before streaming decrypted content

### Result

Consistent ownership verification across all 20+ API endpoints. No endpoint returns data belonging to another user.

---

## Challenge 4: Secure File Upload Pipeline

File uploads must be validated, encrypted, stored securely, and the original temporary file must be deleted — all without creating temporary plaintext copies.

### Solution

* Validate file type (whitelist of extensions), size (50MB max), and upload error status
* Read the temporary file, encrypt it immediately with AES-256-GCM, and write the `.enc` file
* Delete the original temporary file with `@unlink()` immediately after encryption
* Store files with randomized hex names (16 random bytes = 32 hex characters) to prevent filename-based enumeration

### Result

No plaintext file ever persists on disk after the upload completes. Encrypted files have random names that don't reveal the original filename.

---

# Lessons Learned

Through this project I strengthened my understanding of:

* **Authenticated encryption (AES-256-GCM)** — IV generation, authentication tags, and the difference between confidentiality and integrity
* **Zero-knowledge architecture** — PBKDF2 key derivation, Web Crypto API, and the tradeoffs of client-side vs. server-side encryption
* **TOTP 2FA implementation** — secret generation, QR code provisioning, two-step login flows, and recovery code management
* **PDO security** — native prepared statements, `EMULATE_PREPARES => false`, and parameterized queries
* **Session security** — httponly/secure cookies, SameSite policy, periodic regeneration, and database-backed session tracking
* **Defense-in-depth** — CSRF tokens, security headers (CSP, X-Frame-Options), rate limiting, and input validation working together
* **No-framework PHP architecture** — single-entry-point routing, service class organization, and manual security implementation

---

# Repository Structure

```text
.
├── api/
│   └── api.php                        # Central JSON API router (single entry point)
│
├── config/
│   └── config.php                     # DB creds, encryption key, security headers, session config
│
├── database/
│   └── schema.sql                     # MySQL schema (8 tables with foreign keys)
│
├── public/
│   ├── index.html                     # Redirects to login.html
│   ├── login.html                     # Login + registration + 2FA setup
│   ├── dashboard.html                 # Main app (vault, security, sessions, trash tabs)
│   ├── share.html                     # Share link creation & public access
│   ├── download.php                   # Public file download via share token
│   ├── css/
│   │   └── style.css                  # Application stylesheet (461 lines)
│   └── js/
│       └── app.js                     # Single-file frontend (844 lines, vanilla JS)
│
├── src/
│   ├── Auth.php                       # Registration, login, 2FA, sessions, rate limiting
│   ├── Crypto.php                     # AES-256-GCM encrypt/decrypt (text + files)
│   ├── DB.php                         # PDO singleton connection
│   ├── Vault.php                      # File/note CRUD, folders, trash, audit logs
│   └── ShareManager.php              # Time-limited share tokens with access control
│
├── storage/
│   └── uploads/                       # Encrypted .enc files (gitignored)
│
├── composer.json                      # PHP dependencies (robthree/twofactorauth)
├── requirements.txt                   # PHP extension requirements
├── AGENTS.md                          # Developer/agent instructions
└── README.md
```

---

# Getting Started

## Clone Repository

```bash
git clone https://github.com/amir-khoshdel-louyeh/secure-vault-and-identity-platform.git

cd secure-vault-and-identity-platform
```

---

## Install Dependencies

```bash
composer install
```

---

## Set Up MySQL

```bash
# Create the database and tables
mysql -u root < database/schema.sql

# Create the application user
mysql -u root -e "CREATE USER IF NOT EXISTS 'vault_user'@'localhost' IDENTIFIED BY 'VaultSecret123!';"
mysql -u root -e "GRANT ALL PRIVILEGES ON secure_vault.* TO 'vault_user'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"
```

---

## Configuration

Edit `config/config.php` and update the following for production:

```php
define('ENCRYPTION_KEY', 'your-256-bit-hex-key-here');  // MUST change from placeholder
define('DB_HOST', 'localhost');
define('DB_NAME', 'secure_vault');
define('DB_USER', 'vault_user');
define('DB_PASS', 'your-secure-password');
```

Required PHP extensions:

* `ext-pdo` + `ext-pdo_mysql` — database connectivity
* `ext-openssl` — AES-256-GCM encryption
* `ext-mbstring` — multibyte string handling
* `ext-gd` — QR code generation for 2FA setup

---

## Run

```bash
php -S localhost:8000
```

Navigate to `http://localhost:8000` to access the application.

---

# Testing & Verification

## Manual Verification

### 1. Registration and 2FA Setup

```bash
# Open http://localhost:8000/login.html
# Register with username, email, and password
# Scan the QR code with Google Authenticator or Authy
# Save the displayed recovery code
```

### 2. Encrypted File Upload

```bash
# Login at http://localhost:8000/login.html
# Navigate to the Vault tab
# Upload a file — verify it appears in the vault list
# Check storage/uploads/ — verify the file has a .enc extension
```

### 3. Zero-Knowledge Note

```bash
# Create a note with a client-side encryption passphrase
# Open the note — verify it requires the passphrase to decrypt
# Access the note from a different browser session — confirm the server cannot read it
```

### 4. Secure Sharing

```bash
# Generate a share link for a file or note
# Set expiration and usage limits
# Open the share link in a private/incognito window
# Verify the file downloads or note displays correctly
# Attempt to access after expiration — verify access is denied
```

### Expected Outcome

* Registration creates a user with bcrypt-hashed password and optional TOTP 2FA
* Files are stored encrypted on disk with randomized filenames
* Notes are encrypted in the database with server-side or zero-knowledge encryption
* Share links expire and respect usage limits
* Session tracking shows active sessions with IP and user agent
* Audit log records all actions

---

# Future Improvements

* **Password-protected share links** — schema column exists (`share_tokens.password_hash`) but is not yet implemented
* **Folder management API endpoints** — backend supports folders but API routing is not wired
* **Tag filtering in API** — `Vault.php` supports tag filtering but `api.php` doesn't pass parameters through
* **HTTPS enforcement** — session cookie `secure` flag is currently `false`; enable for production with TLS
* **Config externalization** — support `.env` file loading or `config.local.php` overrides (`.gitignore` lists both but neither is wired)
* **End-to-end testing** — add PHPUnit tests for Auth, Crypto, Vault, and ShareManager services
* **Rich text editor** for notes (currently plain text only)
* **Search functionality** across files and notes
* **Docker deployment** — Dockerfile and docker-compose for one-command setup
* **Migration tooling** — schema versioning and migration management

---

# Author

## Amir Khoshdel Louyeh

### Connect

* **GitHub:** [github.com/amir-khoshdel-louyeh](https://github.com/amir-khoshdel-louyeh)
* **LinkedIn:** [linkedin.com/in/amir-khoshdel-louyeh](https://linkedin.com/in/amir-khoshdel-louyeh)

---

## Disclaimer

This project is intended for educational and research purposes only.
