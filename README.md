
# SecureFile Share

A secure file-sharing prototype built with **Python, Flask, SQLite, and
AES-256-GCM**. It combines file classification, encryption at rest,
multi-factor authentication, and recipient-bound sharing links with
expiry and revocation.

> **Project context:** This is an academic prototype developed as a
> summer-training project inspired by the training material at Securred
> Inc. It is not Securred's production software.

## Overview

Files are often shared through email attachments or ordinary links,
making it difficult for the owner to retain control after sharing.
SecureFile Share demonstrates a simplified workflow that brings
classification, encryption, identity checks, and sharing permissions
together.

### Core workflow

**Upload → Classify → Encrypt → Set permissions → Share secure link →
Revoke**

## Features

### Authentication and account security

-   User registration and login.
-   Passwords stored as salted password hashes.
-   Six-digit OTP-based multi-factor authentication (MFA).
-   OTP validity of five minutes, a maximum of five attempts, and
    single-use verification.
-   Generic login errors that do not disclose whether the email or
    password was incorrect.

### File upload and classification

-   File classifications: **Public, Private, and Confidential**.
-   Supported file types: PDF, DOCX, XLSX, PPTX, and TXT.
-   Maximum upload size: 10 MB.
-   Randomized stored filenames.
-   Public files are stored without encryption; non-public files require
    an encryption key.

### Encryption at rest

-   AES-256-GCM authenticated encryption for non-public files.
-   Passphrase-based key derivation using scrypt.
-   A fresh random salt and nonce for each file.
-   Incorrect keys and modified ciphertext are rejected.
-   Non-public file content is stored as ciphertext on disk.

### Controlled sharing

-   Cryptographically random 256-bit share tokens; only the token hash
    is stored.
-   Share links are bound to a recipient email address.
-   View-only or download permission.
-   Configurable link expiry from 1 to 720 hours.
-   Owners can revoke their own active links.
-   Link validity, recipient identity, and access permissions are
    checked on the server.

## Technology stack

  Area                                Technology
  ----------------------------------- ----------------------------------------------------
  Language                            Python 3.12
  Web framework                       Flask 3.1
  Authentication/session management   Flask-Login
  Database                            SQLite
  Cryptography                        Python `cryptography` package (AES-GCM and scrypt)
  Front end                           HTML, Jinja2
  Testing                             pytest 9.1
  Development environment             Visual Studio Code

## Project structure

``` text
securefile-share/
├── app.py
├── db.py
├── crypto_utils.py
├── test_security.py
├── requirements.txt
├── .gitignore
└── templates/
    ├── base.html
    ├── dashboard.html
    ├── download.html
    ├── login.html
    ├── open_share.html
    ├── register.html
    ├── share.html
    ├── shared.html
    ├── upload.html
    └── verify.html
```

Local database files, uploaded user files, Python caches, and editor
settings are excluded from version control.

## Getting started

### Prerequisites

-   Python 3.12
-   Git
-   pip

### 1. Clone the repository

``` bash
git clone https://github.com/itahisha-singh/securefile-share.git
cd securefile-share
```

### 2. Create and activate a virtual environment

**Windows PowerShell**

``` powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux**

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

``` bash
pip install -r requirements.txt
```

### 4. Run the application

``` bash
python app.py
```

Open the local URL printed by Flask in your terminal (typically
`http://127.0.0.1:5000/`).

> **Development note:** The training prototype uses a development-mode
> OTP flow. Do not expose this configuration to the public internet or
> use real sensitive files. Review the application configuration and
> replace development-only behavior before any deployment.

## Running the security tests

Run the automated test suite from the project directory:

``` bash
pytest -v
```

The current test suite reports **18 passed**.

### What the tests cover

-   Encrypted file content is not stored as plaintext.
-   Correct keys decrypt files; incorrect keys are rejected.
-   Ciphertext tampering is detected.
-   Authentication is required for protected routes.
-   One user cannot access another user's file by changing an identifier
    (IDOR protection).
-   Disallowed file types are rejected.
-   Shared-file access requires the intended recipient and the correct
    key.
-   View-only links block downloads.
-   Revoked and expired links stop working.
-   Only the file owner can revoke a share.
-   Raw share tokens are not stored.
-   Passwords are stored as hashes.
-   Login errors do not reveal which credential was incorrect.
-   OTP attempt limits and single-use verification are enforced.

## Security design notes

SecureFile Share demonstrates several layers of protection rather than
relying on a share URL alone:

1.  **Confidentiality:** non-public files are encrypted before being
    stored.
2.  **Integrity:** AES-GCM authentication detects ciphertext
    modification.
3.  **Identity:** login and OTP verification establish the user's
    session.
4.  **Authorization:** share access is restricted to the intended
    recipient and configured permission.
5.  **Lifecycle control:** expiry and owner-initiated revocation are
    checked by the server.

A recipient needs a valid share link, a matching authenticated identity,
and the correct encryption key.

## Limitations and future work

This is a learning prototype, not a production-ready file-sharing
service. The presentation identifies the following limitations:

-   CSRF protection is not implemented.
-   Rate limiting is not implemented.
-   There is no audit log.
-   OTP is printed in development mode.
-   The application uses HTTP on localhost.

Potential next steps include CSRF tokens, rate limiting, email-based OTP
delivery, HTTPS, a tamper-evident audit log, a production-grade
database, and a stronger document viewer.

## Screenshots

Screenshots from the project presentation can be added here. Suggested
files and captions:

-   `screenshots/upload-classification.png` --- upload form and
    classification options.
-   `screenshots/share-management.png` --- recipient, permission,
    expiry, and active-share controls.
-   `screenshots/recipient-view.png` --- recipient view with
    encryption-key entry.
-   `screenshots/security-tests.png` --- automated test run showing 18
    passing tests.

After adding the image files to the `screenshots/` folder, uncomment or
add Markdown image references, for example:

``` markdown
![Upload and classification](screenshots/upload-classification.png)
```

## Author

**Itahisha Singh**\
B.Tech, Computer Science and Engineering\
Jaypee Institute of Information Technology, Noida

-   GitHub: [@itahisha-singh](https://github.com/itahisha-singh)

------------------------------------------------------------------------

*Built as an academic summer-training prototype, May--July 2026.*
