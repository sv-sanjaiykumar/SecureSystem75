# SecureSystem 75

SecureSystem 75 is a secure web-based Flask application built for the Cyber Security domain and aligned with SDG 9: Industry, Innovation, and Infrastructure. The project focuses on secure user authentication, AES-based encryption and decryption, encrypted data storage in MongoDB, secure messaging, and encrypted file sharing between users.

## Features

- User registration with username, email, and bcrypt-hashed password
- User login and logout with Flask session management
- Personal text encryption and decryption
- Personal file encryption and decryption for files below 1 MB
- Secure encrypted messaging between registered users
- Secure encrypted file sharing between users
- MongoDB storage for users, encrypted text, encrypted files, messages, and shared files
- Dark themed responsive user interface using HTML and CSS
- Environment variable support for secrets and database configuration

## Tech Stack

- Frontend: HTML, CSS
- Backend: Python Flask
- Database: MongoDB
- Authentication: bcrypt
- Encryption: AES-256 style key length using `pycryptodome`
- Configuration: `python-dotenv`

## Project Structure

```text
SecureSystem75/
├── app.py
├── crypto_utils.py
├── requirements.txt
├── .env.example
├── README.md
├── model/
│   └── db.py
├── static/
│   └── style.css
└── templates/
    ├── base.html
    ├── index.html
    ├── register.html
    ├── login.html
    ├── dashboard.html
    ├── encrypt.html
    └── decrypt.html
```

## Implemented Modules

### 1. User Authentication

- New users can register with username, email, and password
- Passwords are hashed with `bcrypt` before storing
- Registered users can log in securely
- Session-based authentication protects secure routes
- Users can log out to end their session

### 2. Encryption and Decryption

- Text is encrypted before being stored in MongoDB
- Encryption keys are derived per user using a master secret and user ID
- Stored encrypted text can be decrypted only by the logged-in owner
- AES encryption is implemented in `crypto_utils.py`

### 3. Personal File Security

- Users can upload files smaller than 1 MB
- Files are encrypted as binary data before storage
- Only encrypted file bytes are stored in MongoDB
- Users can later decrypt and download their own files

### 4. Secure Messaging

- Users can send encrypted text messages to other registered users
- Messages are encrypted using the receiver's derived key
- Only the intended receiver can decrypt the message

### 5. Secure File Sharing

- Users can send encrypted files to other users
- Shared files are encrypted with the receiver's key
- Shared files are stored in MongoDB in a separate collection
- Only the intended receiver can decrypt and download the shared file

## MongoDB Collections

### `users`

```json
{
  "username": "example_user",
  "email": "user@example.com",
  "password_hash": "bcrypt_hash"
}
```

### `data`

Used for personal encrypted text and personal encrypted files.

```json
{
  "user_id": "user_object_id",
  "data_type": "text",
  "encrypted_text": "base64_ciphertext",
  "timestamp": "utc_timestamp"
}
```

```json
{
  "user_id": "user_object_id",
  "data_type": "file",
  "file_name": "image.png",
  "content_type": "image/png",
  "original_size": 23456,
  "encrypted_blob": "binary_ciphertext",
  "timestamp": "utc_timestamp"
}
```

### `messages`

```json
{
  "sender_id": "sender_object_id",
  "receiver_id": "receiver_object_id",
  "encrypted_message": "base64_ciphertext",
  "timestamp": "utc_timestamp"
}
```

### `shared_files`

```json
{
  "sender_id": "sender_object_id",
  "receiver_id": "receiver_object_id",
  "file_name": "report.pdf",
  "content_type": "application/pdf",
  "original_size": 84219,
  "encrypted_blob": "binary_ciphertext",
  "timestamp": "utc_timestamp"
}
```

## Routes

- `/` : Home page
- `/register` : Register a new user
- `/login` : Log in
- `/dashboard` : View user dashboard
- `/encrypt` : Encrypt text, store files, send messages, and share files
- `/decrypt` : Decrypt text, messages, stored files, and received shared files
- `/download/<record_id>` : Download decrypted personal file
- `/download/shared/<record_id>` : Download decrypted shared file
- `/logout` : Log out

## How It Works

### Registration and Login

1. A user registers with username, email, and password.
2. The password is hashed using bcrypt.
3. After login, the user session is created using Flask session.

### Text Encryption

1. The user enters plain text.
2. The application derives a user-specific key.
3. The text is encrypted and stored in MongoDB.
4. Raw text is never stored in the database.

### Personal File Encryption

1. The user uploads a file below 1 MB.
2. The file is read as bytes.
3. The bytes are encrypted before storage.
4. Encrypted binary data is stored in MongoDB.
5. The user can later decrypt and download it.

### Secure Messaging

1. The sender chooses a receiver and writes a message.
2. The message is encrypted using the receiver's derived key.
3. The receiver logs in and decrypts the message.

### Secure File Sharing

1. The sender selects a receiver and uploads a file.
2. The file is encrypted with the receiver's key.
3. The encrypted file is stored in the `shared_files` collection.
4. The receiver logs in and prepares a secure decrypted download.

## Setup Instructions

### 1. Clone or open the project

Open the project folder:

```powershell
cd D:\ccs-project\SecureSystem75
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

### 3. Configure environment variables

Create a `.env` file based on `.env.example`:

```env
FLASK_SECRET_KEY=replace-with-a-long-random-secret
APP_ENCRYPTION_SECRET=replace-with-a-different-long-random-secret
MONGO_URI=mongodb://127.0.0.1:27017/
MONGO_DB_NAME=secure_system_75
```

### 4. Start MongoDB

Make sure your MongoDB server is running locally before starting the app.

### 5. Run the application

```powershell
python app.py
```

### 6. Open in browser

```text
http://127.0.0.1:5000
```

## Security Practices Used

- Passwords are hashed with bcrypt
- Sensitive routes require login
- Encryption keys are not stored directly in the database
- Plain text and raw files are not stored in MongoDB
- Shared data is encrypted specifically for the receiver
- File size limits help reduce upload abuse
- Secrets are loaded from environment variables

## Current Status

The project currently supports:

- Secure user authentication
- Encrypted text storage
- Encrypted personal file storage
- Encrypted text message sharing
- Encrypted file sharing between users
- Dark themed responsive UI
- MongoDB backend integration

## Future Improvements

- Add CSRF protection with Flask-WTF
- Add email verification and password reset
- Add sent history for shared files and messages
- Add image preview for decrypted image files
- Add file type validation and malware scanning layer
- Add audit logs and admin monitoring
- Deploy with production WSGI server and HTTPS

## Author Note

SecureSystem 75 is designed as a cybersecurity-focused academic and practical full-stack project that demonstrates secure storage, controlled access, and encrypted communication in a web application environment.
